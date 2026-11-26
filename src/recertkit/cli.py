# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
"""Command line interface: ``recertkit <command>``.

Exit status: 0 = issued, or record VALID and — when a policy is given — policy ACCEPTED; 1 = REFUSED, record INVALID
or policy REJECTED; 3 = record VALID but the policy could NOT BE EVALUATED completely; 2 = usage or configuration
error, including a policy file that is not a well-formed policy (nothing is evaluated then).  Without ``--policy`` a
valid record exits 0: that is a statement about the record, not a release decision.  A release gate must pass
``--policy`` to ``verify-chain`` and release only on exit status 0.
"""
from __future__ import annotations
import argparse, collections, json, os, sys
from . import __version__
from .canon import load_json
from .engine import VERDICT_SEMANTICS, issue, issue_root, verify_chain, verify_link
from .inventory import make_inventory
from .methods import default_registry, load_plugins
from .policy import PolicyError, load_policy
from .profiles import DEFAULT_PROFILE, load_profile, profile_ref
from .report import Report
from .roots import read_root
from .signing import TrustStore, keygen


def _common(p, verify=True):
    p.add_argument("--profile", help="profile JSON (default: the built-in recertkit-default-1)")
    p.add_argument("--plugin", action="append", default=[], help="Python file exposing register(registry) with extra equivalence methods")
    p.add_argument("--evidence-dir", help="directory holding inventories and evidence files (default: next to the certificate)")
    p.add_argument("--json-report", help="write the machine-readable check report here")
    p.add_argument("--trust", action="append", required=verify, default=None, metavar="[ID=]PUBKEY.pem",
                   help="trusted public key (repeatable)" + ("" if verify else "; with it, issue also verifies the parent's signature"))
    if verify:
        p.add_argument("--policy", help="acceptance policy JSON: decides whether the unchecked conditions are acceptable (see docs/policy.md)")
        p.add_argument("--require-all-evidence", action="store_true", help="treat an absent detached evidence file as a record failure")


def _unchecked_summary(R):
    c = collections.Counter("judgement" if n["kind"].startswith("judgement ") else "trust assumption" if n["kind"].startswith("trust assumption ") else n["kind"]
                            for n in R.notices)
    return f"{len(R.notices)} unchecked item{'s' if len(R.notices) != 1 else ''}" + (" (" + ", ".join(f"{v} {k}" for k, v in sorted(c.items())) + ")" if c else "")


def _finish(R, args, label):
    verdict = "VALID" if R.ok else "INVALID"
    print(f"{label}: {verdict}" + (f" — conditional on {_unchecked_summary(R)}" if R.ok else f"  (failed: {', '.join(R.fails)})"))
    if R.policy_name is None:
        pv = None; print("POLICY: none applied — record verification is not a release decision")
    else:
        pv = R.policy_verdict
        n = len(R.policy_records)
        why = {"ACCEPTED": f"  ({n} policy check{'s' if n != 1 else ''} evaluated and satisfied)",
               "REJECTED": "  (record invalid)" if not R.ok else f"  (failed: {', '.join(R.policy_fails)})",
               "NOT EVALUATED": f"  (could not be evaluated, and is therefore not accepted: {', '.join(R.policy_not_evaluated)})"}[pv]
        print(f"POLICY {R.policy_name}: {pv}{why}")
    print(VERDICT_SEMANTICS)
    if getattr(args, "json_report", None): R.dump(args.json_report, verdict=verdict, policy_verdict=pv, semantics=VERDICT_SEMANTICS)
    return 0 if R.accepted else (3 if R.ok and pv == "NOT EVALUATED" else 1)


def main(argv=None) -> int:
    """Run the CLI; input problems (missing or malformed files) are usage errors (exit 2), never tracebacks.

    Any input that cannot be processed ends with exit status 2 and one line on stderr — including a certificate, a
    declaration or a plugin whose content has an unexpected shape.  Nothing is accepted in that case.  Set
    ``RECERTKIT_DEBUG=1`` to see the traceback instead."""
    try:
        return _main(argv)
    except PolicyError as ex:
        print(f"recertkit: policy error (PolicyError): {ex}. The policy file is not a well-formed policy: nothing was evaluated and nothing is accepted.", file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError) as ex:
        print(f"recertkit: error: {type(ex).__name__}: {ex}", file=sys.stderr)
        return 2
    except Exception as ex:                                  # malformed content (wrong JSON shape, null members, a missing plugin file)
        if os.environ.get("RECERTKIT_DEBUG"): raise
        print(f"recertkit: error: malformed input ({type(ex).__name__}: {ex}); nothing was issued or accepted", file=sys.stderr)
        return 2


def _main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="recertkit", description=__doc__)
    ap.add_argument("--version", action="version", version=f"recertkit {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("keygen", help="create an Ed25519 key pair"); p.add_argument("--private", required=True); p.add_argument("--public", required=True)
    p = sub.add_parser("inventory", help="write an inventory (sha256 per artifact)"); p.add_argument("files", nargs="+"); p.add_argument("--out", required=True)
    p = sub.add_parser("profile", help="print the built-in profile and its digest")
    p = sub.add_parser("checks", help="print the catalogue of verifier checks (markdown)")
    p = sub.add_parser("texts", help="print the SHA-256 of each judgement and trust-assumption text of a certificate (to pin reviewed texts in a policy)"); p.add_argument("--certificate", required=True)
    p = sub.add_parser("root-info", help="show what the root adapter reads from a root certificate"); p.add_argument("--root", required=True); p.add_argument("--profile")
    p = sub.add_parser("root-issue", help="sign a minimal root attestation")
    p.add_argument("--claim", required=True, help="JSON file with the claim fields"); p.add_argument("--role", action="append", required=True, metavar="ROLE=FILE")
    p.add_argument("--inventory", help="inventory of the certified configuration; its digest is bound into the root")
    p.add_argument("--basis", required=True, help="how the claim was established (free text)"); p.add_argument("--decision", default="certified")
    p.add_argument("--key", required=True); p.add_argument("--key-id", required=True); p.add_argument("--out", required=True); p.add_argument("--profile")
    p = sub.add_parser("issue", help="apply the profile checks to a change declaration and, only if they pass, sign a derived certificate")
    p.add_argument("--parent", required=True); p.add_argument("--spec", required=True); p.add_argument("--parent-inventory", required=True); p.add_argument("--derived-inventory", required=True)
    p.add_argument("--key", required=True); p.add_argument("--key-id", required=True); p.add_argument("--out", required=True); _common(p, verify=False)
    p = sub.add_parser("verify", help="verify one derived certificate against its parent")
    p.add_argument("--certificate", required=True); p.add_argument("--parent", required=True); _common(p)
    p = sub.add_parser("verify-chain", help="verify a root and every derived link after it")
    p.add_argument("--root", required=True); p.add_argument("--links", nargs="+", required=True); _common(p)
    args = ap.parse_args(argv)

    if args.cmd == "keygen":
        keygen(args.private, args.public); print(f"wrote {args.private} (keep secret) and {args.public}"); return 0
    if args.cmd == "inventory":
        text = make_inventory(args.files)                 # raises before anything is written (duplicate names, unreadable files)
        open(args.out, "w", encoding="utf-8").write(text); print(f"wrote {args.out} ({len(args.files)} artifacts)"); return 0
    if args.cmd == "texts":
        import hashlib
        cert = load_json(args.certificate)
        print(json.dumps({k: {n: hashlib.sha256(str(t).encode("utf-8")).hexdigest() for n, t in sorted((cert.get(k) or {}).items())} for k in ("judgements", "trust_assumptions")}, indent=1)); return 0
    if args.cmd == "checks":
        from .checks import markdown
        print(markdown()); return 0
    if args.cmd == "profile":
        print(json.dumps({"profile": DEFAULT_PROFILE, "ref": profile_ref(DEFAULT_PROFILE)}, indent=1)); return 0
    profile = load_profile(getattr(args, "profile", None))
    if args.cmd == "root-info":
        print(json.dumps(read_root(load_json(args.root), profile).describe(), indent=1)); return 0
    if args.cmd == "root-issue":
        roles = dict(r.split("=", 1) for r in args.role)
        root = issue_root(load_json(args.claim), roles, args.decision, args.basis, args.key, args.key_id, args.out, profile, inventory=args.inventory)
        print(f"issued root {root['certificate_id']} -> {args.out}"); return 0
    registry = load_plugins(default_registry(), args.plugin)
    R = Report(require_all_evidence=getattr(args, "require_all_evidence", False))
    store = TrustStore(args.trust) if args.trust else None
    if args.cmd == "issue":
        cert = issue(R, args.parent, load_json(args.spec), args.parent_inventory, args.derived_inventory, args.key, args.key_id, args.out, profile, registry, args.evidence_dir,
                     spec_dir=os.path.dirname(os.path.abspath(args.spec)), store=store)
        if args.json_report: R.dump(args.json_report, verdict="ISSUED" if cert else "REFUSED")
        if cert is None:
            print(f"REFUSED: the declaration violates profile {profile['name']} (failed: {', '.join(R.fails)}); nothing was signed"); return 1
        print(f"issued {cert['certificate_id']} -> {args.out}")
        print("Issuance applies the profile checks to the declaration; it is not a release decision. Release gate: recertkit verify-chain --trust ... --policy ...")
        return 0
    policy = load_policy(args.policy) if args.policy else None
    if policy is not None: R.policy_name = policy["name"]
    if args.cmd == "verify":
        verify_link(R, args.certificate, args.parent, store, profile, registry, args.evidence_dir, policy=policy); return _finish(R, args, "LINK RECORD")
    if args.cmd == "verify-chain":
        verify_chain(R, args.root, args.links, store, profile, registry, args.evidence_dir, policy=policy); return _finish(R, args, "CHAIN RECORD")
    return 2


if __name__ == "__main__":
    sys.exit(main())
