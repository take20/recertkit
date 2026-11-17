"""Acceptance policies: the relying party's decision about CONDITIONS.

Record verification answers "is this chain internally consistent under the profile?".  It deliberately accepts chains
that rest on written judgements, trust assumptions, undistributed evidence or weak root bindings, and prints them.
Whether such conditions are acceptable for a release is a separate decision that belongs to the relying party.  A
policy states that decision as data, and ``verify`` / ``verify-chain --policy FILE`` apply it to every link.

A policy is evaluated on the LINK STATE the engine established while verifying the record (``engine.link_state``) —
never on fields the issuer wrote into the certificate where the engine has a verified value.  A member whose input
was not verified in this run (for example the root format, when a single link whose parent is itself a derived
certificate is verified) is reported as NOT EVALUATED, and a policy with such a member is not ACCEPTED.  A policy is
a statement about a whole chain: applied to a single link whose parent is a derived certificate, it is never ACCEPTED,
because the earlier links were not evaluated (``policy.chain``).

A policy is a JSON object.  Every member except ``name`` is optional; an absent member imposes no restriction.

``require_all_evidence``   true: every evidence file named by a certificate must be present (no detached evidence)
``coverage_by_judgement``  "forbid", "allow", or a list of artifact names that may be covered by a judgement
``residual_rebuilt``       "forbid" or "allow": artifacts whose bytes changed without being part of the block
``unrecorded``             "forbid" or "allow": artifacts not recorded for the derived configuration
``reference_kinds``        list of accepted comparison references, e.g. ["parent_artifact", "parent_link"]
``reference_by_declaration`` "forbid" or "allow": comparisons whose reference the verifier could NOT tie to the
                           certificate by a digest recorded in the transcript (it is then identified by name only)
``binding_levels``         list of accepted root binding levels, e.g. ["digest"] (excludes "identifiers-only", "unbound")
``transcript_mapping``     "forbid" or "allow": transcripts in a foreign layout mapped by issuer-declared pointers
``enumeration_domains``    {artifact: N}: every equivalence entry must be an exhaustive enumeration whose subjects are
                           all listed here and whose enumerated domain has exactly N inputs for each of them
``accepted_judgements``    "*", a list of judgement names, or an object {name: "*" | sha256}: with a digest, the judgement is
                           accepted only if its TEXT has that SHA-256 (the text the relying party actually reviewed);
                           a name alone accepts whatever text a certificate carries under that name
``accepted_assumptions``   the same, for trust assumptions
``root_adapters``          list of accepted root formats, e.g. ["gate-2.0"]
``require_prospective``    true: reject certificates that do not DECLARE prospective issuance (the declaration is the issuer's)
"""
from __future__ import annotations
import json

KEYS = {"name", "description", "require_all_evidence", "coverage_by_judgement", "residual_rebuilt", "unrecorded", "reference_kinds",
        "binding_levels", "transcript_mapping", "reference_by_declaration", "enumeration_domains", "accepted_judgements", "accepted_assumptions",
        "root_adapters", "require_prospective"}
SINGLE_LINK = "not verified in this run: the parent is itself a derived certificate — verify the whole chain with verify-chain"


class PolicyError(ValueError):
    pass


def load_policy(path: str) -> dict:
    p = json.load(open(path, encoding="utf-8"))
    if not isinstance(p, dict) or not isinstance(p.get("name"), str) or not p["name"]: raise PolicyError("a policy needs a name")
    unknown = sorted(set(p) - KEYS)
    if unknown: raise PolicyError(f"unknown policy members {unknown}")
    for k in ("residual_rebuilt", "unrecorded", "transcript_mapping", "reference_by_declaration"):
        if k in p and p[k] not in ("forbid", "allow"): raise PolicyError(f"{k} must be 'forbid' or 'allow'")
    cj = p.get("coverage_by_judgement")
    if cj is not None and cj not in ("forbid", "allow") and not isinstance(cj, list): raise PolicyError("coverage_by_judgement must be 'forbid', 'allow' or a list")
    for k in ("accepted_judgements", "accepted_assumptions"):
        v = p.get(k)
        if v is None or v == "*" or (isinstance(v, list) and all(isinstance(x, str) for x in v)): continue
        if isinstance(v, dict) and all(isinstance(x, str) and (x == "*" or (len(x) == 64 and set(x) <= set("0123456789abcdef"))) for x in v.values()): continue
        raise PolicyError(f"{k} must be '*', a list of names, or an object mapping names to '*' or a SHA-256 of the accepted text")
    for k in ("reference_kinds", "binding_levels", "root_adapters"):
        if k in p and not isinstance(p[k], list): raise PolicyError(f"{k} must be a list")
    ed = p.get("enumeration_domains")
    if ed is not None and not (isinstance(ed, dict) and all(isinstance(v, int) and not isinstance(v, bool) and v > 0 for v in ed.values())):
        raise PolicyError("enumeration_domains must map artifact names to positive integers")
    return p


def apply_policy(R, policy: dict, state: dict):
    """Evaluate ``policy`` on the verified state of one link; results are recorded as ``policy.<member>[link]``."""
    link = state["link"]; P = lambda member: f"policy.{member}[{link}]"
    entries = state["entries"]
    if state["parent_kind"] == "derived" and not state["chain_verified"]:
        R.policy(P("chain"), None, "a policy decides about a whole chain; the links before this one were not evaluated in this run — use verify-chain")
    if policy.get("require_all_evidence"):
        missing = state["evidence_absent"]
        R.policy(P("require_all_evidence"), not missing, "every evidence file is present" if not missing else f"absent: {missing}")
    cj = policy.get("coverage_by_judgement")
    if cj is not None and cj != "allow":
        arts = sorted(state["judgement_covered"])
        bad = arts if cj == "forbid" else sorted(set(arts) - set(cj))
        R.policy(P("coverage_by_judgement"), not bad, "no changed artifact rests on a judgement outside the policy" if not bad else f"covered by judgement only: {bad}")
    for cat in ("residual_rebuilt", "unrecorded"):
        if policy.get(cat) == "forbid":
            items = sorted(state["categories"][cat])
            R.policy(P(cat), not items, f"no {cat} artifacts" if not items else f"{cat}: {items}")
    if "reference_kinds" in policy:
        kinds = sorted({str(e["reference_kind"]) for e in entries.values()} - set(policy["reference_kinds"]))
        R.policy(P("reference_kinds"), not kinds, f"references are of kinds {policy['reference_kinds']}" if not kinds else f"not accepted: {kinds}")
    if policy.get("reference_by_declaration") == "forbid":
        named = sorted(i for i, e in entries.items() if e["reference_binding"] not in ("digest", "unverified-parent"))
        pending = sorted(i for i, e in entries.items() if e["reference_binding"] == "unverified-parent")
        if named: R.policy(P("reference_by_declaration"), False, f"the verifier could not tie the reference to the certificate by a transcript digest for: {named}")
        elif pending: R.policy(P("reference_by_declaration"), None, f"reference inherited from the parent link for {pending}; {SINGLE_LINK}")
        else: R.policy(P("reference_by_declaration"), True, "for every comparison the verifier matched the transcript's reference digest")
    if "binding_levels" in policy:
        levels = state["binding_levels"]
        if levels is None: R.policy(P("binding_levels"), None, f"root binding levels {SINGLE_LINK}")
        else:
            bad = sorted(f"{k}={v}" for k, v in levels.items() if v not in policy["binding_levels"])
            R.policy(P("binding_levels"), not bad, f"root bindings are at levels {policy['binding_levels']}" if not bad else f"not accepted: {bad}")
    if policy.get("transcript_mapping") == "forbid":
        mapped = sorted(i for i, e in entries.items() if e["mapped"])
        R.policy(P("transcript_mapping"), not mapped, "all transcripts use the standard layout" if not mapped else f"mapped by issuer-declared pointers: {mapped}")
    if "enumeration_domains" in policy:
        want = policy["enumeration_domains"]; bad = []
        for i, e in sorted(entries.items()):
            for s in e["subjects"] or ["(no subject)"]:
                if e["domain_size"] is None: bad.append(f"{i}: not an exhaustive enumeration")
                elif s not in want: bad.append(f"{i}: no accepted domain for {s}")
                elif want[s] != e["domain_size"]: bad.append(f"{i}: {s} enumerated on {e['domain_size']} inputs, the policy requires {want[s]}")
        R.policy(P("enumeration_domains"), not bad, "every enumerated domain has the size the policy requires for its subjects" if not bad else "; ".join(bad))
    for member, key in (("accepted_judgements", "judgements"), ("accepted_assumptions", "trust_assumptions")):
        acc = policy.get(member)
        if acc is not None and acc != "*":
            have = state[key]; pins = acc if isinstance(acc, dict) else {n: "*" for n in acc}
            extra = sorted(set(have) - set(pins)); other = sorted(n for n in have if n in pins and pins[n] != "*" and pins[n] != have[n])
            by_name = sorted(n for n in have if pins.get(n) == "*")
            R.policy(P(member), not (extra or other), (f"every one of the {key} is accepted by the policy" + (f" (by NAME only, text not pinned: {by_name})" if by_name else " with the pinned text"))
                     if not (extra or other) else f"not accepted: {extra}; text differs from the text the policy pins: {other}")
    if "root_adapters" in policy:
        ra = state["root_adapter"]
        if ra is None: R.policy(P("root_adapters"), None, f"root format {SINGLE_LINK}")
        else: R.policy(P("root_adapters"), ra in policy["root_adapters"], f"root format {ra!r}")
    if policy.get("require_prospective"):
        st = str(state["issuance_status"])
        R.policy(P("require_prospective"), st.startswith("prospective"), f"declared issuance_status: {st[:60]!r}")
