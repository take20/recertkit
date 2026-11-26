# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
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
A member with a value of the wrong type (``0`` or ``"true"`` for a boolean, ``null`` for any member), a member that
appears twice, and a policy that states no condition at all are configuration errors (``PolicyError``, exit status
2): nothing is evaluated and nothing is accepted.  ``accepted_judgements`` and ``accepted_assumptions`` are
ALLOW-lists: they limit what a certificate may rest on; they do not require a certificate to carry those items.

``require_all_evidence``   true: every evidence file named by a certificate must be present (no detached evidence)
``coverage_by_judgement``  "forbid", "allow", or a list of artifact names that may be covered by a judgement
``residual_rebuilt``       "forbid" or "allow": artifacts whose bytes changed without being part of the block
``unrecorded``             "forbid" or "allow": artifacts not recorded for the derived configuration
``reference_kinds``        list of accepted comparison references, e.g. ["parent_artifact", "parent_link"]
``reference_by_declaration`` "forbid" or "allow": comparisons whose reference the verifier could NOT tie to the
                           certificate by a digest recorded in the transcript (it is then identified by name only)
``binding_levels``         list of accepted root binding levels, e.g. ["digest"] (excludes "identifiers-only", "unbound")
``transcript_mapping``     "forbid" or "allow": transcripts in a foreign layout mapped by issuer-declared pointers
``renamed_replacement``    "forbid" or "allow": equivalence entries whose subjects replace parent artifacts of OTHER names
                           (that the new artifact takes the old one's place is then the judgement 'replacement_correspondence')
``multi_artifact_block``   "forbid" or "allow": equivalence entries with several subjects or several replaced artifacts
                           (which file the comparison exercised, and which new file stands for which old one, is then
                           the same judgement)
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
        "root_adapters", "require_prospective", "renamed_replacement", "multi_artifact_block"}
SINGLE_LINK = "not verified in this run: the parent is itself a derived certificate — verify the whole chain with verify-chain"


class PolicyError(ValueError):
    pass


BOOLEANS = ("require_all_evidence", "require_prospective")
SWITCHES = ("residual_rebuilt", "unrecorded", "transcript_mapping", "reference_by_declaration", "renamed_replacement", "multi_artifact_block")
NAME_LISTS = ("reference_kinds", "binding_levels", "root_adapters")
PINNED = ("accepted_judgements", "accepted_assumptions")


def _names(v) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) and x for x in v) and len(set(v)) == len(v)


def stated_conditions(p: dict) -> list:
    """The members of ``p`` that state a condition, i.e. that produce a policy check on every link."""
    return sorted([k for k in BOOLEANS if p.get(k) is True] + [k for k in SWITCHES if p.get(k) == "forbid"]
                  + [k for k in ("coverage_by_judgement",) if k in p and p[k] != "allow"]
                  + [k for k in NAME_LISTS + ("enumeration_domains",) if k in p] + [k for k in PINNED if k in p and p[k] != "*"])


def validate_policy(p) -> dict:
    """Return ``p`` if it is a well-formed policy that states at least one condition; raise ``PolicyError`` otherwise.

    Every member has one JSON type and a closed set of values.  A value of another type (``0``, ``"true"``, ``null``,
    ``[]`` for a boolean; ``null`` for any member) is an error, never a way to switch a condition off: a condition is
    left unstated by omitting its member.  A policy that states no condition is an error too, because ``ACCEPTED``
    always means that at least one stated condition was evaluated."""
    if not isinstance(p, dict) or not isinstance(p.get("name"), str) or not p["name"]: raise PolicyError("a policy needs a name")
    unknown = sorted(set(p) - KEYS)
    if unknown: raise PolicyError(f"unknown policy members {unknown}")
    show = lambda k: json.dumps(p[k])[:40]
    if "description" in p and not isinstance(p["description"], str): raise PolicyError("description must be a string")
    for k in BOOLEANS:
        if k in p and not isinstance(p[k], bool): raise PolicyError(f"{k} must be true or false (a JSON boolean), not {show(k)}; omit the member to leave the condition unstated")
    for k in SWITCHES:
        if k in p and not (isinstance(p[k], str) and p[k] in ("forbid", "allow")): raise PolicyError(f"{k} must be 'forbid' or 'allow', not {show(k)}")
    if "coverage_by_judgement" in p:
        cj = p["coverage_by_judgement"]
        if not (isinstance(cj, str) and cj in ("forbid", "allow")) and not _names(cj): raise PolicyError(f"coverage_by_judgement must be 'forbid', 'allow' or a list of distinct artifact names, not {show('coverage_by_judgement')}")
    for k in PINNED:
        if k not in p: continue
        v = p[k]
        if (isinstance(v, str) and v == "*") or _names(v): continue
        if isinstance(v, dict) and all(isinstance(x, str) and (x == "*" or (len(x) == 64 and set(x) <= set("0123456789abcdef"))) for x in v.values()): continue
        raise PolicyError(f"{k} must be '*', a list of distinct names, or an object mapping names to '*' or a SHA-256 of the accepted text, not {show(k)}")
    for k in NAME_LISTS:
        if k in p and not _names(p[k]): raise PolicyError(f"{k} must be a list of distinct, non-empty strings, not {show(k)}")
    if "enumeration_domains" in p:
        ed = p["enumeration_domains"]
        if not (isinstance(ed, dict) and all(isinstance(v, int) and not isinstance(v, bool) and v > 0 for v in ed.values())):
            raise PolicyError(f"enumeration_domains must map artifact names to positive integers, not {show('enumeration_domains')}")
    if not stated_conditions(p):
        raise PolicyError("the policy states no condition (every member is absent, false, 'allow' or '*'); to verify the record alone, run without --policy")
    return p


def _no_duplicates(pairs):
    d = {}
    for k, v in pairs:
        if k in d: raise PolicyError(f"member {k!r} appears more than once")
        d[k] = v
    return d


def _no_constant(name):
    raise PolicyError(f"{name} is not a JSON value")


def load_policy(path: str) -> dict:
    """Read and validate a policy file.  A file that is not a well-formed policy raises ``PolicyError``."""
    try:
        with open(path, encoding="utf-8") as f: p = json.load(f, object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except json.JSONDecodeError as ex:
        raise PolicyError(f"not a JSON document ({ex})") from None
    return validate_policy(p)


def apply_policy(R, policy: dict, state: dict):
    """Evaluate ``policy`` on the verified state of one link; results are recorded as ``policy.<member>[link]``."""
    validate_policy(policy)                                   # also when the policy did not come from load_policy
    link = state["link"]; P = lambda member: f"policy.{member}[{link}]"
    entries = state["entries"]
    if state["parent_kind"] == "derived" and not state["chain_verified"]:
        R.policy(P("chain"), None, "a policy decides about a whole chain; the links before this one were not evaluated in this run — use verify-chain")
    if policy.get("require_all_evidence") is True:
        missing = state["evidence_absent"]
        R.policy(P("require_all_evidence"), not missing, "every evidence file is present" if not missing else f"absent: {missing}")
    cj = policy.get("coverage_by_judgement")
    if "coverage_by_judgement" in policy and cj != "allow":
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
    if policy.get("renamed_replacement") == "forbid":
        ren = sorted(i for i, e in entries.items() if e.get("renamed"))
        R.policy(P("renamed_replacement"), not ren, "every replaced parent artifact is replaced under its own name" if not ren
                 else f"parent artifacts replaced under another name (judgement 'replacement_correspondence'): {ren}")
    if policy.get("multi_artifact_block") == "forbid":
        blocks = sorted(i for i, e in entries.items() if e.get("multi_artifact"))
        R.policy(P("multi_artifact_block"), not blocks, "every equivalence entry has one subject and replaces at most one artifact" if not blocks
                 else f"entries that compare several artifacts as one block (judgement 'replacement_correspondence'): {blocks}")
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
        if member in policy and acc != "*":
            have = state[key]; pins = acc if isinstance(acc, dict) else {n: "*" for n in acc}
            extra = sorted(set(have) - set(pins)); other = sorted(n for n in have if n in pins and pins[n] != "*" and pins[n] != have[n])
            by_name = sorted(n for n in have if pins.get(n) == "*")
            R.policy(P(member), not (extra or other), (f"every one of the {key} is accepted by the policy" + (f" (by NAME only, text not pinned: {by_name})" if by_name else " with the pinned text"))
                     if not (extra or other) else f"not accepted: {extra}; text differs from the text the policy pins: {other}")
    if "root_adapters" in policy:
        ra = state["root_adapter"]
        if ra is None: R.policy(P("root_adapters"), None, f"root format {SINGLE_LINK}")
        else: R.policy(P("root_adapters"), ra in policy["root_adapters"], f"root format {ra!r}")
    if policy.get("require_prospective") is True:
        st = str(state["issuance_status"])
        R.policy(P("require_prospective"), st.startswith("prospective"), f"declared issuance_status: {st[:60]!r}")
