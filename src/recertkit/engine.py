# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
"""Issue and verify derived certificates.

A derived certificate states: *if the listed judgements and assumptions hold, the parent's claim also holds for the
changed configuration*, because every changed artifact is accounted for, the changed block is shown equivalent to
what it replaces, and everything else is identical or explicitly argued.  A VALID RECORD means:

* the certificate and its parent are signed by keys in the relying party's trust store, and the certificate names
  its parent by digest;
* the certificate was issued under the profile the verifier applies;
* the claim is the parent's claim, unchanged, and satisfies the profile's constraints;
* every artifact of the parent and derived inventories is declared in exactly one category, the declaration agrees
  with the digests, and no fixed role changed;
* COVERAGE, per side: a changed artifact that exists in the DERIVED inventory must be a subject of exactly one
  equivalence entry or be covered by a named written judgement; a changed artifact that exists in the PARENT
  inventory must be replaced by exactly one equivalence entry or be covered by a named written judgement.  The same
  file name on the two sides is two obligations: naming the parent's file never covers the derived file.  Each
  judgement-covered artifact is printed as not covered by equivalence evidence;
* LINKAGE: each equivalence transcript is about the subject artifacts of the DERIVED inventory (by digest), and its
  reference is tied to the PARENT configuration: it consists of exactly the parent artifacts the entry replaces (by
  digest), or it is the reference the parent link's subjects — exactly the artifacts replaced now — were shown
  equivalent to, or it is a named specification whose link to the parent is a written judgement (printed);
* the configuration is bound to the root at the declared levels, and levels weaker than a digest are printed;
* every evidence file has the digest the certificate records, and each transcript satisfies its method's checks;
* the risk budget is the parent's, exactly (deterministic transfer: alpha = 0 — the transfer adds no sampling error;
  it does not mean that a wrong judgement or a faulty tool carries no risk).

A VALID RECORD does NOT mean that the written judgements and trust assumptions are true, and it is not a release
decision.  Whether the printed conditions are acceptable is decided by an acceptance policy (``policy``).
"""
from __future__ import annotations
import datetime, hashlib, json, os, re, uuid
from . import CERT_VERSION, __version__
from .canon import dec, evidence_path, load_json, resolve_path, sha_file, sha_obj, sha_raw
from .inventory import InventoryError, parse_inventory
from .methods import STANDARD_SCHEMA, _is_int, transcript_field, transcript_subject_names
from .policy import apply_policy
from .profiles import REFERENCE_KINDS, profile_ref
from .roots import RootError, read_root
from .signing import sign

CATEGORIES = ("changed", "unchanged", "residual_rebuilt", "unrecorded")
CORRESPONDENCE = "replacement_correspondence"   # judgement required when an equivalence entry is not name-aligned (see _equivalence_entry)
VERDICT_SEMANTICS = ("A VALID record is a CONDITIONAL statement: signatures, parent linkage, change coverage, evidence linkage and "
                     "profile consistency were checked; the written judgements, trust assumptions and whatever established the root "
                     "claim were not, and are printed. It is not a release decision; apply an acceptance policy for that.")


class ParentView:
    def __init__(self, parent, profile):
        self.kind = "derived" if parent.get("certificate_version") == CERT_VERSION else "root"
        self.cert = parent
        if self.kind == "derived":
            self.claim = dict(parent.get("claim", {})); self.risk = parent.get("risk_budget", {}).get("delta_derived")
            self.decision = "transfer"; self.root = None
        else:
            self.root = read_root(parent, profile)
            self.claim, self.risk, self.decision = self.root.claim, self.root.risk, self.root.decision


def _claim_checks(R, claim, profile, pv):
    fields = profile["claim_fields"]
    R.check("claim.fields", isinstance(claim, dict) and set(claim) == set(fields), f"exactly {sorted(fields)}")
    bad = []
    for f, c in fields.items():
        v = claim.get(f) if isinstance(claim, dict) else None
        if c["kind"] == "string" and not (isinstance(v, str) and v): bad.append(f)
        elif c["kind"] == "enum" and v not in c["values"]: bad.append(f)
        elif c["kind"] == "decimal_open_unit":
            x = dec(v)
            if x is None or not (0 < x < 1): bad.append(f)
    R.check("claim.constraints", not bad, "all fields satisfy the profile" if not bad else f"violated: {bad}")
    R.check("parent.decision", pv.decision in ("certified", "transfer"), str(pv.decision))
    same = isinstance(claim, dict) and all(f in pv.claim and str(pv.claim.get(f)) == str(claim.get(f)) for f in fields)
    R.check("claim.invariance", same, "every claim field equals the parent's")


def _inventories(R, cert, d):
    out = []
    for key in ("parent_inventory", "derived_inventory"):
        ref = cert.get(key, {}); p = evidence_path(d, ref.get("file"))
        ok = R.check(f"inventory.digest.{key.split('_')[0]}", bool(p) and sha_file(p) == ref.get("sha256"), str(ref.get("file")))
        inv = {}
        if ok:
            try: inv = parse_inventory(p)
            except InventoryError as ex: R.check(f"inventory.unique.{key.split('_')[0]}", False, str(ex))
            else: R.check(f"inventory.unique.{key.split('_')[0]}", True, f"{len(inv)} artifacts")
        out.append(inv)
    return out


def _block_checks(R, cert, pinv, dinv, profile):
    block = cert.get("block", {})
    decl = {c: list(block.get(c) or []) for c in CATEGORIES}
    where = {}
    for c, items in decl.items():
        for b in items: where.setdefault(b, []).append(c)
    universe = set(pinv) | set(dinv)
    multi = sorted(b for b, cs in where.items() if len(cs) > 1); unknown = sorted(set(where) - universe); missing = sorted(universe - set(where))
    R.check("block.complete", not (multi or unknown or missing),
            "every inventory artifact is declared in exactly one category" if not (multi or unknown or missing)
            else f"undeclared: {missing}; in several categories: {multi}; not in any inventory: {unknown}")
    for b in decl["changed"]:
        R.check(f"block.changed.{b}", b in universe and not (b in pinv and b in dinv and pinv[b] == dinv[b]), "added, removed or digest differs")
    for b in decl["unchanged"]:
        R.check(f"block.unchanged.{b}", b in pinv and b in dinv and pinv[b] == dinv[b], "equal digest in both inventories")
    for b in decl["residual_rebuilt"]:
        R.check(f"block.residual_rebuilt.{b}", b in pinv and b in dinv and pinv[b] != dinv[b], "present in both, digest differs (equivalence is a written judgement)")
    for b in decl["unrecorded"]:
        R.check(f"block.unrecorded.{b}", b in pinv and b not in dinv, "in the parent inventory only (identity is a trust assumption)")
    roles = cert.get("roles", {})
    R.check("roles.declared", isinstance(roles, dict) and set(roles) == set(profile["roles"]), f"exactly {sorted(profile['roles'])}")
    for role, spec in profile["roles"].items():
        b = roles.get(role) if isinstance(roles, dict) else None
        R.check(f"role.{role}.present", b in pinv and b in dinv, f"{b} is in both inventories")
        if spec.get("fixed"):
            R.check(f"role.{role}.fixed", where.get(b) == ["unchanged"] and pinv.get(b) is not None and pinv.get(b) == dinv.get(b),
                    f"{b} is a fixed role: it must be unchanged")
    return decl


def _root_link_checks(R, cert, pv, d, pinv, profile):
    """First link: bind the declared configuration to the root at the levels the root provides. Returns ``(weak, levels)``:
    ``weak`` is True when some binding is weaker than a digest of the artifact (a written ``root_configuration`` judgement
    is then required); ``levels`` are the binding levels THE ROOT provides, per role and for the inventory."""
    roles, root = cert.get("roles", {}), pv.root
    rb = cert.get("root_binding") if isinstance(cert.get("root_binding"), dict) else {}
    levels = rb.get("roles") if isinstance(rb.get("roles"), dict) else {}
    digests, weak, frame_level, provided = [], False, None, {}
    for role in profile["roles"]:
        b = roles.get(role) if isinstance(roles, dict) else None
        lvl, rd = root.role_binding(role, pinv.get(b))
        provided[role] = lvl
        if role == profile["frame_role"]: frame_level = lvl
        R.check(f"roles.binding_level.{role}", levels.get(role) == lvl, f"declared {levels.get(role)!r}; this root provides {lvl!r}")
        if lvl == "digest":
            R.check(f"roles.root_binding.{role}", rd is not None and rd == pinv.get(b), f"root digest for role {role} == parent inventory[{b}]")
        elif lvl == "unbound":
            weak = True
            R.notice("unbound role", f"the root binds no digest for role {role!r}; that {b} of the parent inventory is the artifact the root run used is a written judgement (root_configuration)")
        fn = root.role_filename(role)
        if fn is not None: R.check(f"roles.root_filename.{role}", fn == b, f"root names {fn}")
        digests.append(pinv.get(b))
    R.check("roles.distinct", None not in digests and len(set(digests)) == len(digests), "role artifacts have pairwise distinct digests")
    inv_d = root.inventory_digest(); lvl = "digest" if inv_d else "unbound"; provided["(inventory)"] = lvl
    R.check("root.inventory_level", rb.get("inventory") == lvl, f"declared {rb.get('inventory')!r}; this root provides {lvl!r}")
    if inv_d:
        R.check("root.inventory_binding", inv_d == cert.get("parent_inventory", {}).get("sha256"), "the root binds the digest of the parent inventory")
    else:
        weak = True
        others = sorted(set(pinv) - {roles.get(r) for r in profile["roles"]}) if isinstance(roles, dict) else sorted(pinv)
        R.notice("unbound inventory", f"the root binds the role artifacts only; that the other artifacts of the parent inventory ({', '.join(others) or 'none'}) "
                 "belong to the configuration the root run used is a written judgement (root_configuration)")
    root.extra_checks(R, cert, d, pinv, frame_level)
    return weak, provided


def _chain_link_checks(R, cert, parent):
    R.check("chain.inventory_continuity", cert.get("parent_inventory", {}).get("sha256") == parent.get("derived_inventory", {}).get("sha256"),
            "this link starts from the inventory the parent certificate ended with")
    R.check("chain.roles", cert.get("roles") == parent.get("roles"), "configuration roles equal the parent's")
    R.check("chain.root_binding", cert.get("root_binding") == parent.get("root_binding"), "root binding levels inherited unchanged")
    R.check("chain.profile", cert.get("profile") == parent.get("profile"), "same profile as the parent link")


def _risk_checks(R, cert, pv, profile):
    rb = cert.get("risk_budget", {})
    a, dp, dd = dec(rb.get("alpha")), dec(rb.get("delta_parent")), dec(rb.get("delta_derived"))
    if not R.check("risk.decimals", None not in (a, dp, dd), "alpha, delta_parent, delta_derived are decimal strings in plain notation"): return
    R.check("risk.alpha_zero", a == 0, f"alpha = {rb.get('alpha')} (deterministic transfer only; a positive alpha is unsupported, not unverified)")
    # Deterministic transfer: alpha is zero, so the derived budget must BE the parent's.  The values are compared, never
    # added: Decimal comparison is exact for any number of digits, Decimal arithmetic rounds to the context precision.
    R.check("risk.composition", 0 < dp < 1 and dd == dp, "delta_derived equals delta_parent as exact decimal values (nothing is added: alpha must be zero)")
    pr = dec(str(pv.risk)) if pv.risk is not None else None
    R.check("risk.parent", pr is not None and pr == dp, f"delta_parent equals the parent's risk ({pv.risk})")
    cr = dec(cert.get("claim", {}).get(profile["risk_field"])) if isinstance(cert.get("claim"), dict) else None
    R.check("risk.claim", cr is not None and cr == dp, "delta_parent equals the claim's risk level")


def _evidence_files(R, cert, d):
    ev = cert.get("evidence_files", {}); absent = []
    for name, e in ev.items():
        p = evidence_path(d, e.get("file"))
        if p is None: absent.append(name)
        if p is None and e.get("detached") is True and not R.require_all_evidence:
            R.notice("detached evidence", f"{name}: {e.get('file')} is not present; its digest {str(e.get('sha256'))[:16]}… is recorded but was NOT checked")
            continue
        R.check(f"evidence.{name}", bool(p) and sha_file(p) == e.get("sha256"), f"{e.get('file')} ({str(e.get('sha256'))[:16]})")
    return sorted(absent)


SIDES = ("derived", "parent")


def _names(v):
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


def _coverage_checks(R, cert, decl, pinv, dinv, profile):
    """Coverage obligations are SIDE-SPECIFIC.

    A changed artifact that exists in the derived inventory is an obligation ``(derived, name)``: the new bytes must be
    a subject of exactly one equivalence entry, or be covered by a named judgement.  A changed artifact that exists
    in the parent inventory is an obligation ``(parent, name)``: the old bytes must be replaced by exactly one
    equivalence entry (whose reference check then ties them to the comparison), or be covered by a named judgement.
    A modified artifact therefore carries two obligations, and listing its name on one side never discharges the other.
    Returns ``(entries, judgement_covered)``.
    """
    eqs = cert.get("equivalence") if isinstance(cert.get("equivalence"), list) else []
    jcs = cert.get("judgement_coverage") if isinstance(cert.get("judgement_coverage"), list) else []
    ids = [x.get("id") for x in eqs if isinstance(x, dict)]
    R.check("equivalence.ids", len(ids) == len(eqs) and all(isinstance(i, str) and re.fullmatch(r"[A-Za-z0-9_-]+", i) for i in ids) and len(set(ids)) == len(ids),
            f"equivalence entries have distinct identifiers {ids}")
    changed = set(decl["changed"]); inv = {"derived": dinv, "parent": pinv}
    need = {(s, n) for s in SIDES for n in changed if n in inv[s]}
    cover, stray = {}, []
    for x in eqs:
        if not isinstance(x, dict): continue
        for n in _names(x.get("subjects")): cover.setdefault(("derived", n), []).append(f"subject of equivalence {x.get('id')}")
        for n in _names(x.get("replaces")): cover.setdefault(("parent", n), []).append(f"replaced by equivalence {x.get('id')}")
    jcovered = {}
    for jc in jcs:
        if not isinstance(jc, dict): stray.append(repr(jc)); continue
        side = jc.get("side", "both")
        if side not in ("both",) + SIDES: stray.append(f"judgement_coverage side {side!r}"); continue
        for n in _names(jc.get("artifacts")):
            sides = [s for s in SIDES if side in ("both", s) and (s, n) in need]
            if not sides: stray.append(f"{n} ({side})")
            for s in sides:
                cover.setdefault((s, n), []).append(f"judgement {jc.get('judgement')}"); jcovered.setdefault(n, []).append(s)
    for s in SIDES:
        todo = sorted(n for (t, n) in need if t == s)
        uncovered = [n for n in todo if (s, n) not in cover]; several = [n for n in todo if len(cover.get((s, n), [])) > 1]
        role = "a subject of exactly one equivalence entry" if s == "derived" else "replaced by exactly one equivalence entry"
        R.check(f"coverage.{s}_side", not (uncovered or several),
                f"each of the {len(todo)} changed artifacts of the {s} inventory is {role} or covered by one named judgement" if not (uncovered or several)
                else f"{s} side — not covered by any evidence or judgement: {uncovered}; covered more than once: {several}")
    stray += sorted(f"{n} ({s} side)" for (s, n) in cover if (s, n) not in need)
    R.check("coverage.declared", not stray, "nothing is listed as covered on a side where it is not a changed artifact" if not stray else f"listed but not an obligation: {stray}")
    if profile.get("require_equivalence", True):
        R.check("coverage.equivalence_present", len(eqs) >= 1, f"{len(eqs)} equivalence entr{'y' if len(eqs) == 1 else 'ies'}")
    j = cert.get("judgements") if isinstance(cert.get("judgements"), dict) else {}
    ev = cert.get("evidence_files", {})
    for jc in jcs:
        if not isinstance(jc, dict): continue
        name = jc.get("judgement"); sup = jc.get("evidence") or []
        ok = bool(profile.get("coverage_by_judgement", True)) and isinstance(j.get(name), str) and bool(j[name].strip()) and all(s in ev for s in sup)
        for a in _names(jc.get("artifacts")):
            R.check(f"coverage.judgement.{a}", ok, f"covered by the written judgement {name!r}" + (f" with supporting evidence {sup}" if sup else "")
                    if ok else f"judgement {name!r} is missing or blank, names unbound evidence, or the profile forbids coverage by judgement")
            R.notice("coverage by judgement", f"changed artifact {a} ({' and '.join(jcovered.get(a, [])) or 'no'} side) is NOT covered by equivalence evidence; "
                     f"it rests on the written judgement {name!r}")
    return [x for x in eqs if isinstance(x, dict)], sorted(jcovered)


def _parent_entry(pv, replaces):
    """The parent link's equivalence entry whose subjects are EXACTLY the artifacts replaced now (not a superset: a
    comparison that established a whole block says nothing about a part of it)."""
    if pv.kind != "derived" or not replaces: return None
    for x in pv.cert.get("equivalence") or []:
        if isinstance(x, dict) and set(replaces) == set(_names(x.get("subjects"))): return x
    return None


def _ref_digest(v):
    """One digest for a reference: the digest itself for a single artifact, a digest of the sorted
    ``{name: digest}`` map for a block of several artifacts.  None if malformed."""
    if isinstance(v, str): return v
    if isinstance(v, dict) and v and all(isinstance(k, str) and isinstance(x, str) for k, x in v.items()):
        return next(iter(v.values())) if len(v) == 1 else sha_obj({"reference_block": dict(sorted(v.items()))})
    return None


def _reference_artifacts(ref):
    if isinstance(ref.get("artifacts"), list): return _names(ref["artifacts"])
    return [ref["artifact"]] if isinstance(ref.get("artifact"), str) else []


def _equivalence_entry(R, e, cert, pv, d, pinv, dinv, decl, profile, registry, parent_state):
    """Identity of both sides of one comparison, then the method's own checks.  Returns the VERIFIED state of the entry
    (what the policy and the notices read): ``reference_binding`` is ``"digest"`` only when the verifier matched a
    reference digest recorded in the transcript against the digest the certificate ties the reference to."""
    P = f"equivalence.{e.get('id')}"
    mc = e.get("method_code"); changed = set(decl["changed"])
    okm = R.check(f"{P}.method", mc in profile["methods"] and mc in registry, f"{mc!r}; this profile accepts {profile['methods']}")
    subs = _names(e.get("subjects")); reps = _names(e.get("replaces"))
    ref = e.get("reference") if isinstance(e.get("reference"), dict) else {}
    kind = ref.get("kind")
    st = {"subjects": subs, "replaces": reps, "method": mc, "reference_kind": kind, "reference_binding": None, "reference_digest": None,
          "mapped": bool(e.get("pointers")), "domain_size": e.get("domain_size") if (mc == "exhaustive_enumeration" and _is_int(e.get("domain_size"))) else None,
          "renamed": sorted(r for r in reps if r not in subs), "multi_artifact": len(subs) > 1 or len(reps) > 1,
          "subject_scope": None}        # "exact": the transcript records exactly these subjects; "declared": a mapped transcript, scope not visible
    R.check(f"{P}.subjects", bool(subs) and subs == e.get("subjects") and len(set(subs)) == len(subs) and all(s in changed and s in dinv for s in subs),
            f"{subs} are distinct changed artifacts of the derived configuration")
    R.check(f"{P}.replaces", reps == (e.get("replaces") or []) and len(set(reps)) == len(reps) and all(r in changed and r in pinv for r in reps),
            f"{reps} are distinct changed artifacts of the parent configuration")
    # The verifier identifies artifacts by NAME.  It cannot see where the running system reaches them, nor which file of
    # a block a comparison exercised.  An entry is NAME-ALIGNED when it has one subject and replaces at most one parent
    # artifact, of the same name: the new file then stands where the old one stood.  Otherwise — a subject of another
    # name (a renamed file; two artifacts declared as each other's replacements) or a block of several artifacts on
    # either side — which new artifact takes the place of which replaced one is a written judgement: required, printed,
    # and refusable by a policy (renamed_replacement, multi_artifact_block).
    jd = cert.get("judgements") if isinstance(cert.get("judgements"), dict) else {}
    has_j = isinstance(jd.get(CORRESPONDENCE), str) and bool(jd.get(CORRESPONDENCE).strip())
    ren, multi = st["renamed"], st["multi_artifact"]
    why = "; ".join(x for x in (f"{ren} of the parent configuration {'is' if len(ren) == 1 else 'are'} replaced under another name" if ren else "",
                                f"the entry is a block of several artifacts ({len(subs)} subject{'s' if len(subs) != 1 else ''}, {len(reps)} replaced)" if multi else "") if x)
    R.check(f"{P}.correspondence", not (ren or multi) or has_j,
            "one subject, replacing at most one parent artifact, of the same name" if not (ren or multi) else
            f"{why}; which new artifact takes the place of which replaced one is the written judgement {CORRESPONDENCE!r}" if has_j else
            f"{why}; this requires the written judgement {CORRESPONDENCE!r}, which the certificate does not carry")
    if ren:
        still = [r for r in ren if r in dinv]
        R.notice("renamed replacement", f"equivalence {e.get('id')}: {ren} of the parent configuration {'is' if len(ren) == 1 else 'are'} replaced by {subs}, "
                 f"which do{'es' if len(subs) == 1 else ''} not carry {'its' if len(ren) == 1 else 'their'} name; that the running system now reaches {subs} where "
                 f"it reached {ren} is not checked — the verifier identifies artifacts by name only. It is the written judgement {CORRESPONDENCE!r}"
                 + (f". {still} still {'exists' if len(still) == 1 else 'exist'} in the derived configuration, as a different file: a system that reaches "
                    f"{'it' if len(still) == 1 else 'them'} by name reaches that file, not {subs}" if still else ""))
    if multi:
        R.notice("multi-artifact block", f"equivalence {e.get('id')}: {subs} {'are' if len(subs) != 1 else 'is'} compared as one block"
                 + (f" replacing {reps}" if reps else "") + "; the transcript states one result for the block. Which of these files the comparison exercised, "
                 f"and that the running system uses each new file where it used the replaced ones, is not checked. It is the written judgement {CORRESPONDENCE!r}")
    okk = R.check(f"{P}.reference_kind", kind in REFERENCE_KINDS and kind in profile.get("reference_kinds", REFERENCE_KINDS),
                  f"{kind!r}; this profile accepts {list(profile.get('reference_kinds', REFERENCE_KINDS))}")
    ev = cert.get("evidence_files", {}); te = ev.get(e.get("transcript") or "\0", {})
    tp = evidence_path(d, te.get("file"))
    if not R.check(f"{P}.transcript", bool(tp) and te.get("detached") is not True, f"transcript {e.get('transcript')!r} is a bound, present evidence file"): return st
    try: tr = load_json(tp)
    except Exception as ex:
        R.check(f"{P}.transcript_json", False, type(ex).__name__); return st
    mapped = st["mapped"]; standard = isinstance(tr, dict) and tr.get("schema") == STANDARD_SCHEMA
    R.check(f"{P}.transcript_layout", (standard and not mapped) or (mapped and not standard),
            f"standard layout {STANDARD_SCHEMA}" if standard and not mapped else
            ("foreign layout mapped by declared pointers" if mapped and not standard else
             "pointers may not re-map a transcript that declares the standard layout" if mapped else f"neither the standard layout {STANDARD_SCHEMA} nor a declared pointer mapping"))
    if mapped:
        st["subject_scope"] = "declared"
        R.notice("transcript mapping", f"equivalence {e.get('id')}: the transcript is in a foreign layout; which of its fields hold the subject digests, the number "
                 f"of inputs compared and the mismatch count is the issuer's declaration ({json.dumps(e.get('pointers'), sort_keys=True)}). Whether the "
                 f"comparison it records covered further files than {subs} is not checked either")
    bad = [s for s in subs if transcript_field(e, tr, "subjects", s) != (True, dinv.get(s)) or dinv.get(s) is None]
    R.check(f"{P}.subject_digest", bool(subs) and not bad,
            f"the transcript's subject digests equal the derived inventory for {subs}" if subs and not bad else f"transcript digest missing or different from the derived inventory for {bad or subs}")
    if standard and not mapped:
        # A standard transcript states ONE result for the block of ALL subjects it records.  The entry must claim that
        # result for exactly that block: claiming it for one file of a recorded block of two would let a comparison of
        # another file stand in for the file named (review of release 1.2.0, finding R8-1).
        recorded = transcript_subject_names(e, tr)
        extra = sorted(set(recorded or []) - set(subs)); missing = sorted(set(subs) - set(recorded or []))
        ok_scope = R.check(f"{P}.subject_scope", recorded is not None and bool(subs) and not extra and not missing,
                           f"the transcript records exactly the subjects of this entry: {subs}" if recorded is not None and subs and not extra and not missing else
                           f"the transcript records the subjects {recorded}, the entry claims its result for {subs}"
                           + (f"; recorded but not claimed: {extra}" if extra else "") + (f"; claimed but not recorded: {missing}" if missing else ""))
        if ok_scope: st["subject_scope"] = "exact"
        elif recorded and len(recorded) > 1: st["multi_artifact"] = True      # the link state follows what the record covers, not only what the entry claims
    found, tref = transcript_field(e, tr, "reference")
    tdig = _ref_digest(tref) if found else None
    j = cert.get("judgements") if isinstance(cert.get("judgements"), dict) else {}
    expected = None          # the digest the certificate's reference.sha256 must carry (None: the field must be absent)
    if okk and kind == "parent_artifact":
        arts = _reference_artifacts(ref)
        okb = R.check(f"{P}.reference_block", bool(arts) and len(set(arts)) == len(arts) and set(arts) == set(reps),
                      f"the reference consists of exactly the parent artifacts this entry replaces: reference {arts}, replaces {reps}")
        want = {a: pinv.get(a) for a in arts}
        expected = _ref_digest(want) if arts and None not in want.values() else None
        same = found and expected is not None and (tref == want if isinstance(tref, dict) else (len(arts) == 1 and tref == want[arts[0]]))
        ok = R.check(f"{P}.reference_digest", bool(same),
                     f"the transcript's reference ({str(tdig)[:16]}) must be {arts} of the PARENT inventory ({str(expected)[:16]})")
        if okb and ok: st["reference_binding"], st["reference_digest"] = "digest", expected
    elif okk and kind == "parent_link":
        pe = _parent_entry(pv, reps)
        R.check(f"{P}.reference_parent_link", pe is not None,
                f"the parent link's equivalence entry {pe.get('id')!r} has exactly {reps} as its subjects" if pe is not None
                else f"the parent is not a derived certificate with an equivalence entry whose subjects are exactly {reps}")
        if pe is not None:
            pref = pe.get("reference") if isinstance(pe.get("reference"), dict) else {}
            if parent_state is not None:                      # the parent link was verified in this run: inherit what was VERIFIED there
                ps = parent_state["entries"].get(pe.get("id"), {})
                pbind, pdig, inherited = ps.get("reference_binding"), ps.get("reference_digest"), "digest"
            else:                                             # single link: the parent's own verification is a precondition
                pbind, pdig, inherited = ("digest" if pref.get("sha256") else "declaration"), pref.get("sha256"), "unverified-parent"
            if pbind == "digest":
                expected = pdig
                ok = R.check(f"{P}.reference_digest", found and tdig is not None and tdig == pdig,
                             f"the transcript's reference ({str(tdig)[:16]}) must be the reference the parent link's subjects were shown equivalent to ({str(pdig)[:16]})")
                if ok: st["reference_binding"], st["reference_digest"] = inherited, pdig
            else:
                ok = R.check(f"{P}.reference_id", bool(ref.get("id")) and ref.get("id") == pref.get("id"), f"same declared reference as the parent link: {pref.get('id')!r}")
                if ok: st["reference_binding"] = "declaration"
                R.notice("reference by declaration", f"equivalence {e.get('id')}: the reference {ref.get('id')!r} is inherited from the parent link by NAME; "
                         "no digest of it was verified in either link, so that both comparisons used the same reference is not machine-checked")
    elif okk and kind == "specification":
        jn = ref.get("judgement")
        oks = R.check(f"{P}.reference_spec", isinstance(ref.get("id"), str) and bool(ref.get("id")) and isinstance(j.get(jn), str) and bool(j[jn].strip()),
                      f"reference is the specification {ref.get('id')!r}; its link to the parent configuration is the written judgement {jn!r}")
        if ref.get("evidence"):
            se = ev.get(ref.get("evidence"), {}); expected = se.get("sha256")
            ok = R.check(f"{P}.reference_digest", found and isinstance(tref, str) and bool(tref) and tref == expected and se.get("detached") is not True,
                         f"the transcript's reference ({str(tdig)[:16]}) is the bound specification file {ref.get('evidence')!r}")
            if oks and ok: st["reference_binding"], st["reference_digest"] = "digest", expected
        else:
            if oks: st["reference_binding"] = "declaration"
            R.notice("reference by declaration", f"equivalence {e.get('id')}: no specification file is bound, so no digest ties the transcript to the specification "
                     f"{ref.get('id')!r}; that the comparison used this specification is the issuer's declaration")
        R.notice("reference by judgement", f"equivalence {e.get('id')}: the subjects were compared against the specification {ref.get('id')!r}, not against an artifact "
                 f"of the parent configuration; that the parent's block ({reps or 'no replaced artifact named'}) computes this specification is the written judgement {jn!r}")
    R.check(f"{P}.reference_field", ref.get("sha256") == expected,
            "the certificate's reference.sha256 is exactly the digest the reference was verified against" if expected is not None
            else "the certificate carries no reference.sha256, because no digest of the reference is verified (a declared, unverified digest is not allowed)")
    if okm:
        for suffix, ok, detail in registry[mc](e, tr): R.check(f"{P}.{suffix}", ok, detail)
    if st["domain_size"] is not None:
        R.notice("enumeration domain", f"equivalence {e.get('id')}: {st['domain_size']} inputs were enumerated; that these are ALL inputs on which {subs} can be "
                 "invoked in the deployed configuration is not checked — it is the written judgement 'boundary', which must be read against this number")
    R.notice("transcript provenance", f"equivalence {e.get('id')}: the transcript is a record written by the issuer's comparison tool; the verifier checks what it "
             "states and what it is bound to, not that the comparison was run as recorded")
    return st


def semantic_checks(R, cert, parent, d, profile, registry, parent_state=None, link="(declaration)"):
    """Every profile check that does not involve a signature. Shared by ``issue`` and ``verify``.

    Returns the LINK STATE: what the checks established about this link.  The acceptance policy is evaluated on this
    state, and the notices are printed from it, so that both always describe the same thing.  ``parent_state`` is the
    state of the parent link when it was verified in the same run (``verify-chain``); without it, everything a link
    inherits from an earlier link — root format, root binding levels, a reference taken over from the parent link —
    is marked as not verified in this run.
    """
    state = {"link": link, "parent_kind": None, "chain_verified": parent_state is not None, "root_adapter": None, "binding_levels": None, "entries": {},
             "judgement_covered": [], "categories": {c: [] for c in CATEGORIES}, "evidence_absent": [], "judgements": {}, "trust_assumptions": {},
             "issuance_status": cert.get("issuance_status", "")}
    try: pv = ParentView(parent, profile)
    except RootError as ex:
        R.check("parent.readable", False, str(ex)); return state
    state["parent_kind"] = pv.kind
    _claim_checks(R, cert.get("claim"), profile, pv)
    pinv, dinv = _inventories(R, cert, d)
    decl = _block_checks(R, cert, pinv, dinv, profile)
    state["categories"] = {c: sorted(decl[c]) for c in CATEGORIES}
    if pv.kind == "root":
        weak, levels = _root_link_checks(R, cert, pv, d, pinv, profile)
        state["root_adapter"], state["binding_levels"] = pv.root.adapter, levels
    else:
        _chain_link_checks(R, cert, parent)
        rb = cert.get("root_binding") if isinstance(cert.get("root_binding"), dict) else {}
        weak = rb.get("inventory") != "digest" or any(v != "digest" for v in (rb.get("roles") or {None: None}).values())
        if parent_state is not None:
            state["root_adapter"], state["binding_levels"] = parent_state["root_adapter"], parent_state["binding_levels"]
    need = list(profile["required_judgements"])
    if decl["unrecorded"]: need += list(profile.get("required_judgements_if_unrecorded", []))
    if weak and pv.kind == "root": need += list(profile.get("required_judgements_if_unbound", []))
    j = cert.get("judgements", {})
    lacking = [k for k in need if not (isinstance(j, dict) and isinstance(j.get(k), str) and j.get(k).strip())]
    R.check("judgements.required", not lacking, f"present: {need}" if not lacking else f"missing: {lacking}")
    text_digest = lambda v: hashlib.sha256(str(v).encode("utf-8")).hexdigest()
    state["judgements"] = {k: text_digest(v) for k, v in sorted(j.items())} if isinstance(j, dict) else {}
    ta = cert.get("trust_assumptions"); state["trust_assumptions"] = {k: text_digest(v) for k, v in sorted(ta.items())} if isinstance(ta, dict) else {}
    for b in state["categories"]["residual_rebuilt"]:
        R.notice("residual rebuilt", f"{b} has different bytes in the two configurations and is NOT covered by equivalence evidence; that it behaves identically is the written judgement 'residual_path'")
    for b in state["categories"]["unrecorded"]:
        R.notice("unrecorded artifact", f"{b} was not recorded for the derived configuration; that it is unchanged is the written judgement 'unrecorded_items'")
    state["evidence_absent"] = _evidence_files(R, cert, d)
    eqs, state["judgement_covered"] = _coverage_checks(R, cert, decl, pinv, dinv, profile)
    for x in eqs:
        state["entries"][str(x.get("id"))] = _equivalence_entry(R, x, cert, pv, d, pinv, dinv, decl, profile, registry, parent_state)
    _risk_checks(R, cert, pv, profile)
    R.notice("inventory completeness", f"that {cert.get('derived_inventory', {}).get('file')} lists every artifact that can affect the outputs of the derived "
             "configuration is the issuer's statement; an artifact absent from both inventories is outside every check")
    return state


def _evidence_entry(p, base="."):
    """A path, relative to the spec file (digest computed now), or a detached entry ``{"file", "sha256", "detached": true}``
    (digest recorded as given)."""
    if isinstance(p, dict):
        if not (p.get("detached") is True and isinstance(p.get("sha256"), str) and len(p["sha256"]) == 64 and p.get("file")):
            raise ValueError(f"malformed detached evidence entry: {p!r}")
        return {"file": os.path.basename(p["file"]), "sha256": p["sha256"].lower(), "detached": True}
    p = p if os.path.isabs(p) else os.path.join(base, p)
    return {"file": os.path.basename(p), "sha256": sha_file(p)}


def issue_root(claim, role_files, decision, basis, key, key_id, out, profile, inventory=None):
    """A minimal signed root attestation (``recertkit-root-1``): claim + decision + configuration role digests and,
    with ``inventory``, the digest of the whole configuration inventory."""
    from . import ROOT_VERSION
    missing = sorted(set(profile["roles"]) - set(role_files))
    if missing: raise ValueError(f"root lacks configuration roles {missing}")
    root = {"certificate_version": ROOT_VERSION, "tool": f"recertkit {__version__}", "certificate_id": str(uuid.uuid4()),
            "issued_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "claim": claim, "decision": decision, "basis": basis,
            "configuration": {r: {"file": os.path.basename(p), "sha256": sha_raw(p)} for r, p in role_files.items()}}
    if inventory:
        inv = parse_inventory(inventory)
        wrong = sorted(r for r, c in root["configuration"].items() if inv.get(c["file"]) != c["sha256"])
        if wrong: raise ValueError(f"role artifacts {wrong} are not in the inventory with the same digest")
        root["configuration_inventory"] = {"file": os.path.basename(inventory), "sha256": sha_file(inventory)}
    root = sign(root, key, key_id)
    with open(out, "w", encoding="utf-8") as f: json.dump(root, f, indent=1)
    return root


def _resolve_references(spec_eq, pv, parent_inventory, evidence):
    """Set ``reference.sha256`` from the source the verifier will check it against — and ONLY from there: a digest the
    issuer writes into the declaration is discarded, so that the certificate never carries a digest nothing verifies."""
    try: pinv = parse_inventory(parent_inventory)
    except InventoryError: pinv = {}
    out = []
    for x in spec_eq if isinstance(spec_eq, list) else []:
        x = json.loads(json.dumps(x))
        ref = x.get("reference") if isinstance(x.get("reference"), dict) else None
        if ref is not None:
            ref.pop("sha256", None)
            if ref.get("kind") == "parent_artifact":
                arts = _reference_artifacts(ref)
                if arts and all(a in pinv for a in arts): ref["sha256"] = _ref_digest({a: pinv[a] for a in arts})
            elif ref.get("kind") == "parent_link":
                pe = _parent_entry(pv, _names(x.get("replaces")))
                pref = (pe or {}).get("reference") or {}
                if pref.get("sha256"): ref["sha256"] = pref["sha256"]
                if pref.get("id") and "id" not in ref: ref["id"] = pref["id"]
            elif ref.get("kind") == "specification" and ref.get("evidence") in evidence:
                ref["sha256"] = evidence[ref["evidence"]].get("sha256")
        out.append(x)
    return out


def build_certificate(parent_path, spec, parent_inventory, derived_inventory, profile, spec_dir="."):
    """Assemble an unsigned derived certificate from a spec (see docs/spec.md)."""
    parent = load_json(parent_path); pv = ParentView(parent, profile)
    claim = spec.get("claim") or {f: pv.claim.get(f) for f in profile["claim_fields"]}
    risk = str(pv.risk)
    block = {c: sorted(spec.get("block", {}).get(c) or []) for c in CATEGORIES}
    evidence = {n: _evidence_entry(p, spec_dir) for n, p in (spec.get("evidence_files") or {}).items()}
    root_binding = spec.get("root_binding") if pv.kind == "root" else parent.get("root_binding")
    return {
        "certificate_version": CERT_VERSION, "tool": f"recertkit {__version__}", "profile": profile_ref(profile),
        "certificate_id": str(uuid.uuid4()), "issued_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "parent": {"certificate_id": parent.get("certificate_id"), "certificate_sha256": sha_file(parent_path), "kind": pv.kind, "decision": pv.decision},
        "claim": claim, "claim_scope": spec.get("claim_scope", ""), "change": spec.get("change", {}),
        "block": block, "roles": spec.get("roles", {}), "root_binding": root_binding or {},
        "parent_inventory": {"file": os.path.basename(parent_inventory), "sha256": sha_file(parent_inventory)},
        "derived_inventory": {"file": os.path.basename(derived_inventory), "sha256": sha_file(derived_inventory)},
        "equivalence": _resolve_references(spec.get("equivalence"), pv, parent_inventory, evidence),
        "judgement_coverage": spec.get("judgement_coverage") or [], "judgements": spec.get("judgements", {}),
        "evidence_files": evidence,
        "risk_budget": spec.get("risk_budget") or {"delta_parent": risk, "alpha": "0", "delta_derived": risk},
        "trust_assumptions": spec.get("trust_assumptions", {}), "issuance_status": spec.get("issuance_status", "prospective"),
    }


def issue(R, parent_path, spec, parent_inventory, derived_inventory, key, key_id, out, profile, registry, evidence_dir=None, spec_dir=".", store=None):
    """Build, apply the profile checks and sign. Nothing is signed unless every check passes.

    With a trust ``store`` the parent's signature is verified too; without one it is NOT, and that is printed.
    Issuance is not a release decision: the release gate is ``verify-chain`` with trusted keys and a policy."""
    d = evidence_dir or os.path.dirname(os.path.abspath(out))
    parent = load_json(parent_path)
    cert = build_certificate(parent_path, spec, parent_inventory, derived_inventory, profile, spec_dir)
    R.section(f"issue: applying profile {profile['name']} before signing")
    if store is not None:
        ok, why = store.verify(parent); R.check("signature.parent", ok, why)
    else:
        R.notice("parent signature", "no trusted key was given to issue (--trust): the parent certificate's signature was NOT verified at issuance")
    semantic_checks(R, cert, parent, d, profile, registry, link=os.path.basename(out))
    if not R.ok: return None
    cert = sign(cert, key, key_id)
    with open(out, "w", encoding="utf-8") as f: json.dump(cert, f, indent=1)
    return cert


def _print_unchecked(R, cert):
    for k, v in (cert.get("judgements") or {}).items(): R.notice(f"judgement {k}", str(v))
    for k, v in (cert.get("trust_assumptions") or {}).items(): R.notice(f"trust assumption {k}", str(v))


def verify_link(R, cert_path, parent_path, store, profile, registry, evidence_dir=None, parent_state=None, policy=None):
    """Verify one link.  ``parent_state`` is the verified state of the parent link (``verify-chain``); when the parent is
    a derived certificate and no state is given, what the link inherits is reported as not verified in this run and a
    policy member that needs it is NOT EVALUATED — never silently satisfied."""
    cert, parent = load_json(cert_path), load_json(parent_path)
    d = evidence_dir or os.path.dirname(os.path.abspath(cert_path))
    name = os.path.basename(cert_path)
    R.section(f"link: {name}  <-  {os.path.basename(parent_path)}")
    R.check("certificate.version", cert.get("certificate_version") == CERT_VERSION, f"{cert.get('certificate_version')!r}; this tool verifies {CERT_VERSION!r}")
    R.check("certificate.profile", cert.get("profile") == profile_ref(profile), f"issued under {cert.get('profile', {}).get('name')!r}; verifier applies {profile['name']!r}")
    ok, why = store.verify(cert); R.check("signature.certificate", ok, why)
    ok, why = store.verify(parent); R.check("signature.parent", ok, why)
    R.check("parent.digest", sha_file(parent_path) == cert.get("parent", {}).get("certificate_sha256"), str(cert.get("parent", {}).get("certificate_sha256"))[:16])
    R.check("parent.id", parent.get("certificate_id") is not None and parent.get("certificate_id") == cert.get("parent", {}).get("certificate_id"))
    state = semantic_checks(R, cert, parent, d, profile, registry, parent_state=parent_state, link=name)
    if state["parent_kind"] == "derived" and parent_state is None:
        R.notice("precondition", "the parent is itself a derived certificate; this result assumes it was verified against ITS parent, and what this link "
                 "inherits through it (root format, root binding levels, an inherited comparison reference) was not verified in this run (use verify-chain)")
    _print_unchecked(R, cert)
    R.links.append(state)
    if policy is not None: apply_policy(R, policy, state)
    return state


def verify_chain(R, root_path, links, store, profile, registry, evidence_dir=None, policy=None):
    root = load_json(root_path)
    R.section(f"root: {os.path.basename(root_path)}")
    ok, why = store.verify(root); R.check("signature.root", ok, why)
    try:
        rv = read_root(root, profile)
        R.check("root.decision", rv.decision == "certified", str(rv.decision))
    except RootError as ex:
        R.check("root.readable", False, str(ex))
    prev, state = root_path, None
    for i, link in enumerate(links):
        state = verify_link(R, link, prev, store, profile, registry, evidence_dir, parent_state=state, policy=policy); prev = link
    return R.ok
