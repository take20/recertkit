"""Exhaustive declaration search.

A counterexample-driven test suite shows that the declarations somebody thought of are refused.  This search asks the
converse question for a bounded but systematic space: for ONE harmful change — an equivalent new kernel shipped with
a ``system.py`` that always predicts class 0 (127 of 200 predictions change) — is there ANY way of declaring it, using
only truthful evidence files, that the verifier accepts under the supplied release policy?

"Truthful" describes the FILES, not the declarations built from them: every digest in a transcript is the digest of
the file named, and every mismatch count is the result of a comparison that was run.  It does not mean that a
transcript supports what a declaration uses it for.  The comparison tool of the toy system executes the kernel
function ``q(a, b)`` only; where a transcript also lists ``system.py`` as a file of the compared block, the file's
digest was collected but its behaviour was not compared.  Such a declaration attaches a true kernel result and a true
file list to a block boundary that the comparison does not justify — which is the kind of declaration the search
exists to try.

Every declaration in the space is signed with the trusted key WITHOUT going through ``issue`` (so that only the
verifier stands between the declaration and acceptance) and verified with ``verify-chain`` semantics.  The space is
the product of:

* the declared category of system.py and of kernel.py;
* the kernel entry's subjects, replaced artifacts, reference (six forms) and transcript (six truthful transcripts,
  among them a self-comparison, a comparison of the new system.py with the old one on ONE input where they agree,
  and kernel comparisons that also list system.py as a file of the compared block, on one side or on both);
* an optional pointer mapping, an optional second equivalence entry for system.py, and judgement coverage of
  system.py on both sides, one side, or not at all.

Scenario ``first``: the change is the first link after the root.  Scenario ``later``: it follows a valid link, so
that ``parent_link`` references are available.  Scenario ``control``: the kernel alone changes (harmless) — the
search must find accepted declarations there, otherwise it would prove nothing.

Invariants (asserted by tests/test_declaration_search.py on a sample; a run of this script in mode ``check`` — the
default — exits with status 1 if one of them is violated; mode ``measure`` only reports, and is meant for measuring a
version that is known to violate them):

I1  no declaration of the harmful change is ACCEPTED under the supplied policy;
I2  every declaration of the harmful change that is a VALID RECORD names system.py among what was not checked
    (coverage by judgement, residual rebuilt) or shows it as a subject with the size of the domain enumerated for it.

I3  the harmless control is accepted in at least one declaration (the search can find acceptances); assessed only
    when the whole control space is evaluated, not on a sample.

    python tests/declaration_search.py OUT.json [jobs] [sample size per scenario, 0 = all] [policy.json | -] [check | measure]
"""
import hashlib, itertools, json, os, random, shutil, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "examples", "quickstart"))
MARKER = "return max(range(len(scores)), key=lambda c: (scores[c], -c))"
K, S = "kernel.py", "system.py"
sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()


def build(work):
    """Root -> C1 (valid link), the harmful configurations and every truthful transcript."""
    import toy
    from recertkit.cli import main as cli
    import contextlib, io
    P = lambda *a: os.path.join(work, *a)
    with contextlib.redirect_stdout(io.StringIO()):
        c0, c1 = toy.write_config(P("config_c0"), "ref"), toy.write_config(P("config_c1"), "lut")
        bad1, bad2, ok1 = toy.write_config(P("config_bad1"), "lut"), toy.write_config(P("config_bad2"), "sel"), toy.write_config(P("config_ok1"), "lut")
        for b in (bad1, bad2):
            s = open(b[S]).read(); assert MARKER in s; open(b[S], "w").write(s.replace(MARKER, "return 0"))
        cli(["keygen", "--private", P("release.key"), "--public", P("release.pub")])
        json.dump(toy.CLAIM, open(P("claim.json"), "w"))
        for n, c in (("c0", c0), ("c1", c1), ("bad1", bad1), ("bad2", bad2), ("ok1", ok1)): cli(["inventory", *c.values(), "--out", P(f"inventory_{n}.txt")])
        assert cli(["root-issue", "--claim", P("claim.json"), "--role", f"server={c0[S]}", "--role", f"model={c0['model.json']}", "--role", f"frame={c0['frame.jsonl']}",
                    "--inventory", P("inventory_c0.txt"), "--basis", "search root", "--key", P("release.key"), "--key-id", "release", "--out", P("root.json")]) == 0
        toy.enumerate_block(c1[K], c0[K], P("enumeration_c1.json")); json.dump(toy.spec_for(P("enumeration_c1.json"), "c1"), open(P("spec_c1.json"), "w"))
        assert cli(["issue", "--parent", P("root.json"), "--spec", P("spec_c1.json"), "--parent-inventory", P("inventory_c0.txt"), "--derived-inventory", P("inventory_c1.txt"),
                    "--key", P("release.key"), "--key-id", "release", "--out", P("derived_c1.json"), "--trust", f"release={P('release.pub')}"]) == 0
    before = toy.evaluate(P("config_c0"))
    def tiny(tag, new_cfg, old_cfg):                      # the two systems compared on ONE frame item on which they agree
        a, b = toy.evaluate(P(new_cfg)), before
        item = next(x["item_id"] for x, y in zip(a, b) if x["pred"] == y["pred"])
        json.dump({"schema": "recertkit-enumeration-1", "what": f"system.py compared with the parent's system.py on the single frame item {item}", "domain": f"frame item {item}",
                   "domain_size": 1, "subjects": {S: sha(P(new_cfg, S))}, "reference": {"sha256": sha(P(old_cfg, S))}, "enumerated": 1, "mismatches": 0}, open(P(f"t_{tag}_systiny.json"), "w"))
    for tag, new, parent in (("first", "config_bad1", "config_c0"), ("later", "config_bad2", "config_c1"), ("control", "config_ok1", "config_c0")):
        toy.enumerate_block(P(new, K), P(parent, K), P(f"t_{tag}_k_parent.json"))                         # vs the parent's kernel
        toy.enumerate_block(P(new, K), P("config_c0", K), P(f"t_{tag}_k_c0.json"))                        # vs C0's kernel (the reference of link 1)
        toy.enumerate_block(P(new, K), P(new, K), P(f"t_{tag}_self.json"))                                # vs itself
        toy.enumerate_block(P(new, K), P(parent, K), P(f"t_{tag}_k_plus_sys.json"), subject_files=[P(new, S)])   # the kernel comparison, listing system.py as a file of the block
        toy.enumerate_block(P(new, K), P(parent, K), P(f"t_{tag}_k_both_sys.json"), subject_files=[P(new, S)], reference_files=[P(parent, S)])   # ... and the parent's system.py as a file of the reference block
        if tag != "control": tiny(tag, new, parent)
    changed = sum(x["pred"] != y["pred"] for x, y in zip(before, toy.evaluate(P("config_bad1"))))
    return {"predictions_changed_by_the_harmful_change": changed, "items": len(before)}


SCENARIOS = {"first": ("root.json", "inventory_c0.txt", "inventory_bad1.txt"), "later": ("derived_c1.json", "inventory_c1.txt", "inventory_bad2.txt"),
             "control": ("root.json", "inventory_c0.txt", "inventory_ok1.txt")}
REFS = {"pa:k": {"kind": "parent_artifact", "artifact": K}, "pa:s": {"kind": "parent_artifact", "artifact": S}, "pa:k+s": {"kind": "parent_artifact", "artifacts": [K, S]},
        "spec": {"kind": "specification", "id": "the arithmetic kernel", "judgement": "boundary"},
        "spec+sha": {"kind": "specification", "id": "the arithmetic kernel", "judgement": "boundary", "sha256": "PARENT_KERNEL"}, "plink": {"kind": "parent_link"}}
DIMS = {"cat_s": ["changed", "unchanged", "residual_rebuilt", "unrecorded"], "cat_k": ["changed", "unchanged", "residual_rebuilt"],
        "subjects": [[K], [K, S], [S], []], "replaces": [[], [K], [K, S], [S]], "reference": list(REFS),
        "transcript": ["k_parent", "k_c0", "self", "k_plus_sys", "k_both_sys", "systiny"], "pointers": [False, True], "second": [False, True], "jc": [None, "both", "parent", "derived"]}


def space(scenario):
    dims = dict(DIMS)
    if scenario == "control": dims.update(cat_s=["unchanged", "changed"], transcript=["k_parent", "k_c0", "self"], second=[False], jc=[None])
    keys = list(dims)
    return [dict(zip(keys, v)) for v in itertools.product(*dims.values())]


def declaration(work, scenario, d):
    import toy
    P = lambda *a: os.path.join(work, *a)
    spec = toy.spec_for(P(f"t_{scenario}_{d['transcript']}.json"), f"search {scenario}")
    block = {c: [] for c in ("changed", "unchanged", "residual_rebuilt", "unrecorded")}
    block[d["cat_s"]].append(S); block[d["cat_k"]].append(K); block["unchanged"] += ["model.json", "frame.jsonl"]
    spec["block"] = block
    e = spec["equivalence"][0]; e.update({"subjects": list(d["subjects"]), "replaces": list(d["replaces"]), "reference": dict(REFS[d["reference"]])})
    if d["transcript"] == "systiny": e.update({"domain_size": 1, "domain": "one frame item"})
    if d["pointers"]: e["pointers"] = {"subjects": {K: "/subjects/kernel.py", S: "/subjects/kernel.py"}, "reference_sha256": "/reference/sha256", "enumerated": "/enumerated", "mismatches": "/mismatches"}
    if d["second"]:
        spec["equivalence"].append({"id": "system", "method_code": "exhaustive_enumeration", "subjects": [S], "replaces": [S], "reference": {"kind": "parent_artifact", "artifact": S},
                                    "transcript": "systiny", "domain_size": 1, "domain": "one frame item"})
        spec["evidence_files"]["systiny"] = f"t_{scenario}_systiny.json"
    if d["jc"]:
        jc = {"artifacts": [S], "judgement": "residual_path"}
        if d["jc"] != "both": jc["side"] = d["jc"]
        spec["judgement_coverage"] = [jc]
    return spec


def evaluate(work, scenario, chunk, policy_path):
    """Sign and verify every declaration of ``chunk``; returns compact outcome rows."""
    from recertkit.engine import build_certificate, verify_chain
    from recertkit.methods import default_registry
    from recertkit.policy import load_policy
    from recertkit.profiles import load_profile
    from recertkit.report import Report
    from recertkit.signing import TrustStore, sign
    P = lambda *a: os.path.join(work, *a)
    parent, pinv, dinv = SCENARIOS[scenario]
    profile, registry, store = load_profile(None), default_registry(), TrustStore([f"release={P('release.pub')}"])
    policy = load_policy(policy_path); relaxed = {k: v for k, v in policy.items() if k != "enumeration_domains"}
    links = [P("derived_c1.json")] if parent != "root.json" else []
    kernel0 = sha(P("config_c0", K)); out = P(f"cand_{os.getpid()}.json"); rows = []
    for d in chunk:
        try:
            cert = build_certificate(P(parent), declaration(work, scenario, d), P(pinv), P(dinv), profile, spec_dir=work)
            if d["reference"] == "spec+sha": cert["equivalence"][0]["reference"]["sha256"] = kernel0          # a digest merely declared in the certificate
            json.dump(sign(cert, P("release.key"), "release"), open(out, "w"))
        except Exception as ex:
            rows.append({"d": d, "record": False, "policy": None, "error": type(ex).__name__}); continue
        res = {}
        for name, pol in (("policy", policy), ("relaxed", relaxed)):
            R = Report(quiet=True, require_all_evidence=True); R.policy_name = pol["name"]
            try: verify_chain(R, P("root.json"), links + [out], store, profile, registry, policy=pol)
            except Exception as ex: res[name] = (False, f"error:{type(ex).__name__}", R); continue
            verdict = R.policy_verdict if hasattr(R, "policy_verdict") else ("ACCEPTED" if (R.ok and R.policy_ok) else "REJECTED")
            res[name] = (R.ok, verdict, R)
            if name == "policy" and not hasattr(R, "links"): break                                                # the reviewed draft: one policy only
        ok, verdict, R = res["policy"]
        named = any(S in n["text"] and n["kind"] in ("coverage by judgement", "residual rebuilt", "unrecorded artifact", "enumeration domain") for n in R.notices)
        rows.append({"d": d, "record": ok, "policy": verdict, "accepted": ok and verdict == "ACCEPTED", "system_named": named,
                     "accepted_without_domain_member": (res["relaxed"][0] and res["relaxed"][1] == "ACCEPTED") if "relaxed" in res else None,
                     "failed": sorted({c.split("[")[0] for c in R.fails + R.policy_fails})[:6] if not (ok and verdict == "ACCEPTED") else []})
    if os.path.exists(out): os.remove(out)
    return rows


def summarise(scenario, rows):
    acc = [r for r in rows if r.get("accepted")]
    s = {"declarations": len(rows), "valid_records": sum(bool(r["record"]) for r in rows), "accepted_under_the_supplied_policy": len(acc),
         "accepted_if_the_policy_omits_enumeration_domains": sum(bool(r.get("accepted_without_domain_member")) for r in rows) if rows and rows[0].get("accepted_without_domain_member") is not None else None,
         "valid_records_that_do_not_name_system_py": sum(1 for r in rows if r["record"] and not r.get("system_named")) if scenario != "control" else None,
         "accepted_examples": [r["d"] for r in acc[:12]]}
    return s


def _shard(work, scenario, i, n, sample, policy, out):
    decls = space(scenario)
    if sample and len(decls) > sample: decls = random.Random(20261116).sample(decls, sample)
    json.dump(evaluate(work, scenario, decls[i::n], policy), open(out, "w"))


def run(out, jobs=4, sample=0, policy=None, mode="check", work=None):
    """Build the fixtures once, evaluate every scenario in ``jobs`` operating-system processes, write ``out``.
    Returns the result; in mode ``check`` the caller (``__main__``) exits with status 1 if an invariant is violated."""
    import subprocess
    jobs, sample = int(jobs), int(sample); policy = None if policy in (None, "", "-") else policy
    if mode not in ("check", "measure"): raise SystemExit("mode must be 'check' or 'measure'")
    work = work or tempfile.mkdtemp(prefix="recertkit_search_")
    facts = build(work)
    policy = os.path.abspath(policy or os.path.join(HERE, "..", "examples", "quickstart", "policy.json"))
    import recertkit
    result = {"recertkit": recertkit.__file__, "certificate_format": recertkit.CERT_VERSION, "policy": json.load(open(policy)), "harmful_change": facts, "scenarios": {}}
    for sc in SCENARIOS:
        parts = [os.path.join(work, f"rows_{sc}_{i}.json") for i in range(jobs)]
        procs = [subprocess.Popen([sys.executable, os.path.abspath(__file__), "--shard", work, sc, str(i), str(jobs), str(sample), policy, parts[i]]) for i in range(jobs)]
        assert all(p.wait() == 0 for p in procs), "a shard failed"
        rows = [r for part in parts for r in json.load(open(part))]
        n = len(space(sc)); assert len(rows) == (min(n, sample) if sample else n)
        result["scenarios"][sc] = {"space": n, **summarise(sc, rows)}
        print(sc, json.dumps({k: v for k, v in result["scenarios"][sc].items() if k != "accepted_examples"}), flush=True)
    sc = result["scenarios"]; harmful = [sc[k] for k in ("first", "later")]
    result["mode"] = mode
    result["invariants"] = {"I1_no_harmful_declaration_accepted": sum(h["accepted_under_the_supplied_policy"] for h in harmful) == 0,
                            "I2_every_valid_harmful_record_names_system_py": sum(h["valid_records_that_do_not_name_system_py"] for h in harmful) == 0,
                            # on a sample of the control space an acceptance may simply not have been drawn: not assessed
                            "I3_control_accepted_at_least_once": (sc["control"]["accepted_under_the_supplied_policy"] > 0) if sc["control"]["declarations"] == sc["control"]["space"] else None}
    json.dump(result, open(out, "w"), indent=1)
    shutil.rmtree(work, ignore_errors=True)
    print("invariants:", json.dumps(result["invariants"]), f"(mode {mode})", flush=True)
    return result


if __name__ == "__main__":
    if sys.argv[1] == "--shard":
        a = sys.argv[2:]; _shard(a[0], a[1], int(a[2]), int(a[3]), int(a[4]), a[5], a[6])
    else:
        res = run(*sys.argv[1:6])
        if res["mode"] == "check" and any(v is False for v in res["invariants"].values()):
            print("INVARIANT VIOLATED — see the 'invariants' member of", sys.argv[1], file=sys.stderr); sys.exit(1)
