"""Replacement under another name (external review of package v6, finding M1-a).

The verifier identifies artifacts by NAME.  The reviewer swapped the contents of two kernels, kernel_add.py and
kernel_mul.py, and declared each new file as the replacement of the OTHER parent file.  Both comparisons are true
(the new kernel_add.py computes exactly what the old kernel_mul.py computed, and vice versa), every name was covered,
and RecertKit 1.0.0 issued the certificate and accepted it under a strict policy — while system.py, which reaches the
kernels by name, now multiplies where it added.

Since 1.1.0 an equivalence entry whose replaced artifacts do not all have a subject of the same name needs the written
judgement ``replacement_correspondence`` (check ``equivalence.<id>.correspondence``); the condition is printed as a
``renamed replacement`` notice on every run, and the policy member ``renamed_replacement: forbid`` refuses it.

The last test signs EVERY declaration of the swap that uses single-subject entries — each subject paired with each
non-empty set of replaced kernels and each choice of the compared reference kernel, one or two entries, with and
without the judgement — using true comparison transcripts, and verifies each under the reviewer's policy and under the
supplied quick-start policy.  Entries whose subject is a block of several artifacts are outside this space (they are
the subject of finding M1-b, which this revision does not address).
"""
import itertools, json, os, random
import pytest
import toy
from recertkit.cli import main as cli
from recertkit.canon import load_json
from recertkit.engine import build_certificate
from recertkit.profiles import load_profile
from recertkit.signing import sign

KERNELS = ("kernel_add.py", "kernel_mul.py")
ADD, MUL = "def q(a, b):\n    return a + b\n", "def q(a, b):\n    return a * b\n"
ADD_EQ, MUL_EQ = "def q(a, b):\n    return b + a\n", "def q(a, b):\n    return b * a\n"       # equivalent re-implementations
SYSTEM2 = '''import importlib.util, json, os
_here = os.path.dirname(os.path.abspath(__file__))
def _load(name):
    s = importlib.util.spec_from_file_location(name, os.path.join(_here, name + ".py")); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
_add, _mul = _load("kernel_add"), _load("kernel_mul")
_W = json.load(open(os.path.join(_here, "model.json")))["weights"]
def predict(features):
    scores = [sum(_mul.q(x, w) for x, w in zip(features[:8], row[:8])) + sum(_add.q(x, w) for x, w in zip(features[8:], row[8:])) for row in _W]
    return max(range(len(scores)), key=lambda c: (scores[c], -c))
def run(frame_path):
    out = []
    for line in open(frame_path):
        if line.strip():
            it = json.loads(line); p = predict(it["features"])
            out.append({"item_id": it["item_id"], "pred": p, "correct": int(p == it["label"])})
    return out
'''
BOUNDARY2 = "system.py calls both kernels only as q(x, w) with x a frame feature and w a model weight, both integers in [-128, 127]."
CORR = "Each new kernel takes the place of the parent kernel it was compared with."
DOMAINS = {k: 65536 for k in KERNELS}
# the reviewer's policy, as written in audit_recertkit.py (TEST 1)
REVIEWER_POLICY = {"name": "strict-policy", "require_all_evidence": True, "coverage_by_judgement": "forbid", "residual_rebuilt": "forbid", "unrecorded": "forbid",
                   "reference_kinds": ["parent_artifact", "parent_link"], "binding_levels": ["digest"], "transcript_mapping": "forbid",
                   "accepted_judgements": ["boundary", "residual_path"], "accepted_assumptions": ["interpreter"], "require_prospective": True,
                   "reference_by_declaration": "forbid", "enumeration_domains": DOMAINS}


def _frame(path, seed=7, n_items=200):
    """The quick-start features and model weights, labelled by a teacher of the SAME structure as SYSTEM2 (products on
    the first eight features, sums on the last eight) with perturbed weights."""
    rng = random.Random(seed)
    weights = [[rng.randint(-100, 100) for _ in range(16)] for _ in range(3)]
    teacher = [[w + rng.randint(-25, 25) for w in row] for row in weights]
    with open(path, "w") as f:
        for i in range(n_items):
            x = [rng.randint(-128, 127) for _ in range(16)]
            s = [sum(a * b for a, b in zip(x[:8], row[:8])) + sum(a + b for a, b in zip(x[8:], row[8:])) for row in teacher]
            f.write(json.dumps({"item_id": f"toy_{i:04d}", "features": x, "label": max(range(3), key=lambda c: (s[c], -c))}) + "\n")


def _world(directory, add_src, mul_src):
    """The quick-start model with a system that reaches two kernels by name."""
    paths = toy.write_config(directory, "ref"); os.remove(paths.pop("kernel.py"))
    open(paths["system.py"], "w").write(SYSTEM2); _frame(paths["frame.jsonl"])
    for name, src in zip(KERNELS, (add_src, mul_src)):
        paths[name] = os.path.join(directory, name); open(paths[name], "w").write(src)
    return paths


class World:
    def __init__(self, work):
        self.work = work; P = self.P
        self.cfg = {"c0": _world(P("c0"), ADD, MUL), "swap": _world(P("swap"), MUL, ADD), "ctrl": _world(P("ctrl"), ADD_EQ, MUL_EQ)}
        assert open(P("swap", "kernel_add.py")).read() == open(P("c0", "kernel_mul.py")).read()              # the contents are swapped, byte for byte
        for f in ("system.py", "model.json", "frame.jsonl"):
            assert open(P("c0", f), "rb").read() == open(P("swap", f), "rb").read() == open(P("ctrl", f), "rb").read()
        assert cli(["keygen", "--private", P("release.key"), "--public", P("release.pub")]) == 0
        for v, c in self.cfg.items(): assert cli(["inventory", *c.values(), "--out", P(f"inventory_{v}.txt")]) == 0
        json.dump(toy.CLAIM, open(P("claim.json"), "w"))
        c = self.cfg["c0"]
        assert cli(["root-issue", "--claim", P("claim.json"), "--role", f"server={c['system.py']}", "--role", f"model={c['model.json']}", "--role", f"frame={c['frame.jsonl']}",
                    "--inventory", P("inventory_c0.txt"), "--basis", "test root", "--key", P("release.key"), "--key-id", "release", "--out", P("root.json")]) == 0
        for name, pol in (("reviewer", REVIEWER_POLICY), ("supplied", self._supplied()), ("forbid_only", self._supplied(accept=True)),
                          ("accepting", self._supplied(accept=True, renamed="allow"))):
            json.dump(pol, open(P(f"policy_{name}.json"), "w"))
        self._t = {}

    def P(self, *a): return os.path.join(self.work, *a)

    @staticmethod
    def _supplied(accept=False, renamed=None):
        """The supplied quick-start release policy, with the two kernels' domain sizes; optionally it also accepts the
        correspondence judgement (``accept``) or allows renamed replacements (``renamed="allow"``)."""
        p = load_json(os.path.join(os.path.dirname(toy.__file__), "policy.json")); p["enumeration_domains"] = DOMAINS
        assert p["renamed_replacement"] == "forbid"
        if accept: p["accepted_judgements"] = sorted(p["accepted_judgements"] + ["replacement_correspondence"])
        if renamed: p["renamed_replacement"] = renamed
        return p

    def transcript(self, world, subject, replaces, compared):
        """A TRUE comparison of the new ``subject`` with the parent's ``compared`` kernel; a composite reference also
        records the digests of the other replaced parent kernels."""
        key = (world, subject, tuple(replaces), compared)
        if key not in self._t:
            name = f"t_{world}_{subject[7:10]}_{'_'.join(r[7:10] for r in replaces)}_{compared[7:10]}.json"
            others = [self.P("c0", r) for r in replaces if r != compared]
            t = toy.enumerate_block(self.P(world, subject), self.P("c0", compared), self.P(name), reference_files=others)
            self._t[key] = (name, t["mismatches"])
        return self._t[key]

    def spec(self, world, entries, judgement):
        eq, ev = [], {}
        for i, (s, R, r) in enumerate(entries, 1):
            name, _ = self.transcript(world, s, R, r)
            ref = {"kind": "parent_artifact", "artifact": R[0]} if len(R) == 1 else {"kind": "parent_artifact", "artifacts": list(R)}
            eq.append({"id": f"e{i}", "method_code": "exhaustive_enumeration", "subjects": [s], "replaces": list(R), "reference": ref,
                       "transcript": f"t{i}", "domain_size": 65536, "domain": "all signed 8-bit operand pairs (a, b)"})
            ev[f"t{i}"] = name
        spec = {"change": {"summary": f"two kernels replaced ({world})"}, "claim_scope": "the parent's claim on the fixed 200-item frame",
                "block": {"changed": list(KERNELS), "unchanged": ["system.py", "model.json", "frame.jsonl"]},
                "roles": {"server": "system.py", "model": "model.json", "frame": "frame.jsonl"},
                "root_binding": {"roles": {"server": "digest", "model": "digest", "frame": "digest"}, "inventory": "digest"},
                "equivalence": eq, "evidence_files": ev,
                "judgements": {"boundary": BOUNDARY2, "residual_path": "system.py, model.json and frame.jsonl are byte-identical (hash identity)."},
                "trust_assumptions": {"interpreter": "the Python interpreter evaluates every kernel as written"}}
        if judgement: spec["judgements"]["replacement_correspondence"] = CORR
        return spec

    def issue(self, world, spec, out="derived.json"):
        json.dump(spec, open(self.P("spec.json"), "w"))
        if os.path.exists(self.P(out)): os.remove(self.P(out))
        rc = cli(["issue", "--parent", self.P("root.json"), "--spec", self.P("spec.json"), "--parent-inventory", self.P("inventory_c0.txt"),
                  "--derived-inventory", self.P(f"inventory_{world}.txt"), "--key", self.P("release.key"), "--key-id", "release", "--out", self.P(out),
                  "--json-report", self.P("issue.json")])
        return rc, load_json(self.P("issue.json"))

    def forge(self, world, spec, out="forged.json"):
        """Sign WITHOUT the issuer-side checks: what a careless or malicious holder of the trusted key could do."""
        c = build_certificate(self.P("root.json"), spec, self.P("inventory_c0.txt"), self.P(f"inventory_{world}.txt"), load_profile(None), spec_dir=self.work)
        json.dump(sign(c, self.P("release.key"), "release"), open(self.P(out), "w"))

    def verify(self, cert="forged.json", policy=None):
        extra = ["--policy", self.P(f"policy_{policy}.json")] if policy else []
        rc = cli(["verify-chain", "--root", self.P("root.json"), "--links", self.P(cert), "--trust", f"release={self.P('release.pub')}", *extra, "--json-report", self.P("verify.json")])
        return rc, load_json(self.P("verify.json"))


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    return World(str(tmp_path_factory.mktemp("swap")))


CROSS = [("kernel_add.py", ("kernel_mul.py",), "kernel_mul.py"), ("kernel_mul.py", ("kernel_add.py",), "kernel_add.py")]
IDENTITY = [("kernel_add.py", ("kernel_add.py",), "kernel_add.py"), ("kernel_mul.py", ("kernel_mul.py",), "kernel_mul.py")]
CROSS_FAILS = ["equivalence.e1.correspondence", "equivalence.e2.correspondence"]


def _accuracy(world, v): return sum(r["correct"] for r in toy.evaluate(world.P(v)))


def test_the_swap_is_harmful_and_the_two_comparisons_are_true(world):
    assert [world.transcript("swap", *e)[1] for e in CROSS] == [0, 0]                       # each new file computes the OTHER old kernel's function
    assert [world.transcript("swap", *e)[1] for e in IDENTITY] != [0, 0]                    # compared under its own name, it does not
    c0, sw = toy.evaluate(world.P("c0")), toy.evaluate(world.P("swap"))
    assert sum(a["pred"] != b["pred"] for a, b in zip(c0, sw)) > 0 and _accuracy(world, "swap") < _accuracy(world, "c0")
    assert toy.evaluate(world.P("ctrl")) == c0


def test_cross_declaration_is_refused_at_issue(world):
    rc, rep = world.issue("swap", world.spec("swap", CROSS, judgement=False))
    assert rc == 1 and rep["failed_checks"] == CROSS_FAILS and not os.path.exists(world.P("derived.json"))


def test_cross_declaration_signed_anyway_is_rejected_by_the_verifier(world):
    world.forge("swap", world.spec("swap", CROSS, judgement=False))
    rc, rep = world.verify(policy="reviewer")
    assert rc == 1 and not rep["record_valid"] and rep["failed_checks"] == CROSS_FAILS and rep["policy_verdict"] == "REJECTED"


def test_with_the_judgement_the_condition_is_printed_and_release_policies_refuse_it(world):
    rc, _ = world.issue("swap", world.spec("swap", CROSS, judgement=True))
    assert rc == 0
    rc, rep = world.verify("derived.json")
    notes = [n["text"] for n in rep["not_checked"] if n["kind"] == "renamed replacement"]
    assert rc == 0 and rep["record_valid"] and len(notes) == 2
    assert "['kernel_mul.py'] of the parent configuration is replaced by ['kernel_add.py']" in notes[0] and "still exists in the derived configuration" in notes[0]
    assert rep["links"][0]["entries"]["e1"]["renamed"] == ["kernel_mul.py"] and rep["links"][0]["entries"]["e2"]["renamed"] == ["kernel_add.py"]
    rc, rep = world.verify("derived.json", policy="reviewer")                                   # the reviewer's policy, unchanged
    assert rc == 1 and rep["record_valid"] and rep["policy"]["failed_checks"] == ["policy.accepted_judgements[derived.json]"]
    rc, rep = world.verify("derived.json", policy="supplied")
    assert rc == 1 and set(rep["policy"]["failed_checks"]) == {"policy.accepted_judgements[derived.json]", "policy.renamed_replacement[derived.json]"}


def test_renamed_replacement_member_refuses_on_its_own(world):
    rc, _ = world.issue("swap", world.spec("swap", CROSS, judgement=True)); assert rc == 0
    rc, rep = world.verify("derived.json", policy="forbid_only")
    assert rc == 1 and rep["policy"]["failed_checks"] == ["policy.renamed_replacement[derived.json]"]
    rc, rep = world.verify("derived.json", policy="accepting")                                  # a relying party that accepts the judgement by name
    assert rc == 0 and rep["policy_verdict"] == "ACCEPTED"


def test_same_name_replacement_needs_no_judgement(world):
    rc, _ = world.issue("ctrl", world.spec("ctrl", IDENTITY, judgement=False))
    assert rc == 0
    rc, rep = world.verify("derived.json", policy="supplied")
    assert rc == 0 and rep["policy_verdict"] == "ACCEPTED" and not [n for n in rep["not_checked"] if n["kind"] == "renamed replacement"]


def _entries():
    for s in KERNELS:
        for R in (("kernel_add.py",), ("kernel_mul.py",), KERNELS):
            for r in R: yield (s, R, r)


def _declarations():
    E = list(_entries())
    for n in (1, 2):
        for combo in itertools.combinations(E, n):
            for judgement in (False, True): yield list(combo), judgement


def _search(world, w):
    rows = []
    for entries, judgement in _declarations():
        spec = world.spec(w, entries, judgement)
        rc_issue, _ = world.issue(w, spec)
        world.forge(w, spec)
        _, plain = world.verify()
        verdicts = {p: world.verify(policy=p)[1]["policy_verdict"] for p in ("reviewer", "supplied")}
        renamed_entries = [f"e{i}" for i, (s, R, r) in enumerate(entries, 1) if any(x != s for x in R)]
        noticed = {t["text"].split(":")[0].replace("equivalence ", "") for t in plain["not_checked"] if t["kind"] == "renamed replacement"}
        rows.append({"entries": [[s, list(R), r] for s, R, r in entries], "judgement": judgement, "issued": rc_issue == 0, "record_valid": plain["record_valid"],
                     "failed_checks": plain["failed_checks"], "renamed_entries": renamed_entries, "renamed_noticed": sorted(noticed),
                     "accepted_reviewer_policy": verdicts["reviewer"] == "ACCEPTED", "accepted_supplied_policy": verdicts["supplied"] == "ACCEPTED"})
    return rows


def test_every_single_subject_declaration_of_the_swap(world):
    swap, ctrl = _search(world, "swap"), _search(world, "ctrl")
    assert len(swap) == len(ctrl) == 72
    # (1) without the judgement, no declaration of the harmful swap is issued or is a valid record
    assert not [r for r in swap if not r["judgement"] and (r["issued"] or r["record_valid"])]
    # (2) with it, every valid record prints the renamed replacement of every entry that has one
    valid = [r for r in swap if r["record_valid"]]
    assert valid and all(r["renamed_entries"] and set(r["renamed_noticed"]) == set(r["renamed_entries"]) for r in valid)
    # (3) none is accepted under the reviewer's policy or under the supplied policy
    assert not [r for r in swap if r["accepted_reviewer_policy"] or r["accepted_supplied_policy"]]
    # control: the same declarations for an equivalent change under the same names; exactly the identity mapping is accepted
    acc = [r for r in ctrl if r["accepted_supplied_policy"]]
    assert [(r["entries"], r["judgement"]) for r in acc] == [([[s, list(R), r_] for s, R, r_ in IDENTITY], False)]
    out = os.environ.get("RECERTKIT_SWAP_SEARCH_OUT")
    if out:
        summary = lambda rows: {"declarations": len(rows), "issued": sum(r["issued"] for r in rows), "valid_records": sum(r["record_valid"] for r in rows),
                                "valid_without_judgement": sum(r["record_valid"] and not r["judgement"] for r in rows),
                                "accepted_reviewer_policy": sum(r["accepted_reviewer_policy"] for r in rows), "accepted_supplied_policy": sum(r["accepted_supplied_policy"] for r in rows)}
        json.dump({"what": __doc__.strip().splitlines()[0], "space": "single-subject entries: subject x non-empty set of replaced kernels x compared kernel; 1 or 2 entries; "
                   "with and without the judgement 'replacement_correspondence'; true comparison transcripts",
                   "accuracy": {v: _accuracy(world, v) for v in ("c0", "swap", "ctrl")},
                   "predictions_changed": {v: sum(a["pred"] != b["pred"] for a, b in zip(toy.evaluate(world.P("c0")), toy.evaluate(world.P(v)))) for v in ("swap", "ctrl")},
                   "swap": summary(swap), "control": summary(ctrl),
                   "swap_rows": swap, "control_rows": ctrl}, open(out, "w"), indent=1)
