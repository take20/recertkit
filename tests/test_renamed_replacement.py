# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
"""Which new artifact takes the place of which replaced one, and what a comparison record is a record OF.

The verifier identifies artifacts by NAME.  It cannot see where the running system reaches them.  Two kernels,
kernel_add.py and kernel_mul.py, have their contents swapped; system.py reaches them by name, so it now multiplies
where it added (130 of 200 predictions change).  Each new file computes exactly what the OTHER parent file computed,
so a comparison of each new file with the other parent file is true and reports zero mismatches.  Three ways of
declaring the swap with transcripts whose numbers are all true were found by review, one per release:

* 1.0.0 — per file, crosswise: each new file declared as the replacement of the other parent file;
* 1.1.0 — as one block: one entry whose subjects and replaced artifacts are both kernels;
* 1.2.0 — per file, under its own name, but bound to a transcript of ANOTHER comparison: the transcript records the
  comparison of the other new file and lists the claimed file as a further subject of the same block (finding R8-1).

Two rules answer them.

NAME ALIGNMENT (1.1.0, 1.2.0): an entry with one subject that replaces at most one parent artifact, of the same name,
needs nothing further; any other entry needs the written judgement ``replacement_correspondence``, is printed
(``renamed replacement``, ``multi-artifact block``) and can be refused by a policy.

SUBJECT SCOPE (1.3.0): a transcript in the standard layout states one result for the block of ALL subjects it
records.  An entry must claim that result for exactly that block (``equivalence.<id>.subject_scope``); the reference
side has been exact since 1.0.0.  With both rules, a name-aligned entry is valid only if the transcript records a
comparison of that one file with the parent file of its name.

The search at the end makes what an entry CLAIMS and what was actually COMPARED independent of each other: an entry is
(claimed subjects, claimed replaced artifacts, a transcript), and the transcripts are all 16 that the package's own
``toy.enumerate_block`` writes for the two kernels (which new file was run, which parent file it was compared with,
whether the other new file is listed as a further subject, whether the other parent file is listed as a further
reference file).  Not in this space: transcripts whose numbers are false (the verifier does not re-run comparisons),
transcripts in a foreign layout, and systems other than this one.
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
                          ("accepting", self._supplied(accept=True, renamed="allow")), ("accepting_blocks", self._supplied(accept=True, blocks="allow"))):
            json.dump(pol, open(P(f"policy_{name}.json"), "w"))
        self._t = {}

    def P(self, *a): return os.path.join(self.work, *a)

    @staticmethod
    def _supplied(accept=False, renamed=None, blocks=None):
        """The supplied quick-start release policy, with the two kernels' domain sizes; optionally it also accepts the
        correspondence judgement (``accept``), allows renamed replacements or allows multi-artifact blocks."""
        p = load_json(os.path.join(os.path.dirname(toy.__file__), "policy.json")); p["enumeration_domains"] = DOMAINS
        assert p["renamed_replacement"] == "forbid" and p["multi_artifact_block"] == "forbid"
        if accept: p["accepted_judgements"] = sorted(p["accepted_judgements"] + ["replacement_correspondence"])
        if renamed: p["renamed_replacement"] = renamed
        if blocks: p["multi_artifact_block"] = blocks
        return p

    def transcript(self, world, new, old, extra_subjects=(), extra_references=()):
        """A TRUE comparison of the new file ``new`` with the parent's file ``old`` on all 65,536 inputs, written by the
        package's own toy.enumerate_block, unmodified.  ``extra_subjects`` / ``extra_references`` are further files the
        tool is told the two blocks consist of; it records their digests.  Returns (file name, mismatches)."""
        key = (world, new, old, tuple(extra_subjects), tuple(extra_references))
        if key not in self._t:
            name = f"t_{world}_{len(self._t):03d}.json"
            t = toy.enumerate_block(self.P(world, new), self.P("c0", old), self.P(name),
                                    subject_files=[self.P(world, x) for x in extra_subjects], reference_files=[self.P("c0", r) for r in extra_references])
            self._t[key] = (name, t["mismatches"])
        return self._t[key]

    def spec(self, world, entries, judgement):
        """``entries``: tuples (subjects, replaces, new, old[, extra_subjects, extra_references]).  ``subjects`` and
        ``replaces`` are what the entry CLAIMS; the rest is the transcript: ``new`` and ``old`` are the two files that
        were actually compared.  In the 4-tuple form the transcript lists the other claimed files as the further files
        of the two blocks (a transcript that follows the declaration); the 6-tuple form states them explicitly."""
        eq, ev = [], {}
        for i, (S, Rp, new, old, *extra) in enumerate(entries, 1):
            xs, xr = extra if extra else (tuple(x for x in S if x != new), tuple(r for r in Rp if r != old))
            name, _ = self.transcript(world, new, old, xs, xr)
            ref = {"kind": "parent_artifact", "artifact": Rp[0]} if len(Rp) == 1 else {"kind": "parent_artifact", "artifacts": list(Rp)}
            eq.append({"id": f"e{i}", "method_code": "exhaustive_enumeration", "subjects": list(S), "replaces": list(Rp), "reference": ref,
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


A, M = KERNELS
CROSS = [((A,), (M,), A, M), ((M,), (A,), M, A)]                 # each new file declared as the replacement of the OTHER parent file
IDENTITY = [((A,), (A,), A, A), ((M,), (M,), M, M)]              # each new file declared as the replacement of the parent file of its name
BLOCK = [(KERNELS, KERNELS, A, M)]                               # ONE entry for both kernels; the files compared are new add and parent mul
BLOCK_ALIGNED = [(KERNELS, KERNELS, A, A)]                       # the same entry for the control: new add compared with parent add
CROSS_FAILS = ["equivalence.e1.correspondence", "equivalence.e2.correspondence"]


def _accuracy(world, v): return sum(r["correct"] for r in toy.evaluate(world.P(v)))


def test_the_swap_is_harmful_and_the_two_comparisons_are_true(world):
    assert [world.transcript("swap", new, old)[1] for _, _, new, old in CROSS] == [0, 0]     # each new file computes the OTHER old kernel's function
    assert 0 not in [world.transcript("swap", new, old)[1] for _, _, new, old in IDENTITY]   # compared under its own name, it does not
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


def test_block_declaration_of_the_swap_is_refused_at_issue_and_when_signed_anyway(world):
    """1.1.0 issued this declaration and accepted it under the reviewer's policy and under the supplied policy, with no
    notice.  Both pairs of files are truly equivalent (0 mismatches each); the transcript states one result for the block."""
    assert world.transcript("swap", A, M, (M,), (A,))[1] == 0 and world.transcript("swap", M, A)[1] == 0
    spec = world.spec("swap", BLOCK, judgement=False)
    rc, rep = world.issue("swap", spec)
    assert rc == 1 and rep["failed_checks"] == ["equivalence.e1.correspondence"] and not os.path.exists(world.P("derived.json"))
    world.forge("swap", spec)
    for pol in ("reviewer", "supplied"):
        rc, rep = world.verify(policy=pol)
        assert rc == 1 and not rep["record_valid"] and rep["failed_checks"] == ["equivalence.e1.correspondence"] and rep["policy_verdict"] == "REJECTED"


def test_block_declaration_with_the_judgement_is_printed_and_refused_by_release_policies(world):
    rc, _ = world.issue("swap", world.spec("swap", BLOCK, judgement=True))
    assert rc == 0
    rc, rep = world.verify("derived.json")
    notes = [n["text"] for n in rep["not_checked"] if n["kind"] == "multi-artifact block"]
    assert rc == 0 and rep["record_valid"] and len(notes) == 1 and "Which of these files the comparison exercised" in notes[0]
    e = rep["links"][0]["entries"]["e1"]; assert e["multi_artifact"] is True and e["renamed"] == []
    rc, rep = world.verify("derived.json", policy="reviewer")                                   # the reviewer's policy, unchanged
    assert rc == 1 and rep["record_valid"] and rep["policy"]["failed_checks"] == ["policy.accepted_judgements[derived.json]"]
    rc, rep = world.verify("derived.json", policy="supplied")
    assert rc == 1 and set(rep["policy"]["failed_checks"]) == {"policy.accepted_judgements[derived.json]", "policy.multi_artifact_block[derived.json]"}
    rc, rep = world.verify("derived.json", policy="forbid_only")                                # accepts the judgement, still forbids blocks
    assert rc == 1 and rep["policy"]["failed_checks"] == ["policy.multi_artifact_block[derived.json]"]
    rc, rep = world.verify("derived.json", policy="accepting_blocks")                           # a relying party that takes the judgement on trust
    assert rc == 0 and rep["policy_verdict"] == "ACCEPTED"


def test_block_declaration_of_the_harmless_control_is_treated_the_same(world):
    """The record cannot tell the swap from an equivalent re-implementation declared as one block: both need the judgement."""
    rc, rep = world.issue("ctrl", world.spec("ctrl", BLOCK_ALIGNED, judgement=False))
    assert rc == 1 and rep["failed_checks"] == ["equivalence.e1.correspondence"]


# ---- finding R8-1 (review of release 1.2.0): a transcript of another comparison, with the claimed file as a further subject
# e1 claims "new add replaces parent add"; its transcript is the comparison of new MUL with parent add (true: 0
# mismatches), in which new add is listed as a further file of the block.  e2 is the mirror image.
SCOPE = [((A,), (A,), M, A, (A,), ()), ((M,), (M,), A, M, (M,), ())]
SCOPE_FAILS = ["equivalence.e1.subject_scope", "equivalence.e2.subject_scope"]


def test_scope_declaration_uses_true_transcripts_of_the_packages_own_tool(world):
    for (S, Rp, new, old, xs, xr) in SCOPE:
        name, mism = world.transcript("swap", new, old, xs, xr); t = load_json(world.P(name))
        assert mism == 0 and t["enumerated"] == 65536 and sorted(t["subjects"]) == list(KERNELS) and S[0] in t["subjects"] and new != S[0]
        inv = dict(reversed(l.split()) for l in open(world.P("inventory_swap.txt")).read().splitlines())
        assert t["subjects"] == {k: inv[k] for k in KERNELS}                                    # every recorded digest is that of the real file


def test_scope_declaration_is_refused_at_issue_and_when_signed_anyway(world):
    """1.2.0 issued this declaration through the normal path and accepted it under the reviewer's policy and under the
    supplied policy, with no judgement and no notice: both entries looked like single files replacing files of their
    own names, and the engine only required the claimed subject to be AMONG the subjects the transcript records."""
    spec = world.spec("swap", SCOPE, judgement=False)
    rc, rep = world.issue("swap", spec)
    assert rc == 1 and rep["failed_checks"] == SCOPE_FAILS and not os.path.exists(world.P("derived.json"))
    world.forge("swap", spec)
    for pol in ("reviewer", "supplied"):
        rc, rep = world.verify(policy=pol)
        assert rc == 1 and not rep["record_valid"] and rep["failed_checks"] == SCOPE_FAILS and rep["policy_verdict"] == "REJECTED"
    assert rep["links"][0]["entries"]["e1"]["subject_scope"] is None


def test_scope_declaration_is_not_rescued_by_the_correspondence_judgement(world):
    """The judgement answers 'which file takes whose place'.  It does not make a result recorded for a block of two
    files a result about one of them."""
    rc, rep = world.issue("swap", world.spec("swap", SCOPE, judgement=True))
    assert rc == 1 and rep["failed_checks"] == SCOPE_FAILS


def test_transcript_that_does_not_record_the_claimed_subject_is_refused(world):
    """The claimed file is missing from the transcript altogether (the transcript records the other new file only)."""
    rc, rep = world.issue("swap", world.spec("swap", [((A,), (A,), M, A, (), ()), ((M,), (M,), A, M, (), ())], judgement=False))
    assert rc == 1 and rep["failed_checks"] == ["equivalence.e1.subject_digest", "equivalence.e1.subject_scope", "equivalence.e2.subject_digest", "equivalence.e2.subject_scope"]


def test_transcript_with_a_further_subject_is_refused_for_the_harmless_control_too(world):
    """The rule is about the record, not about the change: a truthful same-name comparison of an equivalent kernel is
    refused as well when its transcript lists a second file that the entry does not claim."""
    rc, rep = world.issue("ctrl", world.spec("ctrl", [((A,), (A,), A, A, (M,), ()), ((M,), (M,), M, M)], judgement=False))
    assert rc == 1 and rep["failed_checks"] == ["equivalence.e1.subject_scope"]
    rc, rep = world.issue("ctrl", world.spec("ctrl", IDENTITY, judgement=False))                # ... and issued when the transcript records that file alone
    assert rc == 0
    rc, rep = world.verify("derived.json", policy="supplied")
    e = rep["links"][0]["entries"]
    assert rc == 0 and rep["policy_verdict"] == "ACCEPTED" and e["e1"]["subject_scope"] == e["e2"]["subject_scope"] == "exact"
    assert toy.evaluate(world.P("ctrl")) == toy.evaluate(world.P("c0"))


def test_transcript_reference_with_both_forms_is_not_in_the_standard_layout(world):
    """``reference`` is a single digest or a block of named artifacts.  A transcript carrying both was read as the
    single digest, the block ignored."""
    spec = world.spec("ctrl", IDENTITY, judgement=False)
    f = world.P(spec["evidence_files"]["t1"]); t = load_json(f); original = json.dumps(t)
    t["reference"]["artifacts"] = {A: t["reference"]["sha256"], M: "0" * 64}; json.dump(t, open(world.P("t_bothforms.json"), "w"))
    spec["evidence_files"]["t1"] = "t_bothforms.json"
    rc, rep = world.issue("ctrl", spec)
    assert rc == 1 and rep["failed_checks"] == ["equivalence.e1.reference_digest"] and json.dumps(load_json(f)) == original


def test_scope_reduction_through_a_foreign_layout_is_printed_and_refused_by_the_release_policies(world):
    """The boundary of the scope check.  A transcript in a foreign layout is read only through the pointers the issuer
    declares, so the verifier cannot see that it records a second subject.  Here the tool's transcripts of finding
    R8-1 are re-labelled as a foreign layout (the schema member is changed — the numbers are not) and each entry points
    at 'its' file.  Such a record is valid; every run prints that the mapping, including the scope of the comparison, is
    the issuer's declaration; the reviewer's policy and the supplied policy refuse it."""
    spec = world.spec("swap", SCOPE, judgement=False)
    for i, e in enumerate(spec["equivalence"], 1):
        t = load_json(world.P(spec["evidence_files"][f"t{i}"])); t["schema"] = "lab-comparison-1"
        json.dump(t, open(world.P(f"t_foreign_{i}.json"), "w")); spec["evidence_files"][f"t{i}"] = f"t_foreign_{i}.json"
        e["pointers"] = {"subjects": {e["subjects"][0]: f"/subjects/{e['subjects'][0]}"}, "reference_sha256": "/reference/sha256", "enumerated": "/enumerated", "mismatches": "/mismatches"}
    rc, rep = world.issue("swap", spec)
    assert rc == 0, rep["failed_checks"]
    rc, rep = world.verify("derived.json")
    notes = [n["text"] for n in rep["not_checked"] if n["kind"] == "transcript mapping"]
    assert rc == 0 and len(notes) == 2 and all("covered further files" in n for n in notes)
    assert {e["subject_scope"] for e in rep["links"][0]["entries"].values()} == {"declared"}
    for pol in ("reviewer", "supplied"):
        rc, rep = world.verify("derived.json", policy=pol)
        assert rc == 1 and rep["record_valid"] and rep["policy_verdict"] == "REJECTED" and "policy.transcript_mapping[derived.json]" in rep["policy"]["failed_checks"]


# ---- the search: what an entry claims and what was compared vary independently
SETS = ((A,), (M,), KERNELS)
OTHER = {A: M, M: A}


def entry_space():
    """144 entries: claimed subjects (3) x claimed replaced artifacts (3) x the 16 transcripts toy.enumerate_block writes
    for two kernels (new file run, parent file compared with, the other new file listed or not, the other parent file
    listed or not)."""
    out = []
    for S in SETS:
        for Rp in SETS:
            for new in KERNELS:
                for old in KERNELS:
                    for xs in ((), (OTHER[new],)):
                        for xr in ((), (OTHER[old],)): out.append((S, Rp, new, old, xs, xr))
    return out


def declaration_space():
    """Every declaration of one or two entries, with and without the judgement: 2 x (144 + C(144, 2)) = 20,880."""
    E = entry_space()
    for n in (1, 2):
        for combo in itertools.combinations(E, n):
            for judgement in (False, True): yield list(combo), judgement


FULL_SPACE = 20880


def recorded(entry):
    """(subjects, reference artifacts) the entry's transcript records."""
    S, Rp, new, old, xs, xr = entry
    return tuple(sorted({new, *xs})), tuple(sorted({old, *xr}))


def aligned(entry):
    S, Rp = entry[0], entry[1]
    return len(S) == 1 and len(Rp) == 1 and S == Rp


def evaluate(world, w, entries, judgement):
    """Issue through the normal path; sign WITHOUT the issuer-side checks; verify under both policies."""
    spec = world.spec(w, entries, judgement)
    rc_issue, _ = world.issue(w, spec)
    world.forge(w, spec)
    _, rv = world.verify(policy="reviewer"); _, sv = world.verify(policy="supplied")
    noticed = sorted({t["text"].split(":")[0].replace("equivalence ", "") for t in sv["not_checked"] if t["kind"] in ("renamed replacement", "multi-artifact block")})
    return {"entries": [[list(x) if isinstance(x, tuple) else x for x in e] for e in entries], "judgement": judgement, "issued": rc_issue == 0,
            "record_valid": sv["record_valid"], "failed_checks": sv["failed_checks"],
            "unaligned_entries": sorted(f"e{i}" for i, e in enumerate(entries, 1) if not aligned(e)), "noticed_entries": noticed,
            "scope_matches_record": all((tuple(sorted(e[0])), tuple(sorted(e[1]))) == recorded(e) for e in entries),
            "accepted_reviewer_policy": rv["policy_verdict"] == "ACCEPTED", "accepted_supplied_policy": sv["policy_verdict"] == "ACCEPTED"}


def check_rows(w, rows):
    """The invariants, on any set of evaluated declarations of world ``w``; returns the list of violated ones."""
    bad = []
    valid = [r for r in rows if r["record_valid"]]
    if [r for r in rows if r["issued"] != r["record_valid"]]: bad.append("the issuer-side checks and the verifier disagree")
    if [r for r in valid if not r["scope_matches_record"]]: bad.append("a valid record claims a result for other files than its transcript records")
    if [r for r in valid if r["noticed_entries"] != r["unaligned_entries"] or (r["unaligned_entries"] and not r["judgement"])]:
        bad.append("an entry that is not name-aligned is valid without the judgement or without its notice")
    if w == "swap":
        if [r for r in rows if not r["judgement"] and (r["issued"] or r["record_valid"])]: bad.append("a declaration of the swap is valid without the judgement")
        if [r for r in rows if r["accepted_reviewer_policy"] or r["accepted_supplied_policy"]]: bad.append("a declaration of the swap is accepted")
    return bad


IDENTITY_EXACT = [[[A], [A], A, A, [], []], [[M], [M], M, M, [], []]]


def _entry_level_failures(row):
    return [c for c in row["failed_checks"] if c.startswith("equivalence.e1.")]


def test_search_every_single_entry_and_every_pair_of_viable_entries(world):
    """The default run of the search.  All 288 single-entry declarations of each system are evaluated.  An entry with a
    failed check of its own cannot be part of a valid record, so pairs are enumerated in full among the other
    ('viable') entries, and a seeded sample of 200 pairs containing a non-viable entry confirms that they are invalid.
    ``tests/swap_search.py`` evaluates all 20,880 declarations of each system without this shortcut."""
    E = entry_space(); assert len(E) == 144 and len(set(E)) == 144
    rng = random.Random(20261124); summary = {}
    for w in ("swap", "ctrl"):
        rows, viable = [], {False: [], True: []}
        for e in E:
            for j in (False, True):
                r = evaluate(world, w, [e], j); rows.append(r)
                if not _entry_level_failures(r): viable[j].append(e)
        for j in (False, True):
            for pair in itertools.combinations(viable[j], 2): rows.append(evaluate(world, w, list(pair), j))
        nonviable = [e for e in E if e not in viable[True]]
        sample = [evaluate(world, w, [rng.choice(nonviable), rng.choice(E)], rng.choice((False, True))) for _ in range(200)]
        assert not [r for r in sample if r["record_valid"] or r["issued"]]
        assert check_rows(w, rows + sample) == []
        summary[w] = {"viable_entries_without_judgement": len(viable[False]), "viable_entries_with_judgement": len(viable[True]), "declarations_evaluated": len(rows) + len(sample),
                      "valid_records": sum(r["record_valid"] for r in rows), "accepted_supplied_policy": [(r["entries"], r["judgement"]) for r in rows if r["accepted_supplied_policy"]],
                      "accepted_reviewer_policy": sum(r["accepted_reviewer_policy"] for r in rows)}
    assert summary["swap"]["viable_entries_without_judgement"] == 0 and summary["swap"]["accepted_supplied_policy"] == []
    # control: exactly the declaration that pairs each file with the parent file of its name, each transcript recording that one comparison
    assert summary["ctrl"]["accepted_supplied_policy"] == [(IDENTITY_EXACT, False)] and summary["ctrl"]["viable_entries_without_judgement"] == 2
    out = os.environ.get("RECERTKIT_SWAP_SEARCH_OUT")
    if out: json.dump({"mode": "single entries in full; pairs of viable entries in full; 200 sampled pairs with a non-viable entry", "entries": len(E), **summary}, open(out, "w"), indent=1)
