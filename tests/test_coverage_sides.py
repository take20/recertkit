"""Coverage obligations are side-specific (review of the second draft, finding R1).

The same file name in the parent and in the derived configuration denotes two different things.  Naming the parent's
file — as a replaced artifact, or under a judgement restricted to the parent side — never covers the changed file of the
derived configuration.  The tests cover: the reviewer's counterexample on a generic root and on the real gate-issued
root; one name on both sides; a block of several artifacts; additions, deletions and a rename.
"""
import json, os, shutil
import pytest
import toy
from recertkit.cli import main as cli
from recertkit.canon import load_json

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.join(HERE, "..", "examples", "gate_root")
MARKER = "return max(range(len(scores)), key=lambda c: (scores[c], -c))"


def _break_system(path):
    s = open(path).read(); assert MARKER in s; open(path, "w").write(s.replace(MARKER, "return 0"))


def _config(chain, name, kernel, break_system=False, extra=None, drop=()):
    cfg = toy.write_config(chain.P(f"config_{name}"), kernel)
    if break_system: _break_system(cfg["system.py"])
    for fn, text in (extra or {}).items():
        cfg[fn] = chain.P(f"config_{name}", fn); open(cfg[fn], "w").write(text)
    for fn in drop: os.remove(cfg.pop(fn))
    assert cli(["inventory", *cfg.values(), "--out", chain.P(f"inventory_{name}.txt")]) == 0
    return cfg


def _spec(chain, name, transcript, **over):
    spec = toy.spec_for(chain.P(transcript), name); spec.update(over)
    json.dump(spec, open(chain.P(f"spec_{name}.json"), "w")); return spec


def _replaces_only(chain):
    """The reviewer's declaration: an equivalent kernel with TRUE evidence, a system.py that always predicts class 0,
    and system.py merely added to the parent artifacts the kernel comparison 'replaces'."""
    cfg = _config(chain, "bad", "lut", break_system=True)
    assert toy.enumerate_block(cfg["kernel.py"], chain.P("config_v0", "kernel.py"), chain.P("enumeration_bad.json"))["mismatches"] == 0
    spec = _spec(chain, "bad", "enumeration_bad.json", block={"changed": ["kernel.py", "system.py"], "unchanged": ["model.json", "frame.jsonl"]})
    spec["equivalence"][0]["replaces"] = ["kernel.py", "system.py"]
    json.dump(spec, open(chain.P("spec_bad.json"), "w")); return spec


def test_replaces_only_coverage_is_refused_at_issue(chain):
    _replaces_only(chain)
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_bad.txt", "spec_bad.json", "derived_bad.json")
    assert rc == 1 and rep["failed_checks"] == ["coverage.derived_side", "equivalence.kernel.reference_block"] and not os.path.exists(chain.P("derived_bad.json"))
    before, after = toy.evaluate(chain.P("config_v0")), toy.evaluate(chain.P("config_bad"))
    assert sum(a["pred"] != b["pred"] for a, b in zip(before, after)) == 127 and (sum(r["correct"] for r in before), sum(r["correct"] for r in after)) == (150, 67)


def test_replaces_only_coverage_signed_anyway_is_rejected_by_the_verifier(chain):
    chain.forge("root.json", "inventory_v0.txt", "inventory_bad.txt", _replaces_only(chain), "derived_bad.json")
    rc, rep = chain.verify_chain(links=("derived_bad.json",), extra=["--require-all-evidence", "--policy", os.path.join(os.path.dirname(toy.__file__), "policy.json")])
    assert rc == 1 and rep["failed_checks"] == ["coverage.derived_side", "equivalence.kernel.reference_block"] and rep["policy_verdict"] == "REJECTED"


def test_replaces_only_coverage_with_a_composite_reference_is_still_refused(chain):
    """Declaring the reference as the block {kernel.py, system.py} satisfies the reference/replaces relation — but the
    true transcript does not record such a reference, and the new system.py still has no evidence."""
    spec = _replaces_only(chain); spec["equivalence"][0]["reference"] = {"kind": "parent_artifact", "artifacts": ["kernel.py", "system.py"]}
    json.dump(spec, open(chain.P("spec_bad.json"), "w"))
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_bad.txt", "spec_bad.json", "derived_bad.json")
    assert rc == 1 and rep["failed_checks"] == ["coverage.derived_side", "equivalence.kernel.reference_digest"]


def test_replaces_only_coverage_on_the_real_gate_issued_root(tmp_path):
    """The same declaration against the stored root issued by the release gate, bytes unchanged, under the supplied release policy."""
    d = str(tmp_path / "gate"); shutil.copytree(GATE, d); P = lambda *a: os.path.join(d, *a)
    root_before = open(P("gate_root_certificate.json"), "rb").read()
    _break_system(P("config_c1", "system.py"))
    assert cli(["keygen", "--private", P("audit.key"), "--public", P("audit.pub")]) == 0
    assert cli(["inventory", *[P("config_c1", x) for x in ("system.py", "kernel.py", "model.json", "frame.jsonl")], "--out", P("inventory_changed.txt")]) == 0
    assert toy.enumerate_block(P("config_c1", "kernel.py"), P("config_c0", "kernel.py"), P("enumeration_changed.json"))["mismatches"] == 0
    spec = load_json(P("spec_c1.json"))
    spec["block"] = {"changed": ["kernel.py", "system.py"], "unchanged": ["model.json", "frame.jsonl"]}
    spec["equivalence"][0]["replaces"].append("system.py"); spec["evidence_files"]["enumeration"] = "enumeration_changed.json"
    json.dump(spec, open(P("spec_changed.json"), "w"))
    trust = ["--trust", "gate-example=" + P("gate_example.pub"), "--trust", "audit=" + P("audit.pub")]
    rc = cli(["issue", "--parent", P("gate_root_certificate.json"), "--spec", P("spec_changed.json"), "--parent-inventory", P("inventory_c0.txt"), "--derived-inventory", P("inventory_changed.txt"),
              "--key", P("audit.key"), "--key-id", "audit", "--out", P("derived_changed.json"), *trust, "--json-report", P("issue.json")])
    assert rc == 1 and load_json(P("issue.json"))["failed_checks"] == ["coverage.derived_side", "equivalence.kernel.reference_block"]
    from recertkit.engine import build_certificate
    from recertkit.profiles import load_profile
    from recertkit.signing import sign
    c = build_certificate(P("gate_root_certificate.json"), spec, P("inventory_c0.txt"), P("inventory_changed.txt"), load_profile(None), spec_dir=d)
    json.dump(sign(c, P("audit.key"), "audit"), open(P("derived_changed.json"), "w"))
    rc = cli(["verify-chain", "--root", P("gate_root_certificate.json"), "--links", P("derived_changed.json"), *trust, "--policy", P("policy.json"), "--require-all-evidence", "--json-report", P("verify.json")])
    rep = load_json(P("verify.json"))
    assert rc == 1 and not rep["record_valid"] and rep["policy_verdict"] == "REJECTED" and rep["failed_checks"] == ["coverage.derived_side", "equivalence.kernel.reference_block"]
    assert open(P("gate_root_certificate.json"), "rb").read() == root_before
    ref, c0, c1 = (toy.evaluate(P(x)) for x in ("config_reference", "config_c0", "config_c1"))
    assert [sum(r["correct"] for r in x) for x in (ref, c0, c1)] == [150, 150, 67] and sum(a["pred"] != b["pred"] for a, b in zip(c0, c1)) == 127


SIDES = [("parent", ["coverage.derived_side"]), ("derived", ["coverage.parent_side"]), ("both", []), (None, [])]

@pytest.mark.parametrize("side,failed", SIDES, ids=[str(s[0]) for s in SIDES])
def test_one_name_on_both_sides_is_two_obligations(chain, side, failed):
    """system.py is modified.  A judgement restricted to one side leaves the other side uncovered; only a judgement
    for both sides (the default) covers the modification — and it is then printed and can be refused by a policy."""
    cfg = _config(chain, "mod", "lut", break_system=True)
    toy.enumerate_block(cfg["kernel.py"], chain.P("config_v0", "kernel.py"), chain.P("enumeration_mod.json"))
    jc = {"artifacts": ["system.py"], "judgement": "system_change"}
    if side: jc["side"] = side
    spec = _spec(chain, "mod", "enumeration_mod.json", block={"changed": ["kernel.py", "system.py"], "unchanged": ["model.json", "frame.jsonl"]}, judgement_coverage=[jc])
    spec["judgements"]["system_change"] = "asserted harmless (a FALSE judgement)"; json.dump(spec, open(chain.P("spec_mod.json"), "w"))
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_mod.txt", "spec_mod.json", "derived_mod.json")
    assert rep["failed_checks"] == failed and rc == (1 if failed else 0)
    if not failed:
        rc, rep = chain.verify_chain(links=("derived_mod.json",))
        assert rc == 0 and any(n["kind"] == "coverage by judgement" and "system.py (derived and parent side)" in n["text"] for n in rep["not_checked"])
        assert rep["links"][0]["judgement_covered"] == ["system.py"]
        rc, rep = chain.verify_chain(links=("derived_mod.json",), extra=["--policy", os.path.join(os.path.dirname(toy.__file__), "policy.json")])
        assert rc == 1 and "policy.coverage_by_judgement[derived_mod.json]" in rep["policy"]["failed_checks"]


def _split(chain):
    """C0 -> a kernel that consists of TWO artifacts (kernel.py and the added kernel_params.json)."""
    cfg = _config(chain, "split", "split")
    t = toy.enumerate_block(cfg["kernel.py"], chain.P("config_v0", "kernel.py"), chain.P("enumeration_split.json"), subject_files=[cfg["kernel_params.json"]])
    assert t["mismatches"] == 0 and set(t["subjects"]) == {"kernel.py", "kernel_params.json"}
    spec = _spec(chain, "split", "enumeration_split.json", block={"changed": ["kernel.py", "kernel_params.json"], "unchanged": ["system.py", "model.json", "frame.jsonl"]})
    spec["equivalence"][0]["subjects"] = ["kernel.py", "kernel_params.json"]
    json.dump(spec, open(chain.P("spec_split.json"), "w")); return cfg, spec


def _policy_for(chain, domains):
    p = load_json(os.path.join(os.path.dirname(toy.__file__), "policy.json")); p["enumeration_domains"] = domains
    json.dump(p, open(chain.P("policy_t.json"), "w")); return ["--policy", chain.P("policy_t.json")]


def test_block_of_two_artifacts_added_file_is_a_subject(chain):
    _split(chain)
    assert chain.issue("root.json", "inventory_v0.txt", "inventory_split.txt", "spec_split.json", "derived_split.json")[0] == 0
    rc, rep = chain.verify_chain(links=("derived_split.json",), extra=_policy_for(chain, {"kernel.py": 65536, "kernel_params.json": 65536}))
    assert rc == 0 and rep["policy_verdict"] == "ACCEPTED" and rep["links"][0]["entries"]["kernel"]["subjects"] == ["kernel.py", "kernel_params.json"]


def test_added_file_that_is_neither_subject_nor_judged_is_refused(chain):
    _, spec = _split(chain); spec["equivalence"][0]["subjects"] = ["kernel.py"]; json.dump(spec, open(chain.P("spec_split.json"), "w"))
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_split.txt", "spec_split.json", "derived_split.json")
    assert rc == 1 and rep["failed_checks"] == ["coverage.derived_side"]


def test_added_file_named_as_subject_without_a_digest_in_the_transcript_is_refused(chain):
    cfg, spec = _split(chain)
    toy.enumerate_block(cfg["kernel.py"], chain.P("config_v0", "kernel.py"), chain.P("enumeration_split.json"))       # transcript records kernel.py only
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_split.txt", "spec_split.json", "derived_split.json")
    assert rc == 1 and rep["failed_checks"] == ["equivalence.kernel.subject_digest"]


def _merge(chain, replaces, reference, reference_files=True):
    """split kernel (two artifacts) -> the single-file 'sel' kernel: kernel_params.json is DELETED."""
    _split(chain)
    assert chain.issue("root.json", "inventory_v0.txt", "inventory_split.txt", "spec_split.json", "derived_split.json")[0] == 0
    cfg = _config(chain, "merged", "sel")
    old = chain.P("config_split", "kernel.py"), chain.P("config_split", "kernel_params.json")
    toy.enumerate_block(cfg["kernel.py"], old[0], chain.P("enumeration_merged.json"), reference_files=[old[1]] if reference_files else ())
    spec = _spec(chain, "merged", "enumeration_merged.json", block={"changed": ["kernel.py", "kernel_params.json"], "unchanged": ["system.py", "model.json", "frame.jsonl"]})
    spec["equivalence"][0].update({"replaces": replaces, "reference": reference})
    json.dump(spec, open(chain.P("spec_merged.json"), "w"))
    return chain.issue("derived_split.json", "inventory_split.txt", "inventory_merged.txt", "spec_merged.json", "derived_merged.json")


def test_deleted_file_is_covered_when_the_reference_block_contains_it(chain):
    rc, rep = _merge(chain, ["kernel.py", "kernel_params.json"], {"kind": "parent_artifact", "artifacts": ["kernel.py", "kernel_params.json"]})
    assert rc == 0
    rc, rep = chain.verify_chain(links=("derived_split.json", "derived_merged.json"), extra=_policy_for(chain, {"kernel.py": 65536, "kernel_params.json": 65536}))
    assert rc == 0 and rep["policy_verdict"] == "ACCEPTED" and rep["links"][1]["entries"]["kernel"]["reference_binding"] == "digest"


def test_deleted_file_that_nothing_replaces_is_refused(chain):
    rc, rep = _merge(chain, ["kernel.py"], {"kind": "parent_artifact", "artifact": "kernel.py"}, reference_files=False)
    assert rc == 1 and rep["failed_checks"] == ["coverage.parent_side"]


def test_deleted_file_listed_as_replaced_but_absent_from_the_reference_is_refused(chain):
    rc, rep = _merge(chain, ["kernel.py", "kernel_params.json"], {"kind": "parent_artifact", "artifact": "kernel.py"}, reference_files=False)
    assert rc == 1 and rep["failed_checks"] == ["equivalence.kernel.reference_block"]


def test_reference_block_declared_but_transcript_compared_with_one_file_is_refused(chain):
    rc, rep = _merge(chain, ["kernel.py", "kernel_params.json"], {"kind": "parent_artifact", "artifacts": ["kernel.py", "kernel_params.json"]}, reference_files=False)
    assert rc == 1 and rep["failed_checks"] == ["equivalence.kernel.reference_digest"]


def test_parent_link_reference_needs_exactly_the_parent_links_subjects(chain):
    """Link 1 established the two-artifact block.  Link 2 may inherit its reference only for that whole block."""
    rc, rep = _merge(chain, ["kernel.py"], {"kind": "parent_link"}, reference_files=False)
    assert rc == 1 and set(rep["failed_checks"]) == {"coverage.parent_side", "equivalence.kernel.reference_parent_link"}


def test_parent_link_reference_for_the_whole_block_is_accepted(chain):
    _split(chain)
    assert chain.issue("root.json", "inventory_v0.txt", "inventory_split.txt", "spec_split.json", "derived_split.json")[0] == 0
    cfg = _config(chain, "merged", "sel")
    toy.enumerate_block(cfg["kernel.py"], chain.P("config_v0", "kernel.py"), chain.P("enumeration_merged.json"))          # against C0's kernel: link 1's reference
    spec = _spec(chain, "merged", "enumeration_merged.json", block={"changed": ["kernel.py", "kernel_params.json"], "unchanged": ["system.py", "model.json", "frame.jsonl"]})
    spec["equivalence"][0].update({"replaces": ["kernel.py", "kernel_params.json"], "reference": {"kind": "parent_link"}})
    json.dump(spec, open(chain.P("spec_merged.json"), "w"))
    assert chain.issue("derived_split.json", "inventory_split.txt", "inventory_merged.txt", "spec_merged.json", "derived_merged.json")[0] == 0
    rc, rep = chain.verify_chain(links=("derived_split.json", "derived_merged.json"), extra=_policy_for(chain, {"kernel.py": 65536, "kernel_params.json": 65536}))
    assert rc == 0 and rep["policy_verdict"] == "ACCEPTED"


def test_unrelated_added_file_needs_evidence_or_a_printed_judgement(chain):
    cfg = _config(chain, "add", "lut", extra={"plugin.py": "def hook(scores):\n    return scores\n"})
    toy.enumerate_block(cfg["kernel.py"], chain.P("config_v0", "kernel.py"), chain.P("enumeration_add.json"))
    spec = _spec(chain, "add", "enumeration_add.json", block={"changed": ["kernel.py", "plugin.py"], "unchanged": ["system.py", "model.json", "frame.jsonl"]})
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_add.txt", "spec_add.json", "derived_add.json")
    assert rc == 1 and rep["failed_checks"] == ["coverage.derived_side"]
    spec["equivalence"][0]["replaces"] = ["kernel.py", "plugin.py"]; json.dump(spec, open(chain.P("spec_add.json"), "w"))        # naming it on the parent side: it is not there
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_add.txt", "spec_add.json", "derived_add.json")
    assert rc == 1 and {"coverage.derived_side", "coverage.declared", "equivalence.kernel.replaces"} <= set(rep["failed_checks"])
    spec["equivalence"][0]["replaces"] = ["kernel.py"]; spec["judgement_coverage"] = [{"artifacts": ["plugin.py"], "judgement": "plugin_unused", "side": "derived"}]
    spec["judgements"]["plugin_unused"] = "plugin.py is not imported by system.py."; json.dump(spec, open(chain.P("spec_add.json"), "w"))
    assert chain.issue("root.json", "inventory_v0.txt", "inventory_add.txt", "spec_add.json", "derived_add.json")[0] == 0
    rc, rep = chain.verify_chain(links=("derived_add.json",))
    assert rc == 0 and any(n["kind"] == "coverage by judgement" and "plugin.py (derived side)" in n["text"] for n in rep["not_checked"])


def test_unrelated_deleted_file_needs_a_printed_judgement(chain):
    """C0' has an extra file; removing it must be explained on the parent side."""
    base = _config(chain, "base", "ref", extra={"notes.txt": "calibration notes\n"})
    json.dump(toy.CLAIM, open(chain.P("claim.json"), "w"))
    assert cli(["root-issue", "--claim", chain.P("claim.json"), "--role", f"server={base['system.py']}", "--role", f"model={base['model.json']}", "--role", f"frame={base['frame.jsonl']}",
                "--inventory", chain.P("inventory_base.txt"), "--basis", "test root", "--key", chain.P("release.key"), "--key-id", "release", "--out", chain.P("root_base.json")]) == 0
    cfg = _config(chain, "del", "lut")
    toy.enumerate_block(cfg["kernel.py"], base["kernel.py"], chain.P("enumeration_del.json"))
    spec = _spec(chain, "del", "enumeration_del.json", block={"changed": ["kernel.py", "notes.txt"], "unchanged": ["system.py", "model.json", "frame.jsonl"]})
    rc, rep = chain.issue("root_base.json", "inventory_base.txt", "inventory_del.txt", "spec_del.json", "derived_del.json")
    assert rc == 1 and rep["failed_checks"] == ["coverage.parent_side"]
    spec["judgement_coverage"] = [{"artifacts": ["notes.txt"], "judgement": "notes_unused", "side": "derived"}]; spec["judgements"]["notes_unused"] = "notes.txt was never read."
    json.dump(spec, open(chain.P("spec_del.json"), "w"))
    rc, rep = chain.issue("root_base.json", "inventory_base.txt", "inventory_del.txt", "spec_del.json", "derived_del.json")
    assert rc == 1 and set(rep["failed_checks"]) == {"coverage.parent_side", "coverage.declared"}          # it does not exist on the derived side
    spec["judgement_coverage"][0]["side"] = "parent"; json.dump(spec, open(chain.P("spec_del.json"), "w"))
    assert chain.issue("root_base.json", "inventory_base.txt", "inventory_del.txt", "spec_del.json", "derived_del.json")[0] == 0


def test_rename_is_a_deletion_and_an_addition_tied_by_one_entry(chain):
    """kernel.py -> fastkernel.py.  The new file is the subject, the old one is replaced and is the reference; system.py
    had to change to load the new name, and that change is NOT covered by the kernel evidence."""
    cfg = toy.write_config(chain.P("config_ren"), "lut")
    os.rename(cfg["kernel.py"], chain.P("config_ren", "fastkernel.py")); cfg["fastkernel.py"] = chain.P("config_ren", "fastkernel.py"); del cfg["kernel.py"]
    s = open(cfg["system.py"]).read(); assert '"kernel.py"' in s; open(cfg["system.py"], "w").write(s.replace('"kernel.py"', '"fastkernel.py"'))
    assert cli(["inventory", *cfg.values(), "--out", chain.P("inventory_ren.txt")]) == 0
    assert toy.enumerate_block(cfg["fastkernel.py"], chain.P("config_v0", "kernel.py"), chain.P("enumeration_ren.json"))["mismatches"] == 0
    spec = _spec(chain, "ren", "enumeration_ren.json", block={"changed": ["kernel.py", "fastkernel.py", "system.py"], "unchanged": ["model.json", "frame.jsonl"]})
    spec["equivalence"][0]["subjects"] = ["fastkernel.py"]; json.dump(spec, open(chain.P("spec_ren.json"), "w"))
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_ren.txt", "spec_ren.json", "derived_ren.json")
    assert rc == 1 and rep["failed_checks"] == ["coverage.derived_side", "coverage.parent_side"]                      # system.py, both sides
    spec["judgement_coverage"] = [{"artifacts": ["system.py"], "judgement": "loader_change"}]; spec["judgements"]["loader_change"] = "Only the file name passed to the loader changed."
    json.dump(spec, open(chain.P("spec_ren.json"), "w"))
    assert chain.issue("root.json", "inventory_v0.txt", "inventory_ren.txt", "spec_ren.json", "derived_ren.json")[0] == 0
    assert toy.evaluate(chain.P("config_ren")) == toy.evaluate(chain.P("config_v0"))
    rc, rep = chain.verify_chain(links=("derived_ren.json",))
    e = rep["links"][0]["entries"]["kernel"]
    assert rc == 0 and (e["subjects"], e["replaces"], e["reference_binding"]) == (["fastkernel.py"], ["kernel.py"], "digest") and rep["links"][0]["judgement_covered"] == ["system.py"]


def test_residual_rebuilt_and_inventory_completeness_are_printed(chain):
    cfg = _config(chain, "rb", "lut"); open(cfg["system.py"], "a").write("# rebuilt\n")
    assert cli(["inventory", *cfg.values(), "--out", chain.P("inventory_rb.txt")]) == 0
    toy.enumerate_block(cfg["kernel.py"], chain.P("config_v0", "kernel.py"), chain.P("enumeration_rb.json"))
    _spec(chain, "rb", "enumeration_rb.json", block={"changed": ["kernel.py"], "residual_rebuilt": ["system.py"], "unchanged": ["model.json", "frame.jsonl"]})
    assert chain.issue("root.json", "inventory_v0.txt", "inventory_rb.txt", "spec_rb.json", "derived_rb.json")[0] == 0
    rc, rep = chain.verify_chain(links=("derived_rb.json",))
    kinds = {n["kind"] for n in rep["not_checked"]}
    assert rc == 0 and {"residual rebuilt", "inventory completeness", "enumeration domain", "transcript provenance"} <= kinds
    rc, rep = chain.verify_chain(links=("derived_rb.json",), extra=["--policy", os.path.join(os.path.dirname(toy.__file__), "policy.json")])
    assert rc == 1 and rep["policy"]["failed_checks"] == ["policy.residual_rebuilt[derived_rb.json]"]
