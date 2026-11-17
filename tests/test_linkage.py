"""Evidence linkage and change coverage.

The first two tests are the counterexamples found in the review of the first draft (2026-11-16): in both, every
number in the evidence is TRUE and every signature is valid, yet the transfer must not be accepted.
"""
import json, os
import pytest
import toy
from recertkit.canon import load_json, sha_file

STRICT = ["--require-all-evidence"]


def _self_comparison(chain):
    """C2 -> a kernel that always returns 0, 'shown equivalent' by comparing the new kernel with ITSELF."""
    k = chain.P("config_v4", "kernel.py")
    t = toy.enumerate_block(k, k, chain.P("enumeration_v4.json")); assert t["mismatches"] == 0
    spec = toy.spec_for(chain.P("enumeration_v4.json"), "self-comparison"); json.dump(spec, open(chain.P("spec_v4.json"), "w"))
    return spec


def test_wrong_reference_is_refused_at_issue(chain):
    _self_comparison(chain)
    rc, rep = chain.issue("derived_v2.json", "inventory_v2.txt", "inventory_v4.txt", "spec_v4.json", "derived_v4.json")
    assert rc == 1 and rep["failed_checks"] == ["equivalence.kernel.reference_digest"] and not os.path.exists(chain.P("derived_v4.json"))
    before, after = toy.evaluate(chain.P("config_v0")), toy.evaluate(chain.P("config_v4"))
    assert sum(a["pred"] != b["pred"] for a, b in zip(before, after)) > 100          # the refused change really alters the system


def test_wrong_reference_signed_anyway_is_rejected_by_the_verifier(chain):
    chain.forge("derived_v2.json", "inventory_v2.txt", "inventory_v4.txt", _self_comparison(chain), "derived_v4.json")
    rc, rep = chain.verify_chain(links=("derived_v1.json", "derived_v2.json", "derived_v4.json"), extra=STRICT)
    assert rc == 1 and rep["failed_checks"] == ["equivalence.kernel.reference_digest"]


def _kernel_and_system_changed(chain):
    """An equivalent kernel shipped together with a modified system.py; evidence exists for the kernel only."""
    cfg = toy.write_config(chain.P("config_v5"), "ref")
    s = open(cfg["system.py"]).read(); m = "return max(range(len(scores)), key=lambda c: (scores[c], -c))"; assert m in s
    open(cfg["system.py"], "w").write(s.replace(m, "return 0"))
    from recertkit.cli import main as cli
    assert cli(["inventory", *cfg.values(), "--out", chain.P("inventory_v5.txt")]) == 0
    assert toy.enumerate_block(cfg["kernel.py"], chain.P("config_v2", "kernel.py"), chain.P("enumeration_v5.json"))["mismatches"] == 0
    spec = toy.spec_for(chain.P("enumeration_v5.json"), "kernel and system changed")
    spec["block"] = {"changed": ["kernel.py", "system.py"], "unchanged": ["model.json", "frame.jsonl"]}
    json.dump(spec, open(chain.P("spec_v5.json"), "w")); return spec


def test_uncovered_changed_artifact_is_refused_at_issue(chain):
    _kernel_and_system_changed(chain)
    rc, rep = chain.issue("derived_v2.json", "inventory_v2.txt", "inventory_v5.txt", "spec_v5.json", "derived_v5.json")
    assert rc == 1 and rep["failed_checks"] == ["coverage.derived_side", "coverage.parent_side"]


def test_uncovered_changed_artifact_signed_anyway_is_rejected_by_the_verifier(chain):
    chain.forge("derived_v2.json", "inventory_v2.txt", "inventory_v5.txt", _kernel_and_system_changed(chain), "derived_v5.json")
    rc, rep = chain.verify_chain(links=("derived_v1.json", "derived_v2.json", "derived_v5.json"), extra=STRICT)
    assert rc == 1 and rep["failed_checks"] == ["coverage.derived_side", "coverage.parent_side"]


def test_second_changed_artifact_may_be_covered_by_a_named_judgement_and_is_then_printed(chain):
    """Covering an artifact by judgement is permitted by the default profile — but it is never silent, and a policy can refuse it."""
    spec = _kernel_and_system_changed(chain)
    spec["judgement_coverage"] = [{"artifacts": ["system.py"], "judgement": "system_change"}]
    spec["judgements"]["system_change"] = "system.py was edited; the authors assert the edit does not affect predictions."     # a FALSE judgement
    json.dump(spec, open(chain.P("spec_v5.json"), "w"))
    assert chain.issue("derived_v2.json", "inventory_v2.txt", "inventory_v5.txt", "spec_v5.json", "derived_v5.json")[0] == 0
    links = ("derived_v1.json", "derived_v2.json", "derived_v5.json")
    rc, rep = chain.verify_chain(links=links)
    assert rc == 0 and any(n["kind"] == "coverage by judgement" and "system.py" in n["text"] for n in rep["not_checked"])
    rc, rep = chain.verify_chain(links=links, extra=["--policy", os.path.join(os.path.dirname(toy.__file__), "policy.json")])
    assert rc == 1 and rep["record_valid"] and rep["policy"]["accepted"] is False and rep["policy_verdict"] == "REJECTED"
    assert "policy.coverage_by_judgement[derived_v5.json]" in rep["policy"]["failed_checks"] and "policy.accepted_judgements[derived_v5.json]" in rep["policy"]["failed_checks"]


def test_profile_can_forbid_coverage_by_judgement(chain):
    from recertkit.profiles import DEFAULT_PROFILE
    prof = json.loads(json.dumps(DEFAULT_PROFILE)); prof["name"] = "no-judgement-coverage"; prof["coverage_by_judgement"] = False
    json.dump(prof, open(chain.P("prof.json"), "w"))
    spec = _kernel_and_system_changed(chain)
    spec["judgement_coverage"] = [{"artifacts": ["system.py"], "judgement": "system_change"}]; spec["judgements"]["system_change"] = "asserted harmless"
    json.dump(spec, open(chain.P("spec_v5.json"), "w"))
    # the chain must be issued under that profile from the start
    for parent, pinv, v in (("root.json", "v0", "v1"), ("derived_v1.json", "v1", "v2")):
        os.remove(chain.P(f"derived_{v}.json"))
        assert chain.issue(parent, f"inventory_{pinv}.txt", f"inventory_{v}.txt", f"spec_{v}.json", f"derived_{v}.json", extra=["--profile", chain.P("prof.json")])[0] == 0
    rc, rep = chain.issue("derived_v2.json", "inventory_v2.txt", "inventory_v5.txt", "spec_v5.json", "derived_v5.json", extra=["--profile", chain.P("prof.json")])
    assert rc == 1 and rep["failed_checks"] == ["coverage.judgement.system.py"]


def _set_eq(key, value): return lambda c: c["equivalence"][0].update({key: value})

COVERAGE = [
    ("artifact_covered_twice", lambda c: c.update({"judgement_coverage": [{"artifacts": ["kernel.py"], "judgement": "boundary"}]}), "coverage.derived_side"),
    ("unchanged_artifact_listed_as_covered", lambda c: c.update({"judgement_coverage": [{"artifacts": ["system.py"], "judgement": "boundary"}]}), "coverage.declared"),
    ("judgement_coverage_with_an_unknown_side", lambda c: c.update({"judgement_coverage": [{"artifacts": ["kernel.py"], "judgement": "boundary", "side": "left"}]}), "coverage.declared"),
    ("subject_listed_twice", _set_eq("subjects", ["kernel.py", "kernel.py"]), "equivalence.kernel.subjects"),
    ("replaced_artifact_listed_twice", _set_eq("replaces", ["kernel.py", "kernel.py"]), "equivalence.kernel.replaces"),
    ("reference_names_more_than_is_replaced", lambda c: c["equivalence"][0]["reference"].update({"artifacts": ["kernel.py", "system.py"]}), "equivalence.kernel.reference_block"),
    ("reference_digest_field_removed", lambda c: c["equivalence"][0]["reference"].pop("sha256"), "equivalence.kernel.reference_field"),
    ("no_equivalence_entry_everything_by_judgement", lambda c: c.update({"equivalence": [], "judgement_coverage": [{"artifacts": ["kernel.py"], "judgement": "boundary"}]}), "coverage.equivalence_present"),
    ("judgement_coverage_names_missing_judgement", lambda c: c.update({"equivalence": [], "judgement_coverage": [{"artifacts": ["kernel.py"], "judgement": "nope"}]}), "coverage.judgement.kernel.py"),
    ("judgement_coverage_names_unbound_evidence", lambda c: c.update({"equivalence": [], "judgement_coverage": [{"artifacts": ["kernel.py"], "judgement": "boundary", "evidence": ["nope"]}]}), "coverage.judgement.kernel.py"),
    ("two_entries_with_one_id", lambda c: c["equivalence"].append(dict(c["equivalence"][0])), "equivalence.ids"),
    ("replaces_an_artifact_that_did_not_change", _set_eq("replaces", ["kernel.py", "system.py"]), "equivalence.kernel.replaces"),
    ("reference_is_not_a_replaced_artifact", lambda c: c["equivalence"][0]["reference"].update({"artifact": "system.py"}), "equivalence.kernel.reference_digest"),
    ("reference_digest_field_rewritten", lambda c: c["equivalence"][0]["reference"].update({"sha256": "00" * 32}), "equivalence.kernel.reference_field"),
    ("reference_kind_unknown", lambda c: c["equivalence"][0]["reference"].update({"kind": "trust_me"}), "equivalence.kernel.reference_kind"),
    ("first_link_claims_a_parent_link_reference", lambda c: c["equivalence"][0].update({"reference": {"kind": "parent_link"}}), "equivalence.kernel.reference_parent_link"),
    ("specification_reference_without_judgement", lambda c: c["equivalence"][0].update({"reference": {"kind": "specification", "id": "the spec", "judgement": "nope"}}), "equivalence.kernel.reference_spec"),
    ("subjects_empty", _set_eq("subjects", []), "equivalence.kernel.subjects"),
    ("pointer_mapping_to_a_wrong_field", _set_eq("pointers", {"subjects": {"kernel.py": "/reference/sha256"}, "reference_sha256": "/reference/sha256", "enumerated": "/enumerated", "mismatches": "/mismatches"}), "equivalence.kernel.subject_digest"),
]

@pytest.mark.parametrize("name,mutation,check", COVERAGE, ids=[r[0] for r in COVERAGE])
def test_resigned_link_is_rejected_by_the_named_linkage_check(chain, name, mutation, check):
    chain.mutate("derived_v1.json", mutation)
    rc, rep = chain.verify()
    assert rc == 1 and check in rep["failed_checks"], rep["failed_checks"]


def test_parent_link_reference_must_be_the_reference_of_the_parent_link(chain):
    """Link 2 claims 'same reference as link 1' but its transcript compared against a different kernel."""
    toy.enumerate_block(chain.P("config_v2", "kernel.py"), chain.P("config_v1", "kernel.py"), chain.P("enumeration_v2.json"))    # vs C1's kernel, not C0's
    os.remove(chain.P("derived_v2.json"))
    rc, rep = chain.issue("derived_v1.json", "inventory_v1.txt", "inventory_v2.txt", "spec_v2.json", "derived_v2.json")
    assert rc == 1 and rep["failed_checks"] == ["equivalence.kernel.reference_digest"]
    # the same transcript IS acceptable when declared for what it is: a comparison with the parent's own kernel
    json.dump(toy.spec_for(chain.P("enumeration_v2.json"), "kernel -> v2", reference="parent_artifact"), open(chain.P("spec_v2.json"), "w"))
    assert chain.issue("derived_v1.json", "inventory_v1.txt", "inventory_v2.txt", "spec_v2.json", "derived_v2.json")[0] == 0
    assert chain.verify_chain()[0] == 0


def test_specification_reference_is_accepted_only_with_a_judgement_and_is_printed(chain):
    spec = load_json(chain.P("spec_v1.json"))
    specfile = chain.P("q_spec.txt"); open(specfile, "w").write("q(a, b) = clamp((a*b + 8) >> 4, -128, 127)\n")
    t = load_json(chain.P("enumeration_v1.json")); t["reference"] = {"sha256": sha_file(specfile)}; json.dump(t, open(chain.P("enumeration_v1.json"), "w"))
    spec["equivalence"][0]["reference"] = {"kind": "specification", "id": "q_spec.txt", "judgement": "reference_link", "evidence": "q_spec"}
    spec["evidence_files"]["q_spec"] = "q_spec.txt"; spec["judgements"]["reference_link"] = "C0's kernel.py implements q_spec.txt (read by the authors)."
    json.dump(spec, open(chain.P("spec_v1.json"), "w")); os.remove(chain.P("derived_v1.json"))
    assert chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")[0] == 0
    rc, rep = chain.verify()
    assert rc == 0 and any(n["kind"] == "reference by judgement" for n in rep["not_checked"])
    rc, rep = chain.verify(extra=["--policy", os.path.join(os.path.dirname(toy.__file__), "policy.json")])
    assert rc == 1 and "policy.reference_kinds[derived_v1.json]" in rep["policy"]["failed_checks"]


def test_transcript_without_standard_layout_needs_a_declared_mapping(chain):
    t = load_json(chain.P("enumeration_v1.json")); t.pop("schema"); json.dump(t, open(chain.P("enumeration_v1.json"), "w"))
    os.remove(chain.P("derived_v1.json"))
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")
    assert rc == 1 and rep["failed_checks"] == ["equivalence.kernel.transcript_layout"]
    spec = load_json(chain.P("spec_v1.json"))
    spec["equivalence"][0]["pointers"] = {"subjects": {"kernel.py": "/subjects/kernel.py"}, "reference_sha256": "/reference/sha256", "enumerated": "/enumerated", "mismatches": "/mismatches"}
    json.dump(spec, open(chain.P("spec_v1.json"), "w"))
    assert chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")[0] == 0
    rc, rep = chain.verify()
    assert rc == 0 and any(n["kind"] == "transcript mapping" for n in rep["not_checked"]) and rep["links"][0]["entries"]["kernel"]["mapped"] is True


def test_pointers_may_not_remap_a_standard_transcript(chain):
    """A standard transcript has fixed field meanings; a declaration must not be able to point 'mismatches' at another field."""
    spec = load_json(chain.P("spec_v1.json"))
    spec["equivalence"][0]["pointers"] = {"subjects": {"kernel.py": "/subjects/kernel.py"}, "reference_sha256": "/reference/sha256", "enumerated": "/enumerated", "mismatches": "/mismatches"}
    json.dump(spec, open(chain.P("spec_v1.json"), "w")); os.remove(chain.P("derived_v1.json"))
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")
    assert rc == 1 and rep["failed_checks"] == ["equivalence.kernel.transcript_layout"]


def test_standard_transcript_must_state_the_declared_domain(chain):
    t = load_json(chain.P("enumeration_v1.json")); t["domain_size"] = 4096; json.dump(t, open(chain.P("enumeration_v1.json"), "w"))
    os.remove(chain.P("derived_v1.json"))
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")
    assert rc == 1 and rep["failed_checks"] == ["equivalence.kernel.domain_enumerated"]


def test_every_entry_prints_that_the_transcript_itself_is_not_re_run(chain):
    rc, rep = chain.verify(); assert rc == 0 and any(n["kind"] == "transcript provenance" for n in rep["not_checked"])


def test_transcript_that_does_not_say_what_it_compared_against_is_refused(chain):
    t = load_json(chain.P("enumeration_v1.json")); t.pop("reference"); json.dump(t, open(chain.P("enumeration_v1.json"), "w"))
    os.remove(chain.P("derived_v1.json"))
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")
    assert rc == 1 and rep["failed_checks"] == ["equivalence.kernel.reference_digest"]
