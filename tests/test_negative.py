# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
"""Every case is a certificate that must be rejected, and must be rejected BY THE NAMED CHECK."""
import json, os
import pytest
from recertkit.canon import load_json, sha_file

def _set(path, value):
    def f(c):
        cur = c
        for k in path[:-1]: cur = cur[k]
        cur[path[-1]] = value
    return f

def _eq(key, value):
    return lambda c: c["equivalence"][0].update({key: value})

def _risk(alpha, derived):
    return lambda c: c["risk_budget"].update({"alpha": alpha, "delta_derived": derived})

RESIGNED = [  # (id, mutation of derived_v1.json re-signed by the issuer key, check that must fail)
    ("wrong_parent_digest", _set(["parent", "certificate_sha256"], "00" * 32), "parent.digest"),
    ("positive_alpha", _risk("0.010000", "0.060000"), "risk.alpha_zero"),
    ("negative_alpha", _risk("-0.010000", "0.040000"), "risk.alpha_zero"),
    ("tiny_positive_alpha_float_tolerance_probe", _risk("0.0000000000001", "0.050000"), "risk.alpha_zero"),
    ("tiny_positive_alpha_added_to_the_budget", _risk("0.0000000000001", "0.0500000000001"), "risk.alpha_zero"),
    ("derived_budget_differs_with_alpha_zero", _risk("0", "0.050001"), "risk.composition"),
    ("derived_budget_differs_in_the_40th_digit", _risk("0", "0.0500000000000000000000000000000000000001"), "risk.composition"),
    ("risk_budget_in_exponent_notation", _set(["risk_budget", "delta_derived"], "5E-2"), "risk.decimals"),
    ("risk_budget_as_float", _set(["risk_budget", "alpha"], 0.0), "risk.decimals"),
    ("risk_budget_nan", _set(["risk_budget", "delta_derived"], "NaN"), "risk.decimals"),
    ("delta_parent_not_the_parents", lambda c: c["risk_budget"].update({"delta_parent": "0.010000", "delta_derived": "0.010000"}), "risk.parent"),
    ("regime_r1", _set(["claim", "sampling_regime"], "r1"), "claim.constraints"),
    ("claim_field_missing", lambda c: c["claim"].pop("metric_definition"), "claim.fields"),
    ("claim_extra_field", _set(["claim", "population"], "all prompts"), "claim.fields"),
    ("margin_loosened", _set(["claim", "margin"], "0.100000"), "claim.invariance"),
    ("margin_as_float", _set(["claim", "margin"], 0.05), "claim.constraints"),
    ("changed_block_declared_unchanged", lambda c: c["block"].update({"changed": [], "unchanged": sorted(c["block"]["unchanged"] + ["kernel.py"])}), "block.unchanged.kernel.py"),
    ("artifact_not_declared", lambda c: c["block"]["unchanged"].remove("system.py"), "block.complete"),
    ("artifact_in_two_categories", lambda c: c["block"]["changed"].append("system.py"), "block.complete"),
    ("unchanged_file_declared_changed", lambda c: (c["block"]["unchanged"].remove("system.py"), c["block"]["changed"].append("system.py")), "block.changed.system.py"),
    ("server_and_model_roles_swapped", lambda c: c["roles"].update({"server": "model.json", "model": "system.py"}), "roles.root_binding.server"),
    ("role_missing", lambda c: c["roles"].pop("frame"), "roles.declared"),
    ("declared_domain_larger_than_enumerated", _eq("domain_size", 16777216), "equivalence.kernel.domain_enumerated"),
    ("method_not_accepted_by_profile", _eq("method_code", "sampled_agreement"), "equivalence.kernel.method"),
    ("subject_is_not_the_changed_block", _eq("subjects", ["system.py"]), "equivalence.kernel.subjects"),
    ("judgement_missing", lambda c: c["judgements"].pop("boundary"), "judgements.required"),
    ("judgement_blank", _set(["judgements", "residual_path"], "   "), "judgements.required"),
    ("frame_level_overstated_or_wrong", _set(["root_binding", "roles", "frame"], "identifiers-only"), "roles.binding_level.frame"),
    ("issued_under_another_profile", _set(["profile", "sha256"], "ab" * 32), "certificate.profile"),
    ("other_certificate_version", _set(["certificate_version"], "recertkit-0"), "certificate.version"),
    ("wrong_parent_id", _set(["parent", "certificate_id"], "00000000-0000-0000-0000-000000000000"), "parent.id"),
    ("claim_risk_differs_from_budget", _set(["claim", "risk_level"], "0.010000"), "risk.claim"),
    ("role_names_an_unknown_artifact", _set(["roles", "server"], "not_in_any_inventory.bin"), "role.server.present"),
    ("two_roles_share_one_artifact", _set(["roles", "server"], "model.json"), "roles.distinct"),
    ("model_and_frame_roles_swapped", lambda c: c["roles"].update({"model": "frame.jsonl", "frame": "model.json"}), "roles.root_binding.model"),
    ("role_file_is_not_the_one_the_root_names", _set(["roles", "server"], "kernel.py"), "roles.root_filename.server"),
    ("unchanged_file_declared_rebuilt_residual", lambda c: (c["block"]["unchanged"].remove("system.py"), c["block"]["residual_rebuilt"].append("system.py")), "block.residual_rebuilt.system.py"),
    ("present_file_declared_unrecorded", lambda c: (c["block"]["unchanged"].remove("system.py"), c["block"]["unrecorded"].append("system.py")), "block.unrecorded.system.py"),
    ("side_condition_not_met", _eq("require", [{"pointer": "/first_mismatch", "equals": "none"}]), "equivalence.kernel.require[0]"),
]

@pytest.mark.parametrize("name,mutation,check", RESIGNED, ids=[r[0] for r in RESIGNED])
def test_resigned_certificate_is_rejected_by_the_named_check(chain, name, mutation, check):
    chain.mutate("derived_v1.json", mutation)
    rc, rep = chain.verify()
    assert rc == 1 and check in rep["failed_checks"], rep["failed_checks"]
    assert "signature.certificate" not in rep["failed_checks"]      # it IS validly signed: the profile, not the signature, rejects it


def test_body_tampered_without_resigning(chain):
    chain.mutate("derived_v1.json", _set(["change", "summary"], "something else"), resign=False)
    rc, rep = chain.verify(); assert rc == 1 and rep["failed_checks"] == ["signature.certificate"]


def test_evidence_file_tampered(chain):
    t = load_json(chain.P("enumeration_v1.json")); t["mismatches"] = 0; t["note"] = "edited"; json.dump(t, open(chain.P("enumeration_v1.json"), "w"))
    rc, rep = chain.verify(); assert rc == 1 and "evidence.enumeration" in rep["failed_checks"]


def test_inventory_tampered(chain):
    open(chain.P("inventory_v1.txt"), "a").write("# edited\n")
    rc, rep = chain.verify(); assert rc == 1 and "inventory.digest.derived" in rep["failed_checks"]


def test_unknown_signing_key(chain):
    from recertkit.cli import main as cli
    cli(["keygen", "--private", chain.P("other.key"), "--public", chain.P("other.pub")])
    rc = cli(["verify", "--certificate", chain.P("derived_v1.json"), "--parent", chain.P("root.json"), "--trust", f"release={chain.P('other.pub')}", "--json-report", chain.P("r.json")])
    assert rc == 1 and {"signature.certificate", "signature.parent"} <= set(load_json(chain.P("r.json"))["failed_checks"])
    rc = cli(["verify", "--certificate", chain.P("derived_v1.json"), "--parent", chain.P("root.json"), "--trust", f"someone-else={chain.P('release.pub')}", "--json-report", chain.P("r.json")])
    assert rc == 1 and "signature.certificate" in load_json(chain.P("r.json"))["failed_checks"]     # right key, wrong id: never guessed


def test_root_tampered(chain):
    chain.mutate("root.json", _set(["decision"], "certified "), resign=False)
    rc, rep = chain.verify_chain(); assert rc == 1 and "signature.root" in rep["failed_checks"]


def test_root_not_certified(chain):
    chain.mutate("root.json", _set(["decision"], "rejected"))
    chain.mutate("derived_v1.json", lambda c: c["parent"].update({"certificate_sha256": sha_file(chain.P("root.json"))}))
    rc, rep = chain.verify_chain(links=("derived_v1.json",)); assert rc == 1 and {"root.decision", "parent.decision"} <= set(rep["failed_checks"])


def test_link_verified_against_the_wrong_parent(chain):
    rc, rep = chain.verify("derived_v2.json", "root.json"); assert rc == 1 and "parent.digest" in rep["failed_checks"]


def test_chain_link_skipped(chain):
    rc, rep = chain.verify_chain(links=("derived_v2.json",)); assert rc == 1 and "parent.digest" in rep["failed_checks"]


def test_chain_inventory_discontinuity(chain):
    inv0 = chain.P("inventory_v0.txt")
    chain.mutate("derived_v2.json", lambda c: c["parent_inventory"].update({"file": "inventory_v0.txt", "sha256": sha_file(inv0)}))
    rc, rep = chain.verify_chain(); assert rc == 1 and "chain.inventory_continuity" in rep["failed_checks"]


def test_duplicate_inventory_basename(chain):
    open(chain.P("inventory_v1.txt"), "a").write("11" * 32 + "  elsewhere/kernel.py\n")
    chain.mutate("derived_v1.json", lambda c: c["derived_inventory"].update({"sha256": sha_file(chain.P("inventory_v1.txt"))}))
    rc, rep = chain.verify(); assert rc == 1 and "inventory.unique.derived" in rep["failed_checks"]


def _swap_model(chain, declare):
    """A second, different model file appears in the derived configuration."""
    lines = open(chain.P("inventory_v1.txt")).read().splitlines()
    lines = [("22" * 32 + "  model.json") if l.endswith("model.json") else l for l in lines]
    open(chain.P("inventory_v1.txt"), "w").write("\n".join(lines) + "\n")
    spec = load_json(chain.P("spec_v1.json"))
    if declare: spec["block"]["unchanged"].remove("model.json"); spec["block"]["changed"].append("model.json")
    json.dump(spec, open(chain.P("spec_v1.json"), "w"))


def test_issue_refuses_undeclared_model_change_next_to_a_declared_one(chain):
    _swap_model(chain, declare=False); os.remove(chain.P("derived_v1.json"))
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")
    assert rc == 1 and "block.unchanged.model.json" in rep["failed_checks"] and not os.path.exists(chain.P("derived_v1.json"))


def test_issue_refuses_model_change_even_when_declared(chain):
    _swap_model(chain, declare=True); os.remove(chain.P("derived_v1.json"))
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")
    assert rc == 1 and "role.model.fixed" in rep["failed_checks"] and not os.path.exists(chain.P("derived_v1.json"))


def test_issue_refuses_non_equivalent_block(chain):
    rc, rep = chain.issue("derived_v2.json", "inventory_v2.txt", "inventory_v3.txt", "spec_v3.json", "derived_v3.json")
    assert rc == 1 and rep["failed_checks"] == ["equivalence.kernel.zero_mismatches"] and not os.path.exists(chain.P("derived_v3.json"))


def test_issue_refuses_positive_alpha(chain):
    spec = load_json(chain.P("spec_v1.json")); spec["risk_budget"] = {"delta_parent": "0.050000", "alpha": "0.010000", "delta_derived": "0.060000"}
    json.dump(spec, open(chain.P("spec_v1.json"), "w")); os.remove(chain.P("derived_v1.json"))
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")
    assert rc == 1 and "risk.alpha_zero" in rep["failed_checks"] and not os.path.exists(chain.P("derived_v1.json"))


def test_transcript_of_another_block_is_rejected(chain):
    spec = load_json(chain.P("spec_v1.json")); spec["evidence_files"]["enumeration"] = chain.P("enumeration_v2.json")
    json.dump(spec, open(chain.P("spec_v1.json"), "w")); os.remove(chain.P("derived_v1.json"))
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")
    assert rc == 1 and "equivalence.kernel.subject_digest" in rep["failed_checks"]


def test_detached_transcript_is_rejected(chain):
    chain.mutate("derived_v1.json", lambda c: c["evidence_files"]["enumeration"].update({"detached": True}))
    rc, rep = chain.verify(); assert rc == 1 and "equivalence.kernel.transcript" in rep["failed_checks"]


LINK2 = [  # mutations of the SECOND link (derived_v2.json, parent derived_v1.json), re-signed
    ("roles_differ_from_parent_link", lambda c: c["roles"].update({"server": "kernel.py"}), "chain.roles"),
    ("binding_levels_differ_from_parent_link", _set(["root_binding", "roles", "frame"], "identifiers-only"), "chain.root_binding"),
    ("profile_differs_from_parent_link", _set(["profile", "name"], "another-profile"), "chain.profile"),
]

@pytest.mark.parametrize("name,mutation,check", LINK2, ids=[r[0] for r in LINK2])
def test_second_link_is_rejected_by_the_named_check(chain, name, mutation, check):
    chain.mutate("derived_v2.json", mutation)
    rc, rep = chain.verify_chain(); assert rc == 1 and check in rep["failed_checks"], rep["failed_checks"]


def test_parent_inventory_tampered(chain):
    open(chain.P("inventory_v0.txt"), "a").write("# edited\n")
    rc, rep = chain.verify(); assert rc == 1 and "inventory.digest.parent" in rep["failed_checks"]


def test_duplicate_basename_in_parent_inventory(chain):
    open(chain.P("inventory_v0.txt"), "a").write("11" * 32 + "  elsewhere/kernel.py\n")
    chain.mutate("derived_v1.json", lambda c: c["parent_inventory"].update({"sha256": sha_file(chain.P("inventory_v0.txt"))}))
    rc, rep = chain.verify(); assert rc == 1 and "inventory.unique.parent" in rep["failed_checks"]


def test_issue_refuses_frame_change_even_when_declared(chain):
    lines = [("33" * 32 + "  frame.jsonl") if l.endswith("frame.jsonl") else l for l in open(chain.P("inventory_v1.txt")).read().splitlines()]
    open(chain.P("inventory_v1.txt"), "w").write("\n".join(lines) + "\n")
    spec = load_json(chain.P("spec_v1.json")); spec["block"]["unchanged"].remove("frame.jsonl"); spec["block"]["changed"].append("frame.jsonl")
    json.dump(spec, open(chain.P("spec_v1.json"), "w")); os.remove(chain.P("derived_v1.json"))
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")
    assert rc == 1 and "role.frame.fixed" in rep["failed_checks"] and not os.path.exists(chain.P("derived_v1.json"))


def test_issue_refuses_transcript_that_is_not_json(chain):
    open(chain.P("enumeration_v1.json"), "w").write("0 mismatches, trust me")
    os.remove(chain.P("derived_v1.json"))
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")
    assert rc == 1 and "equivalence.kernel.transcript_json" in rep["failed_checks"]


def test_parent_of_unknown_format(chain):
    chain.mutate("root.json", _set(["certificate_version"], "somebody-elses-format"))
    chain.mutate("derived_v1.json", lambda c: c["parent"].update({"certificate_sha256": sha_file(chain.P("root.json"))}))
    rc, rep = chain.verify_chain(links=("derived_v1.json",))
    assert rc == 1 and {"parent.readable", "root.readable"} <= set(rep["failed_checks"])
