# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
"""Record validity and acceptance are separate verdicts."""
import json, os
import pytest
import toy
from recertkit.cli import main as cli
from recertkit.canon import load_json

QS_POLICY = os.path.join(os.path.dirname(toy.__file__), "policy.json")


def _policy(chain, **members):
    p = chain.P("policy.json"); json.dump({"name": "test-policy", **members}, open(p, "w")); return ["--policy", p]


def test_without_a_policy_the_report_says_no_release_decision_was_made(chain, capsys):
    rc, rep = chain.verify_chain()
    out = capsys.readouterr().out
    assert rc == 0 and rep["record_valid"] and rep["policy"]["accepted"] is None and rep["policy_verdict"] is None
    assert "CHAIN RECORD: VALID — conditional on" in out and "POLICY: none applied" in out


def test_quickstart_policy_accepts_the_toy_chain(chain, capsys):
    rc, rep = chain.verify_chain(extra=["--policy", QS_POLICY])
    assert rc == 0 and rep["policy_verdict"] == "ACCEPTED" and rep["accepted"] and len(rep["policy"]["checks"]) == 28 and not rep["policy"]["not_evaluated"]   # 14 members x 2 links
    assert "POLICY quickstart-release-1: ACCEPTED" in capsys.readouterr().out


MEMBERS = [   # (policy members, mutation of spec_v1 before re-issue or None, failing policy check on link 1)
    ({"accepted_judgements": ["boundary"]}, None, "policy.accepted_judgements[derived_v1.json]"),
    ({"accepted_assumptions": []}, None, "policy.accepted_assumptions[derived_v1.json]"),
    ({"reference_kinds": ["parent_link"]}, None, "policy.reference_kinds[derived_v1.json]"),
    ({"root_adapters": ["gate-2.0"]}, None, "policy.root_adapters[derived_v1.json]"),
    ({"require_prospective": True}, lambda s: s.update({"issuance_status": "retrospective: the changed system had already been evaluated"}), "policy.require_prospective[derived_v1.json]"),
    ({"transcript_mapping": "forbid"}, "foreign-layout", "policy.transcript_mapping[derived_v1.json]"),
    ({"enumeration_domains": {"kernel.py": 65537}}, None, "policy.enumeration_domains[derived_v1.json]"),
    ({"enumeration_domains": {"other.py": 65536}}, None, "policy.enumeration_domains[derived_v1.json]"),
    ({"accepted_judgements": {"boundary": "00" * 32, "residual_path": "*"}}, None, "policy.accepted_judgements[derived_v1.json]"),
    ({"accepted_assumptions": {"interpreter": "00" * 32}}, None, "policy.accepted_assumptions[derived_v1.json]"),
]

@pytest.mark.parametrize("members,mutation,check", MEMBERS, ids=[m[2].split("[")[0] for m in MEMBERS])
def test_policy_member_rejects_a_valid_record(chain, members, mutation, check):
    if mutation == "foreign-layout":
        t = load_json(chain.P("enumeration_v1.json")); t.pop("schema"); json.dump(t, open(chain.P("enumeration_v1.json"), "w"))
        mutation = lambda s: s["equivalence"][0].update({"pointers": {"subjects": {"kernel.py": "/subjects/kernel.py"}, "reference_sha256": "/reference/sha256", "enumerated": "/enumerated", "mismatches": "/mismatches"}})
    if mutation:
        spec = load_json(chain.P("spec_v1.json")); mutation(spec); json.dump(spec, open(chain.P("spec_v1.json"), "w")); os.remove(chain.P("derived_v1.json"))
        assert chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")[0] == 0
    rc, rep = chain.verify(extra=_policy(chain, **members))
    assert rc == 1 and rep["record_valid"] is True and rep["policy_verdict"] == "REJECTED" and rep["policy"]["failed_checks"] == [check]


def test_policy_require_all_evidence_and_detached_files(chain):
    spec = load_json(chain.P("spec_v1.json")); note = chain.P("note.txt"); open(note, "w").write("supporting record")
    from recertkit.canon import sha_file
    spec["evidence_files"]["note"] = {"file": "note.txt", "sha256": sha_file(note), "detached": True}
    json.dump(spec, open(chain.P("spec_v1.json"), "w")); os.remove(chain.P("derived_v1.json"))
    assert chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")[0] == 0
    os.remove(note)
    rc, rep = chain.verify(extra=_policy(chain, require_all_evidence=True))
    assert rc == 1 and rep["record_valid"] and rep["policy"]["failed_checks"] == ["policy.require_all_evidence[derived_v1.json]"]
    assert chain.verify(extra=_policy(chain, require_all_evidence=False))[0] == 0


def test_policy_on_unrecorded_and_rebuilt_artifacts_and_reference_by_name():
    ex = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "examples", "fpga_ultra96")
    base = ["verify-chain", "--root", os.path.join(ex, "root_certificate.json"), "--links", os.path.join(ex, "derived_v1.json"), os.path.join(ex, "derived_v1p.json"),
            "--trust", "p5-release-key-1=" + os.path.join(ex, "release_key.pub")]
    import tempfile
    rep = os.path.join(tempfile.mkdtemp(), "r.json")
    assert cli(base + ["--policy", os.path.join(ex, "policy_case_study.json"), "--json-report", rep]) == 0 and load_json(rep)["policy_verdict"] == "ACCEPTED"
    assert cli(base + ["--policy", os.path.join(ex, "policy_strict.json"), "--json-report", rep]) == 1
    r = load_json(rep); kinds = {c.split("[")[0] for c in r["policy"]["failed_checks"]}
    assert r["record_valid"] and kinds == {"policy.require_all_evidence", "policy.coverage_by_judgement", "policy.residual_rebuilt", "policy.unrecorded", "policy.reference_kinds",
                                           "policy.reference_by_declaration", "policy.binding_levels", "policy.transcript_mapping", "policy.require_prospective",
                                           "policy.renamed_replacement"}


def test_invalid_record_is_never_accepted(chain):
    chain.mutate("derived_v1.json", lambda c: c["claim"].update({"margin": "0.100000"}))
    rc, rep = chain.verify(extra=_policy(chain))
    assert rc == 1 and not rep["record_valid"] and rep["policy_verdict"] == "REJECTED" and not rep["accepted"]


@pytest.mark.parametrize("bad", [{"nme": "x"}, {"name": "p", "unknown_member": 1}, {"name": "p", "unrecorded": "maybe"}, {"name": "p", "accepted_judgements": "boundary"}])
def test_malformed_policy_is_a_usage_error(chain, bad, capsys):
    p = chain.P("bad_policy.json"); json.dump(bad, open(p, "w"))
    rc = cli(["verify", "--certificate", chain.P("derived_v1.json"), "--parent", chain.P("root.json"), *chain.trust(), "--policy", p])
    assert rc == 2 and "PolicyError" in capsys.readouterr().err


def test_issue_verifies_the_parent_signature_when_given_trusted_keys(chain, capsys):
    cli(["keygen", "--private", chain.P("other.key"), "--public", chain.P("other.pub")])
    os.remove(chain.P("derived_v1.json"))
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json", extra=["--trust", f"release={chain.P('other.pub')}"])
    assert rc == 1 and rep["failed_checks"] == ["signature.parent"]
    capsys.readouterr()
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")          # no --trust: issued, and the omission is printed
    out = capsys.readouterr().out
    assert rc == 0 and any(n["kind"] == "parent signature" for n in rep["not_checked"]) and "not a release decision" in out
