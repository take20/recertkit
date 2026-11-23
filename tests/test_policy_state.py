# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
"""The policy reads what the engine VERIFIED, and never accepts a condition it could not evaluate
(review of the second draft, findings R2 and R3)."""
import hashlib, json, os
import pytest
import toy
from recertkit.cli import main as cli
from recertkit.canon import load_json, sha_file

QS_POLICY = os.path.join(os.path.dirname(toy.__file__), "policy.json")


def _policy(chain, base=None, **members):
    p = load_json(base) if base else {}
    p.update({"name": "test-policy", **members}); json.dump(p, open(chain.P("policy.json"), "w")); return ["--policy", chain.P("policy.json")]


def _spec_reference(chain, transcript_digest, bind_file, declared_sha=None):
    """Link 1 compared against a named specification.  ``transcript_digest``: the transcript records a digest of it;
    ``bind_file``: the specification file is bound as evidence; ``declared_sha``: a digest merely written in the spec."""
    kernel0 = chain.P("config_v0", "kernel.py")
    t = load_json(chain.P("enumeration_v1.json"))
    t["reference"] = {"sha256": sha_file(kernel0)} if transcript_digest else {"id": "original-arithmetic-kernel"}
    json.dump(t, open(chain.P("enumeration_v1.json"), "w"))
    spec = load_json(chain.P("spec_v1.json"))
    ref = {"kind": "specification", "id": "original-arithmetic-kernel", "judgement": "reference_link"}
    if bind_file:
        import shutil
        shutil.copy(kernel0, chain.P("kernel_spec.py")); ref["evidence"] = "kernel_spec"; spec["evidence_files"]["kernel_spec"] = "kernel_spec.py"
    if declared_sha: ref["sha256"] = declared_sha
    spec["equivalence"][0]["reference"] = ref
    spec["judgements"]["reference_link"] = "The named specification is the arithmetic kernel of C0."
    json.dump(spec, open(chain.P("spec_v1.json"), "w")); os.remove(chain.P("derived_v1.json"))
    return spec


FORBID = dict(reference_by_declaration="forbid", reference_kinds=["parent_artifact", "parent_link", "specification"],
              accepted_judgements=["boundary", "residual_path", "reference_link"])


def test_declared_reference_digest_is_not_a_verified_link(chain):
    """The reviewer's case: no digest in the transcript, no specification file bound, the TRUE digest written in the declaration."""
    _spec_reference(chain, transcript_digest=False, bind_file=False, declared_sha=sha_file(chain.P("config_v0", "kernel.py")))
    assert chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")[0] == 0
    cert = load_json(chain.P("derived_v1.json"))
    assert "sha256" not in cert["equivalence"][0]["reference"]                       # issue never copies an unverifiable digest into the certificate
    rc, rep = chain.verify_chain(links=("derived_v1.json",), extra=_policy(chain, QS_POLICY, **FORBID))
    assert rc == 1 and rep["record_valid"] and rep["policy_verdict"] == "REJECTED" and rep["policy"]["failed_checks"] == ["policy.reference_by_declaration[derived_v1.json]"]
    assert rep["links"][0]["entries"]["kernel"]["reference_binding"] == "declaration"
    assert any(n["kind"] == "reference by declaration" for n in rep["not_checked"])
    assert chain.verify_chain(links=("derived_v1.json",), extra=_policy(chain, QS_POLICY, **{**FORBID, "reference_by_declaration": "allow"}))[0] == 0


def test_unverified_digest_field_in_a_signed_certificate_is_a_record_failure(chain):
    spec = _spec_reference(chain, transcript_digest=False, bind_file=False)
    assert chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")[0] == 0
    chain.mutate("derived_v1.json", lambda c: c["equivalence"][0]["reference"].update({"sha256": sha_file(chain.P("config_v0", "kernel.py"))}))
    rc, rep = chain.verify_chain(links=("derived_v1.json",), extra=_policy(chain, QS_POLICY, **FORBID))
    assert rc == 1 and rep["failed_checks"] == ["equivalence.kernel.reference_field"] and rep["policy_verdict"] == "REJECTED"


@pytest.mark.parametrize("transcript_digest,bind_file,binding", [(True, True, "digest"), (True, False, "declaration"), (False, True, None)], ids=["bound", "digest-in-transcript-only", "file-only"])
def test_specification_is_digest_bound_only_when_transcript_and_bound_file_agree(chain, transcript_digest, bind_file, binding):
    _spec_reference(chain, transcript_digest, bind_file)
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")
    if binding is None:
        assert rc == 1 and rep["failed_checks"] == ["equivalence.kernel.reference_digest"]; return
    assert rc == 0
    rc, rep = chain.verify_chain(links=("derived_v1.json",), extra=_policy(chain, QS_POLICY, **FORBID))
    assert rep["links"][0]["entries"]["kernel"]["reference_binding"] == binding
    assert (rc, rep["policy_verdict"]) == ((0, "ACCEPTED") if binding == "digest" else (1, "REJECTED"))


def test_parent_link_reference_inherits_the_verified_strength_never_more(chain):
    """Link 1 rests on a named specification; link 2 inherits it.  Neither is digest-bound, and the policy rejects both."""
    _spec_reference(chain, transcript_digest=False, bind_file=False)
    assert chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")[0] == 0
    t = load_json(chain.P("enumeration_v2.json")); t["reference"] = {"id": "original-arithmetic-kernel"}; json.dump(t, open(chain.P("enumeration_v2.json"), "w"))
    os.remove(chain.P("derived_v2.json"))
    assert chain.issue("derived_v1.json", "inventory_v1.txt", "inventory_v2.txt", "spec_v2.json", "derived_v2.json")[0] == 0
    assert "sha256" not in load_json(chain.P("derived_v2.json"))["equivalence"][0]["reference"]
    rc, rep = chain.verify_chain(extra=_policy(chain, QS_POLICY, **FORBID))
    assert rc == 1 and rep["record_valid"] and [l["entries"]["kernel"]["reference_binding"] for l in rep["links"]] == ["declaration", "declaration"]
    assert rep["policy"]["failed_checks"] == ["policy.reference_by_declaration[derived_v1.json]", "policy.reference_by_declaration[derived_v2.json]"]
    # a link-2 certificate that claims a digest its parent never verified is a record failure
    chain.mutate("derived_v2.json", lambda c: c["equivalence"][0]["reference"].update({"sha256": sha_file(chain.P("config_v0", "kernel.py"))}))
    rc, rep = chain.verify_chain(extra=_policy(chain, QS_POLICY, **FORBID))
    assert rc == 1 and rep["failed_checks"] == ["equivalence.kernel.reference_field"]


def test_notices_and_policy_read_the_same_state(chain):
    """For every link: an entry is reported as 'reference by declaration' exactly when its verified binding is not a digest."""
    for setup in (lambda: None, lambda: _spec_reference(chain, False, False)):
        if setup() is not None: assert chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")[0] == 0
        rc, rep = chain.verify_chain(links=("derived_v1.json",), extra=_policy(chain, reference_by_declaration="forbid"))
        by_decl = rep["links"][0]["entries"]["kernel"]["reference_binding"] != "digest"
        assert by_decl == any(n["kind"] == "reference by declaration" for n in rep["not_checked"]) == bool(rep["policy"]["failed_checks"])


# ---- R3: a policy condition that cannot be evaluated is never accepted -------------------------------------------------

def test_single_link_does_not_accept_a_root_condition_it_cannot_see(chain):
    pol = _policy(chain, QS_POLICY, root_adapters=["gate-2.0"])                 # the real root is a recertkit-root-1 attestation
    rc, rep = chain.verify(cert="derived_v2.json", parent="derived_v1.json", extra=pol)
    assert rc == 1 and rep["record_valid"] and rep["policy_verdict"] == "NOT EVALUATED" and rep["policy"]["accepted"] is False and not rep["accepted"]
    assert set(rep["policy"]["not_evaluated"]) == {"policy.chain[derived_v2.json]", "policy.root_adapters[derived_v2.json]", "policy.binding_levels[derived_v2.json]",
                                                   "policy.reference_by_declaration[derived_v2.json]"} and not rep["policy"]["failed_checks"]
    rc, rep = chain.verify_chain(extra=pol)
    assert rc == 1 and rep["policy_verdict"] == "REJECTED" and rep["policy"]["failed_checks"] == ["policy.root_adapters[derived_v1.json]", "policy.root_adapters[derived_v2.json]"]


def test_single_later_link_is_never_accepted_even_by_an_empty_policy(chain, capsys):
    rc, rep = chain.verify(cert="derived_v2.json", parent="derived_v1.json", extra=_policy(chain))
    out = capsys.readouterr().out
    assert rc == 1 and rep["policy_verdict"] == "NOT EVALUATED" and rep["policy"]["not_evaluated"] == ["policy.chain[derived_v2.json]"]
    assert "POLICY test-policy: NOT EVALUATED" in out and "[POLICY NOT EVALUATED] policy.chain[derived_v2.json]" in out
    assert chain.verify(cert="derived_v2.json", parent="derived_v1.json")[0] == 0          # record verification of one link is still possible


def test_single_first_link_can_be_evaluated_completely(chain):
    rc, rep = chain.verify(extra=["--policy", QS_POLICY])
    assert rc == 0 and rep["policy_verdict"] == "ACCEPTED" and not rep["policy"]["not_evaluated"]
    rc, rep = chain.verify(extra=_policy(chain, QS_POLICY, root_adapters=["gate-2.0"]))
    assert rc == 1 and rep["policy_verdict"] == "REJECTED" and rep["policy"]["failed_checks"] == ["policy.root_adapters[derived_v1.json]"]


def test_a_violated_condition_wins_over_an_unevaluated_one(chain):
    rc, rep = chain.verify(cert="derived_v2.json", parent="derived_v1.json", extra=_policy(chain, accepted_judgements=["boundary"]))
    assert rc == 1 and rep["policy_verdict"] == "REJECTED" and rep["policy"]["failed_checks"] == ["policy.accepted_judgements[derived_v2.json]"]


def test_chain_state_reports_root_format_and_binding_levels_for_every_link(chain):
    rc, rep = chain.verify_chain()
    assert [(l["root_adapter"], l["binding_levels"]["(inventory)"], l["chain_verified"] or l["parent_kind"] == "root") for l in rep["links"]] == [("recertkit-root-1", "digest", True)] * 2
    rc, rep = chain.verify(cert="derived_v2.json", parent="derived_v1.json")
    assert rep["links"][0]["root_adapter"] is None and rep["links"][0]["binding_levels"] is None and rep["links"][0]["entries"]["kernel"]["reference_binding"] == "unverified-parent"
    assert any(n["kind"] == "precondition" for n in rep["not_checked"])


# ---- conditions a policy can now state ----------------------------------------------------------------------------------

def _tiny_domain(chain):
    """A truthful comparison of the 'zero' kernel with C0's kernel on the ONE operand pair (0, 0), where they agree."""
    k, k0 = chain.P("config_v4", "kernel.py"), chain.P("config_v0", "kernel.py")
    t = {"schema": "recertkit-enumeration-1", "what": "comparison on the operand pair (0, 0) only", "domain": "a = b = 0", "domain_size": 1,
         "subjects": {"kernel.py": sha_file(k)}, "reference": {"sha256": sha_file(k0)}, "enumerated": 1, "mismatches": 0}
    assert toy._load(k, "z").q(0, 0) == toy._load(k0, "r").q(0, 0)
    json.dump(t, open(chain.P("enumeration_tiny.json"), "w"))
    spec = toy.spec_for(chain.P("enumeration_tiny.json"), "kernel -> zero, compared on one input"); spec["equivalence"][0].update({"domain_size": 1, "domain": "the pair (0, 0)"})
    json.dump(spec, open(chain.P("spec_tiny.json"), "w")); return spec


def test_truthful_enumeration_of_an_inadequate_domain_is_printed_and_refused_by_a_domain_policy(chain):
    """Found in the authors' own audit: nothing in the RECORD can know the right domain.  The record is valid and says
    how many inputs were enumerated; a policy that states the required domain rejects it."""
    _tiny_domain(chain)
    assert chain.issue("root.json", "inventory_v0.txt", "inventory_v4.txt", "spec_tiny.json", "derived_tiny.json")[0] == 0
    rc, rep = chain.verify_chain(links=("derived_tiny.json",))
    assert rc == 0 and any(n["kind"] == "enumeration domain" and "1 inputs were enumerated" in n["text"] for n in rep["not_checked"])
    rc, rep = chain.verify_chain(links=("derived_tiny.json",), extra=["--policy", QS_POLICY])
    assert rc == 1 and rep["policy"]["failed_checks"] == ["policy.enumeration_domains[derived_tiny.json]"]
    before, after = toy.evaluate(chain.P("config_v0")), toy.evaluate(chain.P("config_v4"))
    assert sum(a["pred"] != b["pred"] for a, b in zip(before, after)) > 100
    p = load_json(QS_POLICY); del p["enumeration_domains"]; json.dump(p, open(chain.P("p.json"), "w"))
    assert chain.verify_chain(links=("derived_tiny.json",), extra=["--policy", chain.P("p.json")])[0] == 0          # without the member, the false 'boundary' judgement is accepted by name


def test_policy_can_pin_the_text_of_a_judgement(chain, capsys):
    assert cli(["texts", "--certificate", chain.P("derived_v1.json")]) == 0
    texts = json.loads(capsys.readouterr().out)
    assert texts["judgements"]["boundary"] == hashlib.sha256(toy.BOUNDARY.encode()).hexdigest()
    pins = {"accepted_judgements": texts["judgements"], "accepted_assumptions": texts["trust_assumptions"]}
    rc, rep = chain.verify_chain(extra=_policy(chain, QS_POLICY, **pins))
    assert rc == 0 and rep["policy_verdict"] == "ACCEPTED"
    chain.mutate("derived_v1.json", lambda c: c["judgements"].update({"boundary": "the block is only ever called with a = b = 0"}))    # same NAME, another statement
    assert chain.verify_chain(links=("derived_v1.json",), extra=["--policy", QS_POLICY])[0] == 0                          # accepted by name
    rc, rep = chain.verify_chain(links=("derived_v1.json",), extra=_policy(chain, QS_POLICY, **pins))
    assert rc == 1 and rep["record_valid"] and rep["policy"]["failed_checks"] == ["policy.accepted_judgements[derived_v1.json]"]


@pytest.mark.parametrize("bad", [{"enumeration_domains": {"kernel.py": 0}}, {"enumeration_domains": ["kernel.py"]}, {"accepted_judgements": {"boundary": "abc"}}, {"accepted_assumptions": [1]}])
def test_malformed_new_policy_members_are_usage_errors(chain, bad, capsys):
    json.dump({"name": "p", **bad}, open(chain.P("bad.json"), "w"))
    assert chain_verify_rc(chain, chain.P("bad.json")) == 2 and "PolicyError" in capsys.readouterr().err


def chain_verify_rc(chain, policy):
    return cli(["verify", "--certificate", chain.P("derived_v1.json"), "--parent", chain.P("root.json"), *chain.trust(), "--policy", policy])


def test_certificates_of_the_two_unpublished_draft_formats_are_not_accepted(chain):
    chain.mutate("derived_v1.json", lambda c: c.update({"certificate_version": "recertkit-1"}))
    rc, rep = chain.verify()
    assert rc == 1 and "certificate.version" in rep["failed_checks"]
