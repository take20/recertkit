# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
"""The shipped FPGA case-study chain: verified read-only with the public key, then probed on private copies."""
import json, os, shutil, tempfile
import pytest
from recertkit.cli import main as cli
from recertkit.canon import load_json, sha_file
from recertkit.checks import documented

EX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "examples", "fpga_ultra96")
TRUST = ["--trust", "p5-release-key-1=" + os.path.join(EX, "release_key.pub")]


def _verify(d, extra=(), trust=None):
    rep = os.path.join(tempfile.mkdtemp(), "report_test.json")      # never write into the shipped example directory
    rc = cli(["verify-chain", "--root", os.path.join(d, "root_certificate.json"), "--links", os.path.join(d, "derived_v1.json"), os.path.join(d, "derived_v1p.json"),
              *(trust or TRUST), "--json-report", rep, *extra])
    r = load_json(rep); os.remove(rep); return rc, r


def test_shipped_chain_is_valid_and_states_what_it_did_not_check():
    rc, rep = _verify(EX)
    assert rc == 0 and rep["valid"]
    kinds = [n["kind"] for n in rep["not_checked"]]
    assert "frame boundary" in kinds and "detached evidence" in kinds and "root protocol" in kinds
    assert sum(k.startswith("trust assumption") for k in kinds) >= 10 and sum(k.startswith("judgement") for k in kinds) >= 7
    # what the first draft did not say: the changed host library rests on a judgement, the reference is a specification, the inventory is not bound by the root
    assert {"coverage by judgement", "reference by judgement", "reference by declaration", "unbound inventory", "transcript mapping", "transcript provenance"} <= set(kinds)
    assert all(documented(r["check"]) for r in rep["checks"])


def test_detached_evidence_can_be_required():
    rc, rep = _verify(EX, extra=["--require-all-evidence"])
    assert rc == 1 and rep["failed_checks"] == ["evidence.residual_source_identity"]


@pytest.fixture
def copy(tmp_path):
    d = str(tmp_path / "ex"); shutil.copytree(EX, d); return d


def test_frame_file_edit_is_detected(copy):
    p = os.path.join(copy, "eval_mmlu500.jsonl"); open(p, "a").write("\n")
    rc, rep = _verify(copy); assert rc == 1 and "root.frame_file" in rep["failed_checks"]


def test_transcript_edit_is_detected(copy):
    p = os.path.join(copy, "lane_exhaustive_result.json"); t = load_json(p); t["bitstreams"]["V1"]["lane_exhaustive"]["mismatches"] = 0; t["edited"] = True
    json.dump(t, open(p, "w")); rc, rep = _verify(copy)
    assert rc == 1 and "evidence.lane_enumeration" in rep["failed_checks"]


def test_commitment_swap_is_detected(copy):
    p = os.path.join(copy, "root_commitment.json"); c = load_json(p); c["epsilon"] = "0.100000"; json.dump(c, open(p, "w"))
    rc, rep = _verify(copy); assert rc == 1 and "root.commitment" in rep["failed_checks"]


def _reissue(copy, mutate_spec=None):
    """Re-issue link 1 with a key generated here (the release key is not shipped) and trust both keys."""
    cli(["keygen", "--private", os.path.join(copy, "t.key"), "--public", os.path.join(copy, "t.pub")])
    spec = load_json(os.path.join(copy, "spec_v1.json"))
    if mutate_spec: mutate_spec(spec)
    json.dump(spec, open(os.path.join(copy, "spec_v1.json"), "w"))
    out = os.path.join(copy, "derived_v1.json"); os.remove(out)
    rep = os.path.join(copy, "issue.json")
    rc = cli(["issue", "--parent", os.path.join(copy, "root_certificate.json"), "--spec", os.path.join(copy, "spec_v1.json"), "--parent-inventory", os.path.join(copy, "inventory_v0.txt"),
              "--derived-inventory", os.path.join(copy, "inventory_v1.txt"), "--key", os.path.join(copy, "t.key"), "--key-id", "test", "--out", out, "--json-report", rep])
    return rc, load_json(rep)


def test_roles_swapped_is_refused_at_issue(copy):
    rc, rep = _reissue(copy, lambda s: s["roles"].update({"server": "Llama-3.2-1B-Instruct-Q4_K_M.gguf", "model": "llama-server"}))
    assert rc == 1 and "roles.root_binding.server" in rep["failed_checks"]


def test_overstated_frame_binding_is_refused_at_issue(copy):
    rc, rep = _reissue(copy, lambda s: s["root_binding"]["roles"].update({"frame": "digest"}))
    assert rc == 1 and "roles.binding_level.frame" in rep["failed_checks"]


def test_lane_domain_cannot_be_understated(copy):
    rc, rep = _reissue(copy, lambda s: s["equivalence"][0].update({"domain_size": 2 ** 31}))
    assert rc == 1 and "equivalence.pl_kernel.domain_enumerated" in rep["failed_checks"]


def test_identifier_only_root_cannot_detect_a_frame_content_change_and_says_so(copy):
    """KNOWN BOUNDARY, by design: this root binds item identifiers only.  If the frame's content is replaced while the
    identifiers are kept and the inventories are regenerated, a new first link can be issued and verifies — with the
    boundary printed.  The test documents the limit; it is not a defect that a later release should 'fix' silently."""
    p = os.path.join(copy, "eval_mmlu500.jsonl"); lines = open(p).read().splitlines()
    it = json.loads(lines[0]); it["question"] = "A different question with the same identifier."; lines[0] = json.dumps(it)
    open(p, "w").write("\n".join(lines) + "\n"); new = sha_file(p)
    for inv in ("inventory_v0.txt", "inventory_v1.txt"):
        q = os.path.join(copy, inv); L = [(new + "  eval_mmlu500.jsonl") if l.endswith("eval_mmlu500.jsonl") else l for l in open(q).read().splitlines()]
        open(q, "w").write("\n".join(L) + "\n")
    rc, rep = _reissue(copy)
    assert rc == 0
    rep_path = os.path.join(copy, "v.json")
    rc = cli(["verify", "--certificate", os.path.join(copy, "derived_v1.json"), "--parent", os.path.join(copy, "root_certificate.json"),
              "--trust", "p5-release-key-1=" + os.path.join(copy, "release_key.pub"), "--trust", "test=" + os.path.join(copy, "t.pub"), "--json-report", rep_path])
    r = load_json(rep_path)
    assert rc == 0 and any(n["kind"] == "frame boundary" for n in r["not_checked"])


def _edit_first_item_id(copy):
    p = os.path.join(copy, "eval_mmlu500.jsonl"); lines = open(p).read().splitlines()
    it = json.loads(lines[0]); it["item_id"] = it["item_id"] + "_x"; lines[0] = json.dumps(it)
    open(p, "w").write("\n".join(lines) + "\n"); new = sha_file(p)
    for inv in ("inventory_v0.txt", "inventory_v1.txt"):
        q = os.path.join(copy, inv); L = [(new + "  eval_mmlu500.jsonl") if l.endswith("eval_mmlu500.jsonl") else l for l in open(q).read().splitlines()]
        open(q, "w").write("\n".join(L) + "\n")


def test_frame_with_other_identifiers_is_refused(copy):
    """The counterpart of the boundary test: once an IDENTIFIER changes, the root's commitment no longer matches."""
    _edit_first_item_id(copy)
    rc, rep = _reissue(copy)
    assert rc == 1 and {"root.frame_ids", "root.task_manifest"} <= set(rep["failed_checks"])


def test_claim_that_differs_from_the_root_commitment_is_refused(copy):
    def loosen(s): s["claim"] = {"metric_definition": "exact_match_accuracy", "degradation_direction": "reference_minus_candidate", "margin": "0.100000", "risk_level": "0.050000", "sampling_regime": "r2"}
    rc, rep = _reissue(copy, loosen)
    assert rc == 1 and {"root.commitment_params", "claim.invariance"} <= set(rep["failed_checks"])


def test_root_names_another_model_file(copy):
    rc, rep = _reissue(copy, lambda s: s["roles"].update({"model": "libllama.so"}))
    assert rc == 1 and "roles.root_filename.model" in rep["failed_checks"]


def test_changed_host_library_must_be_covered(copy):
    """In the first draft the changed CPU-backend library was covered by nothing. Removing its judgement coverage is now refused."""
    rc, rep = _reissue(copy, lambda s: s.pop("judgement_coverage"))
    assert rc == 1 and {"coverage.derived_side", "coverage.parent_side"} <= set(rep["failed_checks"])


def test_unbound_inventory_needs_the_root_configuration_judgement(copy):
    rc, rep = _reissue(copy, lambda s: s["judgements"].pop("root_configuration"))
    assert rc == 1 and rep["failed_checks"] == ["judgements.required"]


def _reissue_link2(copy, mutate_spec=None):
    """Re-issue link 2 on top of a link 1 re-issued with the test key."""
    assert _reissue(copy)[0] == 0
    spec = load_json(os.path.join(copy, "spec_v1p.json"))
    if mutate_spec: mutate_spec(spec)
    json.dump(spec, open(os.path.join(copy, "spec_v1p.json"), "w"))
    out = os.path.join(copy, "derived_v1p.json"); os.remove(out); rep = os.path.join(copy, "issue2.json")
    rc = cli(["issue", "--parent", os.path.join(copy, "derived_v1.json"), "--spec", os.path.join(copy, "spec_v1p.json"), "--parent-inventory", os.path.join(copy, "inventory_v1.txt"),
              "--derived-inventory", os.path.join(copy, "inventory_v1p.txt"), "--key", os.path.join(copy, "t.key"), "--key-id", "test", "--out", out, "--json-report", rep])
    return rc, load_json(rep)


def test_reference_inherited_by_name_must_be_the_parent_links_reference(copy):
    """Link 1 compared against a specification identified by name. Link 2 may inherit that reference, not name another one."""
    rc, rep = _reissue_link2(copy)
    assert rc == 0 and any(n["kind"] == "reference by declaration" for n in rep["not_checked"])
    open(os.path.join(copy, "derived_v1p.json"), "w").write("{}")
    rc, rep = _reissue_link2(copy, lambda s: s["equivalence"][0].update({"reference": {"kind": "parent_link", "id": "some other model of the kernel"}}))
    assert rc == 1 and rep["failed_checks"] == ["equivalence.pl_kernel.reference_id"]
