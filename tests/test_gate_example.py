# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
"""The gate-root example: a root issued by the release gate (stored), verified read-only and probed on private copies."""
import json, os, shutil, tempfile
import pytest
from recertkit.cli import main as cli
from recertkit.canon import load_json, sha_file
from recertkit.signing import sign

EX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "examples", "gate_root")


def _verify(d, extra=(), trust=()):
    rep = os.path.join(tempfile.mkdtemp(), "report_test.json")      # never write into the shipped example directory
    rc = cli(["verify-chain", "--root", os.path.join(d, "gate_root_certificate.json"), "--links", os.path.join(d, "derived_c1.json"),
              "--trust", "gate-example=" + os.path.join(d, "gate_example.pub"), *trust, "--json-report", rep, *extra])
    r = load_json(rep); os.remove(rep); return rc, r


def test_stored_chain_is_valid_bound_by_digest_and_accepted_by_the_release_policy():
    rc, rep = _verify(EX, extra=["--policy", os.path.join(EX, "policy.json")])
    assert rc == 0 and rep["record_valid"] and rep["policy_verdict"] == "ACCEPTED"
    kinds = {n["kind"] for n in rep["not_checked"]}
    assert "root protocol" in kinds and not kinds & {"frame boundary", "unbound role", "unbound inventory", "coverage by judgement"}
    ok = {c["check"] for c in rep["checks"] if c["ok"]}
    assert {"roles.root_binding.server", "roles.root_binding.model", "roles.root_binding.frame", "root.inventory_binding", "root.task_manifest", "root.commitment_params"} <= ok


@pytest.fixture
def copy(tmp_path):
    d = str(tmp_path / "ex"); shutil.copytree(EX, d)
    cli(["keygen", "--private", os.path.join(d, "t.key"), "--public", os.path.join(d, "t.pub")]); return d


def _reissue(d, mutate_spec=None, root="gate_root_certificate.json"):
    spec = load_json(os.path.join(d, "spec_c1.json"))
    if mutate_spec: mutate_spec(spec)
    json.dump(spec, open(os.path.join(d, "spec_c1.json"), "w"))
    out = os.path.join(d, "derived_c1.json"); os.remove(out); rep = os.path.join(d, "issue.json")
    rc = cli(["issue", "--parent", os.path.join(d, root), "--spec", os.path.join(d, "spec_c1.json"), "--parent-inventory", os.path.join(d, "inventory_c0.txt"),
              "--derived-inventory", os.path.join(d, "inventory_c1.txt"), "--key", os.path.join(d, "t.key"), "--key-id", "test", "--out", out, "--json-report", rep])
    return rc, load_json(rep)


def _reissue_with_file(d, mutate):
    open(os.path.join(d, "derived_c1.json"), "w").write("{}")
    return _reissue(d, mutate)


def _replace_digest(d, name, new):
    for inv in ("inventory_c0.txt", "inventory_c1.txt"):
        q = os.path.join(d, inv); L = [(new + "  " + name) if l.endswith("  " + name) else l for l in open(q).read().splitlines()]
        open(q, "w").write("\n".join(L) + "\n")


def test_frame_content_change_with_unchanged_identifiers_is_detected(copy):
    """The counterpart of the FPGA example's boundary: this root binds the frame FILE, so a content edit cannot pass."""
    p = os.path.join(copy, "frame.jsonl"); lines = open(p).read().splitlines()
    it = json.loads(lines[0]); it["label"] = (it["label"] + 1) % 3; lines[0] = json.dumps(it); open(p, "w").write("\n".join(lines) + "\n")
    rc, rep = _verify(copy); assert rc == 1 and "root.frame_file" in rep["failed_checks"]
    _replace_digest(copy, "frame.jsonl", sha_file(p))                      # the attacker also rewrites both inventories
    rc, rep = _reissue(copy)
    assert rc == 1 and {"roles.binding_level.frame", "root.inventory_binding"} <= set(rep["failed_checks"])
    rc, rep = _reissue_with_file(copy, lambda s: s["root_binding"]["roles"].update({"frame": "identifiers-only"}))
    assert rc == 1 and "root.task_manifest" in rep["failed_checks"]         # ... and cannot retreat to the weaker level either


def test_other_parent_kernel_is_detected_through_the_inventory_binding(copy):
    _replace_digest(copy, "kernel.py", "ab" * 32)
    rc, rep = _reissue(copy)
    assert rc == 1 and "root.inventory_binding" in rep["failed_checks"]


def _minimal_gate_root(d):
    """A gate certificate with only the fields the gate's schema REQUIRES (no server digest, no inventory digest), signed by the test key."""
    root = load_json(os.path.join(d, "gate_root_certificate.json"))
    for k in ("server_binary_sha256", "configuration_inventory_sha256"): root["candidate_configuration"].pop(k)
    json.dump(sign(root, os.path.join(d, "t.key"), "test"), open(os.path.join(d, "gate_root_minimal.json"), "w"), indent=1)


def test_gate_root_with_required_fields_only_is_usable_in_limited_mode(copy):
    _minimal_gate_root(copy)
    rc, rep = _reissue(copy, root="gate_root_minimal.json")                                    # declares digest-level bindings the root does not provide
    assert rc == 1 and {"roles.binding_level.server", "root.inventory_level"} <= set(rep["failed_checks"])
    def limited(s):
        s["root_binding"]["roles"]["server"] = "unbound"; s["root_binding"]["inventory"] = "unbound"
        s["judgements"]["root_configuration"] = "system.py and kernel.py of the parent inventory are the files the gate run evaluated (attested by the issuer)."
    open(os.path.join(copy, "derived_c1.json"), "w").write("{}")
    rc, rep = _reissue(copy, limited, root="gate_root_minimal.json")
    assert rc == 0
    rep_path = os.path.join(copy, "v.json")
    args = ["verify", "--certificate", os.path.join(copy, "derived_c1.json"), "--parent", os.path.join(copy, "gate_root_minimal.json"), "--trust", "test=" + os.path.join(copy, "t.pub"), "--json-report", rep_path]
    assert cli(args) == 0
    kinds = [n["kind"] for n in load_json(rep_path)["not_checked"]]
    assert "unbound role" in kinds and "unbound inventory" in kinds
    assert cli(args + ["--policy", os.path.join(copy, "policy.json")]) == 1
    assert "policy.binding_levels[derived_c1.json]" in load_json(rep_path)["policy"]["failed_checks"]


def test_claim_must_equal_the_gate_commitment(copy):
    rc, rep = _reissue(copy, lambda s: s.update({"claim": {"metric_definition": "exact_match_accuracy", "degradation_direction": "reference_minus_candidate", "margin": "0.100000", "risk_level": "0.050000", "sampling_regime": "r2"}}))
    assert rc == 1 and {"root.commitment_params", "claim.invariance"} <= set(rep["failed_checks"])


def test_stored_root_was_accepted_by_the_gates_own_verifier_including_its_schema():
    """The gate tool skips its schema check silently when ``jsonschema`` is absent; the root stored up to 1.3.1 had
    been issued that way and failed the gate's schema (``engine_commit`` was "n/a").  The stored record of the gate
    run must show the schema check, and the two fields must have the form the gate's schema requires."""
    import re
    log = open(os.path.join(EX, "gate_tool_output.log")).read()
    assert "[OK] schema_valid" in log and "[FAIL]" not in log and log.rstrip().endswith("VERDICT: VALID") and "decision=certified" in log
    root = load_json(os.path.join(EX, "gate_root_certificate.json"))
    for side in ("reference_configuration", "candidate_configuration"):
        assert re.fullmatch(r"[0-9a-f]{7,40}", root[side]["engine_commit"]), root[side]["engine_commit"]
    ident = load_json(os.path.join(EX, "gate_tool_identity.json"))
    assert ident["gate_entry_point"] == "certify_v29_legacy.py" and ident["schema_valid_reported_by_the_gate"] is True
    assert ident["gate_verifier_checks_ok"] == log.count("[OK] ") == 49 and ident["engine_commit"] == root["candidate_configuration"]["engine_commit"]
    assert ident["jsonschema"] and len(ident["gate_entry_point_sha256"]) == 64 and len(ident["gate_certificate_schema_sha256"]) == 64


def test_engine_commit_of_the_recipe_is_tied_to_the_toy_system_it_names():
    """``engine_commit`` names a public commit of this repository; the recipe pins the digest of the toy system at that
    commit and refuses to run if the file has changed, so the two constants can only be updated together."""
    import re
    src = open(os.path.join(EX, "make_example.py"), encoding="utf-8").read()
    commit = re.search(r'^ENGINE_COMMIT = "([0-9a-f]{40})"$', src, re.M).group(1)
    pinned = re.search(r'^TOY_SHA256_AT_ENGINE_COMMIT = "([0-9a-f]{64})"$', src, re.M).group(1)
    toy_py = os.path.join(EX, "..", "quickstart", "toy.py")
    ident = load_json(os.path.join(EX, "gate_tool_identity.json"))
    assert sha_file(toy_py) == pinned == ident["toy_py_sha256"] and ident["engine_commit"] == commit
