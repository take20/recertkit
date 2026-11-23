# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
import gzip, json, os, shutil
from recertkit.canon import load_json, sha_file


def test_chain_is_valid(chain):
    rc, rep = chain.verify_chain()
    assert rc == 0 and rep["valid"] and rep["verdict"] == "VALID"
    kinds = {n["kind"] for n in rep["not_checked"]}
    assert {"judgement boundary", "judgement residual_path", "trust assumption interpreter", "root attestation"} <= kinds


def test_single_link_prints_precondition_for_derived_parent(chain):
    rc, rep = chain.verify("derived_v2.json", "derived_v1.json")
    assert rc == 0 and any(n["kind"] == "precondition" for n in rep["not_checked"])


def test_gzip_evidence_has_the_same_digest(chain):
    p = chain.P("enumeration_v1.json"); before = sha_file(p)
    with open(p, "rb") as f, gzip.open(p + ".gz", "wb") as g: shutil.copyfileobj(f, g)
    os.remove(p)
    assert sha_file(p + ".gz") == before
    assert chain.verify()[0] == 0


def test_detached_evidence_is_reported_not_silently_accepted(chain):
    spec = load_json(chain.P("spec_v1.json"))
    note = chain.P("design_note.txt"); open(note, "w").write("a large or confidential supporting record")
    spec["evidence_files"]["design_note"] = {"file": "design_note.txt", "sha256": sha_file(note), "detached": True}
    json.dump(spec, open(chain.P("spec_v1.json"), "w"))
    assert chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")[0] == 0
    assert chain.verify()[0] == 0                                   # present: digest checked
    os.remove(note)
    rc, rep = chain.verify()
    assert rc == 0 and any(n["kind"] == "detached evidence" for n in rep["not_checked"])
    rc, rep = chain.verify(extra=["--require-all-evidence"])
    assert rc == 1 and "evidence.design_note" in rep["failed_checks"]
    open(note, "w").write("something else")
    rc, rep = chain.verify()
    assert rc == 1 and "evidence.design_note" in rep["failed_checks"]   # present but different: rejected


def test_custom_profile_and_plugin_method(chain, tmp_path):
    """A lab adds its own equivalence method. The engine still binds both sides of the comparison; the plugin only adds its own check."""
    from recertkit.profiles import DEFAULT_PROFILE
    prof = json.loads(json.dumps(DEFAULT_PROFILE)); prof["name"] = "lab-profile-1"; prof["methods"] = ["signed_off_proof"]
    pp = chain.P("lab_profile.json"); json.dump(prof, open(pp, "w"))
    plug = chain.P("plugin.py")
    open(plug, "w").write("def proof(entry, transcript):\n    return [('proof_status', transcript.get('status') == 'proved', str(transcript.get('status')))]\n"
                          "def register(reg):\n    reg['signed_off_proof'] = proof\n")
    inv0, inv1 = (dict(reversed(l.split()) for l in open(chain.P(f)).read().splitlines() if l.strip()) for f in ("inventory_v0.txt", "inventory_v1.txt"))
    json.dump({"schema": "recertkit-enumeration-1", "subjects": {"kernel.py": inv1["kernel.py"]}, "reference": {"sha256": inv0["kernel.py"]}, "status": "proved"}, open(chain.P("proof.json"), "w"))
    spec = load_json(chain.P("spec_v1.json"))
    spec["equivalence"] = [{"id": "kernel", "method_code": "signed_off_proof", "subjects": ["kernel.py"], "replaces": ["kernel.py"],
                            "reference": {"kind": "parent_artifact", "artifact": "kernel.py"}, "transcript": "proof"}]
    spec["evidence_files"] = {"proof": chain.P("proof.json")}; json.dump(spec, open(chain.P("spec_v1.json"), "w"))
    common = ["--profile", pp, "--plugin", plug]
    assert chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json", extra=common)[0] == 0
    assert chain.verify(extra=common)[0] == 0
    rc, rep = chain.verify()                                        # default profile: issued under another profile -> rejected
    assert rc == 1 and "certificate.profile" in rep["failed_checks"]
    # the plugin cannot be used to skip the reference binding: a proof about a comparison with some other kernel is refused
    t = load_json(chain.P("proof.json")); t["reference"]["sha256"] = inv1["kernel.py"]; json.dump(t, open(chain.P("proof.json"), "w"))
    os.remove(chain.P("derived_v1.json"))
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json", extra=common)
    assert rc == 1 and rep["failed_checks"] == ["equivalence.kernel.reference_digest"]
