# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
"""Inputs the verifier must not trust (independent review of release 1.0.0, findings M3-1, M3-3, M3-4).

* A file name inside a certificate is read only as a plain name inside the evidence directory.
* Input of an unexpected shape — even inside a certificate signed with a trusted key — ends with exit status 2 and one
  line on stderr: never a traceback, never an acceptance.
* ``recertkit inventory`` refuses what ``parse_inventory`` would refuse.
"""
import json, os
import pytest
import toy
from recertkit.canon import evidence_path, load_json, sha_file, sha_raw
from recertkit.cli import main as cli
from recertkit.inventory import InventoryError, make_inventory
from recertkit.profiles import DEFAULT_PROFILE, ProfileError, validate_profile


@pytest.mark.parametrize("name", ["../outside.txt", "sub/inside.txt", "..", ".", "", None, 7, "a\0b"])
def test_evidence_path_accepts_plain_names_only(tmp_path, name):
    (tmp_path / "d").mkdir(); (tmp_path / "d" / "sub").mkdir()
    for f in ("outside.txt", "d/sub/inside.txt"): (tmp_path / f).write_text("x")
    assert evidence_path(str(tmp_path / "d"), name) is None


def test_evidence_path_rejects_an_absolute_path_and_finds_plain_names(tmp_path):
    (tmp_path / "inside.txt").write_text("x")
    assert evidence_path(str(tmp_path), str(tmp_path / "inside.txt")) is None
    assert evidence_path(str(tmp_path), "inside.txt") == str(tmp_path / "inside.txt")


def _outside_copy(chain, name):
    """A byte-identical copy of an evidence file OUTSIDE the evidence directory; returns the name that would reach it."""
    out = os.path.join(os.path.dirname(chain.dir), "outside"); os.makedirs(out, exist_ok=True)
    with open(chain.P(name), "rb") as f, open(os.path.join(out, name), "wb") as g: g.write(f.read())
    os.remove(chain.P(name))
    return f"../outside/{name}"


def test_signed_certificate_cannot_point_an_evidence_file_outside_the_directory(chain):
    """The digest is right and the file exists — outside.  1.1.0 read it and passed the check."""
    key = next(k for k, v in load_json(chain.P("derived_v1.json"))["evidence_files"].items() if v["file"] == "enumeration_v1.json")
    name = _outside_copy(chain, "enumeration_v1.json")
    chain.mutate("derived_v1.json", lambda c: c["evidence_files"][key].update({"file": name}))
    rc, rep = chain.verify()
    assert rc == 1 and not rep["record_valid"] and f"evidence.{key}" in rep["failed_checks"]


def test_signed_certificate_cannot_point_an_inventory_outside_the_directory(chain):
    name = _outside_copy(chain, "inventory_v1.txt")
    chain.mutate("derived_v1.json", lambda c: c["derived_inventory"].update({"file": name}))
    rc, rep = chain.verify()
    assert rc == 1 and not rep["record_valid"] and "inventory.digest.derived" in rep["failed_checks"]


MALFORMED = [("block", None), ("risk_budget", None), ("parent_inventory", None), ("equivalence", {"not": "a list"}), ("evidence_files", [1, 2]), ("judgements", 5)]


@pytest.mark.parametrize("member,value", MALFORMED, ids=[m for m, _ in MALFORMED])
def test_signed_certificate_of_an_unexpected_shape_is_never_accepted_and_never_a_traceback(chain, capsys, member, value):
    chain.mutate("derived_v1.json", lambda c: c.update({member: value}))
    rc = cli(["verify-chain", "--root", chain.P("root.json"), "--links", chain.P("derived_v1.json"), *chain.trust()])
    err = capsys.readouterr().err
    assert rc in (1, 2) and "Traceback" not in err
    if rc == 2: assert err.startswith("recertkit: error:") and len(err.strip().splitlines()) == 1


@pytest.mark.parametrize("content", ["[]", "null", "3", '"text"'])
def test_certificate_file_that_is_not_an_object_is_a_usage_error(chain, capsys, content):
    open(chain.P("derived_v1.json"), "w").write(content)
    rc = cli(["verify-chain", "--root", chain.P("root.json"), "--links", chain.P("derived_v1.json"), *chain.trust()])
    err = capsys.readouterr().err
    assert rc == 2 and err.startswith("recertkit: error:") and "Traceback" not in err


def test_missing_plugin_file_is_a_usage_error(chain, capsys):
    rc = cli(["verify-chain", "--root", chain.P("root.json"), "--links", chain.P("derived_v1.json"), *chain.trust(), "--plugin", chain.P("no_such_plugin.py")])
    assert rc == 2 and capsys.readouterr().err.startswith("recertkit: error:")


def test_debug_switch_shows_the_traceback(chain, monkeypatch):
    open(chain.P("derived_v1.json"), "w").write("[]"); monkeypatch.setenv("RECERTKIT_DEBUG", "1")
    with pytest.raises(Exception):
        cli(["verify-chain", "--root", chain.P("root.json"), "--links", chain.P("derived_v1.json"), *chain.trust()])


def test_inventory_command_refuses_two_files_of_the_same_name(tmp_path, capsys):
    for d in ("a", "b"):
        (tmp_path / d).mkdir(); (tmp_path / d / "__init__.py").write_text(f"# {d}\n")
    out = str(tmp_path / "inv.txt")
    rc = cli(["inventory", str(tmp_path / "a" / "__init__.py"), str(tmp_path / "b" / "__init__.py"), "--out", out])
    assert rc == 2 and "duplicate file names" in capsys.readouterr().err and not os.path.exists(out)
    with pytest.raises(InventoryError): make_inventory([str(tmp_path / "a" / "__init__.py"), str(tmp_path / "b" / "__init__.py")])


def test_inventory_digests_are_those_of_sha256sum_also_for_compressed_artifacts(tmp_path):
    """An artifact is hashed as stored.  Until 1.1.0 an artifact named ``*.gz`` was hashed after decompression, so its
    inventory line differed from what ``sha256sum`` prints."""
    import gzip, hashlib
    (tmp_path / "x.bin").write_bytes(b"abc")
    with gzip.open(tmp_path / "weights.bin.gz", "wb") as f: f.write(b"payload")
    stored = (tmp_path / "weights.bin.gz").read_bytes()
    inv = make_inventory([str(tmp_path / "x.bin"), str(tmp_path / "weights.bin.gz")])
    assert inv == f"{hashlib.sha256(stored).hexdigest()}  weights.bin.gz\n{hashlib.sha256(b'abc').hexdigest()}  x.bin\n"
    assert sha_raw(str(tmp_path / "weights.bin.gz")) != sha_file(str(tmp_path / "weights.bin.gz")) == hashlib.sha256(b"payload").hexdigest()   # records may be stored compressed


def test_root_role_digest_of_a_compressed_artifact_is_that_of_its_stored_bytes(tmp_path):
    import gzip, hashlib
    P = lambda n: str(tmp_path / n)
    with gzip.open(P("model.bin.gz"), "wb") as f: f.write(b"weights")
    for n in ("server.py", "frame.jsonl"): open(P(n), "w").write(n)
    json.dump(toy.CLAIM, open(P("claim.json"), "w"))
    assert cli(["keygen", "--private", P("k.key"), "--public", P("k.pub")]) == 0
    assert cli(["inventory", P("server.py"), P("model.bin.gz"), P("frame.jsonl"), "--out", P("inv.txt")]) == 0
    rc = cli(["root-issue", "--claim", P("claim.json"), "--role", f"server={P('server.py')}", "--role", f"model={P('model.bin.gz')}", "--role", f"frame={P('frame.jsonl')}",
              "--inventory", P("inv.txt"), "--basis", "test", "--key", P("k.key"), "--key-id", "k", "--out", P("root.json")])
    root = load_json(P("root.json")); raw = hashlib.sha256(open(P("model.bin.gz"), "rb").read()).hexdigest()
    assert rc == 0 and raw in json.dumps(root) and raw in open(P("inv.txt")).read()


@pytest.mark.parametrize("switch", ["coverage_by_judgement", "require_equivalence"])
def test_profile_switches_must_be_booleans(switch):
    p = json.loads(json.dumps(DEFAULT_PROFILE)); p[switch] = "false"
    with pytest.raises(ProfileError): validate_profile(p)


def _rebuild_only(chain):
    """C0 -> the same files, system.py rebuilt (bytes differ, behaviour unchanged); no block was replaced and no
    comparison was run.  The only support is the written judgement that the rebuilt file behaves as before."""
    cfg = toy.write_config(chain.P("config_rb"), "ref"); open(cfg["system.py"], "a").write("# rebuilt\n")
    assert cli(["inventory", *cfg.values(), "--out", chain.P("inventory_rb.txt")]) == 0
    spec = toy.spec_for(chain.P("enumeration_v0.json"), "system.py rebuilt")
    spec["block"] = {"changed": [], "residual_rebuilt": ["system.py"], "unchanged": ["kernel.py", "model.json", "frame.jsonl"]}
    spec["equivalence"] = []; spec["evidence_files"] = {}
    spec["judgements"] = {"boundary": "No block was replaced.", "residual_path": "system.py was rebuilt from unchanged sources with the same toolchain; kernel.py, model.json and frame.jsonl are byte-identical."}
    json.dump(spec, open(chain.P("spec_rb.json"), "w"))


def test_rebuild_without_any_comparison_is_refused_under_the_built_in_profile(chain):
    _rebuild_only(chain)
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_rb.txt", "spec_rb.json", "derived_rb.json")
    assert rc == 1 and "coverage.equivalence_present" in rep["failed_checks"]


def test_rebuild_without_any_comparison_can_be_recorded_under_a_profile_that_says_so_and_is_printed(chain):
    """A relying party that wants such records supplies a profile with ``require_equivalence: false``.  The record then
    rests on judgement alone; that is printed, and the supplied release policy refuses it."""
    _rebuild_only(chain)
    prof = json.loads(json.dumps(DEFAULT_PROFILE)); prof["name"] = "lab-rebuilds-1"; prof["require_equivalence"] = False
    json.dump(prof, open(chain.P("prof.json"), "w")); P = ["--profile", chain.P("prof.json")]
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_rb.txt", "spec_rb.json", "derived_rb.json", extra=P)
    assert rc == 0, rep["failed_checks"]
    rc, rep = chain.verify_chain(links=("derived_rb.json",), extra=P)
    assert rc == 0 and rep["record_valid"] and "residual rebuilt" in {n["kind"] for n in rep["not_checked"]}
    rc, rep = chain.verify_chain(links=("derived_rb.json",))                                    # the built-in profile does not accept the record
    assert rc == 1 and not rep["record_valid"]
    rc, rep = chain.verify_chain(links=("derived_rb.json",), extra=P + ["--policy", os.path.join(os.path.dirname(toy.__file__), "policy.json")])
    assert rc == 1 and rep["record_valid"] and "policy.residual_rebuilt[derived_rb.json]" in rep["policy"]["failed_checks"]
