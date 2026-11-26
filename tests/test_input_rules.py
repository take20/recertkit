# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
"""Input rules that are the same on every path: duplicate JSON members, JSON pointers, key type, root eligibility."""
import json, os
import pytest
from recertkit import canon
from recertkit.cli import main as cli


def _with_duplicate(path, member):
    """Rewrite the JSON object in ``path`` so that ``member`` appears twice (the second copy carries another value)."""
    text = open(path, encoding="utf-8").read().rstrip()
    assert text.endswith("}") and f'"{member}"' in text
    open(path, "w", encoding="utf-8").write(text[:-1].rstrip() + f', "{member}": "second value"' + "}")


def test_a_transcript_with_a_repeated_member_name_is_never_accepted(chain, capsys):
    """Changing a stored transcript already breaks its digest (record INVALID); re-issuing from it is refused."""
    _with_duplicate(chain.P("enumeration_v1.json"), "mismatches")
    assert chain.verify_chain(links=("derived_v1.json",))[0] == 1
    os.remove(chain.P("derived_v1.json"))
    rc = cli(["issue", "--parent", chain.P("root.json"), "--spec", chain.P("spec_v1.json"), "--parent-inventory", chain.P("inventory_v0.txt"),
              "--derived-inventory", chain.P("inventory_v1.txt"), "--key", chain.P("release.key"), "--key-id", "release", "--out", chain.P("derived_v1.json"), *chain.trust()])
    assert rc != 0 and not os.path.exists(chain.P("derived_v1.json"))


@pytest.mark.parametrize("target,member", [("derived_v1.json", "claim_scope"), ("root.json", "decision")])
def test_a_repeated_member_name_in_a_certificate_is_refused_not_resolved(chain, target, member, capsys):
    _with_duplicate(chain.P(target), member)
    rc = cli(["verify-chain", "--root", chain.P("root.json"), "--links", chain.P("derived_v1.json"), *chain.trust(), "--json-report", chain.P("dup_report.json")])
    err = capsys.readouterr().err
    assert rc == 2 and "duplicate member name" in err and not os.path.exists(chain.P("dup_report.json"))


def test_a_repeated_member_name_in_a_declaration_or_profile_is_refused(chain, capsys):
    _with_duplicate(chain.P("spec_v1.json"), "claim_scope"); os.remove(chain.P("derived_v1.json"))
    rc = cli(["issue", "--parent", chain.P("root.json"), "--spec", chain.P("spec_v1.json"), "--parent-inventory", chain.P("inventory_v0.txt"),
              "--derived-inventory", chain.P("inventory_v1.txt"), "--key", chain.P("release.key"), "--key-id", "release", "--out", chain.P("derived_v1.json"), *chain.trust()])
    assert rc == 2 and "duplicate member name" in capsys.readouterr().err and not os.path.exists(chain.P("derived_v1.json"))
    with pytest.raises(ValueError):
        open(chain.P("p.json"), "w").write('{"a": 1, "a": 2}'); canon.load_json(chain.P("p.json"))


@pytest.mark.parametrize("ptr", ["/a/-1", "/a/01", "/a/+1", "/a/ 1", "/a/1.0", "/a/3", "/a/-", "/a/", "a/0", "/b/0"])
def test_json_pointer_array_indices_follow_rfc_6901(ptr):
    doc = {"a": [10, 20, 30], "b": 5}
    with pytest.raises(KeyError): canon.pointer(doc, ptr)


def test_json_pointer_resolves_valid_references():
    doc = {"a": [10, 20, 30], "x/y": {"~": 7}, "": 9}
    assert canon.pointer(doc, "/a/0") == 10 and canon.pointer(doc, "/a/2") == 30 and canon.pointer(doc, "/x~1y/~0") == 7 and canon.pointer(doc, "") is doc and canon.pointer(doc, "/") == 9


def test_a_trusted_key_that_is_not_ed25519_is_a_usage_error(chain, capsys):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    pem = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    open(chain.P("other.pub"), "wb").write(pem)
    rc = cli(["verify-chain", "--root", chain.P("root.json"), "--links", chain.P("derived_v1.json"), "--trust", f"release={chain.P('other.pub')}"])
    assert rc == 2 and "not an Ed25519 public key" in capsys.readouterr().err


def test_a_root_that_is_not_certified_is_refused_on_every_path(chain, capsys):
    """Up to 1.3.1 ``issue`` and single-link ``verify`` accepted a ROOT whose decision was the string "transfer"
    (the value that marks a derived parent), while ``verify-chain`` required "certified"."""
    cfg = lambda f: chain.P("config_v0", f)
    assert cli(["root-issue", "--claim", chain.P("claim.json"), "--role", f"server={cfg('system.py')}", "--role", f"model={cfg('model.json')}", "--role", f"frame={cfg('frame.jsonl')}",
                "--inventory", chain.P("inventory_v0.txt"), "--basis", "test root", "--decision", "transfer", "--key", chain.P("release.key"), "--key-id", "release", "--out", chain.P("root_t.json")]) == 0
    rc, rep = chain.issue("root_t.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_t.json")
    assert rc == 1 and "parent.decision" in rep["failed_checks"] and not os.path.exists(chain.P("derived_t.json"))
    chain.forge("root_t.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_t.json")
    rc, rep = chain.verify(cert="derived_t.json", parent="root_t.json")
    assert rc == 1 and "parent.decision" in rep["failed_checks"]
    rc = cli(["verify-chain", "--root", chain.P("root_t.json"), "--links", chain.P("derived_t.json"), *chain.trust(), "--json-report", chain.P("t_report.json")])
    rep = json.load(open(chain.P("t_report.json")))
    assert rc == 1 and {"root.decision", "parent.decision[derived_t.json]"} & set(rep["failed_checks"]) and not rep["record_valid"]


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_non_json_constants_are_refused_in_every_input(chain, constant, capsys):
    open(chain.P("c.json"), "w").write('{"a": %s}' % constant)
    with pytest.raises(ValueError): canon.load_json(chain.P("c.json"))
    text = open(chain.P("derived_v1.json"), encoding="utf-8").read().rstrip()
    open(chain.P("derived_v1.json"), "w", encoding="utf-8").write(text[:-1].rstrip() + ', "extra": %s}' % constant)
    assert cli(["verify-chain", "--root", chain.P("root.json"), "--links", chain.P("derived_v1.json"), *chain.trust()]) == 2
    assert "is not a JSON value" in capsys.readouterr().err
    open(chain.P("pol.json"), "w").write('{"name": "p", "unrecorded": "forbid", "enumeration_domains": {"kernel.py": %s}}' % constant)
    assert cli(["verify-chain", "--root", chain.P("root.json"), "--links", chain.P("derived_v2.json"), *chain.trust(), "--policy", chain.P("pol.json")]) == 2
    assert "policy error" in capsys.readouterr().err


@pytest.mark.parametrize("member,value", [("canonicalization", "none"), ("canonicalization", None), ("algorithm", "ED25519"), ("algorithm", "rsa-pss")])
def test_a_signature_block_that_declares_another_algorithm_or_canonical_form_is_not_verified(chain, member, value):
    """The signed bytes do not include the signature block, so its labels can be edited without breaking the
    signature; a certificate must not be verified under an interpretation other than the one it declares."""
    c = json.load(open(chain.P("derived_v1.json")))
    if value is None: del c["signature"][member]
    else: c["signature"][member] = value
    json.dump(c, open(chain.P("derived_v1.json"), "w"))
    rc, rep = chain.verify_chain(links=("derived_v1.json",))
    assert rc == 1 and not rep["record_valid"] and any(f.startswith("signature.certificate") for f in rep["failed_checks"]), rep["failed_checks"]
