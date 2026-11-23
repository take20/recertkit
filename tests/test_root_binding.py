# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
"""How strongly the configuration is tied to the root, and what happens when the tie is weak."""
import json, os
import toy
from recertkit.cli import main as cli
from recertkit.canon import load_json


def _root_without_inventory(chain):
    cfg = {n: chain.P("config_v0", n) for n in ("system.py", "model.json", "frame.jsonl")}
    assert cli(["root-issue", "--claim", chain.P("claim.json"), "--role", f"server={cfg['system.py']}", "--role", f"model={cfg['model.json']}", "--role", f"frame={cfg['frame.jsonl']}",
                "--basis", "root that binds the role artifacts only", "--key", chain.P("release.key"), "--key-id", "release", "--out", chain.P("root.json")]) == 0
    os.remove(chain.P("derived_v1.json"))


def test_root_that_binds_the_inventory_rejects_another_parent_inventory(chain):
    """The parent's kernel.py is not a role, so only the inventory binding ties it to the root. Swap it and the link must fail."""
    open(chain.P("config_v0", "kernel.py"), "w").write(toy.KERNELS["zero"] + "# a different file with the same behaviour as the NEW kernel\n")
    assert cli(["inventory", *[chain.P("config_v0", n) for n in ("system.py", "kernel.py", "model.json", "frame.jsonl")], "--out", chain.P("inventory_v0.txt")]) == 0
    toy.enumerate_block(chain.P("config_v4", "kernel.py"), chain.P("config_v0", "kernel.py"), chain.P("enumeration_v4.json"))        # truthful: 0 mismatches against the forged parent kernel
    json.dump(toy.spec_for(chain.P("enumeration_v4.json"), "forged parent inventory"), open(chain.P("spec_v4.json"), "w"))
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_v4.txt", "spec_v4.json", "derived_v4.json")
    assert rc == 1 and rep["failed_checks"] == ["root.inventory_binding"]


def test_root_without_inventory_binding_must_be_declared_and_argued(chain):
    _root_without_inventory(chain)
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")
    assert rc == 1 and rep["failed_checks"] == ["root.inventory_level", "judgements.required"]
    spec = load_json(chain.P("spec_v1.json")); spec["root_binding"]["inventory"] = "unbound"
    spec["judgements"]["root_configuration"] = "kernel.py of the parent inventory is the kernel the root attestation was made for (attested by the issuer)."
    json.dump(spec, open(chain.P("spec_v1.json"), "w"))
    assert chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")[0] == 0
    rc, rep = chain.verify()
    assert rc == 0 and any(n["kind"] == "unbound inventory" and "kernel.py" in n["text"] for n in rep["not_checked"])
    rc, rep = chain.verify(extra=["--policy", os.path.join(os.path.dirname(toy.__file__), "policy.json")])
    assert rc == 1 and {"policy.binding_levels[derived_v1.json]", "policy.accepted_judgements[derived_v1.json]"} <= set(rep["policy"]["failed_checks"])


def test_binding_level_cannot_be_overstated(chain):
    _root_without_inventory(chain)
    spec = load_json(chain.P("spec_v1.json")); spec["judgements"]["root_configuration"] = "attested"; json.dump(spec, open(chain.P("spec_v1.json"), "w"))
    rc, rep = chain.issue("root.json", "inventory_v0.txt", "inventory_v1.txt", "spec_v1.json", "derived_v1.json")      # still declares inventory: digest
    assert rc == 1 and rep["failed_checks"] == ["root.inventory_level"]


def test_root_issue_refuses_roles_that_are_not_in_the_inventory(chain, capsys):
    open(chain.P("other.json"), "w").write("{}")
    rc = cli(["root-issue", "--claim", chain.P("claim.json"), "--role", f"server={chain.P('config_v0', 'system.py')}", "--role", f"model={chain.P('other.json')}",
              "--role", f"frame={chain.P('config_v0', 'frame.jsonl')}", "--inventory", chain.P("inventory_v0.txt"), "--basis", "x", "--key", chain.P("release.key"), "--key-id", "release", "--out", chain.P("r2.json")])
    assert rc == 2 and "not in the inventory" in capsys.readouterr().err


def test_root_info_reports_what_the_adapter_reads(chain, capsys):
    assert cli(["root-info", "--root", chain.P("root.json")]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["adapter"] == "recertkit-root-1" and info["inventory_digest"] and set(info["role_digests"]) == {"server", "model", "frame"}
