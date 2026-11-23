# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
"""Quick start: certify once, change the system, carry the certificate forward — and see bad changes refused.

    python examples/quickstart/run.py [workdir]

Runs in a few seconds on any machine; needs no hardware and no network.
"""
import json, os, shutil, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import toy
from recertkit.cli import main as recertkit


def step(title):
    print("\n" + "=" * 100 + f"\n{title}\n" + "=" * 100)


def run(work):
    work = os.path.abspath(work)
    shutil.rmtree(work, ignore_errors=True); os.makedirs(work)
    P = lambda *a: os.path.join(work, *a)
    trust = ["--trust", f"release={P('release.pub')}"]
    def issue(parent, spec, pinv, dinv, out):
        return recertkit(["issue", "--parent", P(parent), "--spec", P(spec), "--parent-inventory", P(pinv), "--derived-inventory", P(dinv),
                          "--key", P("release.key"), "--key-id", "release", "--out", P(out), *trust])

    step("1. A deployed configuration C0, its inventory, and a root certificate that binds both")
    c0 = toy.write_config(P("config_v0"), "ref")
    res0 = toy.evaluate(P("config_v0")); acc0 = sum(r["correct"] for r in res0) / len(res0)
    print(f"C0 accuracy on the fixed frame: {acc0:.3f} ({len(res0)} items)")
    recertkit(["keygen", "--private", P("release.key"), "--public", P("release.pub")])
    recertkit(["inventory", *c0.values(), "--out", P("inventory_v0.txt")])
    json.dump(toy.CLAIM, open(P("claim.json"), "w"), indent=1)
    recertkit(["root-issue", "--claim", P("claim.json"), "--role", f"server={c0['system.py']}", "--role", f"model={c0['model.json']}", "--role", f"frame={c0['frame.jsonl']}",
               "--inventory", P("inventory_v0.txt"),
               "--basis", "illustrative attestation for the quick start; in practice the root is produced by a certification procedure",
               "--key", P("release.key"), "--key-id", "release", "--out", P("root.json")])

    step("2. The change: kernel.py is replaced by a table-lookup implementation (C1)")
    c1 = toy.write_config(P("config_v1"), "lut")
    recertkit(["inventory", *c1.values(), "--out", P("inventory_v1.txt")])
    t = toy.enumerate_block(c1["kernel.py"], c0["kernel.py"], P("enumeration_v1.json"))
    print(f"new kernel compared with the PARENT's kernel on {t['enumerated']} operand pairs: {t['mismatches']} mismatches")
    json.dump(toy.spec_for(P("enumeration_v1.json"), "kernel.py: arithmetic -> table lookup"), open(P("spec_v1.json"), "w"), indent=1)

    step("3. Issue the derived certificate (the declaration is checked against the profile BEFORE anything is signed)")
    assert issue("root.json", "spec_v1.json", "inventory_v0.txt", "inventory_v1.txt", "derived_v1.json") == 0

    step("4. A second change (C2): compared with the same reference kernel, which link 1 tied to C1's kernel")
    c2 = toy.write_config(P("config_v2"), "sel")
    recertkit(["inventory", *c2.values(), "--out", P("inventory_v2.txt")])
    toy.enumerate_block(c2["kernel.py"], c0["kernel.py"], P("enumeration_v2.json"))
    json.dump(toy.spec_for(P("enumeration_v2.json"), "kernel.py: table lookup -> compare/select", reference="parent_link"), open(P("spec_v2.json"), "w"), indent=1)
    assert issue("derived_v1.json", "spec_v2.json", "inventory_v1.txt", "inventory_v2.txt", "derived_v2.json") == 0

    step("5. The release gate: a relying party verifies the whole chain with the public key and ITS acceptance policy")
    rc = recertkit(["verify-chain", "--root", P("root.json"), "--links", P("derived_v1.json"), P("derived_v2.json"), *trust,
                    "--policy", os.path.join(HERE, "policy.json"), "--json-report", P("chain_report.json")])
    assert rc == 0
    same = toy.evaluate(P("config_v2")) == res0
    print(f"(observation, not evidence: C2 reproduces C0's {len(res0)} predictions: {same})")

    step("6. A change that is NOT equivalent: truncation instead of rounding — issuance is refused")
    c3 = toy.write_config(P("config_v3"), "trunc")
    recertkit(["inventory", *c3.values(), "--out", P("inventory_v3.txt")])
    t = toy.enumerate_block(c3["kernel.py"], c2["kernel.py"], P("enumeration_v3.json"))
    print(f"block enumeration: {t['mismatches']} mismatches; first: {t['first_mismatch']}")
    json.dump(toy.spec_for(P("enumeration_v3.json"), "kernel.py: rounding -> truncation"), open(P("spec_v3.json"), "w"), indent=1)
    assert issue("derived_v2.json", "spec_v3.json", "inventory_v2.txt", "inventory_v3.txt", "derived_v3.json") == 1 and not os.path.exists(P("derived_v3.json"))
    res3 = toy.evaluate(P("config_v3")); div = sum(a["pred"] != b["pred"] for a, b in zip(res0, res3))
    print(f"(observation: on this frame C3 changes {div} of {len(res0)} predictions, although the block differs on {t['mismatches']} of its inputs. "
          "Agreement on a frame does not show that the block is equivalent; nor does this refusal show that C3's quality on the frame is worse. "
          "Block equivalence — together with the boundary and residual-path conditions — is the conservative requirement this profile adopts for a transfer; "
          "a change that does not meet it is re-evaluated.)")

    step("7. Three declaration mistakes that are refused although every number in the evidence is true")
    # (a) the new kernel is compared with ITSELF: zero mismatches, but the reference is not the parent's kernel
    c4 = toy.write_config(P("config_v4"), "zero")
    recertkit(["inventory", *c4.values(), "--out", P("inventory_v4.txt")])
    t = toy.enumerate_block(c4["kernel.py"], c4["kernel.py"], P("enumeration_v4.json"))
    print(f"(a) a kernel that always returns 0, compared with itself: {t['mismatches']} mismatches")
    json.dump(toy.spec_for(P("enumeration_v4.json"), "kernel.py: constant kernel, self-comparison"), open(P("spec_v4.json"), "w"), indent=1)
    assert issue("derived_v2.json", "spec_v4.json", "inventory_v2.txt", "inventory_v4.txt", "derived_v4.json") == 1
    # (b) an equivalent kernel AND a changed system.py, with evidence for the kernel only
    c5 = toy.write_config(P("config_v5"), "ref")
    src = open(c5["system.py"]).read(); marker = "return max(range(len(scores)), key=lambda c: (scores[c], -c))"; assert marker in src
    open(c5["system.py"], "w").write(src.replace(marker, "return 0"))
    recertkit(["inventory", *c5.values(), "--out", P("inventory_v5.txt")])
    t = toy.enumerate_block(c5["kernel.py"], c2["kernel.py"], P("enumeration_v5.json"))
    print(f"(b) an equivalent kernel ({t['mismatches']} mismatches) shipped together with a modified system.py that has no evidence")
    spec = toy.spec_for(P("enumeration_v5.json"), "kernel.py and system.py changed; evidence for the kernel only")
    spec["block"] = {"changed": ["kernel.py", "system.py"], "unchanged": ["model.json", "frame.jsonl"]}
    json.dump(spec, open(P("spec_v5.json"), "w"), indent=1)
    assert issue("derived_v2.json", "spec_v5.json", "inventory_v2.txt", "inventory_v5.txt", "derived_v5.json") == 1
    # (c) the same change, with system.py merely NAMED among the parent artifacts the kernel comparison "replaces"
    print("\n(c) the same change; system.py is now listed among the parent artifacts the kernel comparison replaces — naming the parent's file "
          "does not cover the new system.py of the derived configuration")
    spec["equivalence"][0]["replaces"] = ["kernel.py", "system.py"]
    json.dump(spec, open(P("spec_v5c.json"), "w"), indent=1)
    assert issue("derived_v2.json", "spec_v5c.json", "inventory_v2.txt", "inventory_v5.txt", "derived_v5.json") == 1
    res5 = toy.evaluate(P("config_v5"))
    print(f"(observation: C5 changes {sum(a['pred'] != b['pred'] for a, b in zip(res0, res5))} of {len(res0)} predictions; accuracy {acc0:.3f} -> {sum(r['correct'] for r in res5) / len(res5):.3f})")
    print(f"\nquick start finished; files are in {work}")


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else "quickstart_out")
