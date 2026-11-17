"""Build the gate-root example: a root certificate issued by the anytime-valid release gate, then a derived link.

    python examples/gate_root/make_example.py --gate /path/to/gate/cert/certify.py --keys /private/dir [--out examples/gate_root]

The release gate (``certify.py``) is a separate tool, described in the release-gate paper cited in the README; it is
NOT distributed with RecertKit.  This script documents, step by step, how a gate certificate becomes a RecertKit root,
and regenerates the stored example when the gate is available.  Without the gate, the stored files in this directory
can still be verified (see README.md).

What happens
------------
1. Two toy systems are written: a REFERENCE (the quick-start model) and the CANDIDATE C0, whose weights are stored
   one bit coarser (rounded to even values) — a stand-in for a quantised model.  Both are evaluated on the 200-item
   frame; the paired outcomes d = correct(reference) - correct(candidate) are the gate's evidence.  The toy data were
   chosen so that the gate certifies; a first variant (fixed-point against exact products) was correctly NOT
   certified by the gate (mean d = +0.12) and is mentioned in README.md.
2. The candidate configuration given to the gate carries two extension fields next to the fields the gate requires:
   ``server_binary_sha256`` (digest of system.py) and ``configuration_inventory_sha256`` (digest of the inventory of
   C0).  The gate commits to the whole configuration object, so both become part of what the root certifies.
3. ``certify.py commit --tasks frame.jsonl`` binds the SHA-256 of the frame FILE (content, not only identifiers).
4. ``certify.py issue`` runs the sequential test on the records and signs the root; ``certify.py verify`` checks it.
5. RecertKit: C0's kernel is replaced by the table-lookup kernel; a derived certificate is issued and the chain
   verified with an acceptance policy.
"""
import argparse, hashlib, importlib.util, json, os, shutil, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "quickstart"))
import toy
from recertkit.cli import main as recertkit

sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--gate", required=True); ap.add_argument("--keys", required=True); ap.add_argument("--out", default=HERE)
    a = ap.parse_args(); out = os.path.abspath(a.out); gate = os.path.abspath(a.gate); os.makedirs(a.keys, exist_ok=True)
    P = lambda *x: os.path.join(out, *x)
    key, pub = os.path.join(a.keys, "gate_example.key"), P("gate_example.pub")
    if not os.path.exists(key): recertkit(["keygen", "--private", key, "--public", pub])
    run_gate = lambda *args: subprocess.run([sys.executable, gate, *args], cwd=out, check=True, capture_output=True, text=True).stdout

    # 1. systems and paired outcomes
    ref = toy.write_config(P("config_reference"), "ref")
    c0 = toy.write_config(P("config_c0"), "ref")
    w = json.load(open(ref["model.json"]))["weights"]
    json.dump({"weights": [[2 * round(x / 2) for x in row] for row in w]}, open(c0["model.json"], "w"))
    r_ref, r_c0 = toy.evaluate(P("config_reference")), toy.evaluate(P("config_c0"))
    d = {x["item_id"]: x["correct"] - y["correct"] for x, y in zip(r_ref, r_c0)}
    recertkit(["inventory", *c0.values(), "--out", P("inventory_c0.txt")])

    # 2. configurations for the gate
    common = {"engine": "toy-integer-classifier", "engine_commit": "n/a", "backend": "python", "hardware_id": "any", "artifact_filename": "model.json"}
    cand = {"configuration_id": "toy-c0-coarse-weights", **common, "artifact_sha256": sha(c0["model.json"]), "server_binary_sha256": sha(c0["system.py"]),
            "configuration_inventory_sha256": sha(P("inventory_c0.txt"))}
    refc = {"configuration_id": "toy-reference", **common, "artifact_sha256": sha(ref["model.json"])}
    json.dump(cand, open(P("gate_candidate.json"), "w"), indent=1); json.dump(refc, open(P("gate_reference.json"), "w"), indent=1)
    json.dump({"reference": {"configuration_id": refc["configuration_id"]}, "count": 1,
               "candidates": [{"configuration_id": cand["configuration_id"], "artifact": "model.json", "artifact_sha256": cand["artifact_sha256"]}]}, open(P("gate_candidates.json"), "w"), indent=1)
    json.dump({"item_ids": sorted(d)}, open(P("gate_frame.json"), "w"))
    shutil.copy(c0["frame.jsonl"], P("frame.jsonl"))

    # 3. commit BEFORE the records are ordered: the frame file's digest is bound through --tasks
    log = run_gate("commit", "--frame", "gate_frame.json", "--dataset-revision", "toy-frame-seed7", "--order-seed", "20261116", "--regime", "r2",
                   "--candidates", "gate_candidates.json", "--tasks", "frame.jsonl", "--eps", "0.05", "--delta", "0.05", "--budget", "200",
                   "--ref-config", "gate_reference.json", "--cand-configs", "gate_candidate.json", "--parser-hash", sha(c0["system.py"]),
                   "--key", key, "--key-id", "gate-example", "--out", "gate_commitment.json")
    spec = importlib.util.spec_from_file_location("gate_tool", gate); g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
    order = g.committed_order(json.load(open(P("gate_commitment.json"))), None)
    with open(P("gate_records.jsonl"), "w") as f:
        for i in order: f.write(json.dumps({"item_id": i, "d": d[i]}) + "\n")

    # 4. issue and verify the root with the gate's own tools
    log += run_gate("issue", "--commitment", "gate_commitment.json", "--records", "gate_records.jsonl", "--records-uri", "gate_records.jsonl",
                    "--ref-config", "gate_reference.json", "--cand-config", "gate_candidate.json", "--pubkey", "gate_example.pub", "--key", key, "--key-id", "gate-example", "--out", "gate_root_certificate.json")
    log += run_gate("verify", "--certificate", "gate_root_certificate.json", "--commitment", "gate_commitment.json", "--records", "gate_records.jsonl", "--pubkey", "gate_example.pub")
    open(P("gate_tool_output.log"), "w").write(log)

    # 5. the derived link
    c1 = toy.write_config(P("config_c1"), "lut"); shutil.copy(c0["model.json"], c1["model.json"])
    recertkit(["inventory", *c1.values(), "--out", P("inventory_c1.txt")])
    toy.enumerate_block(c1["kernel.py"], c0["kernel.py"], P("enumeration_c1.json"))
    s = toy.spec_for(P("enumeration_c1.json"), "kernel.py: arithmetic -> table lookup")
    s["root_binding"]["commitment_file"] = "gate_commitment.json"
    s["evidence_files"]["frame"] = "frame.jsonl"
    json.dump(s, open(P("spec_c1.json"), "w"), indent=1)
    for f in ("derived_c1.json",):
        if os.path.exists(P(f)): os.remove(P(f))
    trust = ["--trust", f"gate-example={pub}"]
    rc = recertkit(["issue", "--parent", P("gate_root_certificate.json"), "--spec", P("spec_c1.json"), "--parent-inventory", P("inventory_c0.txt"), "--derived-inventory", P("inventory_c1.txt"),
                    "--key", key, "--key-id", "gate-example", "--out", P("derived_c1.json"), *trust])
    assert rc == 0
    rc = recertkit(["verify-chain", "--root", P("gate_root_certificate.json"), "--links", P("derived_c1.json"), *trust, "--policy", P("policy.json"), "--json-report", P("chain_report.json")])
    assert rc == 0
    n = len(d); acc = lambda r: sum(x["correct"] for x in r) / n
    print(f"reference accuracy {acc(r_ref):.3f}, candidate accuracy {acc(r_c0):.3f}, mean d {sum(d.values()) / n:+.4f} on {n} items")


if __name__ == "__main__":
    main()
