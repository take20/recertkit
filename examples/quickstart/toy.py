# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
"""A hardware-free toy deployment used by the quick-start and by the test suite.

The "deployed system" is a tiny integer classifier.  One file, ``kernel.py``, is the replaceable block: a fixed-point
multiply ``q(a, b) = clamp((a*b + 8) >> 4, -128, 127)`` on signed 8-bit operands.  Everything else (``system.py``,
``model.json``, ``frame.jsonl``) is the residual path.  Three kernels are provided:

``ref``    the reference implementation (arithmetic)
``lut``    the same function through a precomputed 65,536-entry table       -> equivalent
``sel``    the same function with comparisons instead of min/max            -> equivalent
``trunc``  truncation instead of rounding (``(a*b) >> 4``)                   -> NOT equivalent
``zero``   always returns 0                                                  -> NOT equivalent (used by the tests)
``split``  the same function, with its two constants read from a second file,
           ``kernel_params.json`` — a block that consists of TWO artifacts       -> equivalent

The block's whole input domain is 256 x 256 = 65,536 operand pairs, so equivalence can be ENUMERATED.
"""
from __future__ import annotations
import hashlib, importlib.util, json, os, random

KERNELS = {
"ref": """def q(a, b):
    return max(-128, min(127, (a * b + 8) >> 4))
""",
"lut": """_T = [max(-128, min(127, (a * b + 8) >> 4)) for a in range(-128, 128) for b in range(-128, 128)]
def q(a, b):
    return _T[(a + 128) * 256 + (b + 128)]
""",
"sel": """def q(a, b):
    v = (a * b + 8) >> 4
    if v > 127: return 127
    if v < -128: return -128
    return v
""",
"trunc": """def q(a, b):
    return max(-128, min(127, (a * b) >> 4))
""",
"zero": """def q(a, b):
    return 0
""",
"split": """import json, os
_p = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "kernel_params.json")))
def q(a, b):
    return max(-128, min(127, (a * b + _p["round"]) >> _p["shift"]))
""",
}
KERNEL_PARAMS = {"round": 8, "shift": 4}

SYSTEM = """import importlib.util, json, os
_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("kernel", os.path.join(_here, "kernel.py"))
_k = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_k)
_W = json.load(open(os.path.join(_here, "model.json")))["weights"]
def predict(features):
    scores = [sum(_k.q(x, w) for x, w in zip(features, row)) for row in _W]
    return max(range(len(scores)), key=lambda c: (scores[c], -c))
def run(frame_path):
    out = []
    for line in open(frame_path):
        if line.strip():
            it = json.loads(line); p = predict(it["features"])
            out.append({"item_id": it["item_id"], "pred": p, "correct": int(p == it["label"])})
    return out
"""


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path); mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def write_config(directory: str, kernel: str, seed: int = 7, n_items: int = 200) -> dict:
    """Write one deployed configuration (system.py, kernel.py, model.json, frame.jsonl); returns the file paths."""
    os.makedirs(directory, exist_ok=True)
    rng = random.Random(seed)
    weights = [[rng.randint(-100, 100) for _ in range(16)] for _ in range(3)]
    teacher = [[w + rng.randint(-25, 25) for w in row] for row in weights]
    paths = {n: os.path.join(directory, n) for n in ("system.py", "kernel.py", "model.json", "frame.jsonl")}
    open(paths["system.py"], "w").write(SYSTEM)
    open(paths["kernel.py"], "w").write(KERNELS[kernel])
    if kernel == "split":
        paths["kernel_params.json"] = os.path.join(directory, "kernel_params.json")
        json.dump(KERNEL_PARAMS, open(paths["kernel_params.json"], "w"))
    json.dump({"weights": weights}, open(paths["model.json"], "w"))
    with open(paths["frame.jsonl"], "w") as f:
        for i in range(n_items):
            x = [rng.randint(-128, 127) for _ in range(16)]
            s = [sum(a * b for a, b in zip(x, row)) for row in teacher]
            f.write(json.dumps({"item_id": f"toy_{i:04d}", "features": x, "label": max(range(3), key=lambda c: (s[c], -c))}) + "\n")
    return paths


def evaluate(directory: str) -> list:
    """Run the deployed system of ``directory`` on its frame."""
    return _load(os.path.join(directory, "system.py"), "toy_system_" + hashlib.md5(directory.encode()).hexdigest()).run(os.path.join(directory, "frame.jsonl"))


def enumerate_block(candidate_kernel: str, reference_kernel: str, out: str, subject_files=(), reference_files=()) -> dict:
    """Compare two kernels on EVERY operand pair and write the transcript the certificate will bind.

    ``subject_files`` / ``reference_files`` are further files the candidate / reference kernel consists of (a block of
    several artifacts); the transcript then records the digest of every file of each side."""
    cand, ref = _load(candidate_kernel, "toy_cand"), _load(reference_kernel, "toy_ref")
    n = mism = 0; first = None
    for a in range(-128, 128):
        for b in range(-128, 128):
            n += 1
            if cand.q(a, b) != ref.q(a, b):
                mism += 1
                if first is None: first = {"a": a, "b": b, "candidate": cand.q(a, b), "reference": ref.q(a, b)}
    sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
    t = {"schema": "recertkit-enumeration-1",
         "what": "exhaustive comparison of the block q(a, b) against a reference kernel on the full operand domain",
         "domain": "a, b in [-128, 127] (signed 8-bit), 256 x 256 pairs", "domain_size": 65536,
         "subjects": {os.path.basename(p): sha(p) for p in (candidate_kernel, *subject_files)},
         "reference": {"artifacts": {os.path.basename(p): sha(p) for p in (reference_kernel, *reference_files)}} if reference_files else {"sha256": sha(reference_kernel)},
         "enumerated": n, "mismatches": mism, "first_mismatch": first}
    json.dump(t, open(out, "w"), indent=1)
    return t


CLAIM = {"metric_definition": "exact_match_accuracy", "degradation_direction": "reference_minus_candidate",
         "margin": "0.050000", "risk_level": "0.050000", "sampling_regime": "r2"}


BOUNDARY = ("system.py calls the block only as q(x, w) with x a frame feature and w a model weight, both integers in [-128, 127]; "
            "the enumerated domain therefore covers every input the block can receive, and the block has no state.")


def spec_for(transcript_path: str, change: str, reference: str = "parent_artifact") -> dict:
    """The issuer's declaration for a kernel replacement (see docs/spec.md).

    ``reference`` says what the transcript compared the new kernel against: ``"parent_artifact"`` — the kernel of the
    parent configuration; ``"parent_link"`` — the reference kernel that the parent link's kernel was already shown
    equivalent to (so the comparison need not be repeated against every intermediate kernel).
    """
    ref = {"kind": "parent_artifact", "artifact": "kernel.py"} if reference == "parent_artifact" else {"kind": "parent_link"}
    return {
        "change": {"summary": change},
        "claim_scope": "the parent's claim on the fixed 200-item frame; no claim about other inputs",
        "block": {"changed": ["kernel.py"], "unchanged": ["system.py", "model.json", "frame.jsonl"]},
        "roles": {"server": "system.py", "model": "model.json", "frame": "frame.jsonl"},
        "root_binding": {"roles": {"server": "digest", "model": "digest", "frame": "digest"}, "inventory": "digest"},
        "equivalence": [{"id": "kernel", "method_code": "exhaustive_enumeration", "subjects": ["kernel.py"], "replaces": ["kernel.py"],
                         "reference": ref, "transcript": "enumeration", "domain_size": 65536, "domain": "all signed 8-bit operand pairs (a, b)"}],
        "judgements": {"boundary": BOUNDARY, "residual_path": "system.py, model.json and frame.jsonl are byte-identical (hash identity)."},
        "evidence_files": {"enumeration": os.path.basename(transcript_path)},
        "trust_assumptions": {"interpreter": "the Python interpreter evaluates both kernels as written"},
    }
