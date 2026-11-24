# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
"""The swap search, in full: every declaration of one or two entries, for the swapped kernels and for the control.

    python tests/swap_search.py <out.json> [jobs]            (from the repository root; exit status 1 if an invariant fails)

``tests/test_renamed_replacement.py`` describes the system and the space and runs a shortened version (pairs only among
entries that have no failed check of their own).  This script takes no shortcut: for each of the two systems it signs
all 20,880 declarations — 144 entries, alone or in pairs, with and without the judgement ``replacement_correspondence``
— through the normal ``issue`` path and WITHOUT the issuer-side checks, and verifies each under the reviewer's policy
and under the supplied quick-start policy.  An entry is (claimed subjects, claimed replaced artifacts, transcript);
the 16 transcripts are written by ``toy.enumerate_block``, unmodified, from comparisons that are run.

Invariants (``check_rows`` of the test module):
  * the issuer-side checks and the verifier agree on every declaration;
  * every valid record claims its results for exactly the files its transcripts record;
  * every entry of a valid record that is not name-aligned carries the judgement and prints its notice;
  * swapped kernels: no declaration is valid without the judgement, and none is accepted under either policy;
  * control: under the supplied policy exactly one declaration is accepted — each kernel paired with the parent file of
    its name, each transcript recording that one comparison, no judgement.
"""
import json, os, subprocess, sys, tempfile, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, "..", "examples", "quickstart"))
import test_renamed_replacement as T                                           # noqa: E402


def _shard(i, n, out):
    world = T.World(tempfile.mkdtemp(prefix=f"swapsearch_{i}_"))
    res = {}
    for w in ("swap", "ctrl"):
        rows = [T.evaluate(world, w, entries, j) for k, (entries, j) in enumerate(T.declaration_space()) if k % n == i]
        res[w] = {"declarations": len(rows), "issued": sum(r["issued"] for r in rows), "valid_records": sum(r["record_valid"] for r in rows),
                  "valid_without_judgement": sum(r["record_valid"] and not r["judgement"] for r in rows),
                  "accepted_reviewer_policy": sum(r["accepted_reviewer_policy"] for r in rows), "accepted_supplied_policy": sum(r["accepted_supplied_policy"] for r in rows),
                  "violations": T.check_rows(w, rows), "rows_valid_or_accepted": [r for r in rows if r["record_valid"] or r["issued"] or r["accepted_reviewer_policy"] or r["accepted_supplied_policy"]]}
    json.dump(res, open(out, "w"))


def main(out, jobs=3):
    import recertkit
    t0 = time.time(); work = tempfile.mkdtemp(prefix="swapsearch_"); parts = [os.path.join(work, f"part_{i}.json") for i in range(jobs)]
    procs = [subprocess.Popen([sys.executable, os.path.abspath(__file__), "--shard", str(i), str(jobs), parts[i]], stdout=subprocess.DEVNULL) for i in range(jobs)]
    assert all(p.wait() == 0 for p in procs), "a shard failed"
    res = {"recertkit": recertkit.__version__, "entries": len(T.entry_space()), "space_per_system": T.FULL_SPACE,
           "space": "entries: claimed subjects (3) x claimed replaced artifacts (3) x 16 transcripts of toy.enumerate_block; declarations of 1 or 2 entries; "
                    "with and without the judgement 'replacement_correspondence'"}
    violations = []
    for w in ("swap", "ctrl"):
        P = [json.load(open(p))[w] for p in parts]
        agg = {k: sum(p[k] for p in P) for k in ("declarations", "issued", "valid_records", "valid_without_judgement", "accepted_reviewer_policy", "accepted_supplied_policy")}
        rows = [r for p in P for r in p["rows_valid_or_accepted"]]
        agg["valid_or_accepted_rows"] = sorted(rows, key=lambda r: json.dumps(r, sort_keys=True))
        violations += [f"{w}: {v}" for p in P for v in p["violations"]]
        if agg["declarations"] != T.FULL_SPACE: violations.append(f"{w}: {agg['declarations']} declarations evaluated, expected {T.FULL_SPACE}")
        res["swapped_kernels" if w == "swap" else "control"] = agg
    acc = [(r["entries"], r["judgement"]) for r in res["control"]["valid_or_accepted_rows"] if r["accepted_supplied_policy"]]
    if acc != [(T.IDENTITY_EXACT, False)]: violations.append(f"control: accepted under the supplied policy: {acc}")
    res["violations"] = sorted(set(violations)); res["seconds"] = round(time.time() - t0)
    json.dump(res, open(out, "w"), indent=1)
    for k in ("swapped_kernels", "control"): print(k, {a: b for a, b in res[k].items() if a != "valid_or_accepted_rows"})
    print("violations:", res["violations"] or "none")
    return 1 if res["violations"] else 0


if __name__ == "__main__":
    if sys.argv[1] == "--shard": _shard(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
    else: sys.exit(main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 3))
