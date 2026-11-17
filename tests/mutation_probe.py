"""Check-disabling probe.

For every record and policy check pattern in the catalogue (``recertkit.checks``), force all checks matching that pattern to pass
and re-run the whole test suite.  A pattern is EXERCISED if at least one test then fails, i.e. the suite contains a
certificate or spec whose rejection the tests attribute to that check.  A pattern that is not exercised is a check the
test suite would not miss if it were deleted.

    python tests/mutation_probe.py [out.json] [parallel jobs, default 4] [comma-separated patterns to probe, default all]
"""
import json, os, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))


def main(out="mutation_probe.json", jobs=4, only=None):
    jobs = int(jobs)
    from recertkit.checks import CHECKS, POLICY_CHECKS
    patterns = [p for _, rows in CHECKS for p, _ in rows] + [p for p, _ in POLICY_CHECKS]
    if only: patterns = [p for p in patterns if p in only.split(",")]
    base = subprocess.run([sys.executable, "-m", "pytest", "-q", "--no-header", "-p", "no:cacheprovider", "--tb=no", HERE], capture_output=True, text=True)
    assert base.returncode == 0, "the unmodified suite must pass:\n" + base.stdout[-2000:]
    def one(pat):
        env = dict(os.environ, RECERTKIT_FORCE_OK=pat)
        p = subprocess.run([sys.executable, "-m", "pytest", "-q", "--no-header", "-p", "no:cacheprovider", "-rf", "--tb=no", HERE], env=env, capture_output=True, text=True)
        failed = sorted(l.split(" ")[1].split("::", 1)[1] for l in p.stdout.splitlines() if l.startswith("FAILED "))
        print(f"{'exercised    ' if p.returncode != 0 else 'NOT exercised'}  {pat:44s} {len(failed)} test(s)", flush=True)
        return pat, {"exercised": p.returncode != 0, "tests_failing_when_disabled": failed}
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=jobs) as ex: res = dict(ex.map(one, patterns))
    summary = {"baseline": base.stdout.strip().splitlines()[-1], "check_patterns": len(patterns), "exercised": sum(v["exercised"] for v in res.values()),
               "not_exercised": sorted(k for k, v in res.items() if not v["exercised"]), "per_pattern": res}
    json.dump(summary, open(out, "w"), indent=1)
    print(json.dumps({k: summary[k] for k in ("baseline", "check_patterns", "exercised", "not_exercised")}))


if __name__ == "__main__":
    main(*sys.argv[1:4])
