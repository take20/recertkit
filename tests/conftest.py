# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
import json, os, shutil, sys
import pytest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "examples", "quickstart"))
import toy
from recertkit.cli import main as cli
from recertkit.canon import load_json
from recertkit.signing import sign


def build_chain(work):
    """root (binds the inventory) -> derived_v1 (lut, reference = parent artifact) -> derived_v2 (sel, reference = parent link)."""
    P = lambda *a: os.path.join(work, *a)
    cfg = {v: toy.write_config(P(f"config_{v}"), k) for v, k in (("v0", "ref"), ("v1", "lut"), ("v2", "sel"), ("v3", "trunc"), ("v4", "zero"))}
    assert cli(["keygen", "--private", P("release.key"), "--public", P("release.pub")]) == 0
    json.dump(toy.CLAIM, open(P("claim.json"), "w"))
    for v in cfg: assert cli(["inventory", *cfg[v].values(), "--out", P(f"inventory_{v}.txt")]) == 0
    assert cli(["root-issue", "--claim", P("claim.json"), "--role", f"server={cfg['v0']['system.py']}", "--role", f"model={cfg['v0']['model.json']}",
                "--role", f"frame={cfg['v0']['frame.jsonl']}", "--inventory", P("inventory_v0.txt"), "--basis", "test root",
                "--key", P("release.key"), "--key-id", "release", "--out", P("root.json")]) == 0
    for v in cfg:   # every kernel compared with the ORIGINAL kernel of C0
        toy.enumerate_block(cfg[v]["kernel.py"], cfg["v0"]["kernel.py"], P(f"enumeration_{v}.json"))
        json.dump(toy.spec_for(P(f"enumeration_{v}.json"), f"kernel -> {v}", reference="parent_artifact" if v == "v1" else "parent_link"), open(P(f"spec_{v}.json"), "w"))
    for parent, pinv, v in (("root.json", "v0", "v1"), ("derived_v1.json", "v1", "v2")):
        assert cli(["issue", "--parent", P(parent), "--spec", P(f"spec_{v}.json"), "--parent-inventory", P(f"inventory_{pinv}.txt"),
                    "--derived-inventory", P(f"inventory_{v}.txt"), "--key", P("release.key"), "--key-id", "release", "--out", P(f"derived_{v}.json"),
                    "--trust", f"release={P('release.pub')}"]) == 0
    return work


@pytest.fixture(scope="session")
def chain_master(tmp_path_factory):
    return build_chain(str(tmp_path_factory.mktemp("chain")))


@pytest.fixture
def chain(chain_master, tmp_path):
    """A private copy of the toy chain; ``chain.P(name)`` gives paths, ``chain.verify(...)`` runs the CLI."""
    work = str(tmp_path / "w"); shutil.copytree(chain_master, work)

    class C:
        dir = work
        @staticmethod
        def P(*a): return os.path.join(work, *a)
        @staticmethod
        def trust(): return ["--trust", f"release={os.path.join(work, 'release.pub')}"]
        @staticmethod
        def verify(cert="derived_v1.json", parent="root.json", extra=()):
            rep = os.path.join(work, "report.json")
            rc = cli(["verify", "--certificate", os.path.join(work, cert), "--parent", os.path.join(work, parent), *C.trust(), "--json-report", rep, *extra])
            return rc, load_json(rep)
        @staticmethod
        def verify_chain(links=("derived_v1.json", "derived_v2.json"), extra=()):
            rep = os.path.join(work, "report.json")
            rc = cli(["verify-chain", "--root", os.path.join(work, "root.json"), "--links", *[os.path.join(work, l) for l in links], *C.trust(), "--json-report", rep, *extra])
            return rc, load_json(rep)
        @staticmethod
        def mutate(cert, fn, resign=True):
            """Edit a certificate in place; by default re-sign it with the (trusted) issuer key — an issuer-side error or a malicious issuer."""
            c = load_json(os.path.join(work, cert)); fn(c)
            if resign: c = sign(c, os.path.join(work, "release.key"), "release")
            json.dump(c, open(os.path.join(work, cert), "w"), indent=1)
        @staticmethod
        def forge(parent, pinv, dinv, spec, out):
            """Sign a certificate WITHOUT applying the profile checks — what a careless or malicious holder of the trusted key could do."""
            from recertkit.engine import build_certificate
            from recertkit.profiles import load_profile
            c = build_certificate(os.path.join(work, parent), spec if isinstance(spec, dict) else load_json(os.path.join(work, spec)),
                                  os.path.join(work, pinv), os.path.join(work, dinv), load_profile(None), spec_dir=work)
            json.dump(sign(c, os.path.join(work, "release.key"), "release"), open(os.path.join(work, out), "w"), indent=1)
        @staticmethod
        def issue(parent, pinv, dinv, spec, out, extra=()):
            rep = os.path.join(work, "issue_report.json")
            rc = cli(["issue", "--parent", os.path.join(work, parent), "--spec", os.path.join(work, spec), "--parent-inventory", os.path.join(work, pinv),
                      "--derived-inventory", os.path.join(work, dinv), "--key", os.path.join(work, "release.key"), "--key-id", "release", "--out", os.path.join(work, out), "--json-report", rep, *extra])
            return rc, load_json(rep)
    return C


# --- check-disabling probe (tests/mutation_probe.py): force every check matching one catalogue pattern to pass ---
_FORCE = os.environ.get("RECERTKIT_FORCE_OK")
if _FORCE:
    import fnmatch
    from recertkit.report import Report
    _pat = _FORCE.replace("[*]", "[[]*[]]")
    _orig_check = Report.check
    def _forced(self, check, ok, detail=""):
        return _orig_check(self, check, True if fnmatch.fnmatchcase(check, _pat) else ok, detail)
    Report.check = _forced
    _orig_policy = Report.policy
    def _forced_policy(self, check, ok, detail=""):
        return _orig_policy(self, check, True if fnmatch.fnmatchcase(check, _pat) else ok, detail)
    Report.policy = _forced_policy
