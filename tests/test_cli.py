# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
import os
from recertkit.cli import main as cli
from recertkit.checks import CHECKS, documented, markdown


def test_missing_input_is_a_usage_error_not_a_traceback(tmp_path, capsys):
    rc = cli(["verify", "--certificate", str(tmp_path / "nope.json"), "--parent", str(tmp_path / "nope2.json"), "--trust", str(tmp_path / "k.pub")])
    assert rc == 2 and "error" in capsys.readouterr().err


def test_profile_and_checks_commands(capsys):
    assert cli(["profile"]) == 0 and "recertkit-default-1" in capsys.readouterr().out
    assert cli(["checks"]) == 0 and "risk.alpha_zero" in capsys.readouterr().out


def test_every_check_on_the_toy_chain_is_documented(chain):
    rc, rep = chain.verify_chain()
    assert rc == 0 and all(documented(r["check"]) for r in rep["checks"]), [r["check"] for r in rep["checks"] if not documented(r["check"])]


def test_checks_doc_is_current():
    doc = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "checks.md")
    assert open(doc, encoding="utf-8").read().strip() == markdown().strip()
