# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
"""Check results.

Two kinds of result are kept apart:

* RECORD checks decide whether the certificate chain is internally consistent under the profile (``record_ok``);
* POLICY checks decide whether a relying party's acceptance policy admits the conditions the chain rests on.  They
  exist only when a policy is supplied.  A policy check has three outcomes: satisfied, violated, or NOT EVALUATED
  (the information it needs was not verified in this run).  A policy is ACCEPTED only when every one of its checks
  was evaluated and satisfied; a check that could not be evaluated is never counted as satisfied.

Everything the verifier does not check is recorded as a notice, with a kind and the text of the unchecked statement.
"""
from __future__ import annotations
import json, sys


class Report:
    def __init__(self, stream=None, quiet=False, require_all_evidence=False):
        self.records, self.policy_records, self.notices, self.links = [], [], [], []
        self.require_all_evidence = require_all_evidence
        self.policy_name = None
        self.stream, self.quiet = stream or sys.stdout, quiet

    @property
    def ok(self) -> bool:
        """Record validity: every record check passed."""
        return all(r["ok"] for r in self.records)

    @property
    def policy_verdict(self):
        """None without a policy; otherwise "ACCEPTED", "REJECTED" or "NOT EVALUATED"."""
        if self.policy_name is None: return None
        if not self.ok or any(r["ok"] is False for r in self.policy_records): return "REJECTED"
        if not self.policy_records or any(r["ok"] is None for r in self.policy_records): return "NOT EVALUATED"
        return "ACCEPTED"                                     # at least one policy check, and every one evaluated and satisfied

    @property
    def accepted(self) -> bool:
        """Exit status 0: the record is valid and, when a policy was given, the policy ACCEPTED it."""
        return self.ok and self.policy_verdict in (None, "ACCEPTED")

    @property
    def fails(self) -> list[str]:
        return [r["check"] for r in self.records if not r["ok"]]

    @property
    def policy_fails(self) -> list[str]:
        return [r["check"] for r in self.policy_records if r["ok"] is False]

    @property
    def policy_not_evaluated(self) -> list[str]:
        return [r["check"] for r in self.policy_records if r["ok"] is None]

    def _out(self, text):
        if not self.quiet: print(text, file=self.stream)

    def section(self, title):
        self._out(f"== {title} ==")

    def check(self, check: str, ok, detail: str = "") -> bool:
        ok = bool(ok)
        self.records.append({"check": check, "ok": ok, "detail": detail})
        self._out(f"[{'OK' if ok else 'FAIL'}] {check}" + (f" — {detail}" if detail else ""))
        return ok

    def policy(self, check: str, ok, detail: str = ""):
        """``ok`` is True (satisfied), False (violated) or None (could not be evaluated in this run)."""
        ok = None if ok is None else bool(ok)
        self.policy_records.append({"check": check, "ok": ok, "detail": detail})
        tag = "POLICY NOT EVALUATED" if ok is None else ("POLICY OK" if ok else "POLICY FAIL")
        self._out(f"[{tag}] {check}" + (f" — {detail}" if detail else ""))
        return ok

    def notice(self, kind: str, text: str):
        """Something the verifier does NOT check and therefore prints (assumptions, judgements, boundaries)."""
        self.notices.append({"kind": kind, "text": text})
        self._out(f"[..] {kind}: {text}")

    def as_dict(self, **extra) -> dict:
        return {"record_valid": self.ok, "valid": self.ok, "failed_checks": self.fails, "checks": self.records,
                "not_checked": self.notices, "links": self.links,
                "policy": {"name": self.policy_name, "verdict": self.policy_verdict,
                           "accepted": None if self.policy_name is None else self.policy_verdict == "ACCEPTED",
                           "failed_checks": self.policy_fails, "not_evaluated": self.policy_not_evaluated, "checks": self.policy_records},
                "accepted": self.accepted, **extra}

    def dump(self, path: str, **extra):
        with open(path, "w", encoding="utf-8") as f: json.dump(self.as_dict(**extra), f, indent=1)
