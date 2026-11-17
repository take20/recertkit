"""The risk budget is preserved EXACTLY, for decimals of any length and under any Decimal context
(review of the third draft, finding V2-1: ``delta_parent + alpha == delta_derived`` was evaluated in Decimal arithmetic,
which rounds to 28 significant digits, so an exact copy of a 30-digit risk level was refused and a rounded copy accepted)."""
import decimal, json, os, random
from fractions import Fraction
import pytest
import toy
from recertkit.cli import main as cli
from recertkit.canon import dec, load_json
from recertkit.engine import _risk_checks
from recertkit.report import Report

LONG = "0.050000000000000000000000000001"            # 30 significant digits: more than the default context holds
ROUNDED = "0.05000000000000000000000000000"          # what Decimal(LONG) + 0 gives in the default context
QS_POLICY = ["--policy", os.path.join(os.path.dirname(toy.__file__), "policy.json")]


def _root(chain, risk):
    """Re-issue the root of the toy chain with another risk level; returns the claim."""
    claim = dict(toy.CLAIM, risk_level=risk); json.dump(claim, open(chain.P("claim.json"), "w"))
    c = lambda f: chain.P("config_v0", f)
    os.remove(chain.P("root.json"))
    assert cli(["root-issue", "--claim", chain.P("claim.json"), "--role", f"server={c('system.py')}", "--role", f"model={c('model.json')}", "--role", f"frame={c('frame.jsonl')}",
                "--inventory", chain.P("inventory_v0.txt"), "--basis", "test root", "--key", chain.P("release.key"), "--key-id", "release", "--out", chain.P("root.json")]) == 0
    return claim


def _spec(chain, v, claim, derived, parent=None):
    spec = load_json(chain.P(f"spec_{v}.json")); spec["claim"] = claim
    spec["risk_budget"] = {"delta_parent": parent or claim["risk_level"], "alpha": "0", "delta_derived": derived}
    json.dump(spec, open(chain.P(f"spec_{v}.json"), "w")); return spec


def _issue(chain, v, parent="root.json", pinv="inventory_v0.txt"):
    out = f"derived_{v}.json"
    if os.path.exists(chain.P(out)): os.remove(chain.P(out))
    return chain.issue(parent, pinv, f"inventory_{v}.txt", f"spec_{v}.json", out)


def test_exact_copy_of_a_long_decimal_is_accepted_and_the_chain_continues(chain):
    claim = _root(chain, LONG)
    _spec(chain, "v1", claim, LONG); assert _issue(chain, "v1")[0] == 0
    _spec(chain, "v2", claim, LONG); assert _issue(chain, "v2", "derived_v1.json", "inventory_v1.txt")[0] == 0
    rc, rep = chain.verify_chain(extra=QS_POLICY)
    assert rc == 0 and rep["record_valid"] and rep["policy_verdict"] == "ACCEPTED"
    assert [load_json(chain.P(f))["risk_budget"]["delta_derived"] for f in ("derived_v1.json", "derived_v2.json")] == [LONG, LONG]


def test_rounded_copy_of_a_long_decimal_is_refused_and_rejected_when_force_signed(chain):
    assert decimal.Decimal(LONG) + 0 == decimal.Decimal(ROUNDED) and decimal.Decimal(LONG) != decimal.Decimal(ROUNDED)    # the arithmetic trap itself
    claim = _root(chain, LONG)
    spec = _spec(chain, "v1", claim, ROUNDED)
    rc, rep = _issue(chain, "v1")
    assert rc == 1 and rep["failed_checks"] == ["risk.composition"] and not os.path.exists(chain.P("derived_v1.json"))
    chain.forge("root.json", "inventory_v0.txt", "inventory_v1.txt", spec, "derived_v1.json")
    rc, rep = chain.verify_chain(links=("derived_v1.json",), extra=QS_POLICY)
    assert rc == 1 and rep["failed_checks"] == ["risk.composition"] and rep["policy_verdict"] == "REJECTED"


@pytest.mark.parametrize("prec", [1, 5, 28, 60])
def test_verdicts_do_not_depend_on_the_decimal_context(chain, prec):
    claim = _root(chain, LONG)
    with decimal.localcontext() as ctx:
        ctx.prec = prec
        _spec(chain, "v1", claim, LONG); assert _issue(chain, "v1")[0] == 0
        assert chain.verify_chain(links=("derived_v1.json",), extra=QS_POLICY)[0] == 0
        _spec(chain, "v1", claim, ROUNDED); assert _issue(chain, "v1")[1]["failed_checks"] == ["risk.composition"]


def test_numerically_equal_spellings_are_the_same_budget_and_the_chain_continues(chain):
    """"0.05" and "0.050000" denote one number.  The claim is carried as text (claim.invariance); the budget is compared as a value."""
    claim = dict(toy.CLAIM)                                                      # risk_level "0.050000"
    _spec(chain, "v1", claim, "0.05", parent="0.0500"); assert _issue(chain, "v1")[0] == 0
    _spec(chain, "v2", claim, "0.050000"); assert _issue(chain, "v2", "derived_v1.json", "inventory_v1.txt")[0] == 0
    assert chain.verify_chain(extra=QS_POLICY)[0] == 0


@pytest.mark.parametrize("text", ["5E-2", "5e-2", "+0.05", " 0.05", "0.05 ", "0.05\n", "0_0.05", ".05", "0.", "٠.٠٥", "0,05", "0x1p-4", "NaN", "Infinity", ""])
def test_only_plain_decimal_notation_is_a_decimal(chain, text):
    assert dec(text) is None
    chain.mutate("derived_v1.json", lambda c: c["risk_budget"].update({"delta_derived": text}))
    rc, rep = chain.verify()
    assert rc == 1 and rep["failed_checks"] == ["risk.decimals"]


@pytest.mark.parametrize("text", ["5E-2", " 0.05", "0_0.05", "٠.٠٥"])
def test_a_claim_field_in_another_notation_violates_the_profile(chain, text):
    chain.mutate("derived_v1.json", lambda c: c["claim"].update({"risk_level": text}))
    rc, rep = chain.verify()
    assert rc == 1 and "claim.constraints" in rep["failed_checks"]


def _digits(rng, n):
    return "".join(rng.choice("0123456789") for _ in range(n))


def _near(rng, s):
    """A decimal string close to ``s``: the same value spelled differently, or a value differing far to the right."""
    k = rng.randrange(5)
    if k == 0: return s + "0" * rng.randrange(1, 40)                                   # same value
    if k == 1: return s.rstrip("0") if "." in s and not s.endswith(".") and s.rstrip("0")[-1] != "." else s
    if k == 2: return s + "0" * rng.randrange(0, 40) + "1"                             # differs beyond the last digit
    if k == 3: return s[:-1] + str((int(s[-1]) + 1) % 10)                              # last digit changed
    return str(decimal.Context(prec=rng.choice([5, 28, 34])).create_decimal(s))        # what context arithmetic would produce


def _frac(s):
    return Fraction(s)                                                                  # exact rational value of a plain decimal string


def test_risk_checks_agree_with_exact_rational_arithmetic_on_random_long_decimals():
    """4,000 seeded cases, most with more digits than the default Decimal context holds; oracle: ``fractions.Fraction``."""
    rng = random.Random(20261116); disagreements = []; seen = collections_counter()
    class PV:                                                                           # the parent, as the engine sees it
        risk = None
    profile = {"risk_field": "risk_level"}
    for i in range(4000):
        p = "0." + _digits(rng, rng.choice([2, 6, 27, 28, 29, 30, 45, 80]))
        if _frac(p) == 0: p += "1"
        dp, dd, cl = (rng.choice([p, _near(rng, p)]) for _ in range(3))
        a = rng.choice(["0", "0", "0", "0.0", "0.000000", "0." + "0" * 40 + "1", "-0." + "0" * 30 + "1", "0.01"])
        if "E" in dp + dd + cl: continue                                                # context rounding may give exponent notation: not a plain decimal, tested above
        PV.risk = p
        R = Report(quiet=True)
        _risk_checks(R, {"risk_budget": {"alpha": a, "delta_parent": dp, "delta_derived": dd}, "claim": {"risk_level": cl}}, PV, profile)
        got = {r["check"]: r["ok"] for r in R.records}
        want = {"risk.decimals": True, "risk.alpha_zero": _frac(a) == 0, "risk.composition": 0 < _frac(dp) < 1 and _frac(dd) == _frac(dp),
                "risk.parent": _frac(p) == _frac(dp), "risk.claim": _frac(cl) == _frac(dp)}
        seen[tuple(sorted(k for k, v in want.items() if not v))] += 1
        if got != want: disagreements.append((p, dp, dd, cl, a, got, want))
    assert not disagreements, disagreements[:3]
    assert seen[()] > 100 and seen[("risk.composition",)] > 100 and len(seen) >= 8                                     # the sample contains accepted and refused cases of several kinds


def collections_counter():
    import collections
    return collections.Counter()
