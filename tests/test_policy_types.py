# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
"""A policy file that is not a well-formed policy is a configuration error; it never switches a condition off.

Up to 1.3.1 two members were tested by truthiness and ``null`` was taken as "absent", so that for example
``"require_all_evidence": 0`` produced ACCEPTED with no policy check at all.  Every case below must end with exit
status 2 and the word PolicyError, and must not write a report that says ACCEPTED.
"""
import json, os
import pytest
from recertkit import policy as P
from recertkit.cli import main as cli

MALFORMED = [
    ("require_all_evidence", 0), ("require_all_evidence", 1), ("require_all_evidence", ""), ("require_all_evidence", "true"),
    ("require_all_evidence", "false"), ("require_all_evidence", []), ("require_all_evidence", None),
    ("require_prospective", 0), ("require_prospective", "yes"), ("require_prospective", None),
    ("coverage_by_judgement", None), ("coverage_by_judgement", True), ("coverage_by_judgement", [1]), ("coverage_by_judgement", ["a.bit", "a.bit"]),
    ("accepted_judgements", None), ("accepted_judgements", "boundary"), ("accepted_judgements", [1]), ("accepted_judgements", {"boundary": 1}),
    ("accepted_assumptions", None), ("accepted_assumptions", False),
    ("enumeration_domains", None), ("enumeration_domains", []), ("enumeration_domains", {"kernel.py": "65536"}), ("enumeration_domains", {"kernel.py": True}),
    ("enumeration_domains", {"kernel.py": 65536.0}),
    ("reference_kinds", None), ("reference_kinds", "parent_artifact"), ("reference_kinds", [1]), ("reference_kinds", [""]),
    ("binding_levels", "digest"), ("binding_levels", [None]), ("root_adapters", "gate-2.0"), ("root_adapters", [["gate-2.0"]]),
    ("residual_rebuilt", None), ("residual_rebuilt", "Forbid"), ("residual_rebuilt", True), ("unrecorded", 0),
    ("transcript_mapping", ["forbid"]), ("reference_by_declaration", None), ("renamed_replacement", ""), ("multi_artifact_block", 1),
    ("description", 3), ("require_all_evidences", True),
]
STRICT_BASE = {"name": "p", "residual_rebuilt": "forbid"}        # a well-formed policy that states one condition


def _run(chain, text):
    p = chain.P("typed_policy.json"); open(p, "w", encoding="utf-8").write(text)
    rep = chain.P("typed_report.json")
    if os.path.exists(rep): os.remove(rep)
    rc = cli(["verify-chain", "--root", chain.P("root.json"), "--links", chain.P("derived_v1.json"), chain.P("derived_v2.json"), *chain.trust(),
              "--policy", p, "--json-report", rep])
    return rc, (json.load(open(rep)) if os.path.exists(rep) else None)


@pytest.mark.parametrize("member,value", MALFORMED, ids=[f"{m}={json.dumps(v)}" for m, v in MALFORMED])
def test_wrongly_typed_member_is_a_configuration_error_alone_and_inside_a_strict_policy(chain, member, value, capsys):
    for base in ({"name": "p"}, STRICT_BASE):
        rc, rep = _run(chain, json.dumps({**base, member: value}))
        err = capsys.readouterr().err
        assert rc == 2 and "PolicyError" in err and "nothing is accepted" in err and rep is None, (base, rc, err)
        with pytest.raises(P.PolicyError): P.validate_policy({**base, member: value})


@pytest.mark.parametrize("text", ['{"name": "p", "residual_rebuilt": "forbid", "residual_rebuilt": "allow"}', '{"name": "p", "name": "q", "unrecorded": "forbid"}',
                                  '{"name": "p", "unrecorded": "forbid"', '[]', '"forbid"', 'null', '{"name": ""}', '{"name": 7, "unrecorded": "forbid"}'])
def test_duplicate_members_and_non_policy_documents_are_configuration_errors(chain, text, capsys):
    rc, rep = _run(chain, text)
    assert rc == 2 and "PolicyError" in capsys.readouterr().err and rep is None


@pytest.mark.parametrize("members", [{}, {"description": "nothing"}, {"require_all_evidence": False}, {"residual_rebuilt": "allow", "unrecorded": "allow"},
                                     {"accepted_judgements": "*", "accepted_assumptions": "*", "coverage_by_judgement": "allow", "require_prospective": False}])
def test_a_policy_that_states_no_condition_is_a_configuration_error(chain, members, capsys):
    rc, rep = _run(chain, json.dumps({"name": "p", **members}))
    err = capsys.readouterr().err
    assert rc == 2 and "states no condition" in err and rep is None


def test_well_formed_values_are_still_read_as_before(chain):
    assert _run(chain, json.dumps({"name": "p", "require_all_evidence": True}))[0] == 0
    assert _run(chain, json.dumps({"name": "p", "require_all_evidence": True, "require_prospective": False}))[1]["policy"]["checks"].__len__() == 2
    rc, rep = _run(chain, json.dumps({"name": "p", "accepted_judgements": []}))
    assert rc == 1 and rep["policy_verdict"] == "REJECTED"                         # the toy chain rests on a judgement
    rc, rep = _run(chain, json.dumps({"name": "p", "enumeration_domains": {}}))
    assert rc == 1 and rep["policy_verdict"] == "REJECTED"
    assert P.stated_conditions({"name": "p", "require_all_evidence": True, "unrecorded": "allow", "reference_kinds": []}) == ["reference_kinds", "require_all_evidence"]


def test_the_engine_validates_a_policy_that_did_not_come_from_load_policy(chain):
    """API use: verify_chain(..., policy=dict) applies the same validation as the command line."""
    import recertkit
    from recertkit.engine import verify_chain
    from recertkit.report import Report
    from recertkit.signing import TrustStore
    from recertkit.profiles import load_profile
    from recertkit.methods import default_registry
    args = (Report(quiet=True), chain.P("root.json"), [chain.P("derived_v1.json")], TrustStore(chain.trust()[1:]), load_profile(None), default_registry())
    with pytest.raises(P.PolicyError): verify_chain(*args, policy={"name": "p", "require_all_evidence": 0})
    with pytest.raises(P.PolicyError): verify_chain(*args, policy={"name": "p"})


def test_exit_statuses_distinguish_accepted_rejected_not_evaluated_and_malformed(chain, capsys):
    pol = chain.P("ok_policy.json"); import recertkit; json.dump({"name": "p", "root_adapters": [recertkit.ROOT_VERSION], "require_all_evidence": True}, open(pol, "w"))
    base = [*chain.trust(), "--policy", pol]
    rc_chain = cli(["verify-chain", "--root", chain.P("root.json"), "--links", chain.P("derived_v1.json"), chain.P("derived_v2.json"), *base])
    out = capsys.readouterr().out
    rc_single_later = cli(["verify", "--certificate", chain.P("derived_v2.json"), "--parent", chain.P("derived_v1.json"), *base])
    out2 = capsys.readouterr().out
    json.dump({"name": "p", "root_adapters": ["some-other-format"]}, open(pol, "w"))
    rc_rejected = cli(["verify-chain", "--root", chain.P("root.json"), "--links", chain.P("derived_v1.json"), chain.P("derived_v2.json"), *base])
    json.dump({"name": "p", "root_adapters": "recertkit-root-1"}, open(pol, "w"))
    rc_malformed = cli(["verify-chain", "--root", chain.P("root.json"), "--links", chain.P("derived_v1.json"), chain.P("derived_v2.json"), *base])
    assert (rc_chain, rc_single_later, rc_rejected, rc_malformed) == (0, 3, 1, 2), (rc_chain, rc_single_later, rc_rejected, rc_malformed, out[-300:], out2[-300:])
    assert "POLICY p: ACCEPTED  (4 policy checks evaluated and satisfied)" in out and "POLICY p: NOT EVALUATED" in out2


def test_a_verdict_without_any_evaluated_policy_check_is_never_accepted():
    """Independent of how a policy is validated: ACCEPTED is reported only if at least one policy check was evaluated."""
    from recertkit.report import Report
    R = Report(quiet=True); R.policy_name = "p"; R.check("some.record.check", True, "")
    assert R.ok and R.policy_verdict == "NOT EVALUATED" and not R.accepted
    R.policy("policy.x[link]", True, ""); assert R.policy_verdict == "ACCEPTED" and R.accepted
    R.policy("policy.y[link]", None, ""); assert R.policy_verdict == "NOT EVALUATED" and not R.accepted
    R.policy("policy.z[link]", False, ""); assert R.policy_verdict == "REJECTED" and not R.accepted
