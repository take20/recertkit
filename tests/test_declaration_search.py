# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
"""A sample of the exhaustive declaration search (tests/declaration_search.py): no way of declaring a harmful change is
accepted, none is silent about the changed file, and the harmless control IS accepted."""
import os, sys
import pytest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import declaration_search as ds


@pytest.fixture(scope="module")
def work(tmp_path_factory):
    w = str(tmp_path_factory.mktemp("search")); ds.build(w); return w


POLICY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "examples", "quickstart", "policy.json")


def _sample(scenario, n):
    """A seeded random sample, plus EVERY declaration whose kernel part is the truthful one (so that only the treatment
    of system.py varies — this subset contains the declarations found in the reviews and all valid records)."""
    import random
    decls = ds.space(scenario)
    core = [d for d in decls if d["cat_k"] == "changed" and d["subjects"] in ([ds.K], [ds.K, ds.S]) and d["replaces"] in ([ds.K], [ds.K, ds.S])
            and d["reference"] in ("pa:k", "pa:k+s") and d["transcript"] in ("k_parent", "k_plus_sys", "k_both_sys") and not d["pointers"]]
    return random.Random(7).sample(decls, n) + core


@pytest.mark.parametrize("scenario", ["first", "later"])
def test_no_declaration_of_a_harmful_change_is_accepted_or_silent(work, scenario):
    rows = ds.evaluate(work, scenario, _sample(scenario, 400), POLICY)
    assert len(rows) >= 1000 and not [r["d"] for r in rows if r.get("accepted")]                                    # I1
    valid = [r for r in rows if r["record"]]
    assert valid and not [r["d"] for r in valid if not r["system_named"]]                                           # I2


def test_the_harmless_control_is_accepted_only_when_declared_truthfully(work):
    rows = ds.evaluate(work, "control", ds.space("control"), POLICY)
    acc = [r["d"] for r in rows if r.get("accepted")]
    assert acc and all(d["cat_s"] == "unchanged" and d["cat_k"] == "changed" and d["subjects"] == [ds.K] and d["replaces"] == [ds.K]
                       and (d["reference"], d["transcript"]) in {("pa:k", "k_parent"), ("pa:k", "k_c0")} and not d["pointers"] for d in acc)


def test_without_the_domain_member_a_one_input_comparison_of_system_py_would_be_accepted(work):
    """Why the supplied policies state ``enumeration_domains``: the record cannot know which domain is adequate."""
    d = {"cat_s": "changed", "cat_k": "changed", "subjects": [ds.K], "replaces": [ds.K], "reference": "pa:k", "transcript": "k_parent", "pointers": False, "second": True, "jc": None}
    row = ds.evaluate(work, "first", [d], POLICY)[0]
    assert row["record"] and row["policy"] == "REJECTED" and row["failed"] == ["policy.enumeration_domains"] and row["accepted_without_domain_member"] is True and row["system_named"]


def test_listing_system_py_on_both_sides_of_a_kernel_comparison_is_not_a_valid_record(work):
    """The kernel comparison is true, and both system.py files are listed as files of the compared blocks.  The transcript
    states one result for that block and the verifier cannot see which file was exercised.  Until 1.1.0 this was a valid
    record that only the policy member ``enumeration_domains`` rejected; since 1.2.0 an entry of several artifacts
    requires the written judgement 'replacement_correspondence', which no declaration of the search carries."""
    d = {"cat_s": "changed", "cat_k": "changed", "subjects": [ds.K, ds.S], "replaces": [ds.K, ds.S], "reference": "pa:k+s", "transcript": "k_both_sys", "pointers": False, "second": False, "jc": None}
    row = ds.evaluate(work, "first", [d], POLICY)[0]
    assert not row["record"] and "equivalence.kernel.correspondence" in row["failed"] and not row.get("accepted") and not row.get("accepted_without_domain_member")
