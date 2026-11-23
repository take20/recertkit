# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
import pytest
from recertkit.canon import canon, dec, pointer
from recertkit.inventory import InventoryError, parse_inventory
from recertkit.profiles import DEFAULT_PROFILE, ProfileError, validate_profile


def test_canonical_json_is_key_order_independent():
    assert canon({"b": 1, "a": "x"}) == canon({"a": "x", "b": 1}) == b'{"a":"x","b":1}'


@pytest.mark.parametrize("v", [0.05, 5, None, "NaN", "Infinity", "abc", True])
def test_dec_accepts_only_finite_decimal_strings(v):
    assert dec(v) is None


def test_dec_is_exact():
    assert dec("0.050000") + dec("0") == dec("0.05") and dec("0.1") + dec("0.2") == dec("0.3")


def test_pointer():
    doc = {"a": {"b/c": [10, {"d": 0}]}}
    assert pointer(doc, "/a/b~1c/1/d") == 0 and pointer(doc, "") is doc
    with pytest.raises(KeyError): pointer(doc, "/a/x")


def test_inventory_rejects_duplicates_and_malformed_lines(tmp_path):
    p = tmp_path / "inv.txt"; p.write_text("aa" * 32 + "  dir1/x.bin\n" + "bb" * 32 + "  dir2/x.bin\n")
    with pytest.raises(InventoryError): parse_inventory(str(p))
    p.write_text("not-a-digest  x.bin\n")
    with pytest.raises(InventoryError): parse_inventory(str(p))


def test_profile_must_stay_deterministic_and_fix_the_frame():
    import copy
    p = copy.deepcopy(DEFAULT_PROFILE); p["deterministic_only"] = False
    with pytest.raises(ProfileError): validate_profile(p)
    p = copy.deepcopy(DEFAULT_PROFILE); p["roles"]["frame"]["fixed"] = False
    with pytest.raises(ProfileError): validate_profile(p)
