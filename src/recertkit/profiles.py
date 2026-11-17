"""Profiles: the relying party's rules, as data.

A profile says which claim fields a certificate must carry and how they are constrained, which configuration roles
exist and which of them may never change, which equivalence methods and which kinds of comparison reference are
accepted, whether a changed artifact may be covered by a written judgement instead of equivalence evidence, and which
written judgements must accompany a transfer.  A certificate records the name and digest of the profile it was issued under; the verifier
applies the profile IT was given (built in, or ``--profile file.json``) and rejects a certificate issued under any
other one.  A certificate can therefore not loosen the rules it is checked against.
"""
from __future__ import annotations
import copy, json
from .canon import sha_obj

DEFAULT_PROFILE = {
    "name": "recertkit-default-1",
    "description": "Deterministic transfer of a fixed-frame non-inferiority claim across a localised change.",
    "claim_fields": {
        "metric_definition": {"kind": "string"},
        "degradation_direction": {"kind": "enum", "values": ["reference_minus_candidate"]},
        "margin": {"kind": "decimal_open_unit"},
        "risk_level": {"kind": "decimal_open_unit"},
        "sampling_regime": {"kind": "enum", "values": ["r2"]},
    },
    "risk_field": "risk_level",
    "roles": {"server": {"fixed": False}, "model": {"fixed": True}, "frame": {"fixed": True}},
    "frame_role": "frame",
    "methods": ["exhaustive_enumeration"],
    "reference_kinds": ["parent_artifact", "parent_link", "specification"],
    "coverage_by_judgement": True,
    "require_equivalence": True,
    "deterministic_only": True,
    "required_judgements": ["boundary", "residual_path"],
    "required_judgements_if_unrecorded": ["unrecorded_items"],
    "required_judgements_if_unbound": ["root_configuration"],
}

REFERENCE_KINDS = ("parent_artifact", "parent_link", "specification")

_KINDS = {"string", "enum", "decimal_open_unit"}


class ProfileError(ValueError):
    pass


def validate_profile(p: dict) -> dict:
    for k in ("name", "claim_fields", "risk_field", "roles", "frame_role", "methods", "deterministic_only", "required_judgements"):
        if k not in p: raise ProfileError(f"profile lacks {k!r}")
    for f, c in p["claim_fields"].items():
        if c.get("kind") not in _KINDS: raise ProfileError(f"claim field {f!r}: unknown kind {c.get('kind')!r}")
        if c["kind"] == "enum" and not c.get("values"): raise ProfileError(f"claim field {f!r}: enum without values")
    if p["risk_field"] not in p["claim_fields"]: raise ProfileError("risk_field is not a claim field")
    if p["frame_role"] not in p["roles"]: raise ProfileError("frame_role is not a role")
    if not p["roles"][p["frame_role"]].get("fixed"): raise ProfileError("the frame role must be fixed")
    if not set(p.get("reference_kinds", REFERENCE_KINDS)) <= set(REFERENCE_KINDS):
        raise ProfileError(f"reference_kinds must be a subset of {list(REFERENCE_KINDS)}")
    if p["deterministic_only"] is not True:
        raise ProfileError("this version supports deterministic transfer only (deterministic_only must be true)")
    return p


def load_profile(path: str | None) -> dict:
    """The built-in default profile, or the profile document at ``path``."""
    p = copy.deepcopy(DEFAULT_PROFILE) if path is None else json.load(open(path, encoding="utf-8"))
    return validate_profile(p)


def profile_ref(p: dict) -> dict:
    return {"name": p["name"], "sha256": sha_obj(p)}
