"""Equivalence methods and transcript layouts.

An equivalence entry of a certificate says: *these changed artifacts (subjects) compute the same function as this
reference*, and binds a transcript as evidence.  The work is split in two:

* the ENGINE checks, for every method alike, the identity of both sides of the comparison: that the transcript is
  about the subject artifacts (digests equal the derived inventory) and that its reference is tied to the parent
  configuration (see ``engine``).  A method cannot forget these checks because it never performs them;
* the METHOD checks what is specific to it.  ``exhaustive_enumeration`` checks that the whole declared domain was
  enumerated, that no mismatch was found and that declared side conditions hold.

A method is a callable ``method(entry, transcript) -> [(suffix, ok, detail), ...]``; the engine reports each tuple as
the check ``equivalence.<entry id>.<suffix>``.  Additional methods are registered from a plugin file
(``--plugin my_methods.py`` exposing ``register(registry)``); a plugin is part of the relying party's trusted base.

Transcript layouts
------------------
The standard layout (``"schema": "recertkit-enumeration-1"``) is::

    {"schema": "recertkit-enumeration-1",
     "subjects": {"<artifact name>": "<sha256>", ...},
     "reference": {"sha256": "<sha256>"},                      # one reference artifact, or
     "reference": {"artifacts": {"<name>": "<sha256>", ...}},  # a reference block of several artifacts
     "domain_size": N, "enumerated": N, "mismatches": 0}

A transcript in any other layout is mapped by JSON pointers declared in the entry (``pointers``).  The verifier then
prints that the meaning of the pointed-at fields is the issuer's declaration.  Pointers may NOT be used on a transcript
that declares the standard layout: its fields have a fixed meaning that a declaration must not be able to override.
"""
from __future__ import annotations
import importlib.util
from .canon import pointer

STANDARD_SCHEMA = "recertkit-enumeration-1"


def transcript_field(entry: dict, transcript, name: str, artifact: str | None = None):
    """``(found, value)`` of a logical transcript field: ``subjects`` (per artifact), ``reference`` (a digest string
    for a single reference, or ``{name: digest}`` for a reference block), ``enumerated``, ``mismatches``,
    ``domain_size``."""
    ptr = entry.get("pointers")
    if ptr:
        if name == "reference":
            if isinstance(ptr.get("reference_artifacts"), dict) and ptr["reference_artifacts"]:
                try: return True, {k: pointer(transcript, p) for k, p in ptr["reference_artifacts"].items()}
                except (KeyError, TypeError): return False, None
            name = "reference_sha256"
        p = (ptr.get("subjects") or {}).get(artifact) if name == "subjects" else ptr.get(name)
        if not isinstance(p, str): return False, None
        try: return True, pointer(transcript, p)
        except KeyError: return False, None
    if not isinstance(transcript, dict): return False, None
    if name == "reference":
        r = transcript.get("reference")
        if isinstance(r, dict) and isinstance(r.get("artifacts"), dict) and r["artifacts"] and "sha256" not in r: return True, dict(r["artifacts"])
        v = r.get("sha256") if isinstance(r, dict) else None
        return v is not None, v
    if name == "subjects":
        s = transcript.get("subjects"); v = s.get(artifact) if isinstance(s, dict) else None
        return v is not None, v
    return name in transcript, transcript.get(name)


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def exhaustive_enumeration(entry: dict, transcript):
    """Every input of the declared domain was compared and none differed.

    Entry members used: ``domain_size`` (integer) and optional ``require``, a list of
    ``{"pointer": <JSON pointer>, "equals": <value>}`` side conditions on the transcript.
    """
    out = []
    size = entry.get("domain_size")
    ok, n = transcript_field(entry, transcript, "enumerated")
    good = ok and _is_int(size) and size > 0 and _is_int(n) and n == size
    if good and not entry.get("pointers"):
        ok2, ds = transcript_field(entry, transcript, "domain_size")
        good = ok2 and _is_int(ds) and ds == size
    out.append(("domain_enumerated", good, f"enumerated {n} of the declared domain of {size} inputs"))
    ok, mm = transcript_field(entry, transcript, "mismatches")
    out.append(("zero_mismatches", ok and _is_int(mm) and mm == 0, f"mismatches = {mm}"))
    for i, req in enumerate(entry.get("require") or []):
        try: found, v = True, pointer(transcript, req.get("pointer", "\0"))
        except KeyError: found, v = False, None
        out.append((f"require[{i}]", found and v == req.get("equals") and type(v) is type(req.get("equals")),
                    f"{req.get('pointer')} == {req.get('equals')!r} (found {v!r})"))
    return out


def default_registry() -> dict:
    return {"exhaustive_enumeration": exhaustive_enumeration}


def load_plugins(registry: dict, paths) -> dict:
    for i, p in enumerate(paths or []):
        spec = importlib.util.spec_from_file_location(f"recertkit_plugin_{i}", p)
        mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        mod.register(registry)
    return registry
