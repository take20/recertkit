# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
"""Canonical bytes, digests and exact decimals.

Certificates are signed over RFC 8785 (JCS) canonical JSON.  All risk and margin values are decimal STRINGS and are
compared as exact decimals, never as floats.  Evidence files may be stored gzip-compressed (``name.gz``); digests are
always taken over the uncompressed bytes, so compression is a storage detail and never changes a certificate.
"""
from __future__ import annotations
import gzip, hashlib, json, os, re
from decimal import Decimal, InvalidOperation
import rfc8785


def canon(obj) -> bytes:
    """RFC 8785 canonical JSON bytes of ``obj``."""
    return rfc8785.dumps(obj)


def body_of(cert: dict) -> bytes:
    """The signed body: the certificate without its ``signature`` member, canonicalised."""
    c = dict(cert); c.pop("signature", None)
    return canon(c)


def resolve_path(path: str) -> str | None:
    """Return ``path`` if it exists, else ``path + '.gz'`` if that exists, else None."""
    if os.path.exists(path): return path
    if os.path.exists(path + ".gz"): return path + ".gz"
    return None


def evidence_path(directory: str, name) -> str | None:
    """Path of the evidence file ``name`` inside ``directory`` (or its ``.gz``), or None.

    ``name`` comes from a certificate.  Only a plain file name is accepted: anything with a directory part, an absolute
    path, ``.`` or ``..`` is treated as absent, so a certificate cannot make the verifier read outside the directory."""
    if not isinstance(name, str) or not name or name in (".", "..") or "\0" in name: return None
    if name != os.path.basename(name) or "/" in name or "\\" in name or os.path.isabs(name): return None
    return resolve_path(os.path.join(directory, name))


def open_bytes(path: str):
    """Open a file for reading uncompressed bytes (transparently gunzipping ``*.gz``)."""
    return gzip.open(path, "rb") if path.endswith(".gz") else open(path, "rb")


def sha_raw(path: str) -> str:
    """SHA-256 of the bytes of ``path`` exactly as stored — what ``sha256sum`` prints.  Used for ARTIFACTS of a
    configuration (inventory lines, role files), so that an inventory can be written or checked with ``sha256sum``."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""): h.update(chunk)
    return h.hexdigest()


def sha_file(path: str) -> str:
    """SHA-256 of the uncompressed content of ``path``.  Used for RECORDS (certificates, inventories, evidence files),
    which may be stored gzip-compressed as ``<name>.gz``: the digest is that of the uncompressed record either way.
    Artifacts are hashed with ``sha_raw``."""
    h = hashlib.sha256()
    with open_bytes(path) as f:
        for chunk in iter(lambda: f.read(1 << 20), b""): h.update(chunk)
    return h.hexdigest()


def sha_obj(obj) -> str:
    return hashlib.sha256(canon(obj)).hexdigest()


def load_json(path: str):
    with open_bytes(path) as f: return json.loads(f.read().decode("utf-8"))


_PLAIN_DECIMAL = re.compile(r"-?[0-9]+(\.[0-9]+)?")


def dec(s) -> Decimal | None:
    """Exact decimal from a decimal STRING in plain notation: ASCII digits, an optional fraction, an optional leading
    minus sign (``"0.050000"``).  None for anything else: non-strings, exponents, a plus sign, whitespace, underscores,
    non-ASCII digits, NaN, infinities.

    ``Decimal(str)`` is exact for any number of digits.  Callers must only COMPARE the result (``==``, ``<``): Decimal
    comparisons are exact, whereas Decimal ARITHMETIC rounds to the precision of the current context (28 significant
    digits by default).  No arithmetic on these values is performed anywhere in this package."""
    if not isinstance(s, str) or not _PLAIN_DECIMAL.fullmatch(s): return None
    try: x = Decimal(s)
    except InvalidOperation: return None
    return x if x.is_finite() else None


def pointer(doc, ptr: str):
    """Resolve an RFC 6901 JSON pointer; raises KeyError if it does not resolve."""
    if ptr == "": return doc
    if not ptr.startswith("/"): raise KeyError(f"not a JSON pointer: {ptr!r}")
    cur = doc
    for tok in ptr[1:].split("/"):
        tok = tok.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, list):
            try: cur = cur[int(tok)]
            except (ValueError, IndexError): raise KeyError(ptr)
        elif isinstance(cur, dict):
            if tok not in cur: raise KeyError(ptr)
            cur = cur[tok]
        else: raise KeyError(ptr)
    return cur
