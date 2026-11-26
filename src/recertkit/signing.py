# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
"""Ed25519 signing and a small trust store keyed by ``public_key_id``."""
from __future__ import annotations
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .canon import body_of

SIGNATURE_LABEL = {"algorithm": "ed25519", "canonicalization": "rfc8785_jcs_sorted_utf8_decimal_strings"}


def keygen(private_path: str, public_path: str) -> None:
    key = Ed25519PrivateKey.generate()
    with open(private_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    os.chmod(private_path, 0o600)
    with open(public_path, "wb") as f:
        f.write(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def sign(cert: dict, private_path: str, key_id: str) -> dict:
    """Return ``cert`` with a ``signature`` member over its canonical body."""
    key = serialization.load_pem_private_key(open(private_path, "rb").read(), password=None)
    out = dict(cert); out.pop("signature", None)
    out["signature"] = {"algorithm": SIGNATURE_LABEL["algorithm"], "value": key.sign(body_of(out)).hex(),
                        "public_key_id": key_id, "canonicalization": SIGNATURE_LABEL["canonicalization"]}
    return out


class TrustStore:
    """Public keys the relying party accepts, by key id.

    Each entry is ``ID=path.pem`` or a bare ``path.pem`` (the id is then the file stem).  A certificate whose
    ``signature.public_key_id`` is not in the store is rejected: the verifier never guesses a key.
    """
    def __init__(self, entries):
        self.keys = {}
        for e in entries or []:
            kid, path = e.split("=", 1) if "=" in e else (os.path.splitext(os.path.basename(e))[0], e)
            key = serialization.load_pem_public_key(open(path, "rb").read())
            if not isinstance(key, Ed25519PublicKey): raise ValueError(f"trusted key {kid!r} is not an Ed25519 public key ({type(key).__name__}); only ed25519 signatures are supported")
            self.keys[kid] = key

    def verify(self, cert: dict) -> tuple[bool, str]:
        sig = cert.get("signature") or {}
        kid = sig.get("public_key_id")
        if kid not in self.keys: return False, f"key id {kid!r} not in trust store {sorted(self.keys)}"
        if sig.get("algorithm") != SIGNATURE_LABEL["algorithm"]: return False, f"unsupported algorithm {sig.get('algorithm')!r}"
        if sig.get("canonicalization") != SIGNATURE_LABEL["canonicalization"]:      # never verify under a canonical form other than the declared one
            return False, f"unsupported canonicalization {sig.get('canonicalization')!r}"
        try:
            self.keys[kid].verify(bytes.fromhex(sig.get("value", "")), body_of(cert))
            return True, f"key {kid}"
        except Exception:
            return False, f"bad signature under key {kid}"
