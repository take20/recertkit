"""Root adapters: how a parent ROOT certificate is read.

RecertKit does not establish a quality claim; it carries one.  The claim originates in a root certificate produced
by some certification procedure.  An adapter extracts from a root

* the claim fields, the decision and the risk level;
* for each configuration role, the BINDING LEVEL the root provides and, where it exists, the bound digest:

  ``digest``            the root binds the SHA-256 of the role's artifact;
  ``identifiers-only``  (evaluation frame only) the root binds the frame's item identifiers, not its content;
  ``unbound``           the root says nothing checkable about the role's artifact;

* whether the root binds the digest of the whole parent inventory (``digest``) or only the role artifacts
  (``unbound``).  In the latter case the other artifacts of the parent inventory are tied to the root by a written
  judgement, not by the root.

A first link must DECLARE these levels (``root_binding``); the verifier compares the declaration with what the root
provides, prints every level weaker than ``digest`` as a boundary, and an acceptance policy may refuse them.

Adapters
--------
``recertkit-root-1``  a minimal signed attestation written by ``recertkit root-issue``.

``gate-2.0``          certificates of the anytime-valid non-inferiority release gate (``certificate_version`` "2.0").
                      Fields read: ``estimand`` (claim), ``decision``, ``commitment_digest_sha256``,
                      ``task_manifest_hash``, and in ``candidate_configuration``: ``artifact_sha256`` /
                      ``artifact_filename`` (model role, required by the gate's schema) and two OPTIONAL extension
                      fields that the gate carries and commits to like any other configuration field when they are
                      put into the candidate configuration before ``commit``: ``server_binary_sha256`` (server
                      role) and ``configuration_inventory_sha256`` (whole inventory).  Without them the server role
                      and the inventory are ``unbound``.  The frame is bound at level ``digest`` when
                      ``task_manifest_hash`` equals the SHA-256 of the frame file (the gate hashes the file given
                      as ``--tasks``), and at level ``identifiers-only`` when it equals the hash of an identifier
                      manifest instead.
"""
from __future__ import annotations
import hashlib, json, os
from . import ROOT_VERSION
from .canon import canon, load_json, resolve_path, sha_file, open_bytes


class RootError(ValueError):
    pass


class GenericRoot:
    adapter = ROOT_VERSION

    def __init__(self, root, profile):
        self.root, self.profile = root, profile
        self.claim = dict(root.get("claim", {}))
        self.decision = root.get("decision")
        self.risk = self.claim.get(profile["risk_field"])

    def role_binding(self, role, inventory_digest=None):
        d = (self.root.get("configuration", {}).get(role) or {}).get("sha256")
        return ("digest", d) if d else ("unbound", None)

    def role_filename(self, role):
        return (self.root.get("configuration", {}).get(role) or {}).get("file")

    def inventory_digest(self):
        return (self.root.get("configuration_inventory") or {}).get("sha256")

    def extra_checks(self, R, cert, evidence_dir, pinv, frame_level):
        R.notice("root attestation", "the root claim is an attestation by the holder of key "
                 f"{self.root.get('signature', {}).get('public_key_id')!r}; how it was established "
                 f"(basis: {str(self.root.get('basis', ''))[:160]!r}) is not verified by RecertKit")

    def describe(self):
        return {"adapter": self.adapter, "decision": self.decision, "claim": self.claim,
                "role_digests": {r: self.role_binding(r)[1] for r in self.profile["roles"]},
                "inventory_digest": self.inventory_digest()}


class GateRoot:
    """Release-gate certificates (certificate_version "2.0"); see the module docstring for the fields read."""
    adapter = "gate-2.0"
    ROLE_FIELDS = {"server": "server_binary_sha256", "model": "artifact_sha256"}
    INVENTORY_FIELD = "configuration_inventory_sha256"

    def __init__(self, root, profile):
        self.root, self.profile = root, profile
        self.claim = dict(root.get("estimand", {}))
        d = root.get("decision")
        self.decision = d.get("verdict") if isinstance(d, dict) else d
        self.risk = self.claim.get(profile["risk_field"])
        self.cc = root.get("candidate_configuration", {})
        self.fields = dict(self.ROLE_FIELDS, **(profile.get("gate_role_fields") or {}))

    def role_binding(self, role, inventory_digest=None):
        if role == self.profile["frame_role"]:
            tm = self.root.get("task_manifest_hash")
            return ("digest", tm) if tm and tm == inventory_digest else ("identifiers-only", None)
        d = self.cc.get(self.fields.get(role, "\0"))
        return ("digest", d) if d else ("unbound", None)

    def role_filename(self, role):
        return self.cc.get("artifact_filename") if self.fields.get(role) == "artifact_sha256" else None

    def inventory_digest(self):
        return self.cc.get(self.INVENTORY_FIELD)

    def describe(self):
        return {"adapter": self.adapter, "decision": self.decision, "claim": self.claim,
                "role_digests": {r: self.cc.get(self.fields.get(r, "\0")) for r in self.profile["roles"] if r != self.profile["frame_role"]},
                "frame": {"task_manifest_hash": self.root.get("task_manifest_hash"),
                          "level": "digest if this equals the SHA-256 of the frame file, identifiers-only if it is the hash of an identifier manifest"},
                "inventory_digest": self.inventory_digest(), "commitment_digest_sha256": self.root.get("commitment_digest_sha256")}

    def extra_checks(self, R, cert, evidence_dir, pinv, frame_level):
        root, rb = self.root, cert.get("root_binding", {})
        frame_item = cert.get("roles", {}).get(self.profile["frame_role"])
        cpath = resolve_path(os.path.join(evidence_dir, rb.get("commitment_file") or "\0"))
        okc = R.check("root.commitment", bool(cpath) and sha_file(cpath) == root.get("commitment_digest_sha256"),
                      f"commitment file digest == root.commitment_digest_sha256 ({str(root.get('commitment_digest_sha256'))[:16]})")
        fpath = resolve_path(os.path.join(evidence_dir, frame_item)) if frame_item else None
        okf = R.check("root.frame_file", bool(fpath) and sha_file(fpath) == pinv.get(frame_item),
                      "frame file present and equal to the parent inventory digest")
        if okc and okf:
            cm = load_json(cpath)
            try:
                with open_bytes(fpath) as f:
                    ids = sorted(json.loads(l)["item_id"] for l in f.read().decode("utf-8").splitlines() if l.strip())
            except (ValueError, KeyError, TypeError):
                ids = None
            rec = hashlib.sha256(canon({"item_ids": ids})).hexdigest() if ids is not None else None
            R.check("root.frame_ids", rec is not None and rec == cm.get("sampling_frame_hash"),
                    f"commitment.sampling_frame_hash recomputes from the frame's {len(ids) if ids is not None else '?'} item identifiers")
            if frame_level == "digest":
                R.check("root.task_manifest", root.get("task_manifest_hash") == cm.get("task_manifest_hash") == pinv.get(frame_item),
                        "the root and its commitment bind the SHA-256 of the frame file")
            else:
                tm = hashlib.sha256(json.dumps({"item_ids": ids}).encode()).hexdigest() if ids is not None else None
                R.check("root.task_manifest", tm is not None and tm == root.get("task_manifest_hash") == cm.get("task_manifest_hash"),
                        "root.task_manifest_hash is the hash of the identifier manifest recomputed from the frame")
            c = cert.get("claim", {})
            R.check("root.commitment_params", cm.get("sampling_regime") == c.get("sampling_regime")
                    and str(cm.get("epsilon")) == str(c.get("margin")) and str(cm.get("delta")) == str(c.get(self.profile["risk_field"])),
                    f"commitment regime/epsilon/delta equal the claim ({cm.get('sampling_regime')}, {cm.get('epsilon')}, {cm.get('delta')})")
        if frame_level != "digest":
            R.notice("frame boundary", "this root binds the frame's item IDENTIFIERS, not its content (limited mode: the gate was given an "
                     "identifier manifest as its task file). The verifier checks the identifiers against the root commitment and the frame "
                     "file's digest equality between the two inventories; it cannot detect a frame whose identifiers are unchanged but whose "
                     "content differs from what the root run evaluated. Content identity to the root run is a trust assumption.")
        R.notice("root protocol", "the root's own evidence (ordered records, sequential-test replay) is verified by the release "
                 "gate's verifier, not by RecertKit; here the root's signature, decision and bindings are checked")


def read_root(root: dict, profile: dict):
    v = root.get("certificate_version")
    if v == ROOT_VERSION: return GenericRoot(root, profile)
    if v == "2.0" and "estimand" in root and "commitment_digest_sha256" in root: return GateRoot(root, profile)
    raise RootError(f"no root adapter for certificate_version {v!r}")
