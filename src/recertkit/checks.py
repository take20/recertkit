# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
"""Catalogue of the checks the verifier performs (``recertkit checks`` prints it; docs/checks.md is generated from it).

``*`` stands for an artifact name, a role, an evidence name or the identifier of an equivalence entry.  Record checks
decide ``VALID``; policy checks exist only when ``--policy`` is given.  A policy check is satisfied, violated or NOT
EVALUATED (its input was not verified in this run); the policy is ``ACCEPTED`` only if every check was evaluated and satisfied.
"""
CHECKS = [
 ("signature", [
  ("signature.certificate", "the derived certificate is signed by a key in the trust store, under the key id it names"),
  ("signature.parent", "the parent certificate is signed by a key in the trust store (verify; issue when --trust is given)"),
  ("signature.root", "verify-chain: the root certificate is signed by a key in the trust store")]),
 ("certificate and parent linkage", [
  ("certificate.version", "the certificate format is the one this tool verifies"),
  ("certificate.profile", "the certificate was issued under the profile (name and digest) the verifier applies"),
  ("parent.digest", "the certificate names its parent file by SHA-256"),
  ("parent.id", "the certificate names its parent by certificate id"),
  ("parent.readable", "a root adapter exists for the parent"),
  ("parent.decision", "the parent is a certified root or a transfer certificate"),
  ("root.decision", "verify-chain: the root's decision is 'certified'"),
  ("root.readable", "verify-chain: a root adapter exists for the root")]),
 ("claim", [
  ("claim.fields", "the claim carries exactly the profile's claim fields"),
  ("claim.constraints", "each claim field satisfies the profile (enumerations, decimal strings in (0,1))"),
  ("claim.invariance", "every claim field equals the parent's: the claim is carried, never altered")]),
 ("inventories and declared change", [
  ("inventory.digest.*", "the parent / derived inventory file has the digest the certificate records"),
  ("inventory.unique.*", "no artifact basename occurs twice in an inventory"),
  ("block.complete", "every artifact of either inventory is declared in exactly one category"),
  ("block.changed.*", "an artifact declared changed was added, removed or differs in digest"),
  ("block.unchanged.*", "an artifact declared unchanged has the same digest in both inventories"),
  ("block.residual_rebuilt.*", "an artifact declared residual_rebuilt is in both inventories with different digests"),
  ("block.unrecorded.*", "an artifact declared unrecorded is in the parent inventory only"),
  ("judgements.required", "the judgements the profile requires are present and non-empty (more are required when artifacts are unrecorded or a root binding is weaker than a digest)")]),
 ("change coverage", [
  ("coverage.derived_side", "every changed artifact present in the DERIVED inventory is a subject of exactly one equivalence entry, or is covered by one named judgement"),
  ("coverage.parent_side", "every changed artifact present in the PARENT inventory is replaced by exactly one equivalence entry, or is covered by one named judgement"),
  ("coverage.declared", "nothing is listed as covered on a side where it is not a changed artifact"),
  ("coverage.equivalence_present", "at least one equivalence entry exists (profile switch require_equivalence; the built-in profile sets it, so a change supported by judgements alone — a rebuild with no comparison — cannot be issued under it)"),
  ("coverage.judgement.*", "an artifact covered by judgement names an existing, non-empty judgement and bound supporting evidence, and the profile permits it; the artifact is printed as NOT covered by equivalence evidence"),
  ("equivalence.ids", "equivalence entries have distinct, well-formed identifiers")]),
 ("evidence linkage (per equivalence entry)", [
  ("equivalence.*.method", "the method is accepted by the profile and registered"),
  ("equivalence.*.subjects", "the subjects are distinct changed artifacts of the derived configuration"),
  ("equivalence.*.replaces", "the replaced artifacts are distinct changed artifacts of the parent configuration"),
  ("equivalence.*.correspondence", "the entry is name-aligned (one subject, replacing at most one parent artifact, of the same name), or the certificate carries the written judgement 'replacement_correspondence' (printed): artifacts are identified by name; where the system reaches them, and which file of a block a comparison exercised, is not visible to the verifier"),
  ("equivalence.*.reference_kind", "the kind of reference is one the profile accepts"),
  ("equivalence.*.transcript", "the transcript is a bound evidence file and is present (never detached)"),
  ("equivalence.*.transcript_json", "the transcript parses as JSON"),
  ("equivalence.*.transcript_layout", "the transcript uses the standard layout and no pointers, or a foreign layout with a declared pointer mapping (then printed); pointers never re-map a standard transcript"),
  ("equivalence.*.subject_digest", "the transcript is about the subject artifacts: its digests equal the derived inventory"),
  ("equivalence.*.subject_scope", "a transcript in the standard layout records exactly the subjects of the entry — no further file: the transcript states one result for the block of all subjects it records, and that result may not be claimed for a part of the block (a mapped transcript in a foreign layout cannot be checked in this way; that is printed)"),
  ("equivalence.*.reference_block", "reference 'parent_artifact': the reference consists of exactly the parent artifacts the entry replaces — no more, no fewer"),
  ("equivalence.*.reference_digest", "the transcript's reference digest(s) equal: the replaced parent artifacts in the parent inventory; or the verified reference of the parent link; or a bound specification file"),
  ("equivalence.*.reference_field", "the certificate's reference.sha256 is exactly the digest the reference was verified against, and is absent when no digest is verified"),
  ("equivalence.*.reference_parent_link", "reference 'parent_link': the parent certificate has an equivalence entry whose subjects are exactly the artifacts replaced now"),
  ("equivalence.*.reference_id", "reference 'parent_link' without a digest: the declared reference equals the parent link's (printed as not machine-bound)"),
  ("equivalence.*.reference_spec", "reference 'specification': it is named and its link to the parent configuration is a written judgement (printed)"),
  ("equivalence.*.domain_enumerated", "exhaustive_enumeration: the transcript enumerated the whole declared domain"),
  ("equivalence.*.zero_mismatches", "exhaustive_enumeration: the transcript reports zero mismatches"),
  ("equivalence.*.require[*]", "exhaustive_enumeration: a declared side condition holds in the transcript")]),
 ("configuration roles and root binding", [
  ("roles.declared", "the certificate names exactly the profile's roles"),
  ("role.*.present", "each role's artifact is in both inventories"),
  ("role.*.fixed", "a fixed role (model, frame) is declared unchanged and has equal digests"),
  ("roles.binding_level.*", "first link: the declared binding level of a role is the one the root provides (digest, identifiers-only, unbound)"),
  ("roles.root_binding.*", "first link: at level 'digest', the root's digest for a role equals the parent inventory's"),
  ("roles.root_filename.*", "first link: where the root names the role's file, the certificate names the same"),
  ("roles.distinct", "first link: role artifacts have pairwise distinct digests"),
  ("root.inventory_level", "first link: the declared inventory binding is the one the root provides (digest or unbound)"),
  ("root.inventory_binding", "first link: a root that binds the configuration inventory binds the parent inventory of this link"),
  ("root.commitment", "gate root: the commitment file has the digest the root records"),
  ("root.frame_file", "gate root: the frame file is present and has the parent inventory's digest"),
  ("root.frame_ids", "gate root: the commitment's frame hash recomputes from the frame's item identifiers"),
  ("root.task_manifest", "gate root: the root binds the frame file's digest (level digest) or the identifier manifest recomputed from the frame (level identifiers-only)"),
  ("root.commitment_params", "gate root: regime, margin and risk in the commitment equal the claim"),
  ("chain.inventory_continuity", "later link: the parent inventory is the inventory the parent certificate ended with"),
  ("chain.roles", "later link: roles equal the parent link's"),
  ("chain.root_binding", "later link: root binding levels are inherited unchanged"),
  ("chain.profile", "later link: same profile as the parent link")]),
 ("evidence files", [
  ("evidence.*", "an evidence file is present with the recorded digest (a detached file may be absent: then printed, or failed with --require-all-evidence)")]),
 ("risk budget", [
  ("risk.decimals", "alpha, delta_parent and delta_derived are decimal strings in plain notation (digits, optional fraction; no exponent)"),
  ("risk.alpha_zero", "alpha is exactly zero (deterministic transfer adds no sampling error; a positive alpha is unsupported)"),
  ("risk.composition", "delta_derived equals delta_parent as exact decimal values, compared without arithmetic (alpha is zero, so nothing is added)"),
  ("risk.parent", "delta_parent is the parent's risk"),
  ("risk.claim", "delta_parent is the claim's risk level")]),
]

POLICY_CHECKS = [
  ("policy.require_all_evidence[*]", "every evidence file named by the link is present"),
  ("policy.coverage_by_judgement[*]", "no changed artifact rests on a judgement the policy does not admit"),
  ("policy.residual_rebuilt[*]", "the link declares no residual_rebuilt artifacts"),
  ("policy.unrecorded[*]", "the link declares no unrecorded artifacts"),
  ("policy.reference_kinds[*]", "every comparison reference is of a kind the policy accepts"),
  ("policy.reference_by_declaration[*]", "for every comparison the verifier matched a reference digest recorded in the transcript (a digest merely written in the certificate does not count)"),
  ("policy.enumeration_domains[*]", "every equivalence entry is an exhaustive enumeration over a domain of the size the policy requires for its subjects"),
  ("policy.binding_levels[*]", "every root binding is at a level the policy accepts"),
  ("policy.transcript_mapping[*]", "no transcript is read through issuer-declared pointers"),
  ("policy.renamed_replacement[*]", "no equivalence entry replaces a parent artifact by a subject of another name"),
  ("policy.multi_artifact_block[*]", "no equivalence entry compares several artifacts as one block"),
  ("policy.chain[*]", "single-link verification of a later link: never satisfied — the earlier links were not evaluated (NOT EVALUATED)"),
  ("policy.accepted_judgements[*]", "every written judgement is one the policy accepts — by name, or by name and SHA-256 of its text when the policy pins one"),
  ("policy.accepted_assumptions[*]", "every trust assumption is one the policy accepts — by name, or by name and SHA-256 of its text when the policy pins one"),
  ("policy.root_adapters[*]", "the root is in a format the policy accepts"),
  ("policy.require_prospective[*]", "the link was issued prospectively"),
]


def _match(check_id, pat):
    import fnmatch
    return fnmatch.fnmatchcase(check_id, pat.replace("[*]", "[[]*[]]"))


def documented(check_id: str) -> bool:
    return any(_match(check_id, pat) for _, rows in CHECKS for pat, _ in rows) or any(_match(check_id, pat) for pat, _ in POLICY_CHECKS)


def markdown() -> str:
    out = ["# Checks performed by the verifier", "", "Generated by `recertkit checks`.", "",
           "A record is `VALID` when every emitted record check passed. `VALID` is a conditional statement, not a release decision:",
           "what was not checked is printed, and an acceptance policy (`--policy`) decides whether those conditions are acceptable.", ""]
    for group, rows in CHECKS:
        out += [f"## {group}", "", "| check | meaning |", "|---|---|"] + [f"| `{c}` | {d} |" for c, d in rows] + [""]
    out += ["## acceptance policy (only with `--policy`)", "", "| check | meaning |", "|---|---|"] + [f"| `{c}` | {d} |" for c, d in POLICY_CHECKS] + [""]
    return "\n".join(out)
