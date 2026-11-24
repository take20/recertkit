# The change declaration (`recertkit issue --spec`)

A JSON object. Paths in `evidence_files` are relative to the spec file.

```json
{
  "change": {"summary": "kernel.py: arithmetic -> table lookup"},
  "claim_scope": "the parent's claim on the fixed frame; no claim about other inputs",
  "block": {"changed": ["kernel.py"], "unchanged": ["system.py", "model.json", "frame.jsonl"]},
  "roles": {"server": "system.py", "model": "model.json", "frame": "frame.jsonl"},
  "root_binding": {"roles": {"server": "digest", "model": "digest", "frame": "digest"}, "inventory": "digest"},
  "equivalence": [{
      "id": "kernel", "method_code": "exhaustive_enumeration",
      "subjects": ["kernel.py"], "replaces": ["kernel.py"],
      "reference": {"kind": "parent_artifact", "artifact": "kernel.py"},
      "transcript": "enumeration", "domain_size": 65536
  }],
  "judgements": {"boundary": "…", "residual_path": "…"},
  "evidence_files": {"enumeration": "enumeration_v1.json"},
  "trust_assumptions": {"interpreter": "…"}
}
```

| member | required | meaning |
|---|---|---|
| `block` | yes | all artifacts of both inventories in `changed` / `unchanged` / `residual_rebuilt` / `unrecorded` |
| `roles` | yes | artifact name per profile role |
| `root_binding` | first link | binding level per role (`digest`, `identifiers-only`, `unbound`) and of the inventory (`digest`, `unbound`), exactly as the root provides them (`recertkit root-info`); `commitment_file` for gate roots. Later links inherit it. |
| `equivalence` | yes (≥ 1) | comparisons; see below |
| `judgement_coverage` | when a changed artifact has no equivalence evidence | list of `{"artifacts": […], "judgement": "<name>", "side": "both" \| "parent" \| "derived", "evidence": ["<evidence name>", …]}`; `side` defaults to `both` (every side on which the artifact exists) |
| `judgements` | yes | `boundary` and `residual_path` always; `unrecorded_items` when artifacts are unrecorded; `root_configuration` when a root binding is weaker than a digest; plus any judgement named by a reference or by `judgement_coverage` |
| `evidence_files` | yes | name → path, or `{"file", "sha256", "detached": true}` for evidence that is bound but not distributed |
| `trust_assumptions` | no | named prose |
| `claim`, `risk_budget` | no | default: the parent's claim and `alpha = 0`. Decimal fields are strings in plain notation (`"0.050000"`; no exponent), compared as exact values |
| `issuance_status` | no | default `"prospective"`; say `"retrospective…"` when the changed system had been observed before issuance |

## Equivalence entries

| member | meaning |
|---|---|
| `id` | identifier (`[A-Za-z0-9_-]+`), unique in the certificate; appears in check names |
| `method_code` | a method the profile accepts |
| `subjects` | the changed artifacts of the **derived** configuration the compared block consists of; a transcript in the standard layout must record exactly these, each by digest, and no further subject. Being a subject discharges the derived-side coverage obligation of that artifact |
| `replaces` | the changed artifacts of the **parent** configuration that the subjects replace (empty when the block is new). Being replaced discharges the parent-side obligation only — never the obligation of a same-named file of the derived configuration. An entry that is not one subject replacing at most one artifact of the same name requires the judgement `replacement_correspondence` (below) |
| `reference` | `{"kind": "parent_artifact", "artifact": N}` or `{"kind": "parent_artifact", "artifacts": [N, …]}` — must name exactly the artifacts in `replaces`; `{"kind": "parent_link"}` — the parent link must have an entry whose subjects are exactly `replaces`; or `{"kind": "specification", "id": …, "judgement": …, "evidence": <optional evidence name>}` |
| `transcript` | name of an evidence file (never detached) |
| `domain_size`, `require` | `exhaustive_enumeration`: size of the enumerated domain; optional side conditions `{"pointer", "equals"}` |
| `pointers` | only for transcripts in a foreign layout: JSON pointers for `subjects` (per artifact), `reference_sha256` or `reference_artifacts` (per artifact), `enumerated`, `mismatches`. Not allowed on a transcript that declares the standard layout |

`issue` writes `reference.sha256` itself — from the parent inventory, from the digest recorded in the parent link,
or from the bound specification file — and **discards any value given in the declaration**. Where no such source
exists (a specification without a bound file; a parent link whose reference was itself only named) the certificate
carries no `reference.sha256`, and the verifier rejects a certificate that carries one anyway. For a reference block
of several artifacts the value is the digest of the sorted `{name: digest}` map.

### Typical shapes

| change | `block.changed` | `subjects` | `replaces` | reference |
|---|---|---|---|---|
| one file modified | `[k]` | `[k]` | `[k]` | parent artifact `k` |
| one file becomes two | `[k, p]` | `[k, p]` | `[k]` | parent artifact `k` |
| two files become one | `[k, p]` | `[k]` | `[k, p]` | parent artifacts `[k, p]` (the transcript records both digests) |
| rename `k` → `f` | `[k, f]` (+ whatever loads it) | `[f]` | `[k]` | parent artifact `k` |
| unrelated file added / removed | `[…, x]` | — | — | `judgement_coverage` with `side` `derived` / `parent` |

Only the first row is *name-aligned*: one subject, replacing one artifact of the same name. *One file becomes
two*, *two files become one* and *rename* are entries of several artifacts or of an artifact under another name. The
declaration must then carry the judgement `replacement_correspondence`, stating which new artifact takes the place
of which replaced one and how the running system reaches it — for a split, which file is the entry point and that
the other is read only by it; for a rename, what loads `f` instead of `k`; for a merge, that nothing outside the
block read `p`. It is printed on every run as a *multi-artifact block* and/or a *renamed replacement*
(`docs/concepts.md`), and a policy can refuse either.

## Transcript layout

```json
{"schema": "recertkit-enumeration-1",
 "subjects": {"kernel.py": "<sha256>"},
 "reference": {"sha256": "<sha256 of what the subjects were compared with>"},
 "domain_size": 65536, "enumerated": 65536, "mismatches": 0}
```

For a reference block of several files, `"reference": {"artifacts": {"<name>": "<sha256>", …}}`. Additional members
are allowed. A comparison tool should write the reference digest from the file it actually
loaded, as `examples/quickstart/toy.py` does.
