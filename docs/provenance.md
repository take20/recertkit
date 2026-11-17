# Where RecertKit's parts come from

RecertKit grew out of a case study of one deployment change (an FPGA offload; `examples/fpga_ultra96/`). That study
defined derived certificates and used a single-purpose issuer/verifier script. RecertKit is a new implementation —
no source file is shared with that script — but several of its checks restate rules the script enforced. This page
separates what was carried over as an idea from what is new, so that the contribution of the software is clear.

| part | origin |
|---|---|
| derived certificate naming its parent by digest; chain verification | case study |
| claim invariance; risk budget in exact decimals; `alpha = 0` only | case study |
| roles bound to the root; pairwise-distinct role digests; fixed roles may not change | case study |
| rejection of duplicate inventory basenames | case study |
| frame bound by identifiers, with a printed boundary | case study |
| evidence files bound by digest; assumptions printed rather than checked | case study |
| general certificate format independent of the case (`recertkit-3`; see `CHANGELOG.md` for the two unpublished draft formats) | RecertKit |
| profiles as verifier-side data; certificate bound to the profile digest | RecertKit |
| root adapters; self-issued root attestation; `root-info` | RecertKit |
| equivalence-method registry and plugins; pointer mapping for foreign transcripts | RecertKit |
| four-category change declaration with completeness check | RecertKit |
| detached and compressed evidence | RecertKit |
| check catalogue, generated check documentation, check-disabling probe, JSON reports | RecertKit |
| **evidence linkage**: subjects and reference of every comparison tied to the derived and parent configurations | RecertKit (added after review of the first draft) |
| **change coverage**: every changed artifact covered by evidence or a named judgement | RecertKit (added after review) |
| **binding levels** per role and for the inventory; inventory binding in roots | RecertKit (added after review) |
| **acceptance policies** and the separate policy verdict; `issue --trust` | RecertKit (added after review) |

The release gate that issues root certificates is separate software by the same authors and is not part of
RecertKit; see `docs/roots.md`.
