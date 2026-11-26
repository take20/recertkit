# Gate-root example: from a release-gate certificate to a derived link

The other examples use a root that RecertKit itself signed (quick start) or a gate certificate issued before
RecertKit existed (FPGA). This one starts from a certificate **issued by the anytime-valid release gate** for the
purpose, with every binding RecertKit can use.

## Verify the stored chain

```
cd examples/gate_root
recertkit root-info --root gate_root_certificate.json
recertkit verify-chain --root gate_root_certificate.json --links derived_c1.json \
    --trust gate-example=gate_example.pub --policy policy.json
```

Expected: `CHAIN RECORD: VALID — conditional on 7 unchecked items`, `POLICY gate-root-release-1: ACCEPTED`.
All 69 record checks and 15 policy checks pass. The seven unchecked items are two judgements, one trust assumption,
the transcript's provenance, the enumerated domain (65,536 inputs; that this is the kernel's whole input domain is
the `boundary` judgement), the completeness of the inventory, and the root protocol (the gate's own evidence, which
the gate's verifier checks).
There is no frame boundary and no unbound role: the root binds the server, the model, the frame **file** and the
inventory by digest.

## How the root was made

`make_example.py` is the complete, commented recipe; `gate_tool_output.log` is the gate's own output from the run
that produced the stored files (commit, issue, and the gate verifier's 49 checks, including `schema_valid`, with
`VERDICT: VALID`); `gate_tool_identity.json` records which gate file and schema were used, by SHA-256, and the
versions of the packages the run had installed.

**Which gate.** The gate is public as the supplementary code archive of the release-gate preprint
(<https://doi.org/10.21203/rs.3.rs-10959650/v1>, "Supplementary Files"; archive SHA-256 `75c47a8bab4a642b5f09b6894c1e2a2578066714213a611a0c2aadb341f6b9b9`
when downloaded on 2026-11-26). The archive has two entry points. `cert/certify.py` issues certificates of the
gate's current Protocol 3.1. `cert/certify_v29_legacy.py` issues certificates of format 2.0, which is the format
RecertKit's root adapter `gate-2.0` reads. **This example uses the legacy entry point; RecertKit 1.4.0 cannot use
a Protocol 3.1 certificate as a root.** The stored root was issued on Python 3.11 with the three
packages the gate tool imports, in the versions the archive's `requirements.txt` pins for the machine used
(`cryptography` 48.0.1, `jsonschema` 4.26.0, `rfc8785` 0.1.4); the archive's other pinned packages serve its
analysis scripts and were not installed.

1. Reference system (the quick-start model) and candidate C0 (weights one bit coarser) are evaluated on the 200-item
   frame; `gate_records.jsonl` holds the paired outcomes in the committed order.
2. `gate_candidate.json` carries `server_binary_sha256` and `configuration_inventory_sha256` next to the gate's
   required fields; the gate commits to the whole object.
3. `commit --tasks frame.jsonl` binds the frame file's SHA-256; `issue` signs the root (`certified`, stopped at
   111 of 200 items).
4. C0's kernel is replaced by the table lookup; `recertkit issue` and `verify-chain` as in the quick start.

To regenerate (needs the gate archive above, which is not distributed with RecertKit):

```
pip install . jsonschema==4.26.0          # RecertKit, and the package the gate needs for its schema check
python examples/gate_root/make_example.py --gate <archive>/cert/certify_v29_legacy.py \
    --keys /some/private/dir --out /some/output/dir
```

The script stops if `jsonschema` is missing, and derives nothing unless the gate's own verifier reports
`[OK] schema_valid` and `VERDICT: VALID`. A new signing key is generated, so certificate identifiers, signatures and
the commitment digest differ from the stored files; the decision and the stopping item (111 of 200) do not.

## Notes

* The toy data were chosen so that the gate certifies. A first variant — the fixed-point system against exact
  integer products — was **not** certified by the gate (mean paired difference +0.12), which is the gate working
  as intended; a root that is not `certified` cannot be a parent (`parent.decision`).
* The signing key of this example is not distributed. The tests re-issue links with a key generated on the spot.
* **Correction (1.4.0).** The root stored with versions up to 1.3.1 had `engine_commit: "n/a"` in both
  configurations, which the gate's certificate schema does not allow (it requires a git commit of 7 to 40
  hexadecimal digits). It had been issued in an environment without `jsonschema`, where the gate tool skips its
  schema check without a message; with `jsonschema` installed the gate refuses to issue it and its verifier reports
  `schema_valid` as failed (48 other checks pass). The root now stored carries the public commit of the RecertKit
  repository that contains the toy system (`ENGINE_COMMIT` in `make_example.py`), was issued with the schema check
  active, and is accepted by the gate's verifier. The statistical content is unchanged (same records, same order
  seed, certified at item 111).
* A gate certificate without the two extension fields is usable in limited mode; see `docs/roots.md`.
* This stored root, unchanged, and this policy were used by a reviewer of an earlier draft to show an acceptance
  error: an equivalent kernel shipped with a `system.py` that always predicts class 0, with `system.py` merely added
  to the artifacts the kernel comparison *replaces* (150 → 67 correct, 127 of 200 predictions changed). The draft
  accepted it. It is now refused at issuance and rejected when force-signed
  (`tests/test_coverage_sides.py::test_replaces_only_coverage_on_the_real_gate_issued_root`).
* The root and the gate's files are byte-identical to those of the earlier draft; only `derived_c1.json` was
  re-issued, because the certificate format changed (`CHANGELOG.md`).
