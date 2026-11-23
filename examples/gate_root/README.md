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
All 68 record checks and 15 policy checks pass. The seven unchecked items are two judgements, one trust assumption,
the transcript's provenance, the enumerated domain (65,536 inputs; that this is the kernel's whole input domain is
the `boundary` judgement), the completeness of the inventory, and the root protocol (the gate's own evidence, which
the gate's verifier checks).
There is no frame boundary and no unbound role: the root binds the server, the model, the frame **file** and the
inventory by digest.

## How the root was made

`make_example.py` is the complete, commented recipe; `gate_tool_output.log` is the gate's own output from the run
that produced the stored files (commit, issue, and the gate verifier's `VERDICT: VALID`).

1. Reference system (the quick-start model) and candidate C0 (weights one bit coarser) are evaluated on the 200-item
   frame; `gate_records.jsonl` holds the paired outcomes in the committed order.
2. `gate_candidate.json` carries `server_binary_sha256` and `configuration_inventory_sha256` next to the gate's
   required fields; the gate commits to the whole object.
3. `commit --tasks frame.jsonl` binds the frame file's SHA-256; `issue` signs the root (`certified`, stopped at
   111 of 200 items).
4. C0's kernel is replaced by the table lookup; `recertkit issue` and `verify-chain` as in the quick start.

To regenerate (needs the gate tool, which is distributed with the release-gate paper, not with RecertKit):

```
python examples/gate_root/make_example.py --gate /path/to/cert/certify.py --keys /some/private/dir
```

## Notes

* The toy data were chosen so that the gate certifies. A first variant — the fixed-point system against exact
  integer products — was **not** certified by the gate (mean paired difference +0.12), which is the gate working
  as intended; a root that is not `certified` cannot be a parent (`parent.decision`).
* The signing key of this example is not distributed. The tests re-issue links with a key generated on the spot.
* A gate certificate without the two extension fields is usable in limited mode; see `docs/roots.md`.
* This stored root, unchanged, and this policy were used by a reviewer of an earlier draft to show an acceptance
  error: an equivalent kernel shipped with a `system.py` that always predicts class 0, with `system.py` merely added
  to the artifacts the kernel comparison *replaces* (150 → 67 correct, 127 of 200 predictions changed). The draft
  accepted it. It is now refused at issuance and rejected when force-signed
  (`tests/test_coverage_sides.py::test_replaces_only_coverage_on_the_real_gate_issued_root`).
* The root and the gate's files are byte-identical to those of the earlier draft; only `derived_c1.json` was
  re-issued, because the certificate format changed (`CHANGELOG.md`).
