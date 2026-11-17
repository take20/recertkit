# FPGA case study: verifying a stored two-link chain

This directory holds **stored records** of a case study on an Ultra96-V2 board: a quantised Llama-3.2-1B model was
certified on the board's CPU (V0); the integer dot-product kernel of sixteen projection tensors was then moved to
programmable logic (V1); and the kernel was re-synthesised with a different adder structure (V1′).

What you can do here is **verify the certificates and the evidence files that are included**. You cannot re-run the
experiment from this directory: the bitstreams, the patched inference engine, the model file and the run records are
not distributed. The example shows how RecertKit represents a real transfer whose support is mixed — part
enumeration, part written argument — and how the two verdicts separate.

```
cd examples/fpga_ultra96
T="--trust p5-release-key-1=release_key.pub"; L="--root root_certificate.json --links derived_v1.json derived_v1p.json"
recertkit verify-chain $L $T                                        # RECORD VALID, 44 unchecked items listed
recertkit verify-chain $L $T --policy policy_strict.json            # POLICY REJECTED: 13 of 20 policy checks fail
recertkit verify-chain $L $T --policy policy_case_study.json        # POLICY ACCEPTED
recertkit verify-chain $L $T --require-all-evidence                 # RECORD INVALID: one bound file is not included
```

## What the record rests on

| item | status |
|---|---|
| The PL kernel (`p5_v2tile.bit`, then `p5_v2tile_v1p.bit`) | equivalence entry; transcript `lane_exhaustive_result.json`: 2^30 operand combinations per bitstream, 0 mismatches |
| … compared with what | **a specification** (the exact integer products of the Q4_K × Q8_K dot product), not the compiled CPU kernel of V0; the link to V0 is the judgement `reference_link`; the transcript records no digest of the model it used (*reference by declaration*) |
| … on which domain | each lane's operand domain, not the 256-element block domain; composition is the judgement `composition` |
| The changed CPU-backend library `libggml-cpu.so` (hook, driver, float tail) and the patch record | **covered by judgement** (`host_integration`), not by equivalence evidence |
| Three rebuilt host binaries | `residual_rebuilt`: judgement `residual_path`, supported by a source/build correspondence record that is bound by digest but **not included** (detached) |
| Root binding | server and model by digest; frame by **identifiers only**; the three libraries of the parent inventory are **not bound by the root** (judgement `root_configuration`) |
| Link 2 | three artifacts `unrecorded` at run time (assumption T4); reference inherited from link 1 by name — no digest of the reference was verified in either link, so neither certificate carries one |
| Enumerated domain | 2^30 inputs per bitstream are printed as the domain size; both policies state this number for the two bitstreams (`enumeration_domains`), which fixes *how many* inputs were compared, not that they are the right ones (judgements `boundary`, `composition`) |
| Transcript layout | the lane transcript predates RecertKit; it is read through issuer-declared pointers |
| Issuance | **retrospective**: both links were issued after the changed systems had been run |

`policy_strict.json` refuses each of these; `policy_case_study.json` lists them as accepted, by name. Neither is
"the right" policy — together they show what `VALID` leaves to the relying party. A policy is evaluated on a whole
chain: `recertkit verify --certificate derived_v1p.json --parent derived_v1.json … --policy policy_case_study.json`
reports `NOT EVALUATED`, because the first link and the root were not verified in that run.

## Files

`root_certificate.json`, `root_commitment.json` — the gate root and its commitment · `derived_v1.json`,
`derived_v1p.json` — the two links · `spec_v1.json`, `spec_v1p.json` — the declarations they were issued from ·
`inventory_v0.txt`, `inventory_v1.txt`, `inventory_v1p.txt` — digests only, by basename ·
`lane_exhaustive_result.json`, `ft2_float_tail_correspondence.json` — included evidence · `eval_mmlu500.jsonl` —
the 500-item frame · `release_key.pub` · `verify_chain*.log`, `chain_report.json` — outputs of the commands above.

The frame is a 500-item subset of the MMLU test set (Hendrycks et al., 2021), distributed under the MIT licence.
The certificates in this directory were re-issued in RecertKit's format from the evidence of the original study;
the release key is not distributed.
