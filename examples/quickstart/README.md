# Quick start

```
python examples/quickstart/run.py [workdir]      # default: ./quickstart_out
```

No hardware, no network, a few seconds. The "deployed system" (`toy.py`) is a tiny integer classifier:
`system.py` (program), `model.json` (weights), `frame.jsonl` (200 evaluation items) and `kernel.py`, a fixed-point
multiply `q(a, b)` on signed 8-bit operands. `kernel.py` is the replaceable block; its whole input domain is
256 × 256 = 65,536 operand pairs, so equivalence of two kernels can be enumerated.

| step | what happens | result |
|---|---|---|
| 1 | configuration C0, its inventory, and a root attestation that binds the three roles **and the inventory** | `root.json` |
| 2–3 | the kernel is replaced by a table lookup (C1); the new kernel is compared with **the parent's kernel** on all 65,536 pairs; the declaration is checked and signed | `derived_v1.json` |
| 4 | a second replacement (C2), compared with the same original kernel; the link refers to it as *the reference of the parent link* | `derived_v2.json` |
| 5 | the release gate: `verify-chain` with the public key and the acceptance policy `policy.json` | `CHAIN RECORD: VALID`, `POLICY quickstart-release-1: ACCEPTED` |
| 6 | truncation instead of rounding: 11,756 of 65,536 inputs differ | **refused** (`equivalence.kernel.zero_mismatches`) |
| 7a | a kernel that always returns 0, "shown equivalent" by comparing it with itself (a truthful transcript, 0 mismatches) | **refused** (`equivalence.kernel.reference_digest`) |
| 7b | an equivalent kernel shipped with a modified `system.py` that has no evidence | **refused** (`coverage.derived_side`, `coverage.parent_side`) |
| 7c | the same change, with `system.py` added to the parent artifacts the kernel comparison *replaces* | **refused** (`coverage.derived_side`, `equivalence.kernel.correspondence`, `equivalence.kernel.reference_block`) |

## Reading the output

* Step 5 prints `conditional on 13 unchecked items`: four judgements and two trust assumptions (two and one per
  link), and per link one notice each for transcript provenance, the enumerated domain (65,536 inputs) and inventory
  completeness, plus the root attestation. The policy names the judgements and the assumption it accepts and the
  domain size it requires for `kernel.py`.
* Step 6: on the 200-item frame the truncating kernel reproduces **every** prediction of C0, although the block
  differs on 18% of its inputs. This shows one thing only: *agreement of outputs on a frame does not establish that
  the block is equivalent.* It does not show that the truncating system is worse on this frame (it is not), and the
  refusal is not a quality verdict. Block equivalence is not sufficient on its own: together with the boundary and
  residual-path conditions it is the conservative requirement this profile adopts for carrying a certificate over;
  a change that does not meet it has to be re-evaluated by whatever procedure issued the root.
* Steps 7a–7c are mistakes a declaration can make with entirely truthful evidence: comparing against the wrong
  thing, proving less than what changed, and naming the parent's file where evidence about the new file is needed.
  The system of 7b and 7c changes 127 of 200 predictions (accuracy 0.750 → 0.335). If any of them were signed
  anyway, `verify-chain` would reject it with the same checks (`tests/test_linkage.py`,
  `tests/test_coverage_sides.py`).

## Files

`toy.py` — the toy system, the enumeration and the declaration template · `run.py` — the walkthrough ·
`policy.json` — the relying party's acceptance policy.
