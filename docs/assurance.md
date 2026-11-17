# How the checks themselves are tested — and what that does not show

RecertKit's purpose is to refuse an invalid transfer. A tool of this kind fails silently: a missing check produces
no error, only an acceptance that should not have happened. This page records how the checks are tested, what
independent review nevertheless found in three successive drafts, and what remains untested.

## Four kinds of test

| question | instrument | result for this version |
|---|---|---|
| Do the checks behave as documented on known cases? | `python -m pytest` — positive chains, mutated certificates, refused declarations, policy members, the stored examples | all tests pass |
| Does the suite depend on every check? | `tests/mutation_probe.py` — forces each catalogued check to pass and re-runs the suite | every check is exercised (expected: none unexercised) |
| Can a harmful change be *declared* so that it is accepted? | `tests/declaration_search.py` — exhaustive over a bounded space of declarations; exits with status 1 if an invariant is violated | none accepted under the supplied policy |
| Do the numeric checks agree with exact arithmetic? | `tests/test_risk_exact.py` — 4,000 random decimals, most longer than the default working precision, against a rational-number oracle; the same verdicts under four decimal contexts | no disagreement |

The first two can only confirm checks that somebody thought of. Both were green for the two earlier drafts in
which reviewers then found acceptance errors (below). The third was added for that reason. The fourth was added
after the third review found a defect of a kind the first three do not look for: a check that was present, tested
and exercised, but computed in rounding arithmetic.

## The declaration search

One harmful change of the toy system is fixed: an equivalent new kernel, shipped with a `system.py` that always
predicts class 0 (127 of 200 predictions change). Only **truthful** evidence files exist — truthful as files: each
digest is the digest of the file named and each mismatch count is the result of a comparison that was run. That
does not make every declaration built from them justified. The toy comparison tool executes the kernel function
`q(a, b)` only; a transcript that also lists `system.py` as a file of the compared block records that file's digest
without having compared its behaviour, so a declaration that uses it to cover `system.py` joins a true kernel
result and a true file list across a block boundary the comparison does not support. The files are: the kernel compared with the
parent's kernel, with the original kernel, with itself; the kernel comparison with `system.py` additionally listed
as a file of the compared block, on the new side or on both sides; and the new `system.py` compared with the old one
on a single frame item on which they agree. The search then enumerates every combination of

* declared category of `system.py` (4) and of `kernel.py` (3);
* subjects (4), replaced artifacts (4), reference form (6) and transcript (6) of the kernel entry;
* pointer mapping (2), a second equivalence entry for `system.py` (2), judgement coverage of `system.py` on both
  sides, one side or not at all (4)

— 110,592 declarations — in two chain positions (first link after the root; a later link, where a parent-link
reference is available): 221,184 declarations. Each is signed with the trusted key **without** the issuer-side
checks and verified as a chain under `examples/quickstart/policy.json`.

| engine | policy | declarations | valid records | accepted |
|---|---|---|---|---|
| this version | supplied with this version | 221,184 | 86 | **0** |
| this version | the second draft's policy (= this version's without `enumeration_domains`) | 221,184 | 86 | 8 |
| second draft | the second draft's policy | 221,184 | 642 | 21 |
| this version, harmless control (kernel only) | supplied with this version | 3,456 | 5 | 2 |

The two drafts were each measured under the policy supplied with them, and the two policies differ: this
version's adds the member `enumeration_domains`. The step from 21 to 0 is therefore not the effect of the engine
alone. Under one and the same policy — the second draft's — the engine change takes 21 to 8; the domain-size
member takes 8 to 0. (The second draft's code cannot read this version's policy: it rejects the unknown member.)

Two invariants hold for this version: no declaration of the harmful change is accepted, and every one of the
86 that is a *valid record* names `system.py` among the conditions that were not checked (covered by
judgement, rebuilt, or enumerated on a stated number of inputs). The second invariant shows that the condition is
printed; it does not show that the condition holds or that a reader weighs it correctly. In the control space of
3,456 declarations two are accepted. Both declare the kernel-only change with the kernel as the subject and the
parent's kernel as the reference; they differ only in which of two transcript files they bind, and in the control
those two files record the same comparison. The control shows that the verifier does not reject everything; it
does not show that every legitimate way of declaring a change is accepted. A seeded sample of the search, together with every declaration whose kernel part is the truthful one,
runs in the test suite (`tests/test_declaration_search.py`).

**What the search found in this version.** 8 of the 86 valid records would be accepted by the supplied
policy *if it did not state* `enumeration_domains`: a one-input comparison of `system.py`, and a true kernel
comparison whose transcript lists both `system.py` files as files of the compared blocks. Neither can be rejected
as a record — the record cannot know which domain is adequate for which artifact, nor which files a comparison
really exercised. They are rejected because the supplied policies state the domain size required for each artifact that
may be enumerated. A relying party that omits this member accepts them; `docs/policy.md` says so.

**What the search does not show.** It covers one change of one toy system, one equivalence method, the member
values listed above, single-entry coverage patterns, and chains of at most two links. It does not cover false
transcripts (out of scope: the verifier does not re-run comparisons), root adapters other than the self-issued
attestation, plugin methods, or policies other than the supplied one. It is evidence about the checks, not a proof.

## What review found

| draft | found by | accepted although invalid | now |
|---|---|---|---|
| first | external reviewer | a block compared with something other than the parent's block (e.g. itself) | `equivalence.*.reference_digest` |
| first | external reviewer | a change of several artifacts with evidence for one | coverage checks |
| second | external reviewer | a changed file "covered" by listing the parent's file of the same name as replaced | `coverage.derived_side`, `coverage.parent_side`, `equivalence.*.reference_block` |
| second | external reviewer | a policy forbidding name-only references satisfied by a digest merely written in the certificate | policy evaluated on verified link state; `equivalence.*.reference_field` |
| second | external reviewer | single-link verification skipped a root condition it could not evaluate and reported acceptance | three-valued policy conditions; `policy.chain` |
| second | authors, while revising | a truthful comparison on one input, with a `boundary` judgement accepted by name | printed domain size; policy member `enumeration_domains` |
| second | authors, while revising | pointers could re-map the fields of a standard-layout transcript | `equivalence.*.transcript_layout` |
| second | authors, while revising | a parent-link reference accepted when the parent entry covered a superset of the replaced artifacts | exact match in `equivalence.*.reference_parent_link` |
| third | external reviewer | a risk budget rounded to 28 digits accepted in place of the parent's 30-digit budget, and the exact copy refused (no change of system behaviour involved) | `risk.composition` compares exact values and adds nothing; plain decimal notation only |
| fourth | external reviewer | no defect in the checks; two editorial corrections (a duplicated table header on this page, the naming of a draft in the paper) | — |

The reviewer's reproductions of the second draft's three findings are re-run against both versions in the review
material (`adversarial_probe_v2.py`); each is accepted by the second draft and not accepted by this version, both
through `issue` and when force-signed. The third draft's finding is re-run in the same way (`risk_probe_v3.py`).

## What was executed where (as of 2026-11-16, before any hosted run)

This table records what had been run on the date in the heading. Runs made later, on a hosted service or on other
platforms, are recorded in the release notes of the tagged version and not here.

| what | where | result |
|---|---|---|
| the `run:` steps of `.github/workflows/tests.yml`, as written, with the shell options GitHub uses | locally on macOS (x86-64), Python 3.10, 3.11, 3.12 and 3.13; for each, an archive of the tagged tree was unpacked and installed from PyPI dependencies into a new virtual environment with nothing else on the path | every step exits 0; 233 tests pass; the strict policy rejects a valid record with exit status 1 |
| the same workflow on a hosted runner | not executed | — |
| Linux, Windows | not executed | — |
| the verification step of `examples/ci/release-gate.yml`, as written | locally, on the quick-start chain in the layout the template assumes | exit 0 when the policy accepts, exit 1 when it rejects |
| the FPGA experiment behind `examples/fpga_ultra96` | not re-run by this repository; the example verifies stored records | — |

The workflow's step for the strict policy requires exit status exactly 1 and reads the verdict from the JSON
report. A step that only required a non-zero status would also pass on a usage error (status 2).

## Standing limits

* Sufficiency of the checks is tested by review and by a bounded search, not proved. Review found a defect in each
  of three successive drafts.
* `enumeration_domains` fixes how many inputs were enumerated, not which.
* Truthfulness of transcripts, truth of judgements, adequacy of an enumerated domain and completeness of an
  inventory are outside the verifier; each is printed on every run.
* A policy restricts only what its members name.
