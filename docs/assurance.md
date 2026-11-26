# How the checks themselves are tested — and what that does not show

RecertKit's purpose is to refuse an invalid transfer. A tool of this kind fails silently: a missing check produces
no error, only an acceptance that should not have happened. This page records how the checks are tested, what
review nevertheless found in three pre-release drafts and in the first three public releases, and what remains
untested.

## Four kinds of test

| question | instrument | result for this version |
|---|---|---|
| Do the checks behave as documented on known cases? | `python -m pytest` — positive chains, mutated certificates, refused declarations, policy members, the stored examples | all tests pass |
| Does the suite depend on every check? | `tests/mutation_probe.py` — forces each catalogued check to pass and re-runs the suite | every check is exercised (expected: none unexercised) |
| Can a harmful change be *declared* so that it is accepted? | `tests/declaration_search.py` — exhaustive over a bounded space of declarations; exits with status 1 if an invariant is violated. `tests/swap_search.py` — the same question for two kernels whose contents are swapped (a shortened version runs in the test suite) | none accepted under the supplied policy (both searches) |
| Do the numeric checks agree with exact arithmetic? | `tests/test_risk_exact.py` — 4,000 random decimals, most longer than the default working precision, against a rational-number oracle; the same verdicts under four decimal contexts | no disagreement |

The first two can only confirm checks that somebody thought of. Both were green for two pre-release drafts in
which reviewers then found acceptance errors (below). The third was added for that reason. It was in turn green for
release 1.0.0, in which a reviewer then found an acceptance error outside its space: the search fixes one harmful
change (a modified `system.py` next to an equivalent kernel), and none of its transcripts compares a new file with a
parent file of another name. Two files whose contents are swapped, each truly equivalent to the other's
predecessor, are therefore not in it. The swap search was added for that reason — and in release 1.1.0 it covered
only entries with a single subject, so the same swap declared as one block of two files was accepted; in release
1.2.0 it covered both kinds of entry but always bound a single-file entry to a transcript of *that* file, so the
swap declared with transcripts of the *other* file's comparison was accepted (below). Since 1.3.0 what an entry
claims and what was compared are independent dimensions of the search. Each search is evidence about the space it
enumerates and about nothing else; three times the next finding lay just outside the space. The fourth instrument was added after a
review found a defect of a kind the first three do not look for: a check that was present, tested and exercised,
but computed in rounding arithmetic.

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
| 1.4.0 (unchanged in 1.4.1, which alters documentation only) | supplied with this version | 221,184 | 36 | **0** |
| 1.4.0 (unchanged in 1.4.1) | the supplied policy without `enumeration_domains` | 221,184 | 36 | 4 |
| a pre-release draft (the second) | supplied with that draft, which had no `enumeration_domains` | 221,184 | 642 | 21 |
| this version, harmless control (kernel only) | supplied with this version | 3,456 | 5 | 2 |

The third row is historical and was measured on that draft's code under that draft's policy; the draft cannot read
this version's policy. Rows one and two separate two effects for this version: the record checks leave 36 valid
records, of which the policy members other than `enumeration_domains` reject all but 4, and
`enumeration_domains` rejects those. The members `renamed_replacement` and `multi_artifact_block` cannot change a
verdict in this space: no declaration in it carries the judgement `replacement_correspondence`, so an entry that
would need it is not a valid record in the first place.

The number of valid records fell with each release — these are declarations of a harmful change that earlier
releases treated as well-formed records, though none was accepted — and each step is attributed by re-evaluating the affected
declarations with the search's own functions on the earlier release's code:

| release | valid records | declarations that stopped being valid records |
|---|---|---|
| 1.0.0 | 86 | — |
| 1.1.0 | 74 | 12: the kernel entry lists `system.py` among the parent artifacts it replaces without having it as a subject (a replacement under another name; all 96,768 such declarations were re-evaluated) |
| 1.2.0 | 62 | 12: the kernel entry has several subjects or several replaced artifacts (a block of several artifacts; all 55,296 such declarations that are not also replacements under another name were re-evaluated on the 1.1.0 code) |
| 1.3.0 | 36 | 26: the kernel entry binds a transcript that records both `kernel.py` and `system.py` as subjects but claims its result for other subjects than exactly these two (all 27,648 such declarations were re-evaluated on the 1.2.0 and on the 1.3.0 code: 26 and 0 valid records) |

None of these 50 was accepted by the policy supplied with its release.

Two invariants hold for this version: no declaration of the harmful change is accepted, and every one of the
36 that is a *valid record* names `system.py` among the conditions that were not checked (covered by
judgement, rebuilt, or enumerated on a stated number of inputs). The second invariant shows that the condition is
printed; it does not show that the condition holds or that a reader weighs it correctly. In the control space of
3,456 declarations two are accepted. Both declare the kernel-only change with the kernel as the subject and the
parent's kernel as the reference; they differ only in which of two transcript files they bind, and in the control
those two files record the same comparison. The control shows that the verifier does not reject everything; it
does not show that every legitimate way of declaring a change is accepted. A seeded sample of the search, together with every declaration whose kernel part is the truthful one,
runs in the test suite (`tests/test_declaration_search.py`).

**What the search found in this version.** 4 of the 36 valid records would be accepted by the supplied
policy *if it did not state* `enumeration_domains`. All 4 have the same shape: a truthful kernel entry, and a
second entry for `system.py` whose transcript compares the new and the old file on a single frame item on which
they agree. They cannot be rejected as records — a record cannot know which domain is adequate for which artifact.
They are rejected because the supplied policies state the domain size required for each artifact that may be
enumerated. A relying party that omits this member accepts them; `docs/policy.md` says so. (Earlier releases had
two further shapes. Up to 1.1.0: a true kernel comparison whose transcript lists both `system.py` files as files
of the compared blocks, claimed for both; since 1.2.0 an entry of several artifacts needs the judgement
`replacement_correspondence`. Up to 1.2.0: the same kind of transcript, claimed for the kernel alone; since 1.3.0
an entry must claim a transcript's result for exactly the subjects the transcript records.)

**What the search does not show.** It covers one change of one toy system, one equivalence method, the member
values listed above, single-entry coverage patterns, and chains of at most two links. It does not cover false
transcripts (out of scope: the verifier does not re-run comparisons), root adapters other than the self-issued
attestation, plugin methods, or policies other than the supplied one. It is evidence about the checks, not a proof.

## The swap search

`tests/test_renamed_replacement.py` builds a system that reaches two kernels by name, `kernel_add.py` and
`kernel_mul.py`, and swaps their contents: each new file computes exactly what the *other* parent file computed, so
a comparison of each new file with the other parent file is true and reports zero mismatches. The system now
multiplies where it added: 130 of 200 predictions change (correct: 180 → 72). This is an independent reviewer's
construction (finding M1-a of the review of release 1.0.0).

Review found three ways of declaring this change with transcripts whose numbers are all true, one per release:

| release | declaration | what the release checked |
|---|---|---|
| 1.0.0 | per file, crosswise: each new file as the replacement of the other parent file | coverage and digests; not which name replaces which |
| 1.1.0 | one entry whose subjects and replaced artifacts are both kernels, with a transcript that records one comparison and the digests of all four files | the crosswise form only |
| 1.2.0 | per file, each under its own name — but each entry bound to the transcript of the *other* file's comparison, in which the claimed file is listed as a further subject | that the claimed subject is *among* the subjects a transcript records |

The third shows what the first two searches had in common: they generated declarations from a list of forms. The
search now has two independent dimensions. An **entry** is what it claims — subjects (either kernel, or both) and
replaced parent files (either, or both) — together with a **transcript**, and the transcripts are all 16 that the
package's own `toy.enumerate_block` writes for two kernels: which new file was run (2), which parent file it was
compared with (2), whether the other new file is listed as a further subject (2), whether the other parent file is
listed as a further reference file (2). That gives 3 × 3 × 16 = 144 entries, and every declaration of one or two
entries, with and without the judgement `replacement_correspondence`: 2 × (144 + 10,296) = 20,880 declarations.

Each is issued through the normal path, signed with the trusted key **without** the issuer-side checks, and verified
under the reviewer's policy (as written in the review) and under the supplied quick-start policy
(`python tests/swap_search.py out.json`; exit status 1 if an invariant fails).

| system | engine | declarations | valid records | valid without the judgement | accepted (reviewer's policy) | accepted (supplied policy) |
|---|---|---|---|---|---|---|
| swapped kernels (harmful) | 1.4.0 (unchanged in 1.4.1) | 20,880 | 3 | 0 | **0** | **0** |
| equivalent re-implementations under the same names (control) | 1.4.0 (unchanged in 1.4.1) | 20,880 | 4 | 1 | 1 | 1 |
| swapped kernels, the same search run on the 1.2.0 engine | 1.2.0 | 20,880 | 8 | 1 | 1 | 1 |

The last row is the search's own control: on the 1.2.0 engine it finds the declaration the reviewer found, and
exits with status 1.

Since 1.3.0 the search also checks, on every declaration, that the issuer-side checks and the verifier
agree; that every valid record claims its results for exactly the files its transcripts record; and that every
entry of a valid record that is not name-aligned carries the judgement and prints its notice. The three valid
records of the swap all carry the judgement; the reviewer's policy rejects them because it does not accept that
judgement, the supplied policy also because it forbids renamed replacements and multi-artifact blocks. In the
control exactly one declaration is accepted: each kernel as a single subject, compared — alone — with the parent
file of its own name, without the judgement.

**What the swap search does not show.** It covers one system with two kernels, one change, entries of at most two
files, declarations of at most two entries, and transcripts in the standard layout written by one tool. With the
judgement `replacement_correspondence` and a policy that accepts it, the swap **is** accepted: the tool then relies
on a statement it cannot check, prints that it does so, and leaves the decision to the relying party. A transcript
in a **foreign layout** is read only through the pointers the issuer declares, so the verifier cannot see whether it
records further files; the swap can be declared that way as a valid record
(`test_scope_reduction_through_a_foreign_layout_is_printed_and_refused_by_the_release_policies`). Every run prints
that the mapping, including what the comparison covered, is the issuer's declaration, and the policy member
`transcript_mapping: "forbid"` — set in every supplied release policy — refuses it. `docs/concepts.md` states what
the linkage checks establish for a name-aligned entry with a standard transcript, and under which assumptions; the
search tests that the implementation does what that argument needs, in this space.

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
| release 1.0.0 | independent reviewer | two kernels with swapped contents, each declared as the replacement of the other: true comparisons, complete coverage on both sides, accepted under a strict policy | `equivalence.*.correspondence`; notice *renamed replacement*; policy member `renamed_replacement` (1.1.0) |
| release 1.1.0 | authors, auditing the fix above | the same swap declared as one entry whose subjects and replaced artifacts are both kernels, with a true transcript: issued by the normal path, accepted under the reviewer's policy and the supplied policy, no notice | `equivalence.*.correspondence` extended to every entry that is not name-aligned; notice *multi-artifact block*; policy member `multi_artifact_block` (1.2.0) |
| release 1.2.0 | internal reviewer | the same swap declared per file under each file's own name, each entry bound to the true transcript of the *other* file's comparison, in which the claimed file is listed as a further subject: issued by the normal path, accepted under the reviewer's policy and the supplied policy, no judgement, no notice | `equivalence.*.subject_scope`: a standard transcript's result is claimed for exactly the subjects it records (1.3.0) |
| release 1.0.0 | independent reviewer | (not acceptance errors) a signed certificate could name an evidence file outside the evidence directory; malformed signed input ended in a traceback; `recertkit inventory` wrote an inventory with duplicate names; artifacts named `*.gz` were hashed after decompression | plain file names only; exit status 2; refusal; artifacts hashed as stored (1.2.0, `tests/test_robustness.py`) |
| release 1.3.1 | coauthor-side reviewer | a policy file with a wrongly typed value produced `ACCEPTED` with no policy check: `require_all_evidence` or `require_prospective` set to `0`, `""` or `[]` (tested by truthiness), and `null` for these two, `coverage_by_judgement`, `accepted_judgements` and `accepted_assumptions` (read as "absent"); 7 of the 16 malformed policies among 21 tried on the FPGA example. The error is the relying party's own, not an issuer's, and no supplied policy was affected | `validate_policy`: one JSON type and a closed value set per member, `null` and repeated members refused, a policy without any stated condition refused — exit status 2 before anything is evaluated; exit status 3 separates `NOT EVALUATED` from `REJECTED` (`tests/test_policy_types.py`) |
| release 1.3.1 | coauthor-side reviewer | (not an acceptance error of RecertKit) the stored gate root did not pass the gate's own schema — `engine_commit` was `"n/a"` — because it had been issued where the gate tool skips its schema check (`jsonschema` absent); the public gate archive refused to regenerate it | root re-issued with the public archive's format-2.0 entry point and pinned requirements; the gate's verifier accepts it including `schema_valid`; the recipe refuses to run without `jsonschema` (`examples/gate_root/README.md`) |
| release 1.3.1 | authors, while revising | (input rules, found by reading the code after the review above asked for consistent rules) `issue` and single-link `verify` took a *root* whose decision was the string `transfer` as an eligible parent, while `verify-chain` required `certified`; a repeated member name in a JSON input was resolved silently (last value) and the non-JSON constants `NaN` and `Infinity` were read; array indices of JSON pointers accepted a sign, a leading zero and negative values; a trusted key that is not Ed25519 was reported as a bad signature; the `canonicalization` label of a signature block was not compared with the canonical form actually used | one eligibility rule on all paths; repeated member names and non-JSON constants refused; RFC 6901 indices; key type checked on loading; both labels of the signature block must be the ones implemented (`tests/test_input_rules.py`) |

The reviewer's reproductions of the second draft's three findings are re-run against both versions in the review
material (`adversarial_probe_v2.py`); each is accepted by the second draft and not accepted by this version, both
through `issue` and when force-signed. The third draft's finding is re-run in the same way (`risk_probe_v3.py`).

## What is executed for a release

`.github/workflows/tests.yml` runs the test suite, the quick start and the verification of the stored example
chains on Ubuntu and macOS under Python 3.10, 3.11, 3.12 and 3.13, for every push and every tag. The results for a
tagged version cannot be part of the tagged tree; they are recorded in that version's release notes on GitHub, with
links to the runs, together with a local run on the tag's archive downloaded without signing in.

The workflow's step for the strict policy requires exit status exactly 1 and reads the verdict from the JSON
report. A step that only required a non-zero status would also pass on a usage error (status 2).

Not executed by the authors for any release:

* Windows;
* `examples/ci/release-gate.yml` on a hosted runner — it is a template; its verification step was executed locally
  on the quick-start chain in the layout the template assumes (exit 0 when the policy accepts, 1 when it rejects),
  and so was its step that compares the files to be released with the last inventory (`examples/ci/README.md`);
* the FPGA experiment behind `examples/fpga_ultra96` — the example verifies stored records.

## Standing limits

* Sufficiency of the checks is tested by review and by bounded searches, not proved. Review found a defect in
  each of three pre-release drafts and in releases 1.0.0, 1.1.0, 1.2.0 and 1.3.1 (table above).
* Artifacts are identified by name. How a running system reaches a file, and which file of a block a comparison
  exercised, is not visible to the verifier. Whenever names do not settle it, the record rests on the printed
  judgement `replacement_correspondence`; a policy that accepts that judgement accepts what it cannot check.
* A record can be valid and harmful when a judgement it carries is false. The verifier's contribution is that the
  judgement is required, signed, printed and refusable — not that it is true.
* `enumeration_domains` fixes how many inputs were enumerated, not which.
* What a transcript in a foreign layout covers is the issuer's declaration. `subject_scope` applies to the standard
  layout only; `transcript_mapping: "forbid"` refuses foreign layouts.
* Truthfulness of transcripts, truth of judgements, adequacy of an enumerated domain and completeness of an
  inventory are outside the verifier; each is printed on every run.
* A policy restricts only what its members name.
