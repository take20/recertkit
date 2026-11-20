# Changelog

## 1.1.0 — 2026-11-20

An external review of the first public release found a third way to obtain an accepted certificate with truthful
evidence and valid signatures. The contents of two kernels were swapped, and each new file was declared as the
replacement of the *other* parent file. Both comparisons were true, every changed artifact was covered once on each
side, and 1.0.0 issued the certificate and accepted it under a strict policy — although the system reaches its
kernels by name and now computed something else. The verifier identifies artifacts by name only: which file a running
system reaches in place of a replaced one cannot be read from the record.

* An equivalence entry whose replaced artifacts do not all have a subject of the same name — a renamed file, two
  artifacts declared as each other's replacements, or a deleted file absorbed by a block under another name — now
  requires the written judgement `replacement_correspondence` (check `equivalence.<id>.correspondence`). The
  condition is printed on every run as a `renamed replacement` notice, which also says when a replaced name still
  exists in the derived configuration as a different file.
* New policy member `renamed_replacement` (`"forbid"` or `"allow"`). The release policies of the quick start and of
  the gate-root example forbid renamed replacements; in the FPGA example `policy_strict.json` forbids them and
  `policy_case_study.json` accepts them with the judgement.
* The second link of the FPGA example replaces `p5_v2tile.bit` by `p5_v2tile_v1p.bit`. It was re-issued with the
  judgement, which states how the host reaches the kernel: by physical address, not by file name, and both
  bitstreams place the kernel's registers at the same address (read from their hardware handoff files on the board).
  The root and the first link are unchanged.
* `tests/test_renamed_replacement.py` signs every declaration of the reviewer's swap built from single-subject entries
  (72 declarations with true transcripts, with and without the judgement) and verifies each under the reviewer's
  policy and under the supplied quick-start policy. Entries whose subject is a block of several artifacts are outside
  that space.

The certificate format is unchanged (`recertkit-3`). Certificates issued by 1.1.0 can be read by 1.0.0; a certificate
issued by 1.0.0 remains a valid record under 1.1.0 unless it contains a renamed replacement without the judgement.

## 1.0.0 — 2026-11-17 (first public release)

Commands `keygen`, `inventory`, `root-issue`, `root-info`, `issue`, `verify`, `verify-chain`, `profile`, `checks`;
built-in profile `recertkit-default-1`; acceptance policies; root adapters `recertkit-root-1` and `gate-2.0`;
equivalence method `exhaustive_enumeration`; method plugins; detached and gzip-compressed evidence; machine-readable
reports with separate record and policy verdicts.

### Changes made before release in response to an internal review of the first draft (2026-11-16)

The first draft accepted two kinds of invalid transfer although all evidence was truthful and all signatures valid:
a changed block compared with something other than the parent's block (for instance with itself), and a change of
several artifacts with evidence for only one. The certificate format and the verifier were revised:

* equivalence evidence is declared per comparison (`equivalence` entries) with explicit subjects, replaced parent
  artifacts and a **reference** that must be tied to the parent configuration; the identity of both sides is
  checked by the engine for every method, including plugins;
* **coverage**: every changed artifact must be covered exactly once, by an equivalence entry or a named judgement;
* root **binding levels** per role and for the inventory are declared and compared with the root; `root-issue`
  can bind the inventory; the `gate-2.0` adapter reads optional server and inventory digests and recognises
  content-level frame binding;
* record validity and acceptance are separate verdicts; **acceptance policies** were added;
* `issue --trust` verifies the parent's signature; without it the omission is printed.

Certificates of the first draft's format are not accepted.

### Changes made before release in response to an internal review of the second draft (2026-11-16)

The second draft still accepted invalid transfers with truthful evidence: coverage counted the files of the parent
and of the derived configuration as one set of names, so a changed file could be "covered" by listing the parent's
file of the same name as replaced; a policy forbidding name-only references was satisfied by a digest that was only
written in the certificate; and single-link verification skipped a policy condition about the root that it could
not evaluate, and reported acceptance.

* **coverage is side-specific** (`coverage.derived_side`, `coverage.parent_side`, `coverage.declared`); judgement
  coverage takes an optional `side`;
* a `parent_artifact` reference must consist of **exactly** the replaced artifacts (`reference_block`) and may be a
  block of several artifacts; a `parent_link` reference requires the parent entry's subjects to equal the replaced
  artifacts exactly;
* the engine returns a **verified link state**; notices are printed from it and policies are evaluated on it;
  `reference.sha256` is written only from a verified source and rejected otherwise (`reference_field`);
* policy conditions are **three-valued**; a condition that cannot be evaluated yields `NOT EVALUATED`, never
  acceptance; a policy applied to a single later link is not evaluated (`policy.chain`);
* new policy members `enumeration_domains` and text-pinned `accepted_judgements` / `accepted_assumptions`; new
  command `texts`;
* pointers may not re-map a standard-layout transcript; new notices for enumerated domain size, inventory
  completeness, rebuilt and unrecorded artifacts;
* `tests/declaration_search.py`, an exhaustive search over declarations of a harmful change (`docs/assurance.md`).

**Format label.** The two drafts were both labelled `recertkit-1` although their certificates are incompatible.
Neither was published. The format of this release is `recertkit-3`; certificates labelled `recertkit-1` are
rejected by `certificate.version`.

### Changes made before release in response to an internal review of the third draft (2026-11-16)

The third draft evaluated the preservation of the risk budget as `delta_parent + alpha == delta_derived` in decimal
arithmetic, which rounds to the precision of the working context (28 significant digits by default). For a risk
level of 30 significant digits an exact copy was refused, a copy rounded to 28 digits was accepted, and the next
link could then not be issued. The defect concerned the numeric contract ("exactly"); no change of system
behaviour was accepted through it.

* `risk.composition` now requires `delta_derived` to equal `delta_parent` as exact decimal values; nothing is added
  (`alpha` must be zero). No arithmetic on decimal values remains in the package;
* decimal fields must be in **plain notation** (ASCII digits, optional fraction, optional leading minus sign);
  exponent notation, a plus sign, whitespace, digit separators and non-ASCII digits are rejected
  (`risk.decimals`, `claim.constraints`). This narrows what earlier drafts accepted; no certificate was published;
* `tests/test_risk_exact.py`: the reviewer's cases, independence from the decimal context, and agreement of the
  risk checks with exact rational arithmetic on 4,000 random long decimals;
* `tests/declaration_search.py` exits with status 1 when an invariant is violated (mode `check`, the default);
  mode `measure` only reports, for measuring an earlier draft;
* documentation: the policy member `enumeration_domains` fixes the **size** of an enumerated domain, not its
  identity or coverage.

The certificate format is unchanged (`recertkit-3`).

### Changes made before release in response to an internal review of the fourth draft (2026-11-16)

The review found no defect in the checks. No code, test, policy, certificate or other data file changed; under
`examples/`, only the text of `examples/ci/README.md` did.

* `docs/assurance.md`: a duplicated table header removed; "domain size required"; a new section states what was
  executed where; `examples/ci/README.md` referred to that information without it being there;
* `.github/workflows/tests.yml`: the step that expects the strict policy to reject now requires exit status
  exactly 1 and reads the verdict from the JSON report (a usage error, status 2, no longer passes as a
  rejection); Python 3.11 and 3.12 added to the matrix;
* `pyproject.toml`: the build requirement is `setuptools>=77`; the licence metadata of this project (PEP 639)
  cannot be built with the previously stated lower bound of 68.

### Changes made before release in response to an internal review of the fifth draft (2026-11-17)

The review found no defect in the package. Its two findings concern release-preparation scripts that are not part
of this repository. Changed here, text only:

* `docs/assurance.md`, `examples/ci/README.md`: the statements of what had been executed are dated (2026-11-16,
  before any hosted run) instead of "at this release", so that they stay true after a hosted run;
* this file: the entry for the fourth draft said that no file under `examples/` had changed, although
  `examples/ci/README.md` had.
