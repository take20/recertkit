# Concepts

## Objects

**Configuration and inventory.** A configuration is the set of artifacts a deployed system consists of. Its
*inventory* is a text file with one `sha256  name` line per artifact (`recertkit inventory`, or `sha256sum`: the
digest is that of the file as stored). Names are basenames and must be unique: artifacts are identified by file
name, and `recertkit inventory` refuses two files of the same name.

**Roles.** A profile names the roles every configuration has. The built-in profile has `server` (the program),
`model` and `frame` (the evaluation frame the claim is about). `model` and `frame` are *fixed*: a transfer may
never change them.

**Root certificate.** A signed record that a configuration meets a claim. RecertKit does not produce the evidence
behind it; it reads roots through *adapters* (`docs/roots.md`).

**Derived certificate.** A signed record with these members:

| member | content |
|---|---|
| `parent` | id and SHA-256 of the parent certificate |
| `claim` | the parent's claim, unchanged |
| `block` | every artifact of both inventories, in exactly one of `changed`, `unchanged`, `residual_rebuilt`, `unrecorded` |
| `equivalence` | one entry per comparison: subjects (changed artifacts of the **derived** configuration), the artifacts of the **parent** configuration they replace, the reference they were compared with, the method, the transcript |
| `judgement_coverage` | changed artifacts that are covered by a named written judgement instead of equivalence evidence, optionally for one side only (`"side": "parent"` or `"derived"`) |
| `roles`, `root_binding` | which artifact plays which role, and how strongly the root binds each role and the inventory |
| `judgements`, `trust_assumptions` | prose the transfer rests on; never checked, always printed |
| `evidence_files` | name → file and SHA-256 (optionally `detached`: digest recorded, file not distributed) |
| `risk_budget` | `delta_parent`, `alpha` (must be 0), `delta_derived` |

## The four categories of the change declaration

| category | meaning | what supports it |
|---|---|---|
| `changed` | added, removed, or digest differs — the artifact is part of the change | must be **covered**: equivalence evidence, or a named judgement |
| `unchanged` | same digest in both inventories | hash identity (checked) |
| `residual_rebuilt` | digest differs, but the artifact is claimed not to be part of the change (e.g. a rebuild) | the `residual_path` judgement (printed; refusable by policy) |
| `unrecorded` | in the parent inventory, not recorded for the derived configuration | the `unrecorded_items` judgement (printed; refusable by policy) |

## Coverage and linkage

Three questions are separate, and all three are checked:

1. **Is the list of changes complete?** Every artifact of either inventory is declared in exactly one category, and
   the declaration agrees with the digests (`block.*`).
2. **Does the evidence cover the whole change?** Coverage is counted **per side**, because the file `system.py` of
   the parent configuration and the file `system.py` of the derived configuration are two different objects:

   | the changed artifact … | obligation | discharged by |
   |---|---|---|
   | exists in the **derived** inventory (added or modified) | the new bytes need support | being a `subject` of exactly one equivalence entry, or a named judgement |
   | exists in the **parent** inventory (removed or modified) | the disappearance of the old bytes needs an account | being `replace`d by exactly one equivalence entry, or a named judgement |

   A modified artifact has both obligations; an added one only the first; a removed one only the second; a rename is
   a removal and an addition tied together by one entry. Naming an artifact on one side never discharges the other
   side (`coverage.derived_side`, `coverage.parent_side`), and nothing may be listed on a side where it is not an
   obligation (`coverage.declared`). An artifact covered by judgement is printed as *not covered by equivalence
   evidence*, with the side.
3. **Does each new artifact take the place of what it was compared with?** Artifacts are identified by **name**. The
   verifier sees neither how the running system reaches a file nor which file of a block a comparison exercised. An
   entry is *name-aligned* when it has one subject and replaces at most one parent artifact, of the same name: the new
   file then stands where the old one stood, and nothing further is needed. Any other entry rests on the written
   judgement `replacement_correspondence`, which must say which new artifact takes the place of which replaced one:

   | entry | example | printed as |
   |---|---|---|
   | a replaced artifact has no subject of its name | a renamed file; two files declared as each other's replacements; a deleted file absorbed by another | *renamed replacement* (also names a replaced file that still exists in the derived configuration as a different file) |
   | several subjects, or several replaced artifacts | one file becomes two; two files compared as one block | *multi-artifact block* |

   Without the judgement the declaration is refused (`equivalence.<id>.correspondence`). With it, the notice is printed
   on every run, and the policy members `renamed_replacement` and `multi_artifact_block` can refuse it. The reason is
   the same in both rows: a transcript states one result, and nothing in the record shows that the comparison was
   about the pairing the system actually uses. Two kernels whose contents are swapped can be declared crosswise
   (1.0.0 accepted this) or as one block of two files (1.0.0 and 1.1.0 accepted this) with comparisons that are all
   true, while the system — which reaches them by name — computes something else.

And for each comparison, **both sides are identified**:

* the *subjects* by digest against the derived inventory (`equivalence.<id>.subject_digest`): the transcript must
  record the digest of every subject;
* the *scope* of the record (`equivalence.<id>.subject_scope`): a transcript in the standard layout states **one
  result for the block of all subjects it records**, so the entry must claim that result for exactly those subjects.
  A transcript that records the comparison of another file, with the claimed file listed as a further subject of
  the same block, is refused — also when every digest and every number in it is true (1.2.0 accepted this). The
  reference side is exact in the same way. A transcript in a foreign layout, read through declared pointers, cannot
  be checked like this; that is part of what the *transcript mapping* notice prints and what the policy member
  `transcript_mapping` decides;
* the *reference* against the parent, in one of three ways (`equivalence.<id>.reference_*`):

| reference kind | meaning | what is checked | what is printed |
|---|---|---|---|
| `parent_artifact` | the new block was compared with the parent's block | the reference consists of **exactly** the parent artifacts the entry replaces (`reference_block`), and the transcript records the digest of each of them as in the parent inventory (`reference_digest`) | — |
| `parent_link` | the new block was compared with the same reference the parent link used | the parent has an equivalence entry whose subjects are **exactly** the artifacts replaced now; the transcript's reference digest equals the digest *verified* for the parent link | when no digest was verified in the parent link: *reference by declaration* (the strength is inherited, never raised) |
| `specification` | the new block was compared with a named specification or model | the specification is named; its relation to the parent is a present, non-empty judgement; if a specification file is bound as evidence, the transcript's reference digest equals its digest | always *reference by judgement*; without a bound file also *reference by declaration* |

A comparison of a block with itself, or with anything that is not tied to the parent in one of these ways, is
rejected by `reference_digest` even though the transcript is truthful and reports zero mismatches.

**What these checks establish, and under which assumptions.** Take an entry checked by the built-in
`exhaustive_enumeration` method, with one subject `f` that replaces the parent's `f` (name-aligned, reference kind
`parent_artifact`), bound to a transcript in the standard layout. If the record is valid, then two things hold.
By the engine's checks, which apply to every method: the transcript's subjects are exactly `{f}` with the digest of
the derived inventory (`subject_scope`, `subject_digest`), and its reference is exactly the parent's `f` by the
digest of the parent inventory (`reference_block`, `reference_digest`). By the method's checks: the transcript
states that the whole declared domain was enumerated with zero mismatches (`domain_enumerated`, `zero_mismatches`).
*If the transcript is truthful* — the tool ran the files it names and recorded what it found — the new file `f`
therefore returns, on every enumerated input, what the parent's file `f` returned. A plugin method establishes
equivalence by other means; the engine's identity and scope checks still apply to it, but what its transcript
shows about behaviour is that method's own premise and part of the relying party's trusted base. That the enumerated inputs are all the
inputs `f` can receive, and that `f` reads nothing outside itself, are the judgements `boundary` and
`residual_path`. Nothing in this argument depends on a search having found no counterexample; the searches in
`docs/assurance.md` test that the implementation does what this paragraph says. For any entry that is not
name-aligned the argument does not go through, which is why such an entry needs `replacement_correspondence`.

The certificate member `reference.sha256` is not an input to any of this. `issue` writes it from the source the
verifier checks; the verifier requires it to equal the digest it verified and to be **absent** when it verified
none (`reference_field`). A digest that somebody merely wrote into a declaration is discarded at issuance and is a
record failure in a signed certificate.

## Link state

While verifying, the engine records for every link what it established: per equivalence entry the subjects, the
replaced artifacts, the kind of reference and its **verified binding** (`digest`, `declaration`, or
`unverified-parent` when a single link inherits from a parent that was not verified in the same run), whether the
transcript was pointer-mapped, and the enumerated domain size; which artifacts rest on a judgement; the root format
and the binding levels the root provides; absent evidence; and the digests of the judgement and assumption texts.
The notices are printed from this state and the acceptance policy is evaluated on it (`links` in the JSON report),
so the two cannot disagree.

## Two verdicts

`RECORD: VALID` — every record check passed. It is a conditional statement about a record.

`POLICY: ACCEPTED` — additionally, every condition of the relying party's acceptance policy was evaluated on the
verified link state and is satisfied (`docs/policy.md`). Only this is a release decision. `REJECTED` — a condition
is violated, or the record is invalid. `NOT EVALUATED` — no condition is violated, but at least one could not be
evaluated in this run; this is not acceptance, and the exit status is 1. Without a policy the tool prints
`POLICY: none applied — record verification is not a release decision` and a valid record exits with status 0.

## What is never checked

Printed on every run, with its kind, and listed under `not_checked` in the JSON report:

| kind | meaning |
|---|---|
| `judgement …`, `trust assumption …` | the prose itself |
| `transcript provenance` | the transcript is the issuer's record of a comparison; it is not re-run |
| `coverage by judgement` | a changed artifact without equivalence evidence, with the side(s) the judgement covers |
| `residual rebuilt`, `unrecorded artifact` | an artifact whose bytes differ, or that was not recorded, and that is declared not to be part of the change |
| `enumeration domain` | how many inputs were enumerated for which subjects; that these are all inputs the block can receive is the `boundary` judgement |
| `inventory completeness` | that the inventory lists every artifact that can affect the outputs |
| `reference by judgement`, `reference by declaration` | the comparison reference is tied to the parent by prose, or identified by name only |
| `transcript mapping` | a foreign transcript layout read through issuer-declared pointers |
| `unbound role`, `unbound inventory`, `frame boundary` | the root binds less than a digest |
| `detached evidence` | a bound evidence file is absent; its digest was not checked |
| `root attestation`, `root protocol` | whatever established the root claim |
| `parent signature` | `issue` was run without `--trust` |
| `precondition` | a single link was verified whose parent is itself derived: what it inherits was not verified in this run |

## Risk

The built-in profile supports deterministic transfer only: `alpha` must be zero and `delta_derived` must equal
`delta_parent`, which must equal the parent's risk and the claim's risk level.

These values are decimal **strings in plain notation** — ASCII digits with an optional fraction, such as
`"0.050000"`; exponents, a plus sign, whitespace and digit separators are not accepted. They are compared as exact
decimal values of any length (`"0.05"` and `"0.050000"` are the same budget) and are **never added or otherwise
computed with**: decimal arithmetic rounds to a working precision, comparison does not. A profile that admitted a
positive `alpha` would have to define the precision of that addition; this one does not need to.

`alpha = 0` says that the transfer adds no *sampling*
error to the parent's risk level. It does not say that the transfer is risk-free: a wrong judgement, a faulty
toolchain or a mis-declared boundary are not sampling errors and are not in the budget. They are the printed
conditions.
