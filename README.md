# RecertKit

**Carry a quality certificate across a deployment change — as a record that says exactly what was checked, what was
assumed, and who must still decide.**

A deployed ML system is certified once: some procedure establishes that a configuration (model file, inference
binary, hardware kernel, evaluation frame) meets a quality claim and records it in a signed *root certificate*.
Then the system changes — a kernel is replaced by a faster implementation, moves to an accelerator, or is
re-synthesised.
RecertKit addresses one narrow question about such a change:

> *Someone states that the existing claim carries over to the changed configuration without re-running the
> evaluation. What exactly does that statement rest on, and how does a third party check the checkable part?*

It issues and verifies **derived certificates**. A derived certificate names its parent by digest, declares every
artifact that changed, binds the evidence that the changed block computes the same function **as what it replaces
in the parent configuration**, accounts for **every** changed artifact, records the written judgements and trust
assumptions the transfer rests on, and carries the parent's claim and risk budget unchanged. Derived certificates
chain: `root → derived → derived → …`.

## What the results mean

RecertKit reports two separate verdicts.

| verdict | question it answers | decided by |
|---|---|---|
| `RECORD: VALID / INVALID` | Is the chain internally consistent — signatures, parent linkage, change coverage, evidence linkage, profile rules? | the verifier's record checks (`docs/checks.md`) |
| `POLICY: ACCEPTED / REJECTED / NOT EVALUATED` | Are the conditions the chain rests on acceptable for *this* relying party? | an acceptance policy the relying party supplies (`docs/policy.md`), evaluated on what the verifier established, not on what the certificate declares |

A **VALID record is a conditional statement**: *if* the printed judgements and assumptions hold, the parent's claim
carries over. It is not a release decision, it does not say the evidence is complete, and it does not say that
quality was preserved. Every run prints what was **not** checked: written judgements, trust assumptions, whatever
established the root claim, artifacts covered by judgement instead of evidence, references tied to the parent by
judgement, root bindings weaker than a digest, absent evidence files, how many inputs an enumeration covered (whether
that is the whole input domain is a judgement), a replacement under another name (which file the running system
reaches is a judgement), that the inventory lists everything relevant, and the fact that a transcript is the
issuer's record of a comparison the verifier did not re-run. Without `--policy` the output says so:
`POLICY: none applied — record verification is not a release decision`.

A policy condition has three outcomes: satisfied, violated, or **not evaluated** because the information it needs
was not verified in this run. `ACCEPTED` requires every condition to be evaluated and satisfied; a condition that
could not be evaluated is never treated as met. A policy is a statement about a whole chain, so it is evaluated by
`verify-chain`; `verify` on a single later link reports `NOT EVALUATED`.

`recertkit issue` succeeding means the *declaration* passed the profile checks before it was signed. It is not a
release decision either; the release gate is `verify-chain` with trusted keys and a policy.

RecertKit does **not** establish a quality claim, measure model quality, re-run comparisons, or decide whether an
equivalence argument is true.

## Install

```
pip install .            # Python >= 3.10; depends on cryptography and rfc8785
pip install ".[test]"    # plus pytest
```

## Quick start (no hardware, a few seconds)

```
python examples/quickstart/run.py
```

The script certifies a toy integer classifier, replaces its arithmetic kernel twice with equivalent implementations
(issuing a derived certificate each time), and lets a relying party verify the chain with the public key and an
acceptance policy. It then shows four declarations being **refused at issuance**: a non-equivalent kernel; a kernel
"shown equivalent" by comparing it with itself; an equivalent kernel shipped together with a second changed file
that has no evidence; and the same change with the second file merely named among the parent artifacts the kernel
comparison replaces. See `examples/quickstart/README.md`.

## Commands

| command | purpose |
|---|---|
| `recertkit keygen` | create an Ed25519 key pair |
| `recertkit inventory FILES… --out inv.txt` | record the SHA-256 of every artifact of a configuration |
| `recertkit root-issue` | sign a minimal root attestation that binds the roles and (with `--inventory`) the whole inventory |
| `recertkit root-info --root R` | show what the root adapter reads from a root certificate and which bindings it provides |
| `recertkit issue` | check a change declaration against the profile and — only if it passes — sign a derived certificate (`--trust` also verifies the parent's signature) |
| `recertkit verify` | verify one derived certificate against its parent |
| `recertkit verify-chain` | verify a root and every link after it; `--policy FILE` adds the acceptance decision |
| `recertkit texts --certificate C` | print the SHA-256 of each judgement and assumption text, for pinning reviewed texts in a policy |
| `recertkit profile` / `recertkit checks` | print the built-in profile / the catalogue of checks |

Exit status:

| status | `issue` | `verify`, `verify-chain` without `--policy` | with `--policy` |
|---|---|---|---|
| `0` | issued | record VALID — **not** a release decision | record VALID and policy ACCEPTED |
| `1` | refused, nothing signed | record INVALID | record INVALID, policy REJECTED, or policy NOT EVALUATED |
| `2` | usage error | usage error | usage error (including a malformed policy) |

A release gate must therefore run `verify-chain` **with** `--policy`; exit status 0 without a policy only says that
the record is internally consistent. `--json-report FILE` writes every check, both verdicts, the verified state of
each link (`links`) and everything that was not checked.

```
recertkit verify-chain --root root.json --links derived_v1.json derived_v2.json \
    --trust release=release.pub --policy policy.json
```

## The checks in one paragraph

Identity of both sides of every comparison is checked by the engine, not by the equivalence method: the transcript
must record the subjects of the entry — the changed artifacts of the *derived* inventory, by digest; a transcript in
the standard layout must record exactly these and no further file, because it states one result for the whole block
it records — and its reference must be tied to the
*parent* — exactly the parent artifacts the entry replaces (by digest), the reference the parent link was shown
equivalent to, or a named specification whose relation to the parent is a written judgement (printed). Coverage is
counted **per side**: a changed file of the derived configuration must be a subject of one comparison or be covered
by a named judgement; a changed file of the parent configuration must be replaced by one comparison or be covered by
a named judgement; the same file name on the two sides is two obligations. Artifacts are identified by name, and
the verifier sees neither how the running system reaches a file nor which file of a block a comparison exercised.
An entry with one subject that replaces a file of the same name needs nothing further; any other entry — a renamed
file, several files compared as one block — needs the written judgement `replacement_correspondence` (printed),
which a policy can refuse. The configuration is tied to the root at
a declared level per role — `digest`, `identifiers-only` (frame) or `unbound` — and anything weaker than a digest is
printed and requires a written judgement. The policy is evaluated on the state these checks established.
`docs/checks.md` lists all 71 record checks and 16 policy checks.

## Documentation

* `docs/concepts.md` — the objects, the two verdicts, and what is and is not checked
* `docs/spec.md` — the change declaration (`issue --spec`) field by field
* `docs/profiles.md` — verifier-side rules as data; equivalence-method plugins
* `docs/policy.md` — acceptance policies
* `docs/roots.md` — root adapters, binding levels, and how to make a release-gate certificate usable as a root
* `docs/checks.md` — every check (generated by `recertkit checks`)
* `docs/provenance.md` — which parts restate rules of the originating case study and which are new
* `docs/assurance.md` — how the checks themselves are tested, what reviews found, and what remains untested

## Examples

* `examples/quickstart/` — hardware-free; everything is regenerated on your machine.
* `examples/gate_root/` — a root certificate **issued by the anytime-valid release gate** on the toy system, then a
  derived link; all bindings at digest level; stored outputs plus the script that regenerates them when the gate
  tool is available.
* `examples/fpga_ultra96/` — a two-link chain from an FPGA offload on an edge board, verified from stored
  certificates. It shows the opposite end: a record that is VALID but rests on many named conditions, is rejected by
  a strict policy and accepted by a policy that names those conditions. It is a verification of stored records,
  not a re-run of the experiment.

## Tests

```
python -m pytest -q                         # 283 tests
python tests/mutation_probe.py              # disables each check in turn; reports checks no test depends on (expected: none)
python tests/declaration_search.py out.json # exhaustive search: can a harmful change be declared so that it is accepted? (expected: no; exit status 1 otherwise)
python tests/swap_search.py out.json        # the same question for two kernels with swapped contents (expected: no; exit status 1 otherwise)
```

The first two ask whether the checks that exist are exercised. The third asks the converse — whether the checks are
*sufficient* on a bounded space: it signs every one of 221,184 ways of declaring one harmful change with truthful
evidence files and verifies each under the supplied policy; none is accepted (see `docs/assurance.md`, which also
states what this does not show). `tests/swap_search.py` does the same for two kernels whose contents are swapped. Its entries vary independently
what is claimed and what was actually compared: 144 entries (claimed subjects × claimed replaced files × the 16
transcripts the comparison tool writes for two kernels), all 20,880 declarations of one or two entries; none is
accepted. A shortened version runs in the test suite (`tests/test_renamed_replacement.py`).
`tests/test_risk_exact.py` compares the numeric checks with exact rational arithmetic on random decimals longer than
the default working precision.

## Scope and limits

* **Deterministic transfer only.** The risk budget must be the parent's exactly (`alpha = 0`; decimal strings in
  plain notation, compared as exact values and never added): the transfer adds no sampling error. This does not mean a wrong judgement or a faulty tool carries no risk; those risks are outside the
  budget and are what the printed conditions and the policy are for.
* **Transcripts are the issuer's record.** The verifier checks what a transcript states and what it is bound to. It
  does not re-run the comparison. For a transcript in a foreign layout, read through declared pointers, it also
  cannot see which files the comparison covered; that is printed, and the policy member `transcript_mapping`
  refuses such transcripts.
* **One built-in equivalence method** (exhaustive enumeration). Others are plugins and become part of the relying
  party's trusted base.
* **Judgements are prose.** The tool makes them explicit, signed and attributable; it cannot make them true. A
  policy accepts a judgement by name, or — when it pins a digest — one reviewed text.
* **The adequacy of an enumerated domain is a judgement.** The record states how many inputs were compared; that
  these are all inputs the block can receive is the `boundary` judgement. A policy can require a domain size per
  artifact (`enumeration_domains`); that fixes how many inputs were compared, not which.
* **The inventory is the issuer's statement of what the configuration consists of.** A file that is in neither
  inventory is outside every check.
* **Artifacts are identified by file name.** How a running system reaches a file, and which file of a block a
  comparison exercised, is not visible to the verifier. Whenever names do not settle it — a replacement under another
  name, a block of several files — the record rests on the printed judgement `replacement_correspondence`. Two files
  of the same name cannot be listed in one inventory (`recertkit inventory` refuses them); give them distinct names.
* **A change supported by judgement alone cannot be issued under the built-in profile.** A rebuild with no
  comparison, for example, has no equivalence entry. A relying party that wants such records supplies a profile with
  `require_equivalence: false` (`docs/profiles.md`); the record then says that it rests on judgement.
* **Artifacts are hashed as stored.** Inventory lines are those of `sha256sum`. Records (certificates, inventories,
  evidence files) may be kept gzip-compressed as `<name>.gz`; their digest is that of the uncompressed record.
* **A policy restricts only what its members name.** An absent member imposes no restriction.

## Licence

Apache-2.0. The licence text is in `LICENSE`; `Licence.txt` is an identical copy under the file name the SoftwareX
template asks for. Copyright and third-party notices are in `NOTICE`. Every Python source file carries an SPDX
licence line, except the six files under `examples/gate_root/config_*`, which are artifacts whose digests a stored
certificate binds and are therefore kept byte-identical.
