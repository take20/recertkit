# Acceptance policies

Record verification deliberately accepts chains that rest on judgements, assumptions, undistributed evidence or
weak root bindings — and prints them. Whether such conditions are acceptable for a release is the relying party's
decision. A policy states it as data; `verify-chain --policy FILE` applies it to every link and reports a second
verdict.

## Verdicts and exit status

| verdict | meaning | exit status |
|---|---|---|
| `POLICY <name>: ACCEPTED` | the record is valid, and every condition of the policy was evaluated and is satisfied | 0 |
| `POLICY <name>: REJECTED` | the record is invalid, or a condition is violated | 1 |
| `POLICY <name>: NOT EVALUATED` | no condition is violated, but at least one could not be evaluated in this run | 3 |
| *(no verdict)* `recertkit: policy error (PolicyError): …` | the policy file is not a well-formed policy; nothing was evaluated | 2 |
| `POLICY: none applied` | no `--policy` was given; a valid record exits 0, which is **not** a release decision | 0 if the record is valid |

A condition is evaluated on the **link state the verifier established** (`docs/concepts.md`, "Link state"), not on
fields of the certificate where a verified value exists. For example, `reference_by_declaration: "forbid"` is
satisfied only if, for every comparison, the verifier matched a reference digest recorded in the transcript; a
digest written in the certificate does not count (and is a record failure).

A policy is a statement about a whole chain. `verify --policy` on the first link after a root evaluates it
completely. On a later link it reports `NOT EVALUATED` (`policy.chain`): the earlier links were not evaluated, and
conditions about the root format, the root binding levels or an inherited reference cannot be. Use `verify-chain`
for a release decision.

## Members

A policy is a JSON object. Every member except `name` is optional. **An absent member imposes no restriction**, so
a policy is only as strict as the members it states.

**A malformed policy is a configuration error, never a weaker policy.** Each member has one JSON type and a closed
set of values (table below). The following end with exit status 2 before anything is evaluated: an unknown member;
a value of another type (`0`, `1`, `"true"`, `""` or `[]` where `true`/`false` is required; a string where a list
is required); `null` for any member — a condition is left unstated by omitting its member, not by setting it to
`null`; a member that appears twice; and a policy that states no condition at all (every member absent, `false`,
`"allow"` or `"*"`), because `ACCEPTED` always means that at least one stated condition was evaluated and
satisfied. The same validation applies when a policy is passed to `verify_chain` / `verify_link` as a Python
object. (Up to 1.3.1 `require_all_evidence` and `require_prospective` were tested by truthiness and `null` was
read as "absent" for three members, so that such a policy produced `ACCEPTED` with no policy check; see
`CHANGELOG.md`, 1.4.0.)

**Allowing is not requiring.** `accepted_judgements`, `accepted_assumptions`, `reference_kinds`, `binding_levels`
and `root_adapters` are allow-lists: they limit what a chain may rest on. They do not require a chain to carry a
listed judgement or assumption; a chain that carries none of them satisfies the condition.

| member | values | condition |
|---|---|---|
| `require_all_evidence` | `true` | every evidence file named by a link is present |
| `coverage_by_judgement` | `"forbid"`, `"allow"`, or a list of artifact names | which changed artifacts may rest on a judgement |
| `residual_rebuilt`, `unrecorded` | `"forbid"`, `"allow"` | artifacts in these categories |
| `reference_kinds` | list | accepted comparison references (`parent_artifact`, `parent_link`, `specification`) |
| `reference_by_declaration` | `"forbid"`, `"allow"` | comparisons whose reference the verifier could not tie to the certificate by a transcript digest |
| `binding_levels` | list | accepted root binding levels (`digest`, `identifiers-only`, `unbound`), as provided by the root |
| `transcript_mapping` | `"forbid"`, `"allow"` | foreign transcript layouts read through issuer-declared pointers. For such a transcript the verifier cannot see whether the comparison covered further files than the entry claims (`subject_scope` applies to the standard layout only); allowing the mapping accepts that too |
| `renamed_replacement` | `"forbid"`, `"allow"` | equivalence entries that replace a parent artifact by a subject of another name (they rest on the judgement `replacement_correspondence`) |
| `multi_artifact_block` | `"forbid"`, `"allow"` | equivalence entries with several subjects or several replaced artifacts (they rest on the same judgement: which file the comparison exercised is not visible to the verifier) |
| `enumeration_domains` | `{artifact: N}` | every equivalence entry is an exhaustive enumeration, each of its subjects is listed, and its domain has exactly `N` inputs |
| `accepted_judgements`, `accepted_assumptions` | `"*"`, a list of names, or `{name: "*" \| sha256}` | every judgement / assumption of a link is listed; with a digest, its text must be exactly the reviewed text |
| `root_adapters` | list | accepted root formats |
| `require_prospective` | `true` | the link declares prospective issuance (the declaration is the issuer's) |

### Judgements by name and by text

Accepting a judgement **by name** means: *we are prepared to rely on a judgement of this kind*. Two certificates can
carry different statements under one name, and the policy cannot tell. Where that matters, pin the text:
`recertkit texts --certificate C` prints the SHA-256 of every judgement and assumption text of a certificate; a
policy with `"accepted_judgements": {"boundary": "<sha256>"}` then accepts only the text that was reviewed. The
policy does not, and cannot, check that a text is true.

### Why `enumeration_domains` exists

The record states how many inputs an enumeration covered, and prints it. It cannot know whether that is the whole
input domain of the block: that is the `boundary` judgement. A truthful comparison on a single input, combined with
a `boundary` text that a policy accepts by name, would otherwise be accepted. The supplied release policies
therefore state the required domain **size** per artifact (`{"kernel.py": 65536}`); a comparison whose enumerated
domain has any other size, or with a subject for which no size is stated, is rejected.

The member checks a number, nothing more. Which inputs were enumerated, that they are distinct, and that they are
all the inputs the block can receive in the deployed configuration are not checked: a comparison over a different
set of the same size satisfies the member. Domain identity and coverage remain the `boundary` judgement, which is
printed on every run and which a policy can pin by its text.

## Examples

`examples/quickstart/policy.json`, `examples/gate_root/policy.json` — release policies that admit only
machine-linked evidence with the required number of enumerated inputs for the kernel (65,536), digest-level
bindings and three named conditions. The
quick-start and gate-root chains are accepted.

`examples/fpga_ultra96/policy_strict.json` — the same kind of policy applied to the case-study chain: **rejected**;
14 of its 24 checks fail (an absent evidence file, two artifacts covered by judgement, rebuilt and unrecorded
artifacts, a specification as reference, references the verifier could not tie by digest, identifier-only and
unbound root bindings, pointer-mapped transcripts, a bitstream replaced under another name, retrospective issuance).

`examples/fpga_ultra96/policy_case_study.json` — the conditions under which the authors accept that chain, written
out: every judgement and assumption by name. **Accepted.** The two files together show what "VALID" left open.
