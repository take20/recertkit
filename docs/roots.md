# Roots, adapters and binding levels

RecertKit carries a claim; it does not establish one. The claim comes from a *root certificate*, and an adapter
tells RecertKit how to read it. `recertkit root-info --root FILE` prints what the adapter reads.

## Binding levels

For each configuration role and for the inventory as a whole, a root provides one of:

| level | meaning | consequence |
|---|---|---|
| `digest` | the root binds the SHA-256 of the artifact (or of the inventory file) | checked against the parent inventory |
| `identifiers-only` | frame only: the root binds the item identifiers, not the content | identifiers checked; content identity is printed as a boundary |
| `unbound` | the root says nothing checkable | printed; the `root_configuration` judgement is required |

A first link declares the levels in `root_binding`; the verifier compares the declaration with the root
(`roles.binding_level.*`, `root.inventory_level`). A level can therefore be neither overstated nor silently weak,
and an acceptance policy can refuse anything below `digest` (`binding_levels`).

Why the inventory matters: role artifacts are the program, the model and the frame. A changed block is often
*none* of them (a kernel, a bitstream, a library). Unless the root binds the whole inventory, nothing in the root
says which kernel the certified configuration contained, and "the parent's kernel" is then tied to the root by the
`root_configuration` judgement only.

## `recertkit-root-1`

Written by `recertkit root-issue`. Binds every role by digest and, with `--inventory`, the inventory. It is an
attestation by the key holder: *how* the claim was established is the free-text `basis` and is printed as not
verified. Use it when no certification tool provides a root, and for tests.

## `gate-2.0` — certificates of the anytime-valid release gate

The release gate (described in the release-gate paper cited in the main README) issues certificates with
`certificate_version` `"2.0"`. The adapter reads:

| gate field | used as |
|---|---|
| `estimand` (`metric_definition`, `degradation_direction`, `margin`, `risk_level`, `sampling_regime`) | the claim |
| `decision` | must be `certified` |
| `candidate_configuration.artifact_sha256`, `.artifact_filename` | `model` role (required by the gate's schema) |
| `candidate_configuration.server_binary_sha256` | `server` role — **optional extension field** |
| `candidate_configuration.configuration_inventory_sha256` | inventory binding — **optional extension field** |
| `task_manifest_hash` | frame binding: level `digest` if it equals the SHA-256 of the frame file, `identifiers-only` if it is the hash of an identifier manifest |
| `commitment_digest_sha256` + the commitment file | frame identifiers, regime, margin and risk are re-checked against the commitment |

The two extension fields are not part of the gate's required schema. The gate accepts additional configuration
fields and commits to the *whole* candidate configuration object by digest, so adding them **before `commit`**
makes them part of what the gate certifies, without any change to the gate.

### Recipe: a gate certificate that binds everything

1. Write the inventory of the candidate configuration: `recertkit inventory … --out inventory_c0.txt`.
2. Put `"server_binary_sha256"` and `"configuration_inventory_sha256"` into the candidate configuration JSON.
3. Run the gate's `commit` with `--tasks <the frame file itself>` (not an identifier manifest), then its `issue`.
4. `recertkit root-info --root gate_root_certificate.json` should show both digests and a `task_manifest_hash`
   equal to the frame file's SHA-256.

`examples/gate_root/` does exactly this with the real gate on the toy system; `make_example.py` documents every
command. The resulting chain needs no boundary notice and passes a policy that demands digest-level bindings.

### Limited mode: gate certificates without the extension fields

A gate certificate that carries only the required fields is still usable:

* `server` and the inventory are `unbound` → the link must declare that and include a `root_configuration`
  judgement; both are printed on every verification;
* if `commit` was given an identifier manifest as `--tasks`, the frame is `identifiers-only` → printed as a frame
  boundary.

`examples/fpga_ultra96/` is such a chain (inventory unbound, frame identifiers-only), and
`tests/test_gate_example.py::test_gate_root_with_required_fields_only_is_usable_in_limited_mode` covers the case of
a certificate with the required fields only. Compatibility is therefore *field-level and declared*, not unconditional:
what a given gate certificate binds is shown by `root-info`, and everything it does not bind becomes a printed
condition.

RecertKit does not re-verify the gate's own evidence (record order, sequential-test replay). Run the gate's
verifier for that; RecertKit prints this as `root protocol`.

## Other root formats

An adapter is a small class (`recertkit/roots.py`) with `claim`, `decision`, `risk`, `role_binding(role, digest)`,
`role_filename(role)`, `inventory_digest()` and `extra_checks(...)`. Adapters are part of the tool, not plugins,
because they define what a root is taken to mean.
