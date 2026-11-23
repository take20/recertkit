# Profiles and method plugins

## Profiles

A profile is the verifier's rule set, as data. `recertkit profile` prints the built-in `recertkit-default-1`:

* claim fields: `metric_definition` (string), `degradation_direction` (`reference_minus_candidate`), `margin` and
  `risk_level` (decimal strings in plain notation, in (0,1)), `sampling_regime` (`r2`, a fixed finite evaluation frame);
* roles: `server` (may change), `model` and `frame` (fixed);
* accepted methods: `exhaustive_enumeration`; accepted reference kinds: `parent_artifact`, `parent_link`,
  `specification`;
* `coverage_by_judgement: true` — a changed artifact may be covered by a named judgement (it is then printed);
  set it to `false` to make equivalence evidence mandatory for every changed artifact;
* `require_equivalence: true` — a link must contain at least one equivalence entry. A change supported by judgement
  alone (a rebuild with no comparison: every changed artifact declared `residual_rebuilt`) can therefore not be
  issued under the built-in profile. A profile that sets it to `false` admits such links; they are valid records
  whose notices say that they rest on judgement, and the policy member `residual_rebuilt` can refuse them
  (`tests/test_robustness.py`);
* required judgements: `boundary`, `residual_path`; `unrecorded_items` when artifacts are unrecorded;
  `root_configuration` when a root binding is weaker than a digest;
* `deterministic_only: true` — this version rejects any profile that sets it to false.

A relying party can supply its own profile (`--profile lab.json`): other claim fields, other roles, other accepted
methods or reference kinds. The certificate records the profile's name and digest; verification under any other
profile fails (`certificate.profile`). The profile is the verifier's input, never the certificate's, so a
certificate cannot loosen the rules it is checked against.

Profile versus policy: the profile defines what a *well-formed record* is and is fixed for a whole chain; the
policy (`docs/policy.md`) is a relying party's decision about the *conditions* a well-formed record rests on, and
different relying parties can apply different policies to the same chain.

## Method plugins

A method checks what is specific to one kind of equivalence evidence. It does **not** check which artifacts the
transcript is about or what they were compared with: the engine does that for every method, from the transcript's
`subjects` and `reference` (or the entry's pointer mapping), before the method runs. A plugin can therefore add a
kind of evidence but cannot omit the identity checks.

```python
# my_methods.py
def proof_status(entry, transcript):
    """entry: the certificate's equivalence entry; transcript: the parsed evidence file."""
    return [("proof_status", transcript.get("status") == "proved", str(transcript.get("status")))]

def register(registry):
    registry["signed_off_proof"] = proof_status
```

Each returned tuple `(suffix, ok, detail)` is reported as the check `equivalence.<entry id>.<suffix>`.
Use it with `--plugin my_methods.py --profile lab.json` on `issue`, `verify` and `verify-chain` (the profile must
list `signed_off_proof` in `methods`). A plugin runs inside the verifier and is part of the relying party's trusted
base. `tests/test_positive.py::test_custom_profile_and_plugin_method` is a complete example, including a transcript
that the engine refuses although the plugin's own check passes.

## Extension points at a glance

| extension | how | trust |
|---|---|---|
| claim fields, roles, accepted methods and references | profile JSON | relying party's input |
| acceptance conditions | policy JSON | relying party's input |
| equivalence methods | plugin file | part of the relying party's trusted base |
| transcript layouts of existing tools | `pointers` in the equivalence entry | issuer's declaration (printed; refusable by policy) |
| root formats | adapter class in `recertkit/roots.py` | part of the tool |
