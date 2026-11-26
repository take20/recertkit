# Using RecertKit as a release gate in CI

`release-gate.yml` is a GitHub Actions workflow for a repository that ships a deployed configuration together with
its certificate chain. On every release tag it verifies the chain with the relying party's trusted key and
acceptance policy, and the release job runs only if the record is valid **and** the policy accepts (exit status 0
with `--policy`; a policy that could not be fully evaluated also blocks the release).

The workflow assumes this layout in the repository that uses it:

```
certs/root.json  certs/derived_*.json  certs/inventory_*.txt  certs/<evidence files>
deploy/<the files of the configuration to be released>   # flat; the names used in the last inventory
release/trusted.pub        # the public key the relying party trusts — NOT taken from the certificate
release/policy.json        # the acceptance policy (docs/policy.md)
```

Three points the workflow encodes:

1. `issue` is run by whoever makes the change, on their machine. It is not the gate.
2. The gate is `verify-chain` over the **whole** chain, with a key and a policy that live in the relying party's
   repository, pinned by path.
3. A chain is a statement about the configuration its last inventory lists. `verify-chain` checks that inventory
   against the digest signed in the last certificate; it does not see the files that will be shipped. The second
   step therefore checks the files in `deploy/` against that inventory with `sha256sum --check` and requires
   that `deploy/` holds no further file. Without this step the workflow shows that *some* configuration is
   covered by an acceptable chain, not that the released one is.
4. The JSON report is stored as a build artifact, so the list of unchecked conditions that the policy accepted is
   kept with the release.

Status as of 2026-11-16: the workflow file is a template and has not been executed on GitHub by the authors. This
is a statement about what was done, not about what is possible: GitHub Actions also runs in private repositories.
Its verification step was executed locally, as written, on the quick-start chain arranged in the layout above: it
exits with status 0 under the quick-start policy and with status 1 when the policy is changed so that it no longer
accepts one of the judgements (`docs/assurance.md`, "What is executed for a release"). The step that compares
`deploy/` with the last inventory (added in 1.4.0) was executed locally on the same chain, on macOS with
`shasum -a 256` standing in for `sha256sum`: status 0 for the files of the last configuration, status 1 when one
file is modified, when one is missing, when a further file is present, and when the files of the previous
configuration are deployed.
