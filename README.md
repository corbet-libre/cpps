# cpps

**Privacy Pass admission gate for cvld.**

`cpps` is reserved for redeeming Privacy Pass tokens through an established
implementation. The selected issuer and attester must establish the required
device eligibility; a valid token alone does not imply hardware provenance.
`cvld` receives an opaque result bound to its configured issuer.

Status: name reserved, no implementation or qualified provider adapter yet.
One invocation checks one provider result; `cfbk` owns ordering/fallback and
`crbk` owns requirements. Empty production coverage is a blocking failure.
See [the current contract](docs/CONTRACT.md).

## Boundaries

What it does:

- Verifies Privacy Pass tokens from trusted issuers and returns an opaque gate proof bound to its configured provider.

What it never does:

- Never links a token to a device identity or a member beyond the opaque proof.
- Raw factor data never reaches `cvld`: it receives only an opaque proof bound to its configured provider. No raw data in output, logs, errors or fixtures.
- No own security primitives: a thin wrapper around the established best-practice library for the factor.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under
[LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt)
[WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt).
See [LICENSE.md](LICENSE.md).

## Continuous verification

Dependency updates follow main and are tested against one CI-resolved lockfile.
Line and branch coverage target 100%; failures remain blocking. See
[the coverage contract](docs/COVERAGE.md) for measurement and exclusions.
