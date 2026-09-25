# cpps

**Privacy Pass admission gate for cvld.**

`cpps` will redeem Privacy Pass tokens to prove that a request comes from a real device, wrapping an established Privacy Pass implementation. `cvld` receives only an opaque proof and its trust anchor.

Status: name reserved, no implementation yet.

## Boundaries

What it does:

- Verifies Privacy Pass tokens from trusted issuers and returns an opaque gate proof with its trust anchor.

What it never does:

- Never links a token to a device identity or a member beyond the opaque proof.
- Raw factor data never reaches `cvld`: it receives only an opaque proof with its trust anchor. No raw data in output, logs, errors or fixtures.
- No own security primitives: a thin wrapper around the established best-practice library for the factor.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under
[LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt)
[WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt).
See [LICENSE.md](LICENSE.md).
