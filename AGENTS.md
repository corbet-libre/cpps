# Agent instructions

Write all code comments and documentation in English.

## Product boundary

- Privacy Pass admission gate for cvld: proof of a real device without identifying it.
- Verifies Privacy Pass tokens from trusted issuers and returns an opaque gate proof bound to its configured provider.
- Never links a token to a device identity or a member beyond the opaque proof.
- Raw factor data never reaches `cvld`: it receives only an opaque proof bound to its configured provider. No raw data in output, logs, errors or fixtures.
- No own security primitives: a thin wrapper around the established best-practice library for the factor.
- This crate is LGPL-3.0-only WITH LGPL-3.0-linking-exception. Do not add implementation code available only under the full GPL or AGPL.
- Tests use fixtures only; no live calls to third-party providers.

## Quality boundary

- `cargo fmt --check`, `cargo clippy --all-targets` (no warnings),
  `cargo test` — all green before every commit. No local workstation
  builds; use GHA, Crow as fallback.
