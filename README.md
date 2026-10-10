# cpps

Safe Rust Privacy Pass verification and caller-owned atomic token consumption.
The library authenticates public RFC 9578 tokens with maintained upstream code;
applications decide the issuer policy and protected action. No person or device
identity is invented. Data stays in RAM, with explicit access to requested full
protocol results and redacted diagnostics.

See [the contract](docs/CONTRACT.md) for trust configuration, consumption,
privacy, implemented protocol coverage and qualification limits. No API token or
provider account is needed for local public-token verification; trusted issuer
SPKI material is supplied explicitly. Verification has no provider API charge.
Issuance/attestation fees are separate caller/provider operations and are not
assumed free or performed by this library.

## Scope

A reusable domain library, with minimal consumed-token expiry available to cvld.
Provider ordering and spending authorization belong to cfbk and caller policy.
This crate creates no database connections, performs no live issuer calls and
stores no issuer/member graph. No package has been published or provider enabled.

## Validation

Tests exercise real blind-RSA issuance, unblinding, verification, tampering,
exact operation retries and competing atomic consumption. Crow validation is
required before claiming the implementation tested; live issuer interoperability
is unrun. [Coverage contract](docs/COVERAGE.md).

Copyright 2026 Julian Y. Richard Corbet.
[LGPL-3.0-only WITH LGPL-3.0-linking-exception](LICENSE.md).

See the [provider and protocol catalogue](docs/PROVIDERS.md) for implemented paths,
research candidates, credentials, cost bases and unsupported guarantees.
