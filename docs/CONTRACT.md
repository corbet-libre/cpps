# Privacy Pass contract

cpps verifies RFC 9578 public tokens (type 0x0002, RSA-2048/PSS/SHA-384) using
[privacypass](https://github.com/raphaelrobert/privacypass). The caller supplies
trusted issuer/origin configuration and an authenticated issuer SPKI key.
No issuer discovery, network access, secret acquisition or provider fee occurs.

`PublicVerifier::challenge` creates a challenge from fresh, unpredictable caller
context and an exclusive expiry. The caller binds that context to its actual
subject/action and retains continuation only as needed. `verify` checks exact
binary length, type, complete key ID, challenge digest, expiry and the upstream
signature. It cannot be turned into verification by deserializing a result.

`VerifiedToken` is authenticated but unconsumed. `consume` invokes the caller's
atomic `(scope, marker, operation)` port. Exactly one distinct operation may win;
an identical operation can recover its result. The host must bind operation IDs
to the actual protected action and preserve claims for their required lifetime.
No crate-owned RAM counter substitutes for cross-process replay protection.

The comparison marker is a domain-separated hash of a high-entropy signed token.
It is not a person or device identifier. The caller's issuer policy determines
what attestation preceded issuance; Privacy Pass itself does not establish it.

Inputs, challenge state and optional original token bytes remain in RAM. Full
protocol bytes require an explicit request; ordinary Debug is redacted. Owned
original buffers zeroize on drop. Upstream parsing/crypto may create temporary
copies; host-controlled swap, dumps and caller copies are outside this guarantee.
No database, disk cache, telemetry or generic raw-payload journal is provided.

The maintained implementation is currently on upstream main, prerelease
0.2.0-pre.3; registry 0.1.0 is an empty placeholder and was rejected. Cargo.lock
records the resolved upstream commit. Its authors state it has no independent
security audit; interoperability and independent review remain qualification
limits. Our tests use actual blind issuance/unblinding, verification, tampering
and concurrent caller-state claims. No live issuer has been called.

Public RSA tokens are implemented. Private VOPRF, amortized/batched protocols,
issuer discovery and provider attestation enrolment are documented candidates,
not qualified integrations. Cloudflare, Apple and Fastly are not automatically
trusted merely because they support related protocols.
