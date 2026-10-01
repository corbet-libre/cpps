# Privacy Pass gate boundary

The reserved Privacy Pass gate will validate one token through a maintained
Privacy Pass implementation and a configured issuer. It must not identify the
device or create an issuer/member graph. Eligibility comes from the selected
issuer's documented attestation policy; a protocol token alone does not
establish hardware provenance. This follows the separation between attestation
and token verification in [RFC 9576 sections3.1 and3.5](https://www.rfc-editor.org/rfc/rfc9576.html#section-3.1).

One invocation checks one provider result. `cfbk` owns provider ordering and
fallback under `crbk` requirements. No confidence ranking, raw-factor logging,
local security primitive or accepting placeholder is allowed.

No implementation or qualified adapter exists yet. Tests are fixture-only and
do not authorize live provider calls, registration, spending or outreach.
Empty production coverage must remain a blocking failure until the actual
adapter and its adversarial verification tests exist.
