# Provider and protocol catalogue

## Provider and protocol arsenal

Primary documentation reviewed 2026-10-10. **Implemented** means the local
fixture-tested path described here, not live-provider qualification.
**Extension-compatible** means the existing trusted interface can carry the
integration; provider-specific authentication/correlation still needs work.
**Candidate** means researched only. **Unsupported** means the stated guarantee
must not be inferred. These are integration options, not activated services.

Every future network route needs an explicit injected credential, account/mode
binding, bounded cost quote with provenance and expiry, atomic host reservations,
fresh dispatch deadlines, rich private reports and negative fixtures. Unknown
prices block dispatch. Cost bases below identify what a host must obtain; they
are not current numeric quotations or permission to contact the provider.

| Ecosystem and source | Status / reuse path | Credentials and cost basis | Semantic limit |
|---|---|---|---|
| [Rust `privacypass`](https://github.com/raphaelrobert/privacypass) + [RFC 9578](https://www.rfc-editor.org/rfc/rfc9578.html) | Implemented public token type 0x0002 verification; upstream owns blind-RSA verification. | Inject authenticated issuer SPKI, origin and challenge context; zero remote verification fee, excluding compute and issuance. | Upstream warns it is unaudited; professional security review remains a production qualification requirement. The integrated git-main graph is CI locked. |
| [Cloudflare issuer/origin deployment](https://developers.cloudflare.com/privacy-pass/concepts/deployment-models/) | Extension-compatible protocol candidate where issued token type/key/challenge match; no hosted-provider flow implemented. | Trusted issuer directory keys and origin configuration; obtain account/issuer/attester/edge-service terms, never assume issuance is free. | Issuer, attester and origin roles carry different information. Key selection/anonymity sets affect privacy; no universal person identity follows. |
| [Cloudflare `privacypass-ts`](https://github.com/cloudflare/privacypass-ts/blob/main/README.md) | Candidate interoperability oracle/client or separate issuer service; not a Rust runtime replacement. | Local keys for fixtures; real issuance/hosting credentials and tariff belong to the external deployment. | Public, private, metadata and batch protocols differ. Its additional token types are not automatically supported by cpps. |
| [Apple Private Access Tokens](https://developer.apple.com/icloud/identity/) | Candidate deployment through supported attester/issuer/origin roles; no Apple device ceremony implemented. | Approved issuer/origin trust and deployment credentials; provider programme/hosting quote before any remote operation. | Device attestation is not an identity census. Client eligibility and deployment policy cannot be inferred from a raw token alone. |
| [RFC 9577 HTTP authentication](https://www.rfc-editor.org/rfc/rfc9577.html) and RFC 9578 private tokens | Candidate additional HTTP plumbing/private-token integration using upstream implementations. | Private redemption would need issuer secret-key custody at its designated service; this public-key verifier requires none. Quote remote redemption separately. | No private VOPRF, metadata or batch redemption is currently exposed. Do not reinterpret one token type as another. |
| [Legacy Cloudflare WAF Privacy Pass](https://developers.cloudflare.com/waf/tools/privacy-pass/) | Unsupported legacy route, retained here to prevent stale integration plans. | No credentials or price assumed; current deployment must use current documented interfaces. | Legacy token/API retirement is not a supported modern issuer integration. Turnstile itself belongs to cfrt, not an invented Privacy Pass token format. |

Keep issuer issuance, attestation and origin consumption separate. cpps proves a
valid token for its challenge and uses the caller's atomic consumption port; it
never invents a person identifier or claims live provider/device qualification.
