use crate::{Challenge, Error, PublicVerifier};
use cfbk::cost::{Amount, Mode, Price, Quote, Unit};
use sha2::{Digest, Sha256};

/// Local simulation summary; cannot become a production consumed-token receipt.
#[derive(Debug, PartialEq, Eq)]
pub struct Simulation {
    /// Whether the supplied explicit fixture authenticates.
    pub accepted: bool,
}
impl PublicVerifier {
    /// Inert local-verification preview. Zero provider-call fees excludes local
    /// computation and any earlier third-party issuance or attestation charge.
    /// Config, mode, challenge and exact token bytes bind this preview.
    pub fn preview(&self, challenge: &Challenge, token: &[u8], mode: Mode) -> Result<Quote, Error> {
        if token.len() > 354 {
            return Err(Error::Configuration);
        }
        let mut hash = Sha256::new();
        hash.update(b"cpps:local-verification:v1\0");
        for value in [
            self.issuer.as_bytes(),
            self.origin.as_bytes(),
            challenge.scope.as_bytes(),
            challenge.wire.as_slice(),
            token,
        ] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value);
        }
        hash.update(self.key_id);
        hash.update([match mode {
            Mode::Simulation => 0,
            Mode::Sandbox => 1,
            Mode::Production => 2,
        }]);
        Ok(Quote {
            price: Price::Exact(Amount {
                unit: Unit {
                    code: "provider-api-calls".into(),
                    scale: 0,
                },
                atoms: 0,
            }),
            source: "Local public-token verification; no network; issuance and compute excluded"
                .into(),
            valid_until: challenge.expires_at,
            binding: format!("{:x}", hash.finalize()),
        })
    }
    /// Execute the real verification transformation against local fixtures only.
    /// Does not consume a token, call state ports or issue a production receipt.
    pub async fn simulate(&self, challenge: &Challenge, fixture: &[u8], now: u64) -> Simulation {
        Simulation {
            accepted: self.verify(challenge, fixture, now, false).await.is_ok(),
        }
    }
}
