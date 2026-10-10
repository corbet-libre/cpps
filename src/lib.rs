//! RFC 9578 public-token verification; no device or person identity is inferred.
#![forbid(unsafe_code)]

mod planning;
mod upstream;
pub use planning::Simulation;

use blind_rsa_signatures::{Deterministic, PSS, PublicKey, Sha384};
use privacypass::{
    Deserialize, TokenType,
    auth::{authenticate::TokenChallenge, authorize::Token},
};
use sha2::{Digest, Sha256};
use std::{fmt, future::Future};
use typenum::U256;
use zeroize::Zeroizing;

/// Rejected inputs never expose the token, nonce or upstream error text.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Invalid trusted configuration or bounded request.
    #[error("invalid Privacy Pass configuration")]
    Configuration,
    /// Authentication, challenge, type, key or expiry validation failed.
    #[error("Privacy Pass rejected")]
    Rejected,
    /// Atomic caller state failed or token already consumed for another request.
    #[error("Privacy Pass consumption refused")]
    Consumption,
}

/// Local verifier with explicitly supplied trusted issuer configuration.
pub struct PublicVerifier {
    issuer: String,
    origin: String,
    key: PublicKey<Sha384, PSS, Deterministic>,
    key_id: [u8; 32],
}
impl PublicVerifier {
    /// Import a trusted issuer's RSA-PSS SHA-384 SPKI key out of band.
    /// The caller authenticates configuration; a token cannot choose it.
    pub fn new(issuer: String, origin: String, spki: &[u8]) -> Result<Self, Error> {
        server_name(&issuer)?;
        server_name(&origin)?;
        if spki.is_empty() || spki.len() > 4096 {
            return Err(Error::Configuration);
        }
        let key = PublicKey::from_spki(spki).map_err(|_| Error::Configuration)?;
        let encoded = key.to_spki().map_err(|_| Error::Configuration)?;
        let key_id = Sha256::digest(encoded).into();
        Ok(Self {
            issuer,
            origin,
            key,
            key_id,
        })
    }
    /// Create a challenge for an independently authenticated context.
    /// `context` is a fresh unpredictable application challenge, bound by the
    /// caller to its subject/action. The caller owns continuation across requests.
    pub fn challenge(
        &self,
        scope: String,
        context: [u8; 32],
        expires_at: u64,
    ) -> Result<Challenge, Error> {
        identifier(&scope)?;
        if context == [0; 32] || expires_at == 0 {
            return Err(Error::Configuration);
        }
        let token = TokenChallenge::new(
            TokenType::Public,
            &self.issuer,
            Some(context),
            std::slice::from_ref(&self.origin),
        );
        let wire = token.serialize().map_err(|_| Error::Configuration)?;
        Ok(Challenge {
            issuer: self.issuer.clone(),
            origin: self.origin.clone(),
            scope,
            wire,
            digest: token.digest().map_err(|_| Error::Configuration)?,
            key_id: self.key_id,
            expires_at,
        })
    }
    /// Verify a binary RFC token against this exact, trusted challenge.
    /// Success is not consumption: call [`VerifiedToken::consume`] before acting.
    /// Original protocol bytes are returned only when explicitly requested.
    pub async fn verify(
        &self,
        challenge: &Challenge,
        bytes: &[u8],
        now: u64,
        return_token: bool,
    ) -> Result<VerifiedToken, Error> {
        if now >= challenge.expires_at
            || bytes.len() != 354
            || challenge.key_id != self.key_id
            || challenge.issuer != self.issuer
            || challenge.origin != self.origin
        {
            return Err(Error::Rejected);
        }
        let mut input = bytes;
        let token = Token::<U256>::tls_deserialize(&mut input).map_err(|_| Error::Rejected)?;
        if !input.is_empty()
            || token.token_type() != TokenType::Public
            || token.challenge_digest() != &challenge.digest
            || token.token_key_id() != &self.key_id
        {
            return Err(Error::Rejected);
        }
        upstream::verify(self.key.clone(), token).await?;
        // A consumption marker is not an identity or a registration key.
        let mut hash = Sha256::new();
        hash.update(b"cpps:consumption:v1\0");
        hash.update(self.key_id);
        hash.update(bytes);
        Ok(VerifiedToken {
            marker: hash.finalize().into(),
            scope: challenge.scope.clone(),
            expires_at: challenge.expires_at,
            original: return_token.then(|| Zeroizing::new(bytes.to_vec())),
        })
    }
}

/// Server-created challenge, not deserializable from member input.
pub struct Challenge {
    issuer: String,
    origin: String,
    scope: String,
    wire: Vec<u8>,
    digest: [u8; 32],
    key_id: [u8; 32],
    expires_at: u64,
}
impl Challenge {
    /// Protocol challenge sent to the holder.
    pub fn wire(&self) -> &[u8] {
        &self.wire
    }
    /// Exclusive caller-selected expiry.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// Authenticated token; no device/person interpretation.
pub struct VerifiedToken {
    marker: [u8; 32],
    scope: String,
    expires_at: u64,
    original: Option<Zeroizing<Vec<u8>>>,
}
impl VerifiedToken {
    /// Explicit access to original bytes, if requested during verification.
    pub fn original(&self) -> Option<&[u8]> {
        self.original.as_deref().map(Vec::as_slice)
    }
    /// Atomically consume in caller state. Exact operation retries are idempotent.
    /// The caller binds this operation to its actual protected action.
    pub async fn consume<S: ConsumptionStore>(
        &self,
        store: &S,
        operation: &str,
        now: u64,
    ) -> Result<ConsumedToken, Error> {
        identifier(operation)?;
        if now >= self.expires_at {
            return Err(Error::Rejected);
        }
        store.consume(&self.scope, self.marker, operation).await?;
        Ok(ConsumedToken {
            expires_at: self.expires_at,
        })
    }
}

/// Trusted caller-owned cross-process single-use state. Atomically allow one
/// operation per `(scope, marker)`, permit exact retries, reject changed operations.
/// Storage failures must refuse. No DB connector or process-local counter ships.
pub trait ConsumptionStore: Sync {
    /// Consume only the opaque marker and necessary operational binding.
    fn consume(
        &self,
        scope: &str,
        marker: [u8; 32],
        operation: &str,
    ) -> impl Future<Output = Result<(), Error>> + Send;
}
/// Minimal receipt, constructible only after authentication and atomic claim.
pub struct ConsumedToken {
    expires_at: u64,
}
impl ConsumedToken {
    /// Maximum exclusive lifetime; consumer policy may shorten it.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

macro_rules! redacted {
    ($($ty:ty),* $(,)?) => {$ (impl fmt::Debug for $ty {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(concat!(stringify!($ty), "([redacted])")) }
    })*};
}
redacted!(PublicVerifier, Challenge, VerifiedToken, ConsumedToken);
fn identifier(value: &str) -> Result<(), Error> {
    if value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
        Err(Error::Configuration)
    } else {
        Ok(())
    }
}
fn server_name(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 253
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".-:[]".contains(&c))
    {
        Err(Error::Configuration)
    } else {
        Ok(())
    }
}
#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
