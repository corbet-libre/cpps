//! Maintained protocol verification without delegating durable application state.
use crate::Error;
use async_trait::async_trait;
use blind_rsa_signatures::{Deterministic, PSS, PublicKey, Sha384};
use privacypass::{
    Nonce, NonceStore, TruncatedTokenKeyId,
    auth::authorize::Token,
    public_tokens::server::{OriginKeyStore, OriginServer},
};
use std::sync::atomic::{AtomicBool, Ordering};
use typenum::U256;

struct Key(PublicKey<Sha384, PSS, Deterministic>);
#[async_trait]
impl OriginKeyStore for Key {
    async fn insert(&self, _: TruncatedTokenKeyId, _: PublicKey<Sha384, PSS, Deterministic>) {}
    async fn get(&self, _: &TruncatedTokenKeyId) -> Vec<PublicKey<Sha384, PSS, Deterministic>> {
        vec![self.0.clone()]
    }
    async fn remove(&self, _: &TruncatedTokenKeyId) -> bool {
        false
    }
}
// This private reservation only sequences one upstream verification call. It
// cannot confer application replay protection; that is the caller's atomic port.
#[derive(Default)]
struct VerificationNonce(AtomicBool);
#[async_trait]
impl NonceStore for VerificationNonce {
    async fn reserve(&self, _: &Nonce) -> bool {
        !self.0.swap(true, Ordering::SeqCst)
    }
    async fn commit(&self, _: &Nonce) {}
    async fn release(&self, _: &Nonce) {
        self.0.store(false, Ordering::SeqCst);
    }
}
pub(crate) async fn verify(
    key: PublicKey<Sha384, PSS, Deterministic>,
    token: Token<U256>,
) -> Result<(), Error> {
    OriginServer::new()
        .redeem_token(&Key(key), &VerificationNonce::default(), token)
        .await
        .map_err(|_| Error::Rejected)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_upstream_ports_do_not_confer_application_consumption() {
        futures::executor::block_on(async {
            let v = crate::tests::verifier();
            let key = Key(v.key);
            key.insert(0, key.0.clone()).await;
            assert!(!key.remove(&0).await);
            assert_eq!(key.get(&0).await.len(), 1);
            let nonce = VerificationNonce::default();
            assert!(nonce.reserve(&[1; 32]).await);
            assert!(!nonce.reserve(&[1; 32]).await);
            nonce.commit(&[1; 32]).await;
            nonce.release(&[1; 32]).await;
            assert!(nonce.reserve(&[1; 32]).await);
        });
    }
}
