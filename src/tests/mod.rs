use super::*;
use blind_rsa_signatures::reexports::rand::rng;
use futures::executor::block_on;
use privacypass::{
    Serialize,
    public_tokens::{
        TokenRequest,
        server::{IssuerServer, serialize_public_key},
    },
    test_utils::public_memory_store::IssuerMemoryKeyStore,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, OnceLock},
};

struct Fixture {
    spki: Vec<u8>,
    bytes: Vec<u8>,
}
fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        block_on(async {
            let store = IssuerMemoryKeyStore::default();
            let issuer = IssuerServer::new();
            let key = issuer.create_keypair(&mut rng(), &store).await.unwrap();
            let challenge = TokenChallenge::new(
                TokenType::Public,
                "issuer.example",
                Some([7; 32]),
                &["origin.example".into()],
            );
            let (request, state) = TokenRequest::new(&mut rng(), key.clone(), &challenge).unwrap();
            let token = issuer
                .issue_token_response(&store, request)
                .await
                .unwrap()
                .issue_token(&state)
                .unwrap();
            Fixture {
                spki: serialize_public_key(&key).unwrap(),
                bytes: token.tls_serialize_detached().unwrap(),
            }
        })
    })
}
fn verifier() -> PublicVerifier {
    PublicVerifier::new(
        "issuer.example".into(),
        "origin.example".into(),
        &fixture().spki,
    )
    .unwrap()
}
fn challenge(v: &PublicVerifier) -> Challenge {
    v.challenge("scope".into(), [7; 32], 200).unwrap()
}
#[derive(Default)]
struct Claims(Mutex<BTreeMap<(String, [u8; 32]), String>>);
impl ConsumptionStore for Claims {
    async fn consume(&self, scope: &str, marker: [u8; 32], operation: &str) -> Result<(), Error> {
        let mut claims = self.0.lock().unwrap();
        match claims.get(&(scope.to_owned(), marker)) {
            Some(prior) if prior != operation => Err(Error::Consumption),
            _ => {
                claims.insert((scope.to_owned(), marker), operation.into());
                Ok(())
            }
        }
    }
}
#[test]
fn real_protocol_roundtrip_and_atomic_usage() {
    block_on(async {
        let v = verifier();
        let c = challenge(&v);
        assert_eq!(c.expires_at(), 200);
        assert_eq!(
            TokenChallenge::deserialize(c.wire())
                .unwrap()
                .digest()
                .unwrap(),
            c.digest
        );
        let verified = v.verify(&c, &fixture().bytes, 100, true).await.unwrap();
        assert_eq!(verified.original().unwrap(), &fixture().bytes);
        let store = Claims::default();
        assert_eq!(
            verified
                .consume(&store, "action-a", 100)
                .await
                .unwrap()
                .expires_at(),
            200
        );
        assert!(verified.consume(&store, "action-a", 101).await.is_ok());
        assert_eq!(
            verified.consume(&store, "action-b", 101).await.unwrap_err(),
            Error::Consumption
        );
        assert_eq!(
            verified.consume(&store, "", 101).await.unwrap_err(),
            Error::Configuration
        );
        assert_eq!(
            verified.consume(&store, "action-a", 200).await.unwrap_err(),
            Error::Rejected
        );
        assert!(
            v.verify(&c, &fixture().bytes, 100, false)
                .await
                .unwrap()
                .original()
                .is_none()
        );
        for debug in [
            format!("{v:?}"),
            format!("{c:?}"),
            format!("{verified:?}"),
            format!(
                "{:?}",
                verified.consume(&store, "action-a", 100).await.unwrap()
            ),
        ] {
            assert!(debug.contains("redacted"));
            assert!(!debug.contains("issuer.example"));
        }
    });
}
#[test]
fn reject_malformed_forged_wrong_context_and_expired_tokens() {
    block_on(async {
        let v = verifier();
        let c = challenge(&v);
        assert_eq!(
            v.verify(&c, &fixture().bytes, 200, false)
                .await
                .unwrap_err(),
            Error::Rejected
        );
        for bytes in [&[][..], &fixture().bytes[..353]] {
            assert!(v.verify(&c, bytes, 100, false).await.is_err());
        }
        for index in [0, 1, 2, 34, 66, 353] {
            let mut bad = fixture().bytes.clone();
            bad[index] ^= 0x80;
            assert_eq!(
                v.verify(&c, &bad, 100, false).await.unwrap_err(),
                Error::Rejected
            );
        }
        let other = v.challenge("scope".into(), [8; 32], 200).unwrap();
        assert!(
            v.verify(&other, &fixture().bytes, 100, false)
                .await
                .is_err()
        );
        let mut c = c;
        c.key_id[0] ^= 1;
        assert!(v.verify(&c, &fixture().bytes, 100, false).await.is_err());
    });
}
#[test]
fn configuration_and_upstream_sequencing() {
    block_on(async {
        let v = verifier();
        for bad in [
            "".to_string(),
            "a".repeat(254),
            "https://issuer.example".into(),
            "a\nb".into(),
        ] {
            assert!(
                PublicVerifier::new(bad.clone(), "valid.example".into(), &fixture().spki).is_err()
            );
            assert!(PublicVerifier::new("valid.example".into(), bad, &fixture().spki).is_err());
        }
        for bytes in [vec![], vec![0; 4097], vec![1; 20]] {
            assert!(
                PublicVerifier::new("valid.example".into(), "valid.example".into(), &bytes)
                    .is_err()
            );
        }
        for scope in ["".to_string(), "a".repeat(1025), "a\nb".into()] {
            assert!(v.challenge(scope, [7; 32], 200).is_err());
        }
        assert!(v.challenge("scope".into(), [0; 32], 200).is_err());
        assert!(v.challenge("scope".into(), [7; 32], 0).is_err());
        assert_eq!(
            format!("{}", Error::Consumption),
            "Privacy Pass consumption refused"
        );
        assert_eq!(format!("{}", Error::Rejected), "Privacy Pass rejected");
        assert_eq!(
            format!("{}", Error::Configuration),
            "invalid Privacy Pass configuration"
        );
    });
}
#[test]
fn concurrent_different_actions_have_one_winner() {
    let v = verifier();
    let c = challenge(&v);
    let token = Arc::new(block_on(v.verify(&c, &fixture().bytes, 100, false)).unwrap());
    let store = Arc::new(Claims::default());
    let handles: Vec<_> = ["a", "b"]
        .into_iter()
        .map(|operation| {
            let token = token.clone();
            let store = store.clone();
            std::thread::spawn(move || block_on(token.consume(&*store, operation, 100)).is_ok())
        })
        .collect();
    assert_eq!(
        handles
            .into_iter()
            .filter(|h| h.thread().id() != std::thread::current().id())
            .map(|h| h.join().unwrap() as usize)
            .sum::<usize>(),
        1
    );
}
