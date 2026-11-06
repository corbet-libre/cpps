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
// The fixture is built by awaiting it inside the test's own executor. A test that
// already drives a future must never nest a second block_on: a nested executor is
// rejected at run time (EnterError), and whether the nesting is reached depends on
// which test initialises the fixture first.
async fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    if let Some(fixture) = FIXTURE.get() {
        return fixture;
    }
    let store = IssuerMemoryKeyStore::default();
    let issuer = IssuerServer::new();
    let key = issuer.create_keypair(&mut rng(), &store).await.unwrap();
    let spki = serialize_public_key(&key).unwrap();
    let verifier =
        PublicVerifier::new("issuer.example".into(), "origin.example".into(), &spki).unwrap();
    let bound = verifier.challenge("scope".into(), [7; 32], 200).unwrap();
    let challenge = TokenChallenge::deserialize(bound.wire()).unwrap();
    let (request, state) = TokenRequest::new(&mut rng(), key.clone(), &challenge).unwrap();
    let token = issuer
        .issue_token_response(&store, request)
        .await
        .unwrap()
        .issue_token(&state)
        .unwrap();
    // Two tests may build concurrently; the first value published wins and every
    // caller below reads that one, so a verifier never pairs with foreign bytes.
    let _ = FIXTURE.set(Fixture {
        spki,
        bytes: token.tls_serialize_detached().unwrap(),
    });
    FIXTURE.get().unwrap()
}
pub(crate) async fn verifier() -> PublicVerifier {
    PublicVerifier::new(
        "issuer.example".into(),
        "origin.example".into(),
        &fixture().await.spki,
    )
    .unwrap()
}
fn challenge(v: &PublicVerifier) -> Challenge {
    v.challenge("scope".into(), [7; 32], 200).unwrap()
}
#[derive(Default)]
struct Claims(Mutex<BTreeMap<(String, [u8; 32]), String>>);
impl ConsumptionStore for Claims {
    async fn consume(
        &self,
        scope: &str,
        marker: [u8; 32],
        operation: &str,
        valid_until: u64,
    ) -> Result<(), Error> {
        assert!(valid_until > 100);
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
        let v = verifier().await;
        let c = challenge(&v);
        assert_eq!(c.expires_at(), 200);
        assert_eq!(
            TokenChallenge::deserialize(c.wire())
                .unwrap()
                .digest()
                .unwrap(),
            c.digest
        );
        let verified = v
            .verify(&c, &fixture().await.bytes, 100, true)
            .await
            .unwrap();
        assert_eq!(verified.original().unwrap(), &fixture().await.bytes);
        let store = Claims::default();
        assert_eq!(
            verified
                .consume(&store, "action-a", &|| 100)
                .await
                .unwrap()
                .expires_at(),
            200
        );
        assert!(verified.consume(&store, "action-a", &|| 101).await.is_ok());
        assert_eq!(
            verified
                .consume(&store, "action-b", &|| 101)
                .await
                .unwrap_err(),
            Error::Consumption
        );
        assert_eq!(
            verified.consume(&store, "", &|| 101).await.unwrap_err(),
            Error::Configuration
        );
        assert_eq!(
            verified
                .consume(&store, "action-a", &|| 200)
                .await
                .unwrap_err(),
            Error::Rejected
        );
        assert!(
            v.verify(&c, &fixture().await.bytes, 100, false)
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
                verified.consume(&store, "action-a", &|| 100).await.unwrap()
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
        let v = verifier().await;
        let c = challenge(&v);
        assert_eq!(
            v.verify(&c, &fixture().await.bytes, 200, false)
                .await
                .unwrap_err(),
            Error::Rejected
        );
        for bytes in [&[][..], &fixture().await.bytes[..353]] {
            assert!(v.verify(&c, bytes, 100, false).await.is_err());
        }
        let mut private_type = fixture().await.bytes.clone();
        private_type[1] = 1;
        assert!(v.verify(&c, &private_type, 100, false).await.is_err());
        for index in [0, 1, 2, 34, 66, 353] {
            let mut bad = fixture().await.bytes.clone();
            bad[index] ^= 0x80;
            assert_eq!(
                v.verify(&c, &bad, 100, false).await.unwrap_err(),
                Error::Rejected
            );
        }
        let other = v.challenge("scope".into(), [8; 32], 200).unwrap();
        assert!(
            v.verify(&other, &fixture().await.bytes, 100, false)
                .await
                .is_err()
        );
        let mut c = c;
        c.key_id[0] ^= 1;
        assert!(
            v.verify(&c, &fixture().await.bytes, 100, false)
                .await
                .is_err()
        );
    });
}
#[test]
fn configuration_and_upstream_sequencing() {
    block_on(async {
        let v = verifier().await;
        for bad in [
            "".to_string(),
            "a".repeat(254),
            "https://issuer.example".into(),
            "a\nb".into(),
        ] {
            assert!(
                PublicVerifier::new(bad.clone(), "valid.example".into(), &fixture().await.spki)
                    .is_err()
            );
            assert!(
                PublicVerifier::new("valid.example".into(), bad, &fixture().await.spki).is_err()
            );
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
    block_on(async {
        let v = verifier().await;
        let c = challenge(&v);
        let token = Arc::new(
            v.verify(&c, &fixture().await.bytes, 100, false)
                .await
                .unwrap(),
        );
        let store = Arc::new(Claims::default());
        let handles: Vec<_> = ["a", "b"]
            .into_iter()
            .map(|operation| {
                let token = token.clone();
                let store = store.clone();
                // Each racer blocks on its own thread, outside this executor.
                std::thread::spawn(move || {
                    block_on(token.consume(&*store, operation, &|| 100)).is_ok()
                })
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
    });
}

#[test]
fn cost_binding_and_simulation_are_distinct() {
    block_on(async {
        use cfbk::cost::{Amount, CostOrder, Mode, Offer, Outcome, Plan, Unit};
        use cfbk::{Candidate, Config};
        let v = verifier().await;
        let c = challenge(&v);
        let quote = v
            .preview(&c, &fixture().await.bytes, Mode::Simulation)
            .unwrap();
        let binding = quote.binding.clone();
        let zero = Amount {
            unit: Unit {
                code: "provider-api-calls".into(),
                scale: 0,
            },
            atoms: 0,
        };
        let plan = Plan::new(
            vec![Offer {
                candidate: Candidate::new("cpps", ["public-token"]),
                quote,
            }],
            Config::new(["cpps"], ["public-token"]),
            CostOrder::Configured,
            zero.clone(),
            1,
            Mode::Simulation,
            100,
        )
        .unwrap();
        let mut cascade = plan.start();
        let permit = cascade.begin(100).unwrap();
        permit.validate(&binding, Mode::Simulation, 100).unwrap();
        assert!(permit.validate(&binding, Mode::Production, 100).is_err());
        assert!(v.simulate(&c, &fixture().await.bytes, 100).await.accepted);
        assert!(!v.simulate(&c, &fixture().await.bytes, 200).await.accepted);
        cascade.complete(Outcome::Success, Some(zero)).unwrap();
        assert!(cascade.begin(100).is_err());
        for mode in [Mode::Sandbox, Mode::Production] {
            assert_ne!(
                binding,
                v.preview(&c, &fixture().await.bytes, mode).unwrap().binding
            );
        }
        assert!(v.preview(&c, &[0; 355], Mode::Production).is_err());
        let other = PublicVerifier::new(
            "other.example".into(),
            "origin.example".into(),
            &fixture().await.spki,
        )
        .unwrap();
        assert!(
            other
                .verify(&c, &fixture().await.bytes, 100, false)
                .await
                .is_err()
        );
        let other = PublicVerifier::new(
            "issuer.example".into(),
            "other.example".into(),
            &fixture().await.spki,
        )
        .unwrap();
        assert!(
            other
                .verify(&c, &fixture().await.bytes, 100, false)
                .await
                .is_err()
        );
    });
}

#[test]
fn tokens_cannot_cross_scope_or_extend_validity_with_reused_caller_context() {
    block_on(async {
        let verifier = verifier().await;
        for (scope, expiry) in [("different", 200), ("scope", 201)] {
            let changed = verifier.challenge(scope.into(), [7; 32], expiry).unwrap();
            assert!(
                verifier
                    .verify(&changed, &fixture().await.bytes, 100, false)
                    .await
                    .is_err()
            );
        }
    });
}

mod clock;
