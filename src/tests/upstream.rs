use super::*;
#[test]
fn private_upstream_ports_do_not_confer_application_consumption() {
    futures::executor::block_on(async {
        let v = crate::tests::verifier().await;
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
