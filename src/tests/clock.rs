use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
struct DelayedConsumption {
    clock: AtomicU64,
    completed: u64,
    wait_before_commit: bool,
    committed: AtomicU64,
}
impl ConsumptionStore for DelayedConsumption {
    async fn consume(&self, _: &str, _: [u8; 32], _: &str, valid_until: u64) -> Result<(), Error> {
        assert_eq!(valid_until, 200);
        yield_once().await;
        if self.wait_before_commit {
            self.clock.store(self.completed, Ordering::SeqCst);
        }
        if self.clock.load(Ordering::SeqCst) >= valid_until {
            return Err(Error::Consumption);
        }
        self.committed.fetch_add(1, Ordering::SeqCst);
        yield_once().await;
        self.clock.store(self.completed, Ordering::SeqCst);
        Ok(())
    }
}
#[test]
fn consumption_deadline_is_checked_inside_commit_and_after_the_wait() {
    block_on(async {
        let verifier = verifier().await;
        let token = verifier
            .verify(&challenge(&verifier), &fixture().await.bytes, 100, true)
            .await
            .unwrap();
        for (completed, wait_before_commit) in [(200, true), (200, false), (99, false)] {
            let store = DelayedConsumption {
                clock: AtomicU64::new(100),
                completed,
                wait_before_commit,
                committed: AtomicU64::new(0),
            };
            let result = token
                .consume(&store, "operation", &|| store.clock.load(Ordering::SeqCst))
                .await;
            if wait_before_commit {
                assert!(result.is_err());
                assert_eq!(result.unwrap_err(), Error::Consumption);
                assert_eq!(store.committed.load(Ordering::SeqCst), 0);
            } else {
                assert_eq!(store.committed.load(Ordering::SeqCst), 1);
                if !(100..200).contains(&completed) {
                    assert!(result.is_err());
                    assert_eq!(result.unwrap_err(), Error::Rejected);
                } else {
                    assert_eq!(result.unwrap().expires_at(), 200);
                }
            }
            assert_eq!(token.original().unwrap(), &fixture().await.bytes);
        }
    });
}

async fn yield_once() {
    let mut yielded = false;
    std::future::poll_fn(|cx| {
        if yielded {
            std::task::Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    })
    .await
}
