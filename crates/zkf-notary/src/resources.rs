//! Weighted admission before Ferret allocation or upstream forwarding.
//!
//! One unit represents the smallest (1M) correlation class. Rounding the legacy
//! 3.5M class up to four units limits an eight-unit notary to 8/4/2 concurrent
//! small/medium/large sessions. Existing capability and connection quotas still
//! apply. This is a conservative allocation bound, not an OS RSS guarantee.
use std::sync::{Arc, LazyLock};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

// Sixteen simultaneous small-class extensions exceeded the 1.5 GiB service
// limit in sustained warm testing on t4g.small. Connection quotas may be higher:
// the additional requests wait here before allocating any preprocessing state.
const CAPACITY: usize = 8;
static SLOTS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(CAPACITY)));

pub(crate) fn units(budget: usize) -> u32 {
    budget.div_ceil(1_000_000) as u32
}

pub(crate) async fn acquire(budget: usize) -> anyhow::Result<OwnedSemaphorePermit> {
    acquire_lanes(budget, 1).await
}

pub(crate) async fn acquire_lanes(
    budget: usize,
    lanes: u8,
) -> anyhow::Result<OwnedSemaphorePermit> {
    anyhow::ensure!(
        matches!(lanes, 1 | 2),
        "unsupported authentication lane count"
    );
    let required = units(budget) * u32::from(lanes);
    anyhow::ensure!(
        required <= CAPACITY as u32,
        "session exceeds admission capacity"
    );
    Ok(SLOTS.clone().acquire_many_owned(required).await?)
}

pub(crate) fn active_units() -> usize {
    CAPACITY - SLOTS.available_permits()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn weighted_waits_release_on_completion_and_cancellation() {
        assert_eq!([1_000_000, 2_000_000, 3_500_000].map(units), [1, 2, 4]);
        assert_eq!(
            [1_000_000, 2_000_000, 3_500_000].map(|n| units(n) * 2),
            [2, 4, 8]
        );
        assert!(acquire_lanes(1_000_000, 0).await.is_err());
        assert!(acquire_lanes(5_000_000, 2).await.is_err());
        let slots = Arc::new(Semaphore::new(4));
        let small = slots.clone().acquire_many_owned(1).await.unwrap();
        let middle = slots.clone().acquire_many_owned(2).await.unwrap();
        let mut waiting = Box::pin(slots.clone().acquire_many_owned(2));
        assert!(futures::poll!(&mut waiting).is_pending());
        drop(waiting);
        assert_eq!(slots.available_permits(), 1);
        drop(small);
        let next = slots.clone().acquire_many_owned(2).await.unwrap();
        assert_eq!(slots.available_permits(), 0);
        drop(next);
        drop(middle);
        assert_eq!(slots.available_permits(), 4);
    }
}
