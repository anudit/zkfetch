//! Bounded, in-memory, single-use leases. No state is written to disk.
use std::{collections::HashMap, sync::Mutex, time::Duration};
use web_time::Instant;

/// A device's next lease. The random ticket is an additional bearer secret.
#[derive(Clone, Copy, Default)]
pub struct PoolRequest {
    pub device: [u8; 32],
    pub ticket: [u8; 32],
    pub generation: u64,
}
impl PoolRequest {
    pub fn encode(&self) -> [u8; 72] {
        let mut out = [0; 72];
        out[..32].copy_from_slice(&self.device);
        out[32..64].copy_from_slice(&self.ticket);
        out[64..].copy_from_slice(&self.generation.to_be_bytes());
        out
    }
    pub fn decode(bytes: &[u8; 72]) -> Self {
        Self {
            device: bytes[..32].try_into().unwrap(),
            ticket: bytes[32..64].try_into().unwrap(),
            generation: u64::from_be_bytes(bytes[64..].try_into().unwrap()),
        }
    }
}
struct Entry<T> {
    generation: u64,
    value: T,
    inserted: Instant,
}
/// A cache keyed by authenticated tenant scope, device and random pool ticket.
/// Checkout removes the entry under one lock, before any protocol I/O.
pub struct PoolCache<T> {
    entries: Mutex<HashMap<([u8; 32], [u8; 32], [u8; 32]), Entry<T>>>,
    capacity: usize,
    ttl: Duration,
}
impl<T> PoolCache<T> {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capacity,
            ttl,
        }
    }
    pub fn take(&self, scope: [u8; 32], request: PoolRequest) -> Option<T> {
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|_, e| e.inserted.elapsed() < self.ttl);
        let e = entries.remove(&(scope, request.device, request.ticket))?;
        (e.generation == request.generation).then_some(e.value)
    }
    /// Publishes only a successfully completed lease, at the next index.
    /// Exhausted indices cannot wrap. Evicted state is dropped (zeroized).
    pub fn put(&self, scope: [u8; 32], request: PoolRequest, value: T) {
        let Some(generation) = request.generation.checked_add(1) else {
            return;
        };
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|_, e| e.inserted.elapsed() < self.ttl);
        if self.capacity == 0 {
            return;
        }
        if entries.len() >= self.capacity {
            if let Some(key) = entries
                .iter()
                .min_by_key(|(_, e)| e.inserted)
                .map(|(k, _)| *k)
            {
                entries.remove(&key);
            }
        }
        entries.insert(
            (scope, request.device, request.ticket),
            Entry {
                generation,
                value,
                inserted: Instant::now(),
            },
        );
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn leases_are_consumed_scoped_monotone_and_bounded() {
        let cache = PoolCache::new(1, Duration::from_secs(60));
        let mut r = PoolRequest {
            device: [1; 32],
            ticket: [2; 32],
            generation: 0,
        };
        cache.put([3; 32], r, 42);
        r.generation = 1;
        assert_eq!(cache.take([4; 32], r), None);
        assert_eq!(cache.take([3; 32], r), Some(42));
        assert_eq!(cache.take([3; 32], r), None);
        cache.put([3; 32], r, 43);
        assert_eq!(cache.take([3; 32], r), None); // stale index burns entry
        r.generation = 2;
        assert_eq!(cache.take([3; 32], r), None);
        cache.put([3; 32], r, 44);
        let other = PoolRequest {
            ticket: [5; 32],
            ..r
        };
        cache.put([3; 32], other, 45);
        r.generation = 3;
        assert_eq!(cache.take([3; 32], r), None);
        assert_eq!(
            cache.take(
                [3; 32],
                PoolRequest {
                    generation: 3,
                    ..other
                }
            ),
            Some(45)
        );
    }
    #[test]
    fn concurrent_checkout_has_only_one_winner() {
        let cache = PoolCache::new(1, Duration::from_secs(60));
        let r = PoolRequest::default();
        cache.put([0; 32], r, 1);
        let r = PoolRequest { generation: 1, ..r };
        std::thread::scope(|s| {
            let a = s.spawn(|| cache.take([0; 32], r));
            let b = s.spawn(|| cache.take([0; 32], r));
            assert_eq!(
                a.join().unwrap().is_some() as u8 + b.join().unwrap().is_some() as u8,
                1
            );
        });
    }
    #[test]
    fn expiry_and_counter_exhaustion_discard_state() {
        let cache = PoolCache::new(1, Duration::ZERO);
        cache.put([0; 32], PoolRequest::default(), 1);
        assert_eq!(
            cache.take(
                [0; 32],
                PoolRequest {
                    generation: 1,
                    ..Default::default()
                }
            ),
            None
        );
        cache.put(
            [0; 32],
            PoolRequest {
                generation: u64::MAX,
                ..Default::default()
            },
            2,
        );
        assert!(cache.entries.lock().unwrap().is_empty());
    }
}
