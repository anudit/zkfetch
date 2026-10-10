//! Move-only pair of Ferret pools. A failure burns the entire pair; callers
//! must never park one lane independently or restore either from a snapshot.
use super::*;
use mpz_ot::rcot::shared::{SharedRCOTReceiver, SharedRCOTSender};
use mpz_zk::strict::ZkDelta;
type Error = Box<dyn std::error::Error + Send + Sync>;
fn binding(session: [u8; 32], lane: usize) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"zkf/strict/ferret-pool/v1");
    h.update(&session);
    h.update(&(lane as u64).to_le_bytes());
    *h.finalize().as_bytes()
}
/// Prover lanes have independent seeds, OT transcripts and reserved states.
pub struct ProverPool {
    lanes: [ProverVolePool; 2],
    failed: bool,
}
/// Full entropy deltas remain inside the verifier's exclusively leased pair.
pub struct VerifierPool {
    lanes: [VerifierVolePool; 2],
    failed: bool,
}
impl ProverPool {
    /// Construct independent lanes from fresh entropy.
    pub fn new(session: [u8; 32]) -> Self {
        Self {
            lanes: std::array::from_fn(|i| ProverVolePool::new(binding(session, i))),
            failed: false,
        }
    }
    /// Bind both reserved states to a fresh authenticated session lease.
    pub fn bind(&mut self, session: [u8; 32]) {
        for i in 0..2 {
            self.lanes[i].bind(binding(session, i));
        }
    }
    /// Set a per-lane budget before either lane becomes active.
    pub fn set_budget(&mut self, per_lane: usize) -> Result<(), Error> {
        if self.failed {
            return Err("burned strict pool".into());
        }
        for p in &mut self.lanes {
            if let Err(e) = p.set_budget(per_lane) {
                self.failed = true;
                return Err(e.into());
            }
        }
        Ok(())
    }
    /// Bootstrap both independent OT streams; a failure burns the pair.
    pub async fn cold_prefill(&mut self, ctx: &mut Context) -> Result<(), Error> {
        if self.failed {
            return Err("burned strict pool".into());
        }
        for p in &self.lanes {
            if let Err(e) = p.cold_prefill(ctx).await {
                self.failed = true;
                return Err(e);
            }
        }
        Ok(())
    }
    /// Start both warm extensions in one encoded flight.
    pub fn start_prefill(&mut self) -> Result<Vec<u8>, Error> {
        if self.failed {
            return Err("burned strict pool".into());
        }
        let result = (|| {
            let a = self.lanes[0].start_prefill()?;
            let b = self.lanes[1].start_prefill()?;
            Ok(bincode::serialize(&[a, b])?)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    /// Check both extension replies; failure burns the pair.
    pub fn prefill_check(&mut self, reply: &[u8]) -> Result<Vec<u8>, Error> {
        if self.failed {
            return Err("burned strict pool".into());
        }
        let result = (|| {
            let reply: [Vec<u8>; 2] = bincode::deserialize(reply)?;
            let a = self.lanes[0].prefill_check(&reply[0])?;
            let b = self.lanes[1].prefill_check(&reply[1])?;
            Ok(bincode::serialize(&[a, b])?)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    /// Finish both extensions and validate both reserved budgets.
    pub fn finish_prefill(&mut self, reply: &[u8]) -> Result<(), Error> {
        if self.failed {
            return Err("burned strict pool".into());
        }
        let result = (|| {
            let reply: [Vec<u8>; 2] = bincode::deserialize(reply)?;
            for i in 0..2 {
                self.lanes[i].finish_prefill(&reply[i])?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    /// Discard unused correlations and retain only both bootstrap states.
    pub fn park(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err("burned strict pool".into());
        }
        for p in &mut self.lanes {
            if let Err(e) = p.park() {
                self.failed = true;
                return Err(e);
            }
        }
        Ok(())
    }
    /// Enable compact parking of both warm states.
    pub fn set_low_latency(&mut self, enabled: bool) {
        for p in &mut self.lanes {
            p.set_low_latency(enabled);
        }
    }
    #[allow(dead_code)] // Integrated into the session driver in the next protocol step.
    pub(crate) fn receivers(
        &self,
    ) -> Result<[SharedRCOTReceiver<PooledReceiver, bool, Block>; 2], Error> {
        if self.failed {
            return Err("burned strict pool".into());
        }
        Ok(std::array::from_fn(|i| {
            SharedRCOTReceiver::new(self.lanes[i].receiver())
        }))
    }
}
impl VerifierPool {
    /// Construct independent lanes from fresh entropy.
    pub fn new(session: [u8; 32]) -> Self {
        let mut rng = rand::rng();
        Self {
            lanes: std::array::from_fn(|i| {
                VerifierVolePool::with_block(binding(session, i), Block::random(&mut rng))
            }),
            failed: false,
        }
    }
    /// Bind both reserved states to a fresh authenticated session lease.
    pub fn bind(&mut self, session: [u8; 32]) {
        for i in 0..2 {
            self.lanes[i].bind(binding(session, i));
        }
    }
    /// Set a per-lane budget before either lane becomes active.
    pub fn set_budget(&mut self, per_lane: usize) -> Result<(), Error> {
        if self.failed {
            return Err("burned strict pool".into());
        }
        for p in &mut self.lanes {
            if let Err(e) = p.set_budget(per_lane) {
                self.failed = true;
                return Err(e.into());
            }
        }
        Ok(())
    }
    /// Bootstrap both independent OT streams; a failure burns the pair.
    pub async fn cold_prefill(&mut self, ctx: &mut Context) -> Result<(), Error> {
        if self.failed {
            return Err("burned strict pool".into());
        }
        for p in &self.lanes {
            if let Err(e) = p.cold_prefill(ctx).await {
                self.failed = true;
                return Err(e);
            }
        }
        Ok(())
    }
    /// Accept both warm extensions in one encoded flight.
    pub fn accept_prefill(&mut self, start: &[u8]) -> Result<Vec<u8>, Error> {
        if self.failed {
            return Err("burned strict pool".into());
        }
        let result = (|| {
            let start: [Vec<u8>; 2] = bincode::deserialize(start)?;
            let a = self.lanes[0].accept_prefill(&start[0])?;
            let b = self.lanes[1].accept_prefill(&start[1])?;
            Ok(bincode::serialize(&[a, b])?)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    /// Finish both extensions and validate both reserved budgets.
    pub fn finish_prefill(&mut self, check: &[u8]) -> Result<Vec<u8>, Error> {
        if self.failed {
            return Err("burned strict pool".into());
        }
        let result = (|| {
            let check: [Vec<u8>; 2] = bincode::deserialize(check)?;
            let a = self.lanes[0].finish_prefill(&check[0])?;
            let b = self.lanes[1].finish_prefill(&check[1])?;
            Ok(bincode::serialize(&[a, b])?)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    /// Discard unused correlations and retain only both bootstrap states.
    pub fn park(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err("burned strict pool".into());
        }
        for p in &mut self.lanes {
            if let Err(e) = p.park() {
                self.failed = true;
                return Err(e);
            }
        }
        Ok(())
    }
    /// Return the two full-entropy correlations for strict VM construction.
    pub fn deltas(&self) -> [ZkDelta; 2] {
        std::array::from_fn(|i| ZkDelta::new(*self.lanes[i].delta))
    }
    /// Enable compact parking of both warm states.
    pub fn set_low_latency(&mut self, enabled: bool) {
        for p in &mut self.lanes {
            p.set_low_latency(enabled);
        }
    }
    #[allow(dead_code)] // Integrated into the session driver in the next protocol step.
    pub(crate) fn senders(&self) -> Result<[SharedRCOTSender<PooledSender, Block>; 2], Error> {
        if self.failed {
            return Err("burned strict pool".into());
        }
        Ok(std::array::from_fn(|i| {
            SharedRCOTSender::new(self.lanes[i].sender())
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn paired_cold_and_warm_ferret_preserve_full_deltas_and_never_reuse() {
        let mut p = ProverPool::new([7; 32]);
        let mut v = VerifierPool::new([7; 32]);
        // Deterministic even and odd deltas verify that Ferret does not require a pointer bit.
        v.lanes = std::array::from_fn(|i| {
            VerifierVolePool::with_block(binding([7; 32], i), Block::new([42 + i as u8; 16]))
        });
        p.set_low_latency(true);
        v.set_low_latency(true);
        p.set_budget(1_000_000).unwrap();
        v.set_budget(1_000_000).unwrap();
        let (mut cp, mut cv) = mpz_common::context::test_st_context(8);
        futures::try_join!(p.cold_prefill(&mut cp), v.cold_prefill(&mut cv)).unwrap();
        let mut previous = [None, None];
        for warm in 0..2 {
            if warm != 0 {
                let start = p.start_prefill().unwrap();
                let reply = v.accept_prefill(&start).unwrap();
                let check = p.prefill_check(&reply).unwrap();
                let reply = v.finish_prefill(&check).unwrap();
                p.finish_prefill(&reply).unwrap();
            }
            for lane in 0..2 {
                let recv = p.lanes[lane]
                    .inner
                    .try_lock()
                    .unwrap()
                    .try_recv_rcot(640_000)
                    .unwrap();
                let send = v.lanes[lane]
                    .inner
                    .try_lock()
                    .unwrap()
                    .try_send_rcot(640_000)
                    .unwrap();
                assert_ne!(previous[lane], Some(recv.msgs[0]));
                previous[lane] = Some(recv.msgs[0]);
                let delta = *v.deltas()[lane].as_block();
                assert_eq!(delta.to_bytes(), [42 + lane as u8; 16]);
                for ((tag, choice), key) in recv.msgs.iter().zip(recv.choices).zip(send.keys) {
                    assert_eq!(*tag, key ^ if choice { delta } else { Block::ZERO });
                }
            }
            p.park().unwrap();
            v.park().unwrap();
            for lane in 0..2 {
                assert_eq!(p.lanes[lane].inner.try_lock().unwrap().available(), 0);
            }
        }
        let start = p.start_prefill().unwrap();
        let reply = v.accept_prefill(&start).unwrap();
        let mut encoded: [Vec<u8>; 2] = bincode::deserialize(&reply).unwrap();
        encoded[1] = vec![255];
        assert!(
            p.prefill_check(&bincode::serialize(&encoded).unwrap())
                .is_err()
        );
        assert!(p.park().is_err());
        assert!(p.start_prefill().is_err());
    }
}
