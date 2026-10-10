//! In-memory, move-only Ferret bootstrap state for sequential proxy sessions.
//!
//! The caller must exclusively check out a pool before setup, bind its lease
//! into the authenticated opening, and discard it on any failure. Pools are
//! deliberately neither serializable nor clonable: process restart uses fresh OT.
use async_trait::async_trait;
use futures::future::{BoxFuture, Shared};
/// Completion barrier for authenticated session preprocessing.
pub type PrefillReady = Shared<BoxFuture<'static, Result<(), String>>>;
/// Maximum prefetched correlations for the three-flight protocol.
pub const FLOW_BUDGET: usize = 3_500_000;
/// Authenticated size classes; the largest preserves the legacy limit.
pub const BUDGET_CLASSES: [usize; 3] = [1_000_000, 2_000_000, FLOW_BUDGET];
/// Whether a setup declaration names an accepted size class.
pub fn valid_budget(budget: usize) -> bool {
    BUDGET_CLASSES.contains(&budget)
}
use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_garble_core::Delta;
use mpz_ot::{
    chou_orlandi as co, ferret, kos,
    rcot::{RCOTReceiver, RCOTSender},
};
use std::sync::Arc;
use tokio::sync::Mutex;

type Receiver = ferret::Receiver<kos::Receiver<co::Sender>>;
type Sender = ferret::Sender<kos::Sender<co::Receiver>>;

/// Prover's reserved Ferret correlations. Never restore from a snapshot.
pub struct ProverVolePool {
    pub(crate) binding: [u8; 32],
    pub(crate) low_latency: bool,
    pub(crate) opened_host: Option<String>,
    pub(crate) pipeline_tls: bool,
    pub(crate) ready: Option<PrefillReady>,
    strict: bool,
    budget: usize,
    pub(crate) begin_proof: Option<Arc<dyn Fn() + Send + Sync>>,
    inner: Arc<Mutex<Receiver>>,
    active: Arc<std::sync::atomic::AtomicBool>,
}
/// Notary's reserved Ferret correlations and their secret correlation delta.
pub struct VerifierVolePool {
    pub(crate) binding: [u8; 32],
    pub(crate) low_latency: bool,
    pub(crate) opened_host: Option<String>,
    pub(crate) pipeline_tls: bool,
    pub(crate) ready: Option<PrefillReady>,
    strict: bool,
    budget: usize,
    pub(crate) begin_proof: Option<Arc<dyn Fn() + Send + Sync>>,
    inner: Arc<Mutex<Sender>>,
    active: Arc<std::sync::atomic::AtomicBool>,
    delta: zeroize::Zeroizing<Block>,
}
impl ProverVolePool {
    /// Install the callback that starts collecting the final proof flight.
    pub fn set_begin_proof(&mut self, begin: Arc<dyn Fn() + Send + Sync>) {
        self.begin_proof = Some(begin);
    }

    /// Creates a pool that bootstraps with fresh base OT on first use.
    pub fn new(binding: [u8; 32]) -> Self {
        let mut rng = rand::rng();
        Self {
            binding,
            low_latency: false,
            opened_host: None,
            pipeline_tls: false,
            ready: None,
            strict: false,
            budget: FLOW_BUDGET,
            begin_proof: None,
            active: Default::default(),
            inner: Arc::new(Mutex::new(Receiver::new(
                ferret::FerretConfig::builder()
                    .lpn_type(ferret::LpnType::Regular)
                    // Retain enough seed COTs for a 4M extension, so a smaller
                    // ORIGO circuit cannot leave the next session needing
                    // several small bootstrap-tree iterations.
                    .reserve_count(160_000)
                    .build()
                    .expect("valid Ferret config"),
                Block::random(&mut rng),
                kos::Receiver::new(Default::default(), co::Sender::default()),
            ))),
        }
    }
    /// Select a size class before preprocessing. Changing a live lease is forbidden.
    pub fn set_budget(&mut self, budget: usize) -> Result<(), &'static str> {
        if !valid_budget(budget) {
            return Err("unsupported VOLE budget class");
        }
        if self.active.load(std::sync::atomic::Ordering::Acquire) || self.ready.is_some() {
            return Err("cannot resize a live VOLE lease");
        }
        self.budget = budget;
        Ok(())
    }
    /// Use the proxy configuration authenticated in the first flight.
    pub fn set_opened_host(&mut self, host: Option<String>) {
        self.opened_host = host;
    }
    /// Binds the exclusively checked-out pool to a fresh authenticated lease.
    pub fn bind(&mut self, binding: [u8; 32]) {
        self.binding = binding;
    }
    /// Enables the authenticated v2 pipelined message flow. Both peers must agree.
    pub fn set_low_latency(&mut self, enabled: bool) {
        self.low_latency = enabled;
    }
    /// Overlaps preprocessing with a TLS handshake opened in the first flight.
    pub fn set_pipeline_tls(&mut self, enabled: bool) {
        self.pipeline_tls = enabled;
    }
    /// Prepare the first warm Ferret flight, burning the checked-out lease.
    pub fn start_prefill(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let mut inner = self.inner.try_lock().expect("exclusive prefill");
        inner.alloc(self.budget)?;
        let core = inner.core_mut();
        if core.wants_init() || core.wants_bootstrap() {
            return Err("uninitialized warm pool".into());
        }
        let bytes = if core.wants_extend() {
            bincode::serialize(&core.start_extend()?)?
        } else {
            vec![]
        };
        Ok(bytes)
    }
    /// Process the authenticated first Ferret reply.
    pub fn prefill_check(
        &self,
        reply: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        if reply.is_empty() {
            return Ok(vec![]);
        }
        let mut inner = self.inner.try_lock().expect("exclusive prefill");
        Ok(bincode::serialize(
            &inner.core_mut().extend(bincode::deserialize(reply)?)?,
        )?)
    }
    /// Complete the consistency check and release the temporary reservation.
    pub fn finish_prefill(
        &self,
        reply: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut inner = self.inner.try_lock().expect("exclusive prefill");
        if !reply.is_empty() {
            inner
                .core_mut()
                .finish_extend(bincode::deserialize(reply)?)?;
        }
        inner.core_mut().cancel_alloc(self.budget);
        if inner.available() < self.budget {
            return Err("prefill budget was not fulfilled".into());
        }
        Ok(())
    }
    /// Bootstrap a fresh pool before the online TLS flow.
    pub async fn cold_prefill(
        &self,
        ctx: &mut Context,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut inner = self.inner.lock().await;
        inner.alloc(self.budget)?;
        inner.flush(ctx).await?;
        inner.core_mut().cancel_alloc(self.budget);
        Ok(())
    }
    /// Remove session callbacks before returning the exclusive state to its cache.
    pub fn park(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.opened_host = None;
        self.ready = None;
        self.begin_proof = None;
        self.pipeline_tls = false;
        self.strict = false;
        if !self.low_latency {
            return Ok(());
        }
        if self.active.load(std::sync::atomic::Ordering::Acquire) {
            return Err("cannot park an active VOLE lease".into());
        }
        self.inner
            .try_lock()
            .map_err(|_| "active Ferret operation")?
            .core_mut()
            .compact_bootstrap()?;
        Ok(())
    }
    /// A handle for completing only this exclusively checked-out prefill.
    pub fn prefill_handle(&self) -> Self {
        self.session_handle()
    }
    /// Require prefill completion before constructing the final proof.
    pub fn set_ready(&mut self, ready: PrefillReady) {
        self.ready = Some(ready);
        self.pipeline_tls = true;
        self.strict = true;
    }
    pub(crate) fn session_handle(&self) -> Self {
        Self {
            binding: self.binding,
            low_latency: self.low_latency,
            opened_host: self.opened_host.clone(),
            pipeline_tls: self.pipeline_tls,
            ready: self.ready.clone(),
            strict: self.strict,
            budget: self.budget,
            begin_proof: self.begin_proof.clone(),
            inner: self.inner.clone(),
            active: self.active.clone(),
        }
    }
    pub(crate) fn receiver(&self) -> PooledReceiver {
        PooledReceiver(
            self.inner.clone(),
            Arc::new(Lease::new(self.active.clone())),
            self.strict,
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            self.budget,
        )
    }
}
impl VerifierVolePool {
    /// Creates a pool that bootstraps with fresh base OT on first use.
    pub fn new(binding: [u8; 32]) -> Self {
        let mut rng = rand::rng();
        let delta = Delta::random(&mut rng);
        Self::with_delta(binding, delta)
    }
    pub(crate) fn with_delta(binding: [u8; 32], delta: Delta) -> Self {
        Self::with_block(binding, delta.into_inner())
    }
    fn with_block(binding: [u8; 32], delta: Block) -> Self {
        let mut rng = rand::rng();
        Self {
            binding,
            low_latency: false,
            opened_host: None,
            pipeline_tls: false,
            ready: None,
            strict: false,
            budget: FLOW_BUDGET,
            begin_proof: None,
            delta: zeroize::Zeroizing::new(delta),
            active: Default::default(),
            inner: Arc::new(Mutex::new(Sender::new(
                ferret::FerretConfig::builder()
                    .lpn_type(ferret::LpnType::Regular)
                    // Retain enough seed COTs for a 4M extension, so a smaller
                    // ORIGO circuit cannot leave the next session needing
                    // several small bootstrap-tree iterations.
                    .reserve_count(160_000)
                    .build()
                    .expect("valid Ferret config"),
                Block::random(&mut rng),
                kos::Sender::new(
                    Default::default(),
                    delta,
                    co::Receiver::default(),
                ),
            ))),
        }
    }
    /// Select a size class before preprocessing. Changing a live lease is forbidden.
    pub fn set_budget(&mut self, budget: usize) -> Result<(), &'static str> {
        if !valid_budget(budget) {
            return Err("unsupported VOLE budget class");
        }
        if self.active.load(std::sync::atomic::Ordering::Acquire) || self.ready.is_some() {
            return Err("cannot resize a live VOLE lease");
        }
        self.budget = budget;
        Ok(())
    }
    /// Use the proxy configuration authenticated in the first flight.
    pub fn set_opened_host(&mut self, host: Option<String>) {
        self.opened_host = host;
    }
    /// Binds the exclusively checked-out pool to a fresh authenticated lease.
    pub fn bind(&mut self, binding: [u8; 32]) {
        self.binding = binding;
    }
    /// Enables the authenticated v2 pipelined message flow. Both peers must agree.
    pub fn set_low_latency(&mut self, enabled: bool) {
        self.low_latency = enabled;
    }
    /// Overlaps preprocessing with a TLS handshake opened in the first flight.
    pub fn set_pipeline_tls(&mut self, enabled: bool) {
        self.pipeline_tls = enabled;
    }
    /// Produce the first Ferret reply from an exclusively checked-out pool.
    pub fn accept_prefill(
        &mut self,
        start: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let mut inner = self.inner.try_lock().expect("exclusive prefill");
        inner.alloc(self.budget)?;
        let core = inner.core_mut();
        if start.is_empty() {
            if core.wants_extend() {
                return Err("warm prefill state mismatch".into());
            }
            return Ok(vec![]);
        }
        core.start_extend()?;
        Ok(bincode::serialize(
            &core.extend(bincode::deserialize(start)?)?,
        )?)
    }
    /// Complete the consistency check and release the temporary reservation.
    pub fn finish_prefill(
        &self,
        check: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let mut inner = self.inner.try_lock().expect("exclusive prefill");
        let reply = if check.is_empty() {
            vec![]
        } else {
            let reply = inner.core_mut().check(bincode::deserialize(check)?)?;
            inner.core_mut().finish_extend()?;
            bincode::serialize(&reply)?
        };
        inner.core_mut().cancel_alloc(self.budget);
        if inner.available() < self.budget {
            return Err("prefill budget was not fulfilled".into());
        }
        Ok(reply)
    }
    /// Bootstrap a fresh pool before the online TLS flow.
    pub async fn cold_prefill(
        &self,
        ctx: &mut Context,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut inner = self.inner.lock().await;
        inner.alloc(self.budget)?;
        inner.flush(ctx).await?;
        inner.core_mut().cancel_alloc(self.budget);
        Ok(())
    }
    /// Remove session callbacks before returning the exclusive state to its cache.
    pub fn park(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.opened_host = None;
        self.ready = None;
        self.begin_proof = None;
        self.pipeline_tls = false;
        self.strict = false;
        if !self.low_latency {
            return Ok(());
        }
        if self.active.load(std::sync::atomic::Ordering::Acquire) {
            return Err("cannot park an active VOLE lease".into());
        }
        self.inner
            .try_lock()
            .map_err(|_| "active Ferret operation")?
            .core_mut()
            .compact_bootstrap()?;
        Ok(())
    }
    /// A handle for completing only this exclusively checked-out prefill.
    pub fn prefill_handle(&self) -> Self {
        self.session_handle()
    }
    /// Require prefill completion before constructing the final proof.
    pub fn set_ready(&mut self, ready: PrefillReady) {
        self.ready = Some(ready);
        self.pipeline_tls = true;
        self.strict = true;
    }
    pub(crate) fn session_handle(&self) -> Self {
        Self {
            binding: self.binding,
            low_latency: self.low_latency,
            opened_host: self.opened_host.clone(),
            pipeline_tls: self.pipeline_tls,
            ready: self.ready.clone(),
            strict: self.strict,
            budget: self.budget,
            begin_proof: self.begin_proof.clone(),
            delta: zeroize::Zeroizing::new(*self.delta),
            inner: self.inner.clone(),
            active: self.active.clone(),
        }
    }
    pub(crate) fn sender(&self) -> PooledSender {
        PooledSender(
            self.inner.clone(),
            Arc::new(Lease::new(self.active.clone())),
            self.strict,
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            self.budget,
        )
    }
    pub(crate) fn delta(&self) -> Delta {
        Delta::new(*self.delta)
    }
}
// The parked pool retains the inner Ferret instance without adding a member to
// SharedRCOT's adaptive barrier. Every session creates a fresh SharedRCOT facade.
#[derive(Clone)]
pub(crate) struct PooledReceiver(
    Arc<Mutex<Receiver>>,
    #[allow(dead_code)] Arc<Lease>,
    bool,
    Arc<std::sync::atomic::AtomicUsize>,
    usize,
);
#[derive(Clone)]
pub(crate) struct PooledSender(
    Arc<Mutex<Sender>>,
    #[allow(dead_code)] Arc<Lease>,
    bool,
    Arc<std::sync::atomic::AtomicUsize>,
    usize,
);
impl RCOTReceiver<bool, Block> for PooledReceiver {
    type Error = <Receiver as RCOTReceiver<bool, Block>>::Error;
    type Future = <Receiver as RCOTReceiver<bool, Block>>::Future;
    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        if self.2 {
            let previous = self
                .3
                .fetch_add(count, std::sync::atomic::Ordering::Relaxed);
            if previous
                .checked_add(count)
                .is_none_or(|total| total > self.4)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "declared VOLE budget exceeded",
                )
                .into());
            }
        }
        self.0
            .try_lock()
            .expect("exclusive pool lease")
            .alloc(count)
    }
    fn available(&self) -> usize {
        self.0.try_lock().expect("exclusive pool lease").available()
    }
    fn try_recv_rcot(
        &mut self,
        count: usize,
    ) -> Result<mpz_ot::rcot::RCOTReceiverOutput<bool, Block>, Self::Error> {
        self.0
            .try_lock()
            .expect("exclusive pool lease")
            .try_recv_rcot(count)
    }
    fn queue_recv_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.0
            .try_lock()
            .expect("exclusive pool lease")
            .queue_recv_rcot(count)
    }
}
impl RCOTSender<Block> for PooledSender {
    type Error = <Sender as RCOTSender<Block>>::Error;
    type Future = <Sender as RCOTSender<Block>>::Future;
    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        if self.2 {
            let previous = self
                .3
                .fetch_add(count, std::sync::atomic::Ordering::Relaxed);
            if previous
                .checked_add(count)
                .is_none_or(|total| total > self.4)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "declared VOLE budget exceeded",
                )
                .into());
            }
        }
        self.0
            .try_lock()
            .expect("exclusive pool lease")
            .alloc(count)
    }
    fn available(&self) -> usize {
        self.0.try_lock().expect("exclusive pool lease").available()
    }
    fn delta(&self) -> Block {
        self.0.try_lock().expect("exclusive pool lease").delta()
    }
    fn try_send_rcot(
        &mut self,
        count: usize,
    ) -> Result<mpz_ot::rcot::RCOTSenderOutput<Block>, Self::Error> {
        self.0
            .try_lock()
            .expect("exclusive pool lease")
            .try_send_rcot(count)
    }
    fn queue_send_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.0
            .try_lock()
            .expect("exclusive pool lease")
            .queue_send_rcot(count)
    }
}
#[async_trait]
impl Flush for PooledReceiver {
    type Error = <Receiver as Flush>::Error;
    fn wants_flush(&self) -> bool {
        self.0
            .try_lock()
            .expect("exclusive pool lease")
            .wants_flush()
    }
    async fn flush(&mut self, ctx: &mut Context) -> Result<(), Self::Error> {
        let mut inner = self.0.lock().await;
        if self.2 && inner.wants_flush() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "declared VOLE budget exceeded; no interactive extension is permitted during proof",
            )
            .into());
        }
        inner.flush(ctx).await
    }
}
#[async_trait]
impl Flush for PooledSender {
    type Error = <Sender as Flush>::Error;
    fn wants_flush(&self) -> bool {
        self.0
            .try_lock()
            .expect("exclusive pool lease")
            .wants_flush()
    }
    async fn flush(&mut self, ctx: &mut Context) -> Result<(), Self::Error> {
        let mut inner = self.0.lock().await;
        if self.2 && inner.wants_flush() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "declared VOLE budget exceeded; no interactive extension is permitted during proof",
            )
            .into());
        }
        inner.flush(ctx).await
    }
}

#[derive(Debug)]
struct Lease(Arc<std::sync::atomic::AtomicBool>);
impl Lease {
    fn new(active: Arc<std::sync::atomic::AtomicBool>) -> Self {
        assert!(
            active
                .compare_exchange(
                    false,
                    true,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire
                )
                .is_ok(),
            "VOLE pool already in use"
        );
        Self(active)
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
}

opaque_debug::implement!(PooledReceiver);
opaque_debug::implement!(PooledSender);

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt;
    #[test]
    fn size_class_cannot_change_a_live_or_ready_lease() {
        let mut prover = ProverVolePool::new([1; 32]);
        assert!(prover.set_budget(123).is_err());
        prover.set_budget(BUDGET_CLASSES[0]).unwrap();
        let receiver = prover.receiver();
        assert!(prover.set_budget(BUDGET_CLASSES[1]).is_err());
        drop(receiver);
        prover.set_budget(BUDGET_CLASSES[1]).unwrap();
        prover.set_ready(futures::future::ready(Ok(())).boxed().shared());
        assert!(prover.set_budget(BUDGET_CLASSES[0]).is_err());
        // This uninitialized unit-test pool cannot be parked; clear only
        // its synthetic readiness barrier to test class selection.
        prover.ready = None;
        prover.set_budget(BUDGET_CLASSES[0]).unwrap();

        let mut verifier = VerifierVolePool::new([1; 32]);
        assert!(verifier.set_budget(0).is_err());
        verifier.set_budget(BUDGET_CLASSES[0]).unwrap();
        verifier.set_ready(futures::future::ready(Ok(())).boxed().shared());
        let mut sender = verifier.sender();
        sender.alloc(BUDGET_CLASSES[0]).unwrap();
        assert!(sender.alloc(1).is_err());
        assert!(verifier.set_budget(BUDGET_CLASSES[1]).is_err());
    }

    #[tokio::test]
    async fn changing_classes_preserves_single_use_correlations() {
        let mut prover = ProverVolePool::new([1; 32]);
        let mut verifier = VerifierVolePool::new([1; 32]);
        prover.set_low_latency(true);
        verifier.set_low_latency(true);
        let (mut a, mut b) = mpz_common::context::test_st_context(8);
        let mut previous = None;
        for (i, budget) in [1_000_000, 2_000_000, 1_000_000].into_iter().enumerate() {
            prover.set_budget(budget).unwrap();
            verifier.set_budget(budget).unwrap();
            if i == 0 {
                futures::try_join!(prover.cold_prefill(&mut a), verifier.cold_prefill(&mut b))
                    .unwrap();
            } else {
                let start = prover.start_prefill().unwrap();
                let reply = verifier.accept_prefill(&start).unwrap();
                let check = prover.prefill_check(&reply).unwrap();
                let reply = verifier.finish_prefill(&check).unwrap();
                prover.finish_prefill(&reply).unwrap();
            }
            let recv = prover
                .inner
                .try_lock()
                .unwrap()
                .try_recv_rcot(640_000)
                .unwrap();
            let send = verifier
                .inner
                .try_lock()
                .unwrap()
                .try_send_rcot(640_000)
                .unwrap();
            assert_ne!(previous, Some(recv.msgs[0]));
            previous = Some(recv.msgs[0]);
            let delta = verifier.inner.try_lock().unwrap().delta();
            for ((mac, choice), key) in recv.msgs.iter().zip(recv.choices).zip(send.keys) {
                assert_eq!(*mac, key ^ if choice { delta } else { Block::ZERO });
            }
            prover.park().unwrap();
            verifier.park().unwrap();
            assert_eq!(prover.inner.try_lock().unwrap().available(), 0);
            assert_eq!(verifier.inner.try_lock().unwrap().available(), 0);
        }
    }
    #[test]
    fn declared_budget_is_enforced_on_both_peers() {
        let mut prover = ProverVolePool::new([1; 32]);
        prover.set_ready(futures::future::ready(Ok(())).boxed().shared());
        let mut receiver = prover.receiver();
        receiver.alloc(FLOW_BUDGET).unwrap();
        assert!(
            receiver
                .alloc(1)
                .unwrap_err()
                .to_string()
                .contains("budget exceeded")
        );
        let mut verifier = VerifierVolePool::new([1; 32]);
        verifier.set_ready(futures::future::ready(Ok(())).boxed().shared());
        let mut sender = verifier.sender();
        sender.alloc(FLOW_BUDGET).unwrap();
        assert!(
            sender
                .alloc(1)
                .unwrap_err()
                .to_string()
                .contains("budget exceeded")
        );
    }
    #[tokio::test]
    async fn folded_prefill_checks_correlations_and_rejects_tampering() {
        for tamper in [false, true] {
            let mut prover = ProverVolePool::new([1; 32]);
            let mut verifier = VerifierVolePool::new([1; 32]);
            let (mut a, mut b) = mpz_common::context::test_st_context(8);
            futures::try_join!(prover.cold_prefill(&mut a), verifier.cold_prefill(&mut b)).unwrap();
            // Consume a disjoint range so this opening needs another extension.
            prover
                .inner
                .try_lock()
                .unwrap()
                .try_recv_rcot(1_000_000)
                .unwrap();
            verifier
                .inner
                .try_lock()
                .unwrap()
                .try_send_rcot(1_000_000)
                .unwrap();
            let start = prover.start_prefill().unwrap();
            assert!(!start.is_empty());
            let reply = verifier.accept_prefill(&start).unwrap();
            let check = prover.prefill_check(&reply).unwrap();
            let mut reply = verifier.finish_prefill(&check).unwrap();
            if tamper {
                reply[0] ^= 1;
            }
            let completed = prover.finish_prefill(&reply);
            if tamper {
                assert!(completed.is_err());
                continue;
            }
            completed.unwrap();
            let recv = prover.inner.try_lock().unwrap().try_recv_rcot(512).unwrap();
            let send = verifier
                .inner
                .try_lock()
                .unwrap()
                .try_send_rcot(512)
                .unwrap();
            let delta = verifier.inner.try_lock().unwrap().delta();
            for ((mac, choice), key) in recv.msgs.iter().zip(recv.choices).zip(send.keys) {
                assert_eq!(*mac, key ^ if choice { delta } else { Block::ZERO });
            }
        }
    }
}

/// Independent full-entropy pools for the strict two-lane protocol.
pub mod strict;
