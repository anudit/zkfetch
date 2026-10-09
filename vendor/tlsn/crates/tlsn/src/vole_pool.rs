//! In-memory, move-only Ferret bootstrap state for sequential proxy sessions.
//!
//! The caller must exclusively check out a pool before setup, bind its lease
//! into the authenticated opening, and discard it on any failure. Pools are
//! deliberately neither serializable nor clonable: process restart uses fresh OT.
use async_trait::async_trait;
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
    inner: Arc<Mutex<Receiver>>,
    active: Arc<std::sync::atomic::AtomicBool>,
}
/// Notary's reserved Ferret correlations and their secret correlation delta.
pub struct VerifierVolePool {
    pub(crate) binding: [u8; 32],
    inner: Arc<Mutex<Sender>>,
    active: Arc<std::sync::atomic::AtomicBool>,
    delta: zeroize::Zeroizing<Block>,
}
impl ProverVolePool {
    /// Creates a pool that bootstraps with fresh base OT on first use.
    pub fn new(binding: [u8; 32]) -> Self {
        let mut rng = rand::rng();
        Self {
            binding,
            active: Default::default(),
            inner: Arc::new(Mutex::new(Receiver::new(
                ferret::FerretConfig::builder()
                    .lpn_type(ferret::LpnType::Regular)
                    .build()
                    .expect("valid Ferret config"),
                Block::random(&mut rng),
                kos::Receiver::new(Default::default(), co::Sender::default()),
            ))),
        }
    }
    /// Binds the exclusively checked-out pool to a fresh authenticated lease.
    pub fn bind(&mut self, binding: [u8; 32]) {
        self.binding = binding;
    }
    pub(crate) fn session_handle(&self) -> Self {
        Self {
            binding: self.binding,
            inner: self.inner.clone(),
            active: self.active.clone(),
        }
    }
    pub(crate) fn receiver(&self) -> PooledReceiver {
        PooledReceiver(
            self.inner.clone(),
            Arc::new(Lease::new(self.active.clone())),
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
        let mut rng = rand::rng();
        Self {
            binding,
            delta: zeroize::Zeroizing::new(delta.into_inner()),
            active: Default::default(),
            inner: Arc::new(Mutex::new(Sender::new(
                ferret::FerretConfig::builder()
                    .lpn_type(ferret::LpnType::Regular)
                    .build()
                    .expect("valid Ferret config"),
                Block::random(&mut rng),
                kos::Sender::new(
                    Default::default(),
                    delta.into_inner(),
                    co::Receiver::default(),
                ),
            ))),
        }
    }
    /// Binds the exclusively checked-out pool to a fresh authenticated lease.
    pub fn bind(&mut self, binding: [u8; 32]) {
        self.binding = binding;
    }
    pub(crate) fn session_handle(&self) -> Self {
        Self {
            binding: self.binding,
            delta: zeroize::Zeroizing::new(*self.delta),
            inner: self.inner.clone(),
            active: self.active.clone(),
        }
    }
    pub(crate) fn sender(&self) -> PooledSender {
        PooledSender(
            self.inner.clone(),
            Arc::new(Lease::new(self.active.clone())),
        )
    }
    pub(crate) fn delta(&self) -> Delta {
        Delta::new(*self.delta)
    }
}
// The parked pool retains the inner Ferret instance without adding a member to
// SharedRCOT's adaptive barrier. Every session creates a fresh SharedRCOT facade.
#[derive(Clone)]
pub(crate) struct PooledReceiver(Arc<Mutex<Receiver>>, #[allow(dead_code)] Arc<Lease>);
#[derive(Clone)]
pub(crate) struct PooledSender(Arc<Mutex<Sender>>, #[allow(dead_code)] Arc<Lease>);
impl RCOTReceiver<bool, Block> for PooledReceiver {
    type Error = <Receiver as RCOTReceiver<bool, Block>>::Error;
    type Future = <Receiver as RCOTReceiver<bool, Block>>::Future;
    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
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
        self.0.lock().await.flush(ctx).await
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
        self.0.lock().await.flush(ctx).await
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
