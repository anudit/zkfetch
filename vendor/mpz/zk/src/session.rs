//! Negotiated VM adapter. Strict selection requires two independent OT streams.
use crate::{ProverConfig, VerifierConfig, strict::ZkDelta};
use async_trait::async_trait;
use mpz_common::{Context, Flush};
use mpz_core::{Block, bitvec::BitVec};
use mpz_ot::rcot::{RCOTReceiver, RCOTSender};
use mpz_vm_core::{
    Call, Callable, Execute, Result as VmResult, VmError,
    memory::{DecodeFuture, Memory, Slice, View, binary::Binary},
};
#[derive(Debug)]
pub enum Prover<OT> {
    Legacy(crate::Prover<OT>),
    Strict(crate::strict::Prover<OT>),
}
impl<OT> Prover<OT> {
    pub fn new(config: ProverConfig, ot: OT) -> Self {
        Self::Legacy(crate::Prover::new(config, ot))
    }
    pub fn new_strict(config: ProverConfig, ot: [OT; 2]) -> Self {
        Self::Strict(crate::strict::Prover::new(config, ot))
    }
    pub fn bind_statement(&mut self, statement: &[u8]) {
        match self {
            Self::Legacy(vm) => vm.bind_statement(statement),
            Self::Strict(vm) => vm.bind_statement(statement),
        }
    }
    pub fn field_challenge(&self) -> [u8; 32] {
        match self {
            Self::Legacy(vm) => vm.field_challenge(),
            Self::Strict(vm) => vm.field_challenge(),
        }
    }
    pub fn is_strict(&self) -> bool {
        matches!(self, Self::Strict(_))
    }
}
#[async_trait]
impl<OT> Execute for Prover<OT>
where
    OT: RCOTReceiver<bool, Block> + Flush + Send + 'static,
{
    fn wants_flush(&self) -> bool {
        match self {
            Self::Legacy(vm) => vm.wants_flush(),
            Self::Strict(vm) => vm.wants_flush(),
        }
    }
    fn wants_preprocess(&self) -> bool {
        match self {
            Self::Legacy(vm) => vm.wants_preprocess(),
            Self::Strict(vm) => vm.wants_preprocess(),
        }
    }
    fn wants_execute(&self) -> bool {
        match self {
            Self::Legacy(vm) => vm.wants_execute(),
            Self::Strict(vm) => vm.wants_execute(),
        }
    }
    async fn flush(&mut self, ctx: &mut Context) -> VmResult<()> {
        match self {
            Self::Legacy(vm) => vm.flush(ctx).await,
            Self::Strict(vm) => vm.flush(ctx).await,
        }
    }
    async fn preprocess(&mut self, ctx: &mut Context) -> VmResult<()> {
        match self {
            Self::Legacy(vm) => vm.preprocess(ctx).await,
            Self::Strict(vm) => vm.preprocess(ctx).await,
        }
    }
    async fn execute(&mut self, ctx: &mut Context) -> VmResult<()> {
        match self {
            Self::Legacy(vm) => vm.execute(ctx).await,
            Self::Strict(vm) => vm.execute(ctx).await,
        }
    }
}
impl<OT> Callable<Binary> for Prover<OT>
where
    OT: RCOTReceiver<bool, Block>,
{
    fn call_raw(&mut self, call: Call) -> VmResult<Slice> {
        match self {
            Self::Legacy(vm) => vm.call_raw(call),
            Self::Strict(vm) => vm.call_raw(call),
        }
    }
}
impl<OT> Memory<Binary> for Prover<OT>
where
    OT: RCOTReceiver<bool, Block>,
{
    type Error = VmError;
    fn is_alloc_raw(&self, slice: Slice) -> bool {
        match self {
            Self::Legacy(vm) => vm.is_alloc_raw(slice),
            Self::Strict(vm) => vm.is_alloc_raw(slice),
        }
    }
    fn alloc_raw(&mut self, size: usize) -> VmResult<Slice> {
        match self {
            Self::Legacy(vm) => vm.alloc_raw(size),
            Self::Strict(vm) => vm.alloc_raw(size),
        }
    }
    fn is_assigned_raw(&self, slice: Slice) -> bool {
        match self {
            Self::Legacy(vm) => vm.is_assigned_raw(slice),
            Self::Strict(vm) => vm.is_assigned_raw(slice),
        }
    }
    fn assign_raw(&mut self, slice: Slice, data: BitVec) -> VmResult<()> {
        match self {
            Self::Legacy(vm) => vm.assign_raw(slice, data),
            Self::Strict(vm) => vm.assign_raw(slice, data),
        }
    }
    fn is_committed_raw(&self, slice: Slice) -> bool {
        match self {
            Self::Legacy(vm) => vm.is_committed_raw(slice),
            Self::Strict(vm) => vm.is_committed_raw(slice),
        }
    }
    fn commit_raw(&mut self, slice: Slice) -> VmResult<()> {
        match self {
            Self::Legacy(vm) => vm.commit_raw(slice),
            Self::Strict(vm) => vm.commit_raw(slice),
        }
    }
    fn get_raw(&self, slice: Slice) -> VmResult<Option<BitVec>> {
        match self {
            Self::Legacy(vm) => vm.get_raw(slice),
            Self::Strict(vm) => vm.get_raw(slice),
        }
    }
    fn decode_raw(&mut self, slice: Slice) -> VmResult<DecodeFuture<BitVec>> {
        match self {
            Self::Legacy(vm) => vm.decode_raw(slice),
            Self::Strict(vm) => vm.decode_raw(slice),
        }
    }
}
impl<OT> View<Binary> for Prover<OT>
where
    OT: RCOTReceiver<bool, Block>,
{
    type Error = VmError;
    fn mark_public_raw(&mut self, slice: Slice) -> VmResult<()> {
        match self {
            Self::Legacy(vm) => vm.mark_public_raw(slice),
            Self::Strict(vm) => vm.mark_public_raw(slice),
        }
    }
    fn mark_private_raw(&mut self, slice: Slice) -> VmResult<()> {
        match self {
            Self::Legacy(vm) => vm.mark_private_raw(slice),
            Self::Strict(vm) => vm.mark_private_raw(slice),
        }
    }
    fn mark_blind_raw(&mut self, slice: Slice) -> VmResult<()> {
        match self {
            Self::Legacy(vm) => vm.mark_blind_raw(slice),
            Self::Strict(vm) => vm.mark_blind_raw(slice),
        }
    }
}
#[derive(Debug)]
pub enum Verifier<OT> {
    Legacy(crate::Verifier<OT>),
    Strict(crate::strict::Verifier<OT>),
}
impl<OT> Verifier<OT> {
    pub fn new(
        config: VerifierConfig,
        delta: mpz_vm_core::memory::correlated::Delta,
        ot: OT,
    ) -> Self {
        Self::Legacy(crate::Verifier::new(config, delta, ot))
    }
    pub fn new_strict(config: VerifierConfig, deltas: [ZkDelta; 2], ot: [OT; 2]) -> Self {
        Self::Strict(crate::strict::Verifier::new(config, deltas, ot))
    }
    pub fn bind_statement(&mut self, statement: &[u8]) {
        match self {
            Self::Legacy(vm) => vm.bind_statement(statement),
            Self::Strict(vm) => vm.bind_statement(statement),
        }
    }
    pub fn field_challenge(&self) -> [u8; 32] {
        match self {
            Self::Legacy(vm) => vm.field_challenge(),
            Self::Strict(vm) => vm.field_challenge(),
        }
    }
    pub fn is_strict(&self) -> bool {
        matches!(self, Self::Strict(_))
    }
}
#[async_trait]
impl<OT> Execute for Verifier<OT>
where
    OT: RCOTSender<Block> + Flush + Send + 'static,
{
    fn wants_flush(&self) -> bool {
        match self {
            Self::Legacy(vm) => vm.wants_flush(),
            Self::Strict(vm) => vm.wants_flush(),
        }
    }
    fn wants_preprocess(&self) -> bool {
        match self {
            Self::Legacy(vm) => vm.wants_preprocess(),
            Self::Strict(vm) => vm.wants_preprocess(),
        }
    }
    fn wants_execute(&self) -> bool {
        match self {
            Self::Legacy(vm) => vm.wants_execute(),
            Self::Strict(vm) => vm.wants_execute(),
        }
    }
    async fn flush(&mut self, ctx: &mut Context) -> VmResult<()> {
        match self {
            Self::Legacy(vm) => vm.flush(ctx).await,
            Self::Strict(vm) => vm.flush(ctx).await,
        }
    }
    async fn preprocess(&mut self, ctx: &mut Context) -> VmResult<()> {
        match self {
            Self::Legacy(vm) => vm.preprocess(ctx).await,
            Self::Strict(vm) => vm.preprocess(ctx).await,
        }
    }
    async fn execute(&mut self, ctx: &mut Context) -> VmResult<()> {
        match self {
            Self::Legacy(vm) => vm.execute(ctx).await,
            Self::Strict(vm) => vm.execute(ctx).await,
        }
    }
}
impl<OT> Callable<Binary> for Verifier<OT>
where
    OT: RCOTSender<Block>,
{
    fn call_raw(&mut self, call: Call) -> VmResult<Slice> {
        match self {
            Self::Legacy(vm) => vm.call_raw(call),
            Self::Strict(vm) => vm.call_raw(call),
        }
    }
}
impl<OT> Memory<Binary> for Verifier<OT>
where
    OT: RCOTSender<Block>,
{
    type Error = VmError;
    fn is_alloc_raw(&self, slice: Slice) -> bool {
        match self {
            Self::Legacy(vm) => vm.is_alloc_raw(slice),
            Self::Strict(vm) => vm.is_alloc_raw(slice),
        }
    }
    fn alloc_raw(&mut self, size: usize) -> VmResult<Slice> {
        match self {
            Self::Legacy(vm) => vm.alloc_raw(size),
            Self::Strict(vm) => vm.alloc_raw(size),
        }
    }
    fn is_assigned_raw(&self, slice: Slice) -> bool {
        match self {
            Self::Legacy(vm) => vm.is_assigned_raw(slice),
            Self::Strict(vm) => vm.is_assigned_raw(slice),
        }
    }
    fn assign_raw(&mut self, slice: Slice, data: BitVec) -> VmResult<()> {
        match self {
            Self::Legacy(vm) => vm.assign_raw(slice, data),
            Self::Strict(vm) => vm.assign_raw(slice, data),
        }
    }
    fn is_committed_raw(&self, slice: Slice) -> bool {
        match self {
            Self::Legacy(vm) => vm.is_committed_raw(slice),
            Self::Strict(vm) => vm.is_committed_raw(slice),
        }
    }
    fn commit_raw(&mut self, slice: Slice) -> VmResult<()> {
        match self {
            Self::Legacy(vm) => vm.commit_raw(slice),
            Self::Strict(vm) => vm.commit_raw(slice),
        }
    }
    fn get_raw(&self, slice: Slice) -> VmResult<Option<BitVec>> {
        match self {
            Self::Legacy(vm) => vm.get_raw(slice),
            Self::Strict(vm) => vm.get_raw(slice),
        }
    }
    fn decode_raw(&mut self, slice: Slice) -> VmResult<DecodeFuture<BitVec>> {
        match self {
            Self::Legacy(vm) => vm.decode_raw(slice),
            Self::Strict(vm) => vm.decode_raw(slice),
        }
    }
}
impl<OT> View<Binary> for Verifier<OT>
where
    OT: RCOTSender<Block>,
{
    type Error = VmError;
    fn mark_public_raw(&mut self, slice: Slice) -> VmResult<()> {
        match self {
            Self::Legacy(vm) => vm.mark_public_raw(slice),
            Self::Strict(vm) => vm.mark_public_raw(slice),
        }
    }
    fn mark_private_raw(&mut self, slice: Slice) -> VmResult<()> {
        match self {
            Self::Legacy(vm) => vm.mark_private_raw(slice),
            Self::Strict(vm) => vm.mark_private_raw(slice),
        }
    }
    fn mark_blind_raw(&mut self, slice: Slice) -> VmResult<()> {
        match self {
            Self::Legacy(vm) => vm.mark_blind_raw(slice),
            Self::Strict(vm) => vm.mark_blind_raw(slice),
        }
    }
}
