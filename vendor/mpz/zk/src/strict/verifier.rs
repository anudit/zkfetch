//! Strict two-lane VM. Not selected by legacy sessions.
use crate::{callstack::CallStack, config::VerifierConfig};
use async_trait::async_trait;
use blake3::Hasher;
use mpz_common::{Context, Flush};
use mpz_core::{Block, bitvec::BitVec};
use mpz_ot::rcot::RCOTSender;
use mpz_vm_core::{
    Call, Callable, Execute, Result as VmResult, VmError,
    memory::{DecodeFuture, Memory, Repr, Slice, View, binary::Binary},
};
use mpz_zk_core::auth::{ZkDelta, ZkKey, check, circuit, store::*};
use serio::stream::IoStreamExt;
#[derive(Debug)]
pub struct Verifier<OT> {
    config: VerifierConfig,
    store: VerifierStore,
    ot: [OT; 2],
    callstack: CallStack,
    transcript: Hasher,
}
fn transcript() -> Hasher {
    let mut t = Hasher::new();
    t.update(b"zkf/strict-quicksilver/two-full-entropy-lanes/v1");
    t
}
impl<OT> Verifier<OT> {
    pub fn new(config: VerifierConfig, deltas: [ZkDelta; 2], ot: [OT; 2]) -> Self {
        Self {
            config,
            store: VerifierStore::new(deltas),
            ot,
            callstack: CallStack::default(),
            transcript: transcript(),
        }
    }
    pub fn bind_statement(&mut self, statement: &[u8]) {
        self.transcript
            .update(&(statement.len() as u64).to_le_bytes());
        self.transcript.update(statement);
    }
    pub fn field_challenge(&self) -> [u8; 32] {
        let mut t = self.transcript.clone();
        t.update(b"degree-three/strict/v1");
        *t.finalize().as_bytes()
    }
    pub fn get_keys<R: Repr<Binary>>(&self, value: R) -> VmResult<&[ZkKey<2>]> {
        self.store
            .try_get_keys(value.to_raw())
            .map_err(VmError::memory)
    }
    pub fn deltas(&self) -> &[ZkDelta; 2] {
        self.store.deltas()
    }
}
#[async_trait]
impl<OT> Execute for Verifier<OT>
where
    OT: RCOTSender<Block> + Flush + Send + 'static,
{
    fn wants_flush(&self) -> bool {
        self.ot.iter().any(|ot| ot.wants_flush())
            || self.store.wants_flush()
            || self.store.wants_keys()
    }
    async fn flush(&mut self, ctx: &mut Context) -> VmResult<()> {
        // Deterministic lane ordering gives each independent OT stream its own flight.
        for ot in &mut self.ot {
            if ot.wants_flush() {
                ot.flush(ctx).await.map_err(VmError::execute)?;
            }
        }
        if self.store.wants_keys() {
            let n = self.store.key_count();
            let a = self.ot[0].try_send_rcot(n).map_err(VmError::execute)?;
            let b = self.ot[1].try_send_rcot(n).map_err(VmError::execute)?;
            let keys: Vec<_> = (0..n)
                .map(|i| ZkKey::from_rcot([a.keys[i], b.keys[i]], [false; 2], self.store.deltas()))
                .collect();
            self.store.set_keys(&keys).map_err(VmError::memory)?;
        }
        while self.store.wants_flush() {
            self.store.mark_flush_pending().map_err(VmError::memory)?;
            let flush: ProverFlush = ctx.io_mut().expect_next().await?;
            let bytes = bincode::serialize(&flush).map_err(VmError::execute)?;
            self.store
                .receive_flush(flush, &mut self.transcript)
                .map_err(VmError::memory)?;
            self.transcript.update(&(bytes.len() as u64).to_le_bytes());
            self.transcript.update(&bytes);
        }
        Ok(())
    }
    fn wants_preprocess(&self) -> bool {
        false
    }
    async fn preprocess(&mut self, _: &mut Context) -> VmResult<()> {
        Ok(())
    }
    fn wants_execute(&self) -> bool {
        self.callstack
            .iter()
            .any(|(c, _)| c.inputs().iter().all(|s| self.store.is_committed_raw(*s)))
    }
    async fn execute(&mut self, ctx: &mut Context) -> VmResult<()> {
        let mut triples = Vec::new();
        while !self.callstack.is_empty() {
            let ready: Vec<_> = self
                .callstack
                .extract_if(
                    self.config.batch_size().saturating_sub(triples.len()),
                    |c| c.inputs().iter().all(|s| self.store.is_committed_raw(*s)),
                )
                .collect();
            if ready.is_empty() {
                break;
            }
            for (call, output) in ready {
                let inputs: Vec<_> = call
                    .inputs()
                    .iter()
                    .flat_map(|s| self.store.try_get_keys(*s).expect("committed input"))
                    .copied()
                    .collect();
                let (circ, _) = call.into_parts();
                let n = circ.and_count();
                let a = self.ot[0].try_send_rcot(n).map_err(VmError::execute)?;
                let b = self.ot[1].try_send_rcot(n).map_err(VmError::execute)?;
                let keys: Vec<_> = (0..n).map(|i| [a.keys[i], b.keys[i]]).collect();
                let mut adjust = Vec::with_capacity(n);
                while adjust.len() < n {
                    let bits: [BitVec; 2] = ctx.io_mut().expect_next().await?;
                    let expected = (n - adjust.len()).min(8000);
                    if bits.iter().any(|b| b.len() != expected) {
                        return Err(VmError::execute("incorrect dual-lane correction chunk"));
                    }
                    let bytes = bincode::serialize(&bits).map_err(VmError::execute)?;
                    self.transcript.update(&(bytes.len() as u64).to_le_bytes());
                    self.transcript.update(&bytes);
                    for i in 0..expected {
                        adjust.push([bits[0][i], bits[1][i]]);
                    }
                }
                let result = circuit::verify(&circ, &inputs, &keys, &adjust, self.store.deltas())
                    .map_err(VmError::execute)?;
                self.store
                    .set_output_keys(output, &result.outputs)
                    .map_err(VmError::memory)?;
                triples.extend(result.triples);
            }
            if triples.len() >= self.config.batch_size() {
                self.check(ctx, &triples).await?;
                triples.clear();
            }
        }
        if !triples.is_empty() {
            self.check(ctx, &triples).await?;
        }
        if !self.callstack.is_empty() {
            for ot in &mut self.ot {
                ot.alloc(128).map_err(VmError::execute)?;
            }
        }
        Ok(())
    }
}
impl<OT> Verifier<OT>
where
    OT: RCOTSender<Block> + Flush + Send + 'static,
{
    async fn check(
        &mut self,
        ctx: &mut Context,
        triples: &[(ZkKey<2>, ZkKey<2>, ZkKey<2>)],
    ) -> VmResult<()> {
        let a = self.ot[0].try_send_rcot(128).map_err(VmError::execute)?;
        let b = self.ot[1].try_send_rcot(128).map_err(VmError::execute)?;
        let keys = [
            a.keys
                .try_into()
                .map_err(|_| VmError::execute("mask count"))?,
            b.keys
                .try_into()
                .map_err(|_| VmError::execute("mask count"))?,
        ];
        let proof: check::CheckProof = ctx.io_mut().expect_next().await?;
        // Do not expose which lane failed to the peer.
        check::verify(
            &mut self.transcript,
            triples,
            self.store.deltas(),
            &keys,
            &proof,
        )
        .map_err(|_| VmError::execute("strict consistency check rejected"))
    }
}
impl<OT> Callable<Binary> for Verifier<OT>
where
    OT: RCOTSender<Block>,
{
    fn call_raw(&mut self, call: Call) -> VmResult<Slice> {
        let output = self.store.alloc_output(call.circ().outputs().len());

        let count = call.circ().and_count();

        if count == 0 {
            self.callstack.push((call, output));
            return Ok(output);
        }

        // The number of additional consistency checks to allocate for.
        let mut check_count = 0;

        let partial_len = self.callstack.and_count() % self.config.batch_size();

        if partial_len == 0 {
            // Allocate for the first batch or when the previous batch
            // landed exactly on the batch boundary.
            check_count += 1;
        }

        // Using -1 because we allocate whenever a batch boundary is
        // **crossed**, not when we land exactly on the boundary.
        check_count += (partial_len + count - 1) / self.config.batch_size();

        for ot in &mut self.ot {
            ot.alloc(count + check_count * 128)
                .map_err(VmError::execute)?;
        }

        self.callstack.push((call, output));

        Ok(output)
    }
}

impl<OT> Memory<Binary> for Verifier<OT>
where
    OT: RCOTSender<Block>,
{
    type Error = VmError;

    fn is_alloc_raw(&self, slice: Slice) -> bool {
        self.store.is_alloc_raw(slice)
    }

    fn alloc_raw(&mut self, size: usize) -> VmResult<Slice> {
        self.store.alloc_raw(size).map_err(VmError::memory)
    }

    fn is_assigned_raw(&self, slice: Slice) -> bool {
        self.store.is_assigned_raw(slice)
    }

    fn assign_raw(&mut self, slice: Slice, data: BitVec) -> VmResult<()> {
        self.store.assign_raw(slice, data).map_err(VmError::memory)
    }

    fn is_committed_raw(&self, slice: Slice) -> bool {
        self.store.is_committed_raw(slice)
    }

    fn commit_raw(&mut self, slice: Slice) -> VmResult<()> {
        self.store.commit_raw(slice).map_err(VmError::memory)
    }

    fn get_raw(&self, slice: Slice) -> VmResult<Option<BitVec>> {
        self.store.get_raw(slice).map_err(VmError::memory)
    }

    fn decode_raw(&mut self, slice: Slice) -> VmResult<DecodeFuture<BitVec>> {
        self.store.decode_raw(slice).map_err(VmError::memory)
    }
}

impl<OT> View<Binary> for Verifier<OT>
where
    OT: RCOTSender<Block>,
{
    type Error = VmError;

    fn mark_public_raw(&mut self, slice: Slice) -> VmResult<()> {
        self.store.mark_public_raw(slice).map_err(VmError::view)
    }

    fn mark_private_raw(&mut self, _slice: Slice) -> VmResult<()> {
        Err(VmError::view(
            "marking as private is not allowed for zk verifier",
        ))
    }

    fn mark_blind_raw(&mut self, slice: Slice) -> VmResult<()> {
        self.store.mark_blind_raw(slice).map_err(VmError::view)?;
        for ot in &mut self.ot {
            ot.alloc(slice.len()).map_err(VmError::view)?;
        }

        Ok(())
    }
}
