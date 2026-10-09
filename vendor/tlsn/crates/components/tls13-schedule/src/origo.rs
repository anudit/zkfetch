//! ORIGO Figure 10 key schedule. Only inner pad states below dHS are public;
//! their outer pad states and all application secrets stay in the VM.
use crate::{
    ApplicationKeys, FError,
    hmac::{IPAD, OPAD, clear, compute_partial, hmac_sha256},
    kdf::expand::hkdf_expand_label,
    sha256, state_to_bytes,
};
use mpz_core::bitvec::BitVec;
use mpz_hash::sha256::Sha256;
use mpz_vm_core::{
    Vm,
    memory::{
        Array, DecodeFutureTyped, MemoryExt, Vector, ViewExt,
        binary::{Binary, U8, U32},
    },
};

/// Public ORIGO preprocessing values. Never contains application secrets or
/// outer pad states below the handshake secret.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct OrigoClaim {
    hs_outer: [u32; 8],
    client_hs_inner: [u8; 32],
    server_hs_inner: [u8; 32],
    derived_inner: [u32; 8],
    master_inner: [u32; 8],
    client_inner: [u32; 8],
    server_inner: [u32; 8],
}
fn inner(state: [u32; 8], msg: &[u8]) -> [u8; 32] {
    state_to_bytes(sha256(state, 64, msg))
}
fn label(label: &[u8], ctx: &[u8], len: usize) -> Vec<u8> {
    let mut msg = crate::kdf::expand::label::make_hkdf_label(label, ctx, len);
    msg.push(1);
    msg
}
impl OrigoClaim {
    /// Computes public preprocessing and the private dHS inner hash witness
    /// from a fresh full-handshake ECDHE shared secret.
    pub fn preprocess(
        secret: &[u8; 32],
        hello_hash: [u8; 32],
        handshake_hash: [u8; 32],
    ) -> (Self, [u8; 32]) {
        let salt = [
            0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5, 0x67, 0x8f, 0x54, 0xfc, 0x9d, 0xba,
            0xb6, 0x97, 0x16, 0xc0, 0x76, 0x18, 0x9c, 0x48, 0x25, 0x0c, 0xeb, 0xea, 0xc3, 0x57,
            0x6c, 0x36, 0x11, 0xba,
        ];
        use zeroize::Zeroize;
        let mut hs = clear::hmac_sha256(&salt, secret);
        let mut hs_inner = clear::compute_inner_partial(&hs);
        let hs_outer = clear::compute_outer_partial(&hs);
        let empty = state_to_bytes(sha256(crate::hmac::SHA256_IV, 0, &[]));
        let witness = inner(hs_inner, &label(b"derived", &empty, 32));
        let mut derived = inner(hs_outer, &witness);
        let mut master = clear::hmac_sha256(&derived, &[0; 32]);
        let mut client = hkdf_expand_label(&master, b"c ap traffic", &handshake_hash, 32);
        let mut server = hkdf_expand_label(&master, b"s ap traffic", &handshake_hash, 32);
        let claim = Self {
            hs_outer,
            client_hs_inner: inner(hs_inner, &label(b"c hs traffic", &hello_hash, 32)),
            server_hs_inner: inner(hs_inner, &label(b"s hs traffic", &hello_hash, 32)),
            derived_inner: clear::compute_inner_partial(&derived),
            master_inner: clear::compute_inner_partial(&master),
            client_inner: clear::compute_inner_partial(&client),
            server_inner: clear::compute_inner_partial(&server),
        };
        hs.zeroize();
        hs_inner.zeroize();
        derived.zeroize();
        master.zeroize();
        client.zeroize();
        server.zeroize();
        (claim, witness)
    }
    /// Handshake traffic secrets derived out of circuit for authentication.
    pub fn handshake_secrets(&self) -> ([u8; 32], [u8; 32]) {
        (
            inner(self.hs_outer, &self.client_hs_inner),
            inner(self.hs_outer, &self.server_hs_inner),
        )
    }
}
struct PublicInput {
    value: Array<U8, 32>,
    kind: usize,
}
/// A single-execution ORIGO schedule with 16 SHA-256 compressions for both
/// application directions, including proof of the two public IVs.
pub struct OrigoSchedule {
    outer: Array<U32, 8>,
    witness: Array<U8, 32>,
    inputs: Vec<PublicInput>,
    checks: Vec<DecodeFutureTyped<BitVec, [u32; 8]>>,
    /// Application keys available as VM references immediately after allocation.
    pub keys: ApplicationKeys,
    prover: bool,
}
impl OrigoSchedule {
    /// Allocates the circuit; no intermediate execution or disclosure round is needed.
    pub fn alloc(vm: &mut dyn Vm<Binary>, prover: bool) -> Result<Self, FError> {
        let outer = vm.alloc().map_err(FError::vm)?;
        vm.mark_public(outer).map_err(FError::vm)?;
        let witness = vm.alloc().map_err(FError::vm)?;
        if prover {
            vm.mark_private(witness).map_err(FError::vm)?;
        } else {
            vm.mark_blind(witness).map_err(FError::vm)?;
        }
        let derived = hmac_sha256(vm, Sha256::new_from_state(outer, 1), witness)?;
        let mut inputs = Vec::new();
        let mut checks = Vec::new();
        fn pads(
            vm: &mut dyn Vm<Binary>,
            key: Array<U8, 32>,
            checks: &mut Vec<DecodeFutureTyped<BitVec, [u32; 8]>>,
        ) -> Result<Sha256, FError> {
            let ipad = compute_partial(vm, key.into(), IPAD)?;
            checks.push(
                vm.decode(ipad.state().expect("compressed pad").0)
                    .map_err(FError::vm)?,
            );
            compute_partial(vm, key.into(), OPAD)
        }
        fn output(
            vm: &mut dyn Vm<Binary>,
            outer: Sha256,
            inputs: &mut Vec<PublicInput>,
            kind: usize,
        ) -> Result<Array<U8, 32>, FError> {
            let value = vm.alloc().map_err(FError::vm)?;
            vm.mark_public(value).map_err(FError::vm)?;
            inputs.push(PublicInput { value, kind });
            hmac_sha256(vm, outer, value)
        }
        let derived_outer = pads(vm, derived, &mut checks)?;
        let master = output(vm, derived_outer, &mut inputs, 0)?;
        let master_outer = pads(vm, master, &mut checks)?;
        let client = output(vm, master_outer.clone(), &mut inputs, 1)?;
        let server = output(vm, master_outer, &mut inputs, 2)?;
        let client_outer = pads(vm, client, &mut checks)?;
        let server_outer = pads(vm, server, &mut checks)?;
        fn prefix<const N: usize>(a: Array<U8, 32>) -> Array<U8, N> {
            Vector::from(a)
                .get(0..N)
                .expect("valid prefix")
                .try_into()
                .ok()
                .expect("fixed prefix")
        }
        let keys = ApplicationKeys {
            client_write_key: prefix(output(vm, client_outer.clone(), &mut inputs, 3)?),
            client_iv: prefix(output(vm, client_outer, &mut inputs, 4)?),
            server_write_key: prefix(output(vm, server_outer.clone(), &mut inputs, 5)?),
            server_iv: prefix(output(vm, server_outer, &mut inputs, 6)?),
        };
        Ok(Self {
            outer,
            witness,
            inputs,
            checks,
            keys,
            prover,
        })
    }
    /// Assigns public preprocessing values and the prover's private witness.
    pub fn assign(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        claim: &OrigoClaim,
        handshake_hash: [u8; 32],
        witness: Option<[u8; 32]>,
    ) -> Result<(), FError> {
        vm.assign(self.outer, claim.hs_outer).map_err(FError::vm)?;
        vm.commit(self.outer).map_err(FError::vm)?;
        if self.prover {
            vm.assign(
                self.witness,
                witness.ok_or_else(|| FError::state("ORIGO witness missing"))?,
            )
            .map_err(FError::vm)?;
        }
        vm.commit(self.witness).map_err(FError::vm)?;
        for input in &self.inputs {
            let value = match input.kind {
                0 => inner(claim.derived_inner, &[0; 32]),
                1 => inner(
                    claim.master_inner,
                    &label(b"c ap traffic", &handshake_hash, 32),
                ),
                2 => inner(
                    claim.master_inner,
                    &label(b"s ap traffic", &handshake_hash, 32),
                ),
                3 => inner(claim.client_inner, &label(b"key", &[], 16)),
                4 => inner(claim.client_inner, &label(b"iv", &[], 12)),
                5 => inner(claim.server_inner, &label(b"key", &[], 16)),
                6 => inner(claim.server_inner, &label(b"iv", &[], 12)),
                _ => unreachable!(),
            };
            vm.assign(input.value, value).map_err(FError::vm)?;
            vm.commit(input.value).map_err(FError::vm)?;
        }
        Ok(())
    }
    /// Checks every disclosed inner pad against its proven private key.
    /// Must succeed before any attestation is signed.
    pub fn verify(&mut self, claim: &OrigoClaim) -> Result<(), FError> {
        for (check, expected) in self.checks.iter_mut().zip([
            claim.derived_inner,
            claim.master_inner,
            claim.client_inner,
            claim.server_inner,
        ]) {
            if check
                .try_recv()
                .map_err(FError::vm)?
                .ok_or_else(|| FError::state("ORIGO check not decoded"))?
                != expected
            {
                return Err(FError::state("ORIGO inner pad mismatch"));
            }
        }
        Ok(())
    }
}
