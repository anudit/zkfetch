//! AES-128-GCM record operations over alpha.15's binary MPC VM.
//!
//! Keys, static IVs, GHASH subkeys and plaintext are never decoded here.
//! The caller decodes outgoing ciphertext/tag publicly, or compares the public
//! computed tag with the received tag before using/declassifying inner plaintext.
//! This is a correctness-first circuit backend, not the optimized OLE backend.
use std::sync::Arc;

use anyhow::{Result, ensure};
use mpz_circuits::{AES128_KS, AES128_POST_KS, Circuit, CircuitBuilder, circuits::xor};
use mpz_vm_core::{
    Call, CallableExt, Vm,
    memory::{
        Array, MemoryExt, Vector, ViewExt,
        binary::{Binary, U8},
    },
};
use subtle::ConstantTimeEq;

use crate::record::{self, Sequence, TAG_LEN};

pub struct Aead {
    schedule: Array<U8, 176>,
    iv: Array<U8, 12>,
    h: Array<U8, 16>,
    sequence: Sequence,
}

pub struct Encrypted {
    pub header: [u8; 5],
    pub ciphertext: Vector<U8>,
    pub tag: Array<U8, 16>,
}

/// The tag must be decoded and checked before the inner plaintext is accepted.
pub struct PendingDecryption {
    inner: Vector<U8>,
    computed_tag: Array<U8, 16>,
    expected_tag: [u8; 16],
}
impl PendingDecryption {
    /// Decode the actual MPC tag and compare it before exposing the plaintext
    /// reference. Both participants must execute this step together.
    pub async fn authenticate(
        self,
        vm: &mut (dyn Vm<Binary> + Send),
        ctx: &mut mpz_common::Context,
    ) -> Result<Vector<U8>> {
        let mut computed = vm.decode(self.computed_tag)?;
        vm.execute_all(ctx).await?;
        let computed = computed
            .try_recv()?
            .ok_or_else(|| anyhow::anyhow!("record tag not decoded"))?;
        ensure!(
            bool::from(computed.ct_eq(&self.expected_tag)),
            "TLS 1.3 record tag mismatch"
        );
        Ok(self.inner)
    }
}

fn public(vm: &mut dyn Vm<Binary>, bytes: &[u8]) -> Result<Vector<U8>> {
    let value = vm.alloc_vec(bytes.len())?;
    vm.mark_public(value)?;
    vm.assign(value, bytes.to_vec())?;
    vm.commit(value)?;
    Ok(value)
}

impl Aead {
    /// Application-key and IV references can come directly from Tls13KeySched.
    pub fn alloc(vm: &mut dyn Vm<Binary>, key: Array<U8, 16>, iv: Array<U8, 12>) -> Result<Self> {
        let schedule = vm.call(Call::builder(AES128_KS.clone()).arg(key).build()?)?;
        let zero = public(vm, &[0; 16])?;
        let h = vm.call(
            Call::builder(AES128_POST_KS.clone())
                .arg(schedule)
                .arg(zero)
                .build()?,
        )?;
        Ok(Self {
            schedule,
            iv,
            h,
            sequence: Sequence::default(),
        })
    }

    fn nonce(&mut self, vm: &mut dyn Vm<Binary>) -> Result<Array<U8, 12>> {
        let seq = self.sequence.take()?;
        let mut padded = [0; 12];
        padded[4..].copy_from_slice(&seq.to_be_bytes());
        let seq = public(vm, &padded)?;
        Ok(vm.call(
            Call::builder(Arc::new(xor(96)))
                .arg(self.iv)
                .arg(seq)
                .build()?,
        )?)
    }

    fn block(
        &self,
        vm: &mut dyn Vm<Binary>,
        nonce: Array<U8, 12>,
        counter: u32,
    ) -> Result<Array<U8, 16>> {
        let counter = public(vm, &counter.to_be_bytes())?;
        Ok(vm.call(
            Call::builder(AES128_POST_KS.clone())
                .arg(self.schedule)
                .arg(nonce)
                .arg(counter)
                .build()?,
        )?)
    }

    fn apply(
        &self,
        vm: &mut dyn Vm<Binary>,
        nonce: Array<U8, 12>,
        input: Vector<U8>,
    ) -> Result<Vector<U8>> {
        let mut blocks = Vec::new();
        for counter in 0..input.len().div_ceil(16) {
            blocks.push(self.block(vm, nonce, (counter + 2) as u32)?);
        }
        let mut call = Call::builder(Arc::new(xor(input.len() * 8))).arg(input);
        for (i, block) in blocks.into_iter().enumerate() {
            call = call.arg(
                Vector::from(block)
                    .get(0..(input.len() - i * 16).min(16))
                    .expect("valid stream slice"),
            );
        }
        Ok(vm.call(call.build()?)?)
    }

    fn tag(
        &self,
        vm: &mut dyn Vm<Binary>,
        nonce: Array<U8, 12>,
        header: [u8; 5],
        ct: Vector<U8>,
    ) -> Result<Array<U8, 16>> {
        let header = public(vm, &header)?;
        let hash: Array<U8, 16> = vm.call(
            Call::builder(Arc::new(ghash(ct.len())))
                .arg(self.h)
                .arg(header)
                .arg(ct)
                .build()?,
        )?;
        let mask = self.block(vm, nonce, 1)?;
        Ok(vm.call(
            Call::builder(Arc::new(xor(128)))
                .arg(hash)
                .arg(mask)
                .build()?,
        )?)
    }

    /// Inner plaintext includes its content type and padding; record::encode_inner
    /// handles public data, while private data must be assembled inside the VM.
    pub fn encrypt(&mut self, vm: &mut dyn Vm<Binary>, inner: Vector<U8>) -> Result<Encrypted> {
        let header = record::aad(
            inner
                .len()
                .checked_add(TAG_LEN)
                .ok_or_else(|| anyhow::anyhow!("record length overflow"))?,
        )?;
        let nonce = self.nonce(vm)?;
        let ciphertext = self.apply(vm, nonce, inner)?;
        let tag = self.tag(vm, nonce, header, ciphertext)?;
        Ok(Encrypted {
            header,
            ciphertext,
            tag,
        })
    }

    /// Ciphertext is public and fixed in the VM before any plaintext decoding.
    /// Full wire headers are checked, including legacy version and exact length.
    pub fn decrypt(&mut self, vm: &mut dyn Vm<Binary>, wire: &[u8]) -> Result<PendingDecryption> {
        ensure!(wire.len() > 5 + TAG_LEN, "truncated TLS 1.3 record");
        let header = record::aad(wire.len() - 5)?;
        ensure!(wire[..5] == header, "invalid TLS 1.3 record header");
        let split = wire.len() - TAG_LEN;
        let expected_tag = wire[split..].try_into()?;
        let ct = public(vm, &wire[5..split])?;
        let nonce = self.nonce(vm)?;
        let computed_tag = self.tag(vm, nonce, header, ct)?;
        let inner = self.apply(vm, nonce, ct)?;
        Ok(PendingDecryption {
            inner,
            computed_tag,
            expected_tag,
        })
    }
}

/// NIST SP 800-38D Algorithm 2. Inputs are little-endian bits within each byte
/// in mpz; multiplication uses the big-endian polynomial convention of GCM.
fn ghash(ct_len: usize) -> Circuit {
    let mut b = CircuitBuilder::new();
    let h: [_; 128] = std::array::from_fn(|_| b.add_input());
    let aad: [_; 40] = std::array::from_fn(|_| b.add_input());
    let ct: Vec<_> = (0..ct_len * 8).map(|_| b.add_input()).collect();
    // A real zero wire avoids constant-only output feeds in CircuitBuilder.
    let zero = b.add_xor_gate(h[0], h[0]);
    let h: [_; 128] = std::array::from_fn(|i| h[(i / 8) * 8 + 7 - i % 8]);
    let mut blocks = Vec::new();
    let mut first = [zero; 128];
    for i in 0..40 {
        first[i] = aad[(i / 8) * 8 + 7 - i % 8];
    }
    blocks.push(first);
    for start in (0..ct_len).step_by(16) {
        let mut block = [zero; 128];
        for i in 0..(ct_len - start).min(16) * 8 {
            block[i] = ct[start * 8 + (i / 8) * 8 + 7 - i % 8];
        }
        blocks.push(block);
    }
    let mut length = [0u8; 16];
    length[..8].copy_from_slice(&40u64.to_be_bytes());
    length[8..].copy_from_slice(&((ct_len as u64) * 8).to_be_bytes());
    let one = b.add_inv_gate(zero);
    blocks.push(std::array::from_fn(|i| {
        if (length[i / 8] >> (7 - i % 8)) & 1 == 1 {
            one
        } else {
            zero
        }
    }));
    let mut y = [zero; 128];
    for block in blocks {
        let x: [_; 128] = std::array::from_fn(|i| b.add_xor_gate(y[i], block[i]));
        let mut z = [zero; 128];
        let mut v = h;
        for bit in x {
            for j in 0..128 {
                let term = b.add_and_gate(bit, v[j]);
                z[j] = b.add_xor_gate(z[j], term);
            }
            let lsb = v[127];
            v = std::array::from_fn(|j| {
                let shifted = if j == 0 { zero } else { v[j - 1] };
                if [0, 1, 2, 7].contains(&j) {
                    b.add_xor_gate(shifted, lsb)
                } else {
                    shifted
                }
            });
        }
        y = z;
    }
    for i in 0..128 {
        let out = b.add_id_gate(y[(i / 8) * 8 + 7 - i % 8]);
        b.add_output(out);
    }
    b.build().expect("valid GHASH circuit")
}

#[cfg(test)]
mod tests;
