//! AES-GCM authentication relation for split-mode record proofs.
//!
//! The caller binds the public AAD/ciphertext/tag to the captured record and
//! borrows the private key from the authenticated session VM. This gadget
//! alone does not establish provenance, completeness or split-key ordering.
use crate::{Byte, Circuit, Term, Wire, aes::ExpandedKey, field::Fe};

pub const MAX_RECORD_BYTES: usize = (1 << 14) + 256;

#[derive(Debug, thiserror::Error)]
pub enum GcmError {
    #[error("GCM record exceeds TLS ciphertext limit")]
    RecordLimit,
    #[error("GCM key must be 16 or 32 bytes")]
    KeyLength,
}

/// GHASH encodes the leftmost network bit as the constant polynomial term.
/// The IR field uses the same irreducible polynomial with little-endian
/// coefficient order; reverse all 128 network bits, not just the byte order.
fn field_block(bytes: [u8; 16]) -> Fe {
    Fe(u128::from_be_bytes(bytes).reverse_bits())
}
fn field_wires(c: &mut Circuit, bytes: [Byte; 16]) -> Wire {
    c.linear(
        (0..128)
            .map(|i| (Fe(1u128 << i), bytes[i / 8].0[7 - i % 8]))
            .collect(),
        Fe::ZERO,
    )
}

/// Compute GHASH over public padded AAD, ciphertext and the length block.
/// Each Horner multiplication contributes one 128-bit field commitment and
/// one degree-two constraint; the secret H remains bound to AES_k(0).
pub fn ghash(c: &mut Circuit, h: Wire, aad: &[u8], ciphertext: &[u8]) -> Result<Wire, GcmError> {
    if aad.len() > MAX_RECORD_BYTES || ciphertext.len() > MAX_RECORD_BYTES {
        return Err(GcmError::RecordLimit);
    }
    let mut acc = c.public_fe(Fe::ZERO);
    for bytes in [aad, ciphertext] {
        for chunk in bytes.chunks(16) {
            let mut block = [0; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            let add = c.linear(vec![(Fe::ONE, acc)], field_block(block));
            acc = c.mul(add, h);
        }
    }
    let mut lengths = [0; 16];
    lengths[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    lengths[8..].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
    let add = c.linear(vec![(Fe::ONE, acc)], field_block(lengths));
    Ok(c.mul(add, h))
}

/// Bind the tag to a reused expanded AES key. The 96-bit nonce must be derived
/// from the signed static IV and record sequence by the integrating statement.
pub fn assert_tag(
    c: &mut Circuit,
    key: &ExpandedKey,
    nonce: [u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: [u8; 16],
) -> Result<(), GcmError> {
    if aad.len() > MAX_RECORD_BYTES || ciphertext.len() > MAX_RECORD_BYTES {
        return Err(GcmError::RecordLimit);
    }
    let zero = std::array::from_fn(|_| c.public_byte(0));
    let h_bytes = key.encrypt_norm(c, zero);
    let h = field_wires(c, h_bytes);
    let hash = ghash(c, h, aad, ciphertext)?;
    let mut j0 = [0; 16];
    j0[..12].copy_from_slice(&nonce);
    j0[15] = 1;
    let counter = j0.map(|byte| c.public_byte(byte));
    let mask_bytes = key.encrypt_norm(c, counter);
    let mask = field_wires(c, mask_bytes);
    c.assert_zero(vec![
        Term::Linear(Fe::ONE, hash),
        Term::Linear(Fe::ONE, mask),
        Term::Constant(field_block(tag)),
    ]);
    Ok(())
}

/// Reference statement with the session key as the first committed bytes.
/// This is not registered as a production profile until split integration.
pub fn tag_statement(
    key_bytes: usize,
    nonce: [u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: [u8; 16],
) -> Result<Circuit, GcmError> {
    if !matches!(key_bytes, 16 | 32) {
        return Err(GcmError::KeyLength);
    }
    if aad.len() > MAX_RECORD_BYTES || ciphertext.len() > MAX_RECORD_BYTES {
        return Err(GcmError::RecordLimit);
    }
    let mut c = Circuit::default();
    let key = (0..key_bytes).map(|_| c.commit_byte()).collect::<Vec<_>>();
    let key = ExpandedKey::new(&mut c, &key).map_err(|_| GcmError::KeyLength)?;
    assert_tag(&mut c, &key, nonce, aad, ciphertext, tag)?;
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::byte_inputs;
    use aes_gcm::{
        Aes128Gcm, Aes256Gcm,
        aead::{Aead, KeyInit, Payload},
    };

    #[test]
    fn nist_empty_and_single_block_vectors() {
        for (ciphertext, tag) in [
            ("", "58e2fccefa7e3061367f1d57a4e7455a"),
            (
                "0388dace60b6a392f328c2b971b2fe78",
                "ab6e47d42cec13bdf53a67b21257bddf",
            ),
        ] {
            let ct = hex::decode(ciphertext).unwrap();
            let tag = hex::decode(tag).unwrap().try_into().unwrap();
            let c = tag_statement(16, [0; 12], &[], &ct, tag).unwrap();
            c.eval_checked(&byte_inputs(&[0; 16])).unwrap();
        }
    }

    #[test]
    fn differential_aes128_aes256_partial_blocks_and_tampering() {
        for key_len in [16, 32] {
            let key = vec![37; key_len];
            let nonce = [49; 12];
            for len in [0, 1, 15, 16, 17, 255, 1024] {
                let plaintext = vec![61; len];
                let aad = [23, 3, 3, 0, 17];
                let payload = Payload {
                    msg: &plaintext,
                    aad: &aad,
                };
                let output = if key_len == 16 {
                    Aes128Gcm::new_from_slice(&key)
                        .unwrap()
                        .encrypt((&nonce).into(), payload)
                        .unwrap()
                } else {
                    Aes256Gcm::new_from_slice(&key)
                        .unwrap()
                        .encrypt((&nonce).into(), payload)
                        .unwrap()
                };
                let (ct, tag) = output.split_at(output.len() - 16);
                let tag: [u8; 16] = tag.try_into().unwrap();
                tag_statement(key_len, nonce, &aad, ct, tag)
                    .unwrap()
                    .eval_checked(&byte_inputs(&key))
                    .unwrap();
                let mut bad_tag = tag;
                bad_tag[15] ^= 1;
                assert!(
                    tag_statement(key_len, nonce, &aad, ct, bad_tag)
                        .unwrap()
                        .eval_checked(&byte_inputs(&key))
                        .is_err()
                );
                let mut bad_aad = aad;
                bad_aad[0] ^= 1;
                assert!(
                    tag_statement(key_len, nonce, &bad_aad, ct, tag)
                        .unwrap()
                        .eval_checked(&byte_inputs(&key))
                        .is_err()
                );
                let mut bad_nonce = nonce;
                bad_nonce[0] ^= 1;
                assert!(
                    tag_statement(key_len, bad_nonce, &aad, ct, tag)
                        .unwrap()
                        .eval_checked(&byte_inputs(&key))
                        .is_err()
                );
                if !ct.is_empty() {
                    let mut bad_ct = ct.to_vec();
                    bad_ct[0] ^= 1;
                    assert!(
                        tag_statement(key_len, nonce, &aad, &bad_ct, tag)
                            .unwrap()
                            .eval_checked(&byte_inputs(&key))
                            .is_err()
                    );
                }
            }
        }
    }

    #[test]
    fn lengths_are_bound_and_oversized_records_are_refused() {
        let key = [0; 16];
        let tag: [u8; 16] = hex::decode("58e2fccefa7e3061367f1d57a4e7455a")
            .unwrap()
            .try_into()
            .unwrap();
        assert!(
            tag_statement(16, [0; 12], &[0], &[], tag)
                .unwrap()
                .eval_checked(&byte_inputs(&key))
                .is_err()
        );
        assert!(
            tag_statement(16, [0; 12], &[], &[0], tag)
                .unwrap()
                .eval_checked(&byte_inputs(&key))
                .is_err()
        );
        assert!(matches!(
            tag_statement(16, [0; 12], &[], &vec![0; MAX_RECORD_BYTES + 1], tag),
            Err(GcmError::RecordLimit)
        ));
        assert!(matches!(
            tag_statement(24, [0; 12], &[], &[], tag),
            Err(GcmError::KeyLength)
        ));
    }
}
