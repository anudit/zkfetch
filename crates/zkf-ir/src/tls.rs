//! TLS 1.3 key-commitment and counter-block statement building.
use crate::{Byte, Circuit, aes::ExpandedKey};
use sha2::{Digest, Sha256};

/// Fixed commitment blocks with a zero counter suffix, outside GCM's data and
/// tag-mask counter domain. Index encoding is one byte, with indices 1 and 2.
pub fn commitment_block(index: u8) -> Result<[u8; 16], TlsError> {
    if index != 1 && index != 2 {
        return Err(TlsError::CommitmentIndex);
    }
    let mut hash = Sha256::new();
    hash.update(b"zkf/2/ck");
    hash.update([index]);
    let digest = hash.finalize();
    let mut block = [0; 16];
    block[..12].copy_from_slice(&digest[..12]);
    Ok(block)
}

pub fn key_commitment(c: &mut Circuit, key: &ExpandedKey) -> [Byte; 32] {
    let blocks = [1, 2].map(|index| {
        let block = commitment_block(index)
            .expect("fixed index")
            .map(|b| c.public_byte(b));
        key.encrypt_norm(c, block)
    });
    std::array::from_fn(|i| blocks[i / 16][i % 16])
}

/// The interactive backend favors fewer constraint terms over fewer VOLE bits.
pub fn key_commitment_session(c: &mut Circuit, key: &ExpandedKey) -> [Byte; 32] {
    let blocks = [1, 2].map(|index| {
        let block = commitment_block(index)
            .expect("fixed index")
            .map(|b| c.public_byte(b));
        key.encrypt(c, block)
    });
    std::array::from_fn(|i| blocks[i / 16][i % 16])
}

/// The in-session statement: a committed AES-128 key (the first 16 committed
/// bytes, borrowed from the TLS VM) encrypts the commitment blocks to `ck`.
/// Both parties build it from the public `ck`; the key is the only witness.
pub fn key_commitment_statement(ck: [u8; 32]) -> Circuit {
    let mut c = Circuit::default();
    let key: Vec<_> = (0..16).map(|_| c.commit_byte()).collect();
    let expanded = ExpandedKey::new(&mut c, &key).expect("16-byte key");
    for (wire, expected) in key_commitment(&mut c, &expanded).into_iter().zip(ck) {
        c.assert_byte(wire, expected);
    }
    c
}

/// Both authenticated session keys are the first 32 committed bytes, in
/// client/server order. Neither is reassigned into a new MAC commitment.
pub fn keys_commitment_statement(client: [u8; 32], server: [u8; 32]) -> Circuit {
    let mut c = Circuit::default();
    let keys: Vec<_> = (0..32).map(|_| c.commit_byte()).collect();
    for (key, ck) in keys.chunks_exact(16).zip([client, server]) {
        let expanded = ExpandedKey::new(&mut c, key).expect("16-byte key");
        for (wire, expected) in key_commitment_session(&mut c, &expanded)
            .into_iter()
            .zip(ck)
        {
            c.assert_byte(wire, expected);
        }
    }
    c.register_profile(KEYS_PROFILE);
    c
}

/// RFC 8446 §5.3: XOR the padded record sequence into the 96-bit static IV.
pub fn nonce(iv: [u8; 12], seq: u64) -> [u8; 12] {
    let mut result = iv;
    for (i, byte) in seq.to_be_bytes().into_iter().enumerate() {
        result[i + 4] ^= byte;
    }
    result
}

/// A data block index is relative to the TLSInnerPlaintext, not an HTTP body.
/// Refuse wraparound, tag-mask counter 1, and blocks beyond TLS record limits.
pub fn counter_block(iv: [u8; 12], seq: u64, block_index: u32) -> Result<[u8; 16], TlsError> {
    // TLSInnerPlaintext maximum is 2^14 + 1 bytes (RFC 8446 §5.2).
    if block_index > 1024 {
        return Err(TlsError::BlockIndex);
    }
    let mut counter = [0; 16];
    counter[..12].copy_from_slice(&nonce(iv, seq));
    counter[12..].copy_from_slice(&(block_index + 2).to_be_bytes());
    Ok(counter)
}

/// Decrypt a touched CTR block and bind only the requested public bytes.
/// Ciphertext is public; callers must authenticate it through a Bao opening.
/// The returned hidden-byte wires belong only in the private predicate graph.
pub fn ctr_block(
    c: &mut Circuit,
    key: &ExpandedKey,
    counter: [u8; 16],
    ciphertext: [u8; 16],
    revealed: [Option<u8>; 16],
) -> Result<[Byte; 16], TlsError> {
    if u32::from_be_bytes(counter[12..].try_into().unwrap()) < 2 {
        return Err(TlsError::Counter);
    }
    let input = counter.map(|b| c.public_byte(b));
    let stream = key.encrypt_norm(c, input);
    let plaintext = std::array::from_fn(|i| {
        let ct = c.public_byte(ciphertext[i]);
        let byte = c.byte_xor(ct, stream[i]);
        if let Some(expected) = revealed[i] {
            c.assert_byte(byte, expected);
        }
        byte
    });
    Ok(plaintext)
}

/// Cheaper authenticated checks for in-session framing proof. Offline proofs
/// use the smaller inverse-norm encoding through `ctr_block` instead.
pub fn ctr_block_session(
    c: &mut Circuit,
    key: &ExpandedKey,
    counter: [u8; 16],
    ciphertext: [u8; 16],
    revealed: [Option<u8>; 16],
) -> Result<[Byte; 16], TlsError> {
    if u32::from_be_bytes(counter[12..].try_into().unwrap()) < 2 {
        return Err(TlsError::Counter);
    }
    let input = counter.map(|b| c.public_byte(b));
    let stream = key.encrypt(c, input);
    let plaintext = std::array::from_fn(|i| {
        let ct = c.public_byte(ciphertext[i]);
        let byte = c.byte_xor(ct, stream[i]);
        if let Some(expected) = revealed[i] {
            c.assert_byte(byte, expected);
        }
        byte
    });
    Ok(plaintext)
}

/// Prove a declared application content-type position and every padding byte
/// after it. Callers must supply the complete decrypted suffix of the record;
/// proving a last nonzero byte in a shorter window is insufficient.
pub fn assert_application_suffix(c: &mut Circuit, suffix: &[Byte]) -> Result<(), TlsError> {
    let (content_type, padding) = suffix.split_first().ok_or(TlsError::EmptySuffix)?;
    c.assert_byte(*content_type, 0x17);
    for byte in padding {
        c.assert_byte(*byte, 0);
    }
    Ok(())
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TlsError {
    #[error("key commitment index must be 1 or 2")]
    CommitmentIndex,
    #[error("counter block exceeds TLSInnerPlaintext limit")]
    BlockIndex,
    #[error("data counter must be at least 2")]
    Counter,
    #[error("content-type suffix is empty")]
    EmptySuffix,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{byte_inputs, field::Fe};
    use ::aes::{
        Aes128,
        cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
    };

    #[test]
    fn commitment_domain_is_disjoint_from_gcm() {
        let blocks = [1, 2].map(|i| commitment_block(i).unwrap());
        assert_ne!(blocks[0], blocks[1]);
        for rho in blocks {
            assert_eq!(&rho[12..], &[0; 4]);
            for seq in [0, 1, u64::MAX] {
                for index in 0..=1024 {
                    assert_ne!(
                        rho,
                        counter_block(rho[..12].try_into().unwrap(), seq, index).unwrap()
                    );
                }
            }
        }
        assert!(counter_block([0; 12], 0, 1025).is_err());
        assert!(commitment_block(0).is_err());
    }

    #[test]
    fn nonce_and_ctr_match_sp_800_38a() {
        // AES-CTR SP 800-38A F.5.1; the first counter ends feff (a legal
        // generic CTR input). TLS uses the same AES-CTR operation.
        let raw_key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let ctr = hex::decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
            .unwrap()
            .try_into()
            .unwrap();
        let ct = hex::decode("874d6191b620e3261bef6864990db6ce")
            .unwrap()
            .try_into()
            .unwrap();
        let expected: [u8; 16] = hex::decode("6bc1bee22e409f96e93d7e117393172a")
            .unwrap()
            .try_into()
            .unwrap();
        let mut c = Circuit::default();
        let refs: Vec<_> = (0..16).map(|_| c.commit_byte()).collect();
        let key = ExpandedKey::new(&mut c, &refs).unwrap();
        let out = ctr_block(&mut c, &key, ctr, ct, expected.map(Some)).unwrap();
        let w = c.eval(&byte_inputs(&raw_key)).unwrap();
        assert_eq!(out.map(|b| w.byte(b)), expected);
        let iv = [0xa5; 12];
        assert_eq!(nonce(iv, 0), iv);
        let mut altered = iv;
        altered[11] ^= 1;
        assert_eq!(nonce(iv, 1), altered);
        assert_eq!(&counter_block(iv, 0, 0).unwrap()[12..], &2u32.to_be_bytes());
    }

    #[test]
    fn commitment_matches_aes_and_wrong_key_is_rejected() {
        let raw_key = [7u8; 16];
        let cipher = Aes128::new_from_slice(&raw_key).unwrap();
        let expected: Vec<_> = [1, 2]
            .into_iter()
            .flat_map(|i| {
                let mut block = GenericArray::clone_from_slice(&commitment_block(i).unwrap());
                cipher.encrypt_block(&mut block);
                block.to_vec()
            })
            .collect();
        let mut c = Circuit::default();
        let refs: Vec<_> = (0..16).map(|_| c.commit_byte()).collect();
        let key = ExpandedKey::new(&mut c, &refs).unwrap();
        let ck = key_commitment(&mut c, &key);
        for (b, expected) in ck.into_iter().zip(expected) {
            c.assert_byte(b, expected);
        }
        assert!(c.eval(&byte_inputs(&raw_key)).is_ok());
        assert!(c.eval(&byte_inputs(&[8u8; 16])).is_err());
        assert_eq!(c.committed_bits(), 128 + 320 + 2 * 960);
    }

    #[test]
    fn alerts_tickets_and_nonzero_padding_are_rejected() {
        let mut c = Circuit::default();
        let suffix: Vec<_> = (0..3).map(|_| c.commit_byte()).collect();
        assert_application_suffix(&mut c, &suffix).unwrap();
        assert!(c.eval(&byte_inputs(&[0x17, 0, 0])).is_ok());
        for wrong in [[0x15, 0, 0], [0x16, 0, 0], [0x17, 0, 1]] {
            assert!(c.eval(&byte_inputs(&wrong)).is_err());
        }
        assert!(matches!(c.eval(&[Fe::ZERO]), Err(crate::Error::InputCount)));
    }
}

pub const KEYS_PROFILE: &str = "zkf/2/session/standard-aes/both-key-commitments/v4";
