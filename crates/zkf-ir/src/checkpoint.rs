//! Hiding, binding commitments to JSON parser checkpoints.
//!
//! Checkpoint `i ≥ 1` is the parser state before body byte `i · SPACING`. Its
//! [`STATE_BITS`] are packed into [`PARTS`] blocks of [`PAYLOAD_BYTES`] and
//! committed as `AES_K(TAG ‖ index·4+part ‖ payload ‖ 0³²)` under the server
//! application key `K`, which `C_k` already binds.
//!
//! - **Hiding:** `K` is never revealed and every block input is distinct, so
//!   the outputs are pseudorandom (AES as a PRP), independent of the states.
//! - **Binding:** for the key fixed by `C_k`, AES is a permutation, so a
//!   commitment determines its block and hence the state bits.
//! - **Domain separation:** the zero counter field is never a TLS 1.3 GCM
//!   counter block (counters start at 1); the tag differs from the first
//!   byte of both `C_k` blocks and from zero (`H = AES_K(0¹²⁸)` stays hidden).
use crate::aes::ExpandedKey;
use crate::json_segment::{CHECKPOINT_SPACING, STATE_BITS, State};
use crate::{Byte, Circuit};

pub const TAG: u8 = 0xc7;
pub const PARTS: usize = 3;
pub const PAYLOAD_BYTES: usize = 9;
pub const COMMITMENT_BYTES: usize = 16 * PARTS;
pub const MAX_INDEX: usize = (1 << 14) - 1;
const _: () = assert!(STATE_BITS <= PARTS * PAYLOAD_BYTES * 8);

pub type Commitment = [u8; COMMITMENT_BYTES];

/// The number of checkpoints for a body: one per interior SPACING boundary.
pub fn count(body_len: usize) -> usize {
    body_len.saturating_sub(1) / CHECKPOINT_SPACING
}

fn header(index: usize, part: usize) -> [u8; 3] {
    assert!((1..=MAX_INDEX).contains(&index) && part < PARTS);
    let v = (index << 2 | part) as u16;
    [TAG, (v >> 8) as u8, v as u8]
}

/// Native block for `part` of checkpoint `index`, from the state bits.
pub fn block(index: usize, part: usize, bits: &[bool]) -> [u8; 16] {
    assert_eq!(bits.len(), STATE_BITS);
    let mut out = [0u8; 16];
    out[..3].copy_from_slice(&header(index, part));
    for i in 0..PAYLOAD_BYTES * 8 {
        let at = part * PAYLOAD_BYTES * 8 + i;
        if bits.get(at).copied().unwrap_or(false) {
            out[3 + i / 8] |= 1 << (i % 8);
        }
    }
    out
}

/// Native commitment (the prover computes this before the session relation).
pub fn commit_native(key: &[u8; 16], index: usize, bits: &[bool]) -> Commitment {
    use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
    let cipher = aes::Aes128::new_from_slice(key).expect("16-byte key");
    let mut out = [0u8; COMMITMENT_BYTES];
    for part in 0..PARTS {
        let mut b = GenericArray::from(block(index, part, bits));
        cipher.encrypt_block(&mut b);
        out[part * 16..][..16].copy_from_slice(&b);
    }
    out
}

/// Native checkpoint states of a body, by evaluating the parse-only relation.
/// Fails if the body is not a complete JSON document of bounded depth.
pub fn native_states(body: &[u8]) -> Result<Vec<Vec<bool>>, String> {
    if body.is_empty() || body.len() > crate::json_segment::MAX_BODY {
        return Err("checkpoint body size outside profile".into());
    }
    let mut c = Circuit::default();
    let bytes: Vec<_> = (0..body.len()).map(|_| c.commit_byte()).collect();
    let states = crate::json_segment::checkpoint_states(&mut c, &bytes);
    let w = c
        .eval(&crate::byte_inputs(body))
        .map_err(|_| "body is not a complete JSON document within depth eight".to_string())?;
    Ok(states
        .iter()
        .map(|s| crate::json_segment::state_values(&w, s))
        .collect())
}

/// Compact storage of state bits (little-endian bit order).
pub fn pack(bits: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (i, b) in bits.iter().enumerate() {
        out[i / 8] |= u8::from(*b) << (i % 8);
    }
    out
}
pub fn unpack(bytes: &[u8]) -> Option<Vec<bool>> {
    (bytes.len() == STATE_BITS.div_ceil(8)).then(|| {
        (0..STATE_BITS).map(|i| bytes[i / 8] >> (i % 8) & 1 == 1).collect()
    })
}

fn block_wires(c: &mut Circuit, index: usize, part: usize, state: &State) -> [Byte; 16] {
    let bits = state.bits();
    let zero = c.public_bit(false);
    let header = header(index, part);
    std::array::from_fn(|i| match i {
        0..3 => c.public_byte(header[i]),
        3..12 => Byte(std::array::from_fn(|b| {
            let at = part * PAYLOAD_BYTES * 8 + (i - 3) * 8 + b;
            bits.get(at).copied().unwrap_or(zero)
        })),
        _ => c.public_byte(0),
    })
}

/// Assert `commitment` opens to `state` under `key`. `session` selects the
/// interactive AES encoding (fewer constraint terms) over the compact one.
pub fn assert_commitment(
    c: &mut Circuit,
    key: &ExpandedKey,
    index: usize,
    state: &State,
    commitment: &Commitment,
    session: bool,
) {
    for part in 0..PARTS {
        let input = block_wires(c, index, part, state);
        let output = if session {
            key.encrypt(c, input)
        } else {
            key.encrypt_norm(c, input)
        };
        for (wire, expected) in output.into_iter().zip(&commitment[part * 16..][..16]) {
            c.assert_byte(wire, *expected);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{byte_inputs, json_segment};

    #[test]
    fn domain_is_disjoint_from_key_commitments_gcm_and_zero() {
        for i in [1, 2] {
            assert_ne!(crate::tls::commitment_block(i).unwrap()[0], TAG);
        }
        assert_ne!(TAG, 0);
        // The counter field is zero; TLS 1.3 GCM counters start at one.
        assert_eq!(block(MAX_INDEX, PARTS - 1, &[true; STATE_BITS])[12..], [0; 4]);
        assert_eq!(count(32), 0);
        assert_eq!(count(33), 1);
        assert_eq!(count(64), 1);
        assert_eq!(count(65), 2);
    }

    #[test]
    fn session_states_open_their_native_commitments_and_reject_others() {
        let body = br#"{"a":"0123456789012345678901234567890123","b":{"c":[1,2,3]},"d":"end"}"#;
        let key = [7u8; 16];
        // Phase 1: native state values from the parse-only circuit.
        let mut c = Circuit::default();
        let bytes: Vec<_> = (0..body.len()).map(|_| c.commit_byte()).collect();
        let states = json_segment::checkpoint_states(&mut c, &bytes);
        let w = c.eval(&byte_inputs(body)).unwrap();
        let commitments: Vec<_> = states
            .iter()
            .enumerate()
            .map(|(i, s)| commit_native(&key, i + 1, &json_segment::state_values(&w, s)))
            .collect();
        assert_eq!(commitments.len(), count(body.len()));
        // Phase 2: the session relation with the key as witness.
        let build = |commitments: &[Commitment]| {
            let mut c = Circuit::default();
            let k: Vec<_> = (0..16).map(|_| c.commit_byte()).collect();
            let bytes: Vec<_> = (0..body.len()).map(|_| c.commit_byte()).collect();
            let expanded = ExpandedKey::new(&mut c, &k).unwrap();
            let states = json_segment::checkpoint_states(&mut c, &bytes);
            for (i, (s, ck)) in states.iter().zip(commitments).enumerate() {
                assert_commitment(&mut c, &expanded, i + 1, s, ck, true);
            }
            let mut inputs = key.to_vec();
            inputs.extend_from_slice(body);
            c.eval(&byte_inputs(&inputs)).map(|_| ())
        };
        build(&commitments).unwrap();
        let mut wrong = commitments.clone();
        wrong[1][5] ^= 1;
        assert!(build(&wrong).is_err());
        let mut swapped = commitments.clone();
        swapped.swap(0, 1);
        assert!(build(&swapped).is_err());
    }
}
