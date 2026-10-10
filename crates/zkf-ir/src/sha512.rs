//! SHA-512 compression, also used by SHA-384 (different IV, truncated digest).
//! RFC 6234 §§5.2, 6.3–6.4: https://www.rfc-editor.org/rfc/rfc6234#section-6.4
//! Network-order state/message bytes; internal words use little-endian bits.
//! This node alone does not enable AES-256 TLS negotiation or its key schedule.
use crate::{Byte, Circuit, Wire};

pub const IV512: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];
pub const IV384: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];
pub const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

type Word = [Wire; 64];
fn word(bytes: &[Byte]) -> Word {
    std::array::from_fn(|bit| bytes[7 - bit / 8].0[bit % 8])
}
fn public_word(c: &mut Circuit, value: u64) -> Word {
    std::array::from_fn(|bit| c.public_bit((value >> bit) & 1 != 0))
}
fn xor(c: &mut Circuit, a: Word, b: Word) -> Word {
    std::array::from_fn(|i| c.xor_bit(a[i], b[i]))
}
fn rotate(a: Word, count: usize) -> Word {
    std::array::from_fn(|i| a[(i + count) % 64])
}
fn shift(c: &mut Circuit, a: Word, count: usize) -> Word {
    let zero = c.public_bit(false);
    std::array::from_fn(|i| if i + count < 64 { a[i + count] } else { zero })
}
fn add(c: &mut Circuit, a: Word, b: Word) -> Word {
    let mut carry = c.public_bit(false);
    std::array::from_fn(|i| {
        let ab = c.xor_bit(a[i], b[i]);
        let sum = c.xor_bit(ab, carry);
        if i != 63 {
            let first = c.and_bit(a[i], b[i]);
            let second = c.and_bit(ab, carry);
            carry = c.xor_bit(first, second);
        }
        sum
    })
}
fn sigma(c: &mut Circuit, a: Word, r1: usize, r2: usize, third: usize, small: bool) -> Word {
    let ab = xor(c, rotate(a, r1), rotate(a, r2));
    let third = if small {
        shift(c, a, third)
    } else {
        rotate(a, third)
    };
    xor(c, ab, third)
}
fn choose(c: &mut Circuit, e: Word, f: Word, g: Word) -> Word {
    std::array::from_fn(|i| {
        let fg = c.xor_bit(f[i], g[i]);
        let selected = c.and_bit(e[i], fg);
        c.xor_bit(g[i], selected)
    })
}
fn majority(c: &mut Circuit, a: Word, b: Word, d: Word) -> Word {
    std::array::from_fn(|i| {
        let ab = c.and_bit(a[i], b[i]);
        let axb = c.xor_bit(a[i], b[i]);
        let rest = c.and_bit(axb, d[i]);
        c.xor_bit(ab, rest)
    })
}

pub fn public_state(c: &mut Circuit, state: [u64; 8]) -> [Byte; 64] {
    let bytes: Vec<_> = state.into_iter().flat_map(u64::to_be_bytes).collect();
    std::array::from_fn(|i| c.public_byte(bytes[i]))
}

/// One full 1024-bit block, including any padding supplied by the caller.
/// SHA-384 retains all eight state words between blocks and truncates only the
/// final digest to its first 48 bytes; truncating intermediate state is invalid.
pub fn compression(c: &mut Circuit, state: [Byte; 64], message: [Byte; 128]) -> [Byte; 64] {
    let initial: [Word; 8] = std::array::from_fn(|i| word(&state[i * 8..i * 8 + 8]));
    let mut schedule: Vec<Word> = message.chunks_exact(8).map(word).collect();
    for i in 16..80 {
        let s0 = sigma(c, schedule[i - 15], 1, 8, 7, true);
        let s1 = sigma(c, schedule[i - 2], 19, 61, 6, true);
        let partial = add(c, schedule[i - 16], s0);
        let partial = add(c, partial, schedule[i - 7]);
        schedule.push(add(c, partial, s1));
    }
    let mut working = initial;
    for i in 0..80 {
        let [a, b, cw, d, e, f, g, h] = working;
        let upper = sigma(c, e, 14, 18, 41, false);
        let chosen = choose(c, e, f, g);
        let k = public_word(c, K[i]);
        let t1 = add(c, h, upper);
        let t1 = add(c, t1, chosen);
        let t1 = add(c, t1, k);
        let t1 = add(c, t1, schedule[i]);
        let lower = sigma(c, a, 28, 34, 39, false);
        let majority = majority(c, a, b, cw);
        let t2 = add(c, lower, majority);
        let next_a = add(c, t1, t2);
        let next_e = add(c, d, t1);
        working = [next_a, a, b, cw, next_e, e, f, g];
    }
    let final_words: [Word; 8] = std::array::from_fn(|i| add(c, initial[i], working[i]));
    std::array::from_fn(|byte| {
        Byte(std::array::from_fn(|bit| {
            final_words[byte / 8][(7 - byte % 8) * 8 + bit]
        }))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::byte_inputs;
    use sha2::{Digest, Sha384, Sha512};

    #[test]
    fn arbitrary_state_and_private_block_match_sha2_compressor() {
        for fill in [0u8, 69, 255] {
            let mut c = Circuit::default();
            let block = std::array::from_fn(|_| c.commit_byte());
            let mut expected = IV384.map(|x| x ^ u64::from(fill));
            let state = public_state(&mut c, expected);
            let out = compression(&mut c, state, block);
            sha2::compress512(&mut expected, &[([fill; 128]).into()]);
            let expected: Vec<_> = expected.into_iter().flat_map(u64::to_be_bytes).collect();
            for (wire, byte) in out.into_iter().zip(&expected) {
                c.assert_byte(wire, *byte);
            }
            let w = c.eval(&byte_inputs(&[fill; 128])).unwrap();
            assert_eq!(out.map(|b| w.byte(b)).as_slice(), expected);
            let mut changed = [fill; 128];
            changed[37] ^= 1;
            assert!(c.eval(&byte_inputs(&changed)).is_err());
        }
    }

    #[test]
    fn sha384_and_sha512_padding_boundaries_match_standard_hashes() {
        // At 112 bytes the 128-bit length no longer fits in the first block.
        for length in [0usize, 3, 111, 112, 128] {
            let message: Vec<_> = (0..length).map(|i| (i * 19) as u8).collect();
            let mut padded = message.clone();
            padded.push(0x80);
            while padded.len() % 128 != 112 {
                padded.push(0);
            }
            padded.extend_from_slice(&((message.len() as u128) * 8).to_be_bytes());
            for (iv, expected) in [
                (IV384, Sha384::digest(&message).to_vec()),
                (IV512, Sha512::digest(&message).to_vec()),
            ] {
                let mut c = Circuit::default();
                let mut state = public_state(&mut c, iv);
                for block in padded.chunks_exact(128) {
                    let input = std::array::from_fn(|i| c.public_byte(block[i]));
                    state = compression(&mut c, state, input);
                }
                let w = c.eval(&[]).unwrap();
                let actual = state.map(|b| w.byte(b));
                assert_eq!(&actual[..expected.len()], expected);
            }
        }
    }
}
