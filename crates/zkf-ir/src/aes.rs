//! AES byte-field gadgets with zero-safe inverse constraints.
//! Key expansion is shared by every block encrypted under the same key.
use crate::{Byte, Circuit, field::byte_mul};

fn affine(x: u8) -> u8 {
    x ^ x.rotate_left(1) ^ x.rotate_left(2) ^ x.rotate_left(3) ^ x.rotate_left(4)
}

pub fn sbox(c: &mut Circuit, input: Byte) -> Byte {
    let inverse = c.inverse_byte(input);
    c.byte_linear(inverse, std::array::from_fn(|i| affine(1 << i)), 0x63)
}

pub struct ExpandedKey {
    pub(crate) rounds: Vec<[Byte; 16]>,
}

impl ExpandedKey {
    /// Only AES-128/AES-256 are allowed on the planned TLS v2 path.
    pub fn new(c: &mut Circuit, key: &[Byte]) -> Result<Self, KeyLength> {
        if key.len() != 16 {
            return Self::new_uncached(c, key);
        }
        static TEMPLATE: std::sync::OnceLock<crate::template::Template> =
            std::sync::OnceLock::new();
        let template = TEMPLATE.get_or_init(|| {
            let mut graph = Circuit::default();
            let refs: Vec<_> = (0..16).map(|_| graph.commit_byte()).collect();
            let expanded = Self::new_uncached(&mut graph, &refs).unwrap();
            let outputs = expanded
                .rounds
                .iter()
                .flat_map(|round| round.iter().flat_map(|b| b.0))
                .collect();
            crate::template::Template::new(graph, outputs)
        });
        let inputs: Vec<_> = key.iter().flat_map(|b| b.0).collect();
        let outputs = template.instantiate(c, &inputs);
        let rounds = outputs
            .chunks_exact(128)
            .map(|round| std::array::from_fn(|i| Byte(round[i * 8..i * 8 + 8].try_into().unwrap())))
            .collect();
        Ok(Self { rounds })
    }
    fn new_uncached(c: &mut Circuit, key: &[Byte]) -> Result<Self, KeyLength> {
        let nk = match key.len() {
            16 => 4,
            32 => 8,
            _ => return Err(KeyLength),
        };
        let nr = nk + 6;
        let mut words: Vec<[Byte; 4]> = key.as_chunks::<4>().0.to_vec();
        let mut rcon = 1;
        for i in nk..4 * (nr + 1) {
            let mut temp = words[i - 1];
            if i % nk == 0 {
                temp.rotate_left(1);
                temp = temp.map(|b| sbox(c, b));
                let rc = c.public_byte(rcon);
                temp[0] = c.byte_xor(temp[0], rc);
                rcon = byte_mul(rcon, 2);
            } else if nk == 8 && i % nk == 4 {
                temp = temp.map(|b| sbox(c, b));
            }
            let word = std::array::from_fn(|j| c.byte_xor(words[i - nk][j], temp[j]));
            words.push(word);
        }
        let rounds = words
            .as_chunks::<4>()
            .0
            .iter()
            .map(|w| std::array::from_fn(|i| w[i / 4][i % 4]))
            .collect();
        Ok(Self { rounds })
    }

    pub fn encrypt_norm(&self, c: &mut Circuit, input: [Byte; 16]) -> [Byte; 16] {
        crate::aes_norm::encrypt(self, c, input)
    }

    pub fn encrypt(&self, c: &mut Circuit, input: [Byte; 16]) -> [Byte; 16] {
        let mut state = std::array::from_fn(|i| c.byte_xor(input[i], self.rounds[0][i]));
        for round in 1..self.rounds.len() {
            state = state.map(|b| sbox(c, b));
            // AES state is column-major. Shift row r to the left by r.
            state = std::array::from_fn(|i| state[((i / 4 + i % 4) % 4) * 4 + i % 4]);
            if round + 1 != self.rounds.len() {
                state = mix_columns(c, state);
            }
            state = std::array::from_fn(|i| c.byte_xor(state[i], self.rounds[round][i]));
        }
        state
    }
}

pub(crate) fn mix_columns(c: &mut Circuit, state: [Byte; 16]) -> [Byte; 16] {
    let coeffs = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
    std::array::from_fn(|i| {
        let col = i / 4;
        let row = i % 4;
        let mut terms = (0..4).map(|j| {
            let coefficient = coeffs[row][j];
            c.byte_linear(
                state[col * 4 + j],
                std::array::from_fn(|bit| byte_mul(1 << bit, coefficient)),
                0,
            )
        });
        let first = terms.next().unwrap();
        let rest: Vec<_> = terms.collect();
        rest.into_iter().fold(first, |acc, b| c.byte_xor(acc, b))
    })
}

#[derive(Debug, thiserror::Error)]
#[error("AES key must be exactly 16 or 32 bytes")]
pub struct KeyLength;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{byte_inputs, field::byte_inverse};
    use ::aes::{
        Aes128, Aes256,
        cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
    };
    use proptest::prelude::*;

    fn evaluate(key: &[u8], block: [u8; 16]) -> [u8; 16] {
        let mut c = Circuit::default();
        let key_refs: Vec<_> = key.iter().map(|_| c.commit_byte()).collect();
        let expanded = ExpandedKey::new(&mut c, &key_refs).unwrap();
        let public = block.map(|b| c.public_byte(b));
        let output = expanded.encrypt(&mut c, public);
        let witness = c.eval(&byte_inputs(key)).unwrap();
        output.map(|b| witness.byte(b))
    }

    #[test]
    fn all_sbox_values() {
        // Compare with the independent AES implementation's published S-box
        // sample and the inverse definition for every byte.
        for x in 0..=255u8 {
            let mut c = Circuit::default();
            let input = c.commit_byte();
            let output = sbox(&mut c, input);
            let w = c.eval(&byte_inputs(&[x])).unwrap();
            assert_eq!(w.byte(output), affine(byte_inverse(x)) ^ 0x63);
        }
        assert_eq!(affine(byte_inverse(0x53)) ^ 0x63, 0xed);
    }

    #[test]
    fn fips_197_vectors() {
        let block: [u8; 16] = hex::decode("00112233445566778899aabbccddeeff")
            .unwrap()
            .try_into()
            .unwrap();
        for (key, expected) in [
            (
                "000102030405060708090a0b0c0d0e0f",
                "69c4e0d86a7b0430d8cdb78070b4c55a",
            ),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "8ea2b7ca516745bfeafc49904b496089",
            ),
        ] {
            assert_eq!(
                hex::encode(evaluate(&hex::decode(key).unwrap(), block)),
                expected
            );
        }
    }

    #[test]
    fn shared_expansion_has_no_per_block_key_commitments() {
        let mut c = Circuit::default();
        let key: Vec<_> = (0..16).map(|_| c.commit_byte()).collect();
        let expanded = ExpandedKey::new(&mut c, &key).unwrap();
        assert_eq!(c.committed_bits(), 128 + 40 * 8);
        for blocks in 1..=3 {
            let input = [0u8; 16].map(|b| c.public_byte(b));
            expanded.encrypt(&mut c, input);
            assert_eq!(c.committed_bits(), 128 + 40 * 8 + blocks * 160 * 8);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]
        #[test]
        fn aes128_differential(key in any::<[u8; 16]>(), block in any::<[u8; 16]>()) {
            let mut expected = GenericArray::clone_from_slice(&block);
            Aes128::new_from_slice(&key).unwrap().encrypt_block(&mut expected);
            let actual = evaluate(&key, block);
            prop_assert_eq!(actual.as_slice(), expected.as_slice());
        }
        #[test]
        fn aes256_differential(key in any::<[u8; 32]>(), block in any::<[u8; 16]>()) {
            let mut expected = GenericArray::clone_from_slice(&block);
            Aes256::new_from_slice(&key).unwrap().encrypt_block(&mut expected);
            let actual = evaluate(&key, block);
            prop_assert_eq!(actual.as_slice(), expected.as_slice());
        }
    }
}

pub(crate) use crate::aes_norm::hint;
