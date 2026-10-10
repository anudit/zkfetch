//! FAEST v2-style round pairs: four inverse-norm bits for the first S-box,
//! eight inverse bits for the second. Intermediate quadratic expressions
//! appear directly in cubic checks, without authenticated AND outputs.
use crate::{
    Byte, Circuit, Op, Term, Wire,
    aes::ExpandedKey,
    field::{Fe, byte_inverse, byte_mul},
};
use std::sync::OnceLock;
const BASIS: [u8; 4] = [1, 12, 80, 237];
fn pow(mut x: u8, mut exponent: u16) -> u8 {
    let mut value = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            value = byte_mul(value, x);
        }
        x = byte_mul(x, x);
        exponent >>= 1;
    }
    value
}
pub(crate) fn hint(value: Fe, bit: usize, norm: bool) -> Fe {
    static TABLE: OnceLock<[Fe; 256]> = OnceLock::new();
    let table = TABLE.get_or_init(|| std::array::from_fn(|x| Fe::byte(x as u8)));
    // No secret-dependent table address. The circuit equations, never this
    // local hint, are authoritative for a verifier.
    let mut byte = 0u8;
    for (x, entry) in table.iter().enumerate() {
        byte |= (x as u8) & 0u8.wrapping_sub(u8::from(*entry == value));
    }
    let inverse = byte_inverse(byte);
    if !norm {
        return Fe(u128::from((inverse >> bit) & 1));
    }
    let norm = pow(inverse, 17);
    let mut coordinates = 0u8;
    for mask in 0..16u8 {
        let x = BASIS
            .iter()
            .enumerate()
            .fold(0, |x, (i, b)| x ^ (*b & 0u8.wrapping_sub((mask >> i) & 1)));
        coordinates |= mask & 0u8.wrapping_sub(u8::from(x == norm));
    }
    Fe(u128::from((coordinates >> bit) & 1))
}
fn conjugate(c: &mut Circuit, byte: Byte, j: usize) -> Wire {
    let projected = c.byte_linear(byte, std::array::from_fn(|i| pow(1 << i, 1 << j)), 0);
    c.lift(projected)
}
fn multiply_by_wire(poly: &[Term], wire: Wire) -> Vec<Term> {
    poly.iter()
        .map(|term| match *term {
            Term::Constant(k) => Term::Linear(k, wire),
            Term::Linear(k, x) => Term::Quadratic(k, x, wire),
            Term::Quadratic(k, x, y) => Term::Cubic(k, x, y, wire),
            Term::Cubic(..) => panic!("round-pair input degree exceeds two"),
        })
        .collect()
}
// Unique linearized polynomial for the AES affine map L(x)=sum a_j*x^(2^j).
// Solve its public 8x8 Moore matrix once, in the AES byte field.
fn affine_coefficients() -> &'static [u8; 8] {
    static COEFFICIENTS: OnceLock<[u8; 8]> = OnceLock::new();
    COEFFICIENTS.get_or_init(|| {
        let mut rows: [[u8; 9]; 8] = std::array::from_fn(|i| {
            let x = 1u8 << i;
            std::array::from_fn(|j| {
                if j == 8 {
                    x ^ x.rotate_left(1) ^ x.rotate_left(2) ^ x.rotate_left(3) ^ x.rotate_left(4)
                } else {
                    pow(x, 1 << j)
                }
            })
        });
        for j in 0..8 {
            let pivot = (j..8)
                .find(|i| rows[*i][j] != 0)
                .expect("invertible Moore matrix");
            rows.swap(j, pivot);
            let inverse = byte_inverse(rows[j][j]);
            for k in j..9 {
                rows[j][k] = byte_mul(rows[j][k], inverse);
            }
            for i in 0..8 {
                if i != j {
                    let factor = rows[i][j];
                    for k in j..9 {
                        rows[i][k] ^= byte_mul(factor, rows[j][k]);
                    }
                }
            }
        }
        std::array::from_fn(|i| rows[i][8])
    })
}
pub(crate) fn encrypt(key: &ExpandedKey, c: &mut Circuit, input: [Byte; 16]) -> [Byte; 16] {
    if key.rounds.len() != 11 {
        return encrypt_raw(key, c, input);
    }
    static TEMPLATE: OnceLock<crate::template::Template> = OnceLock::new();
    let template = TEMPLATE.get_or_init(|| {
        let mut graph = Circuit::default();
        let rounds = (0..11)
            .map(|_| std::array::from_fn(|_| graph.commit_byte()))
            .collect();
        let key = ExpandedKey { rounds };
        let block = std::array::from_fn(|_| graph.commit_byte());
        let encrypted = encrypt_raw(&key, &mut graph, block);
        crate::template::Template::new(graph, encrypted.iter().flat_map(|b| b.0).collect())
    });
    let inputs: Vec<_> = key
        .rounds
        .iter()
        .flat_map(|r| r.iter().flat_map(|b| b.0))
        .chain(input.iter().flat_map(|b| b.0))
        .collect();
    let output = template.instantiate(c, &inputs);
    std::array::from_fn(|i| Byte(output[i * 8..i * 8 + 8].try_into().unwrap()))
}
fn encrypt_raw(key: &ExpandedKey, c: &mut Circuit, input: [Byte; 16]) -> [Byte; 16] {
    let mut state = std::array::from_fn(|i| c.byte_xor(input[i], key.rounds[0][i]));
    let coeffs = affine_coefficients();
    let mix = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
    for round in (1..key.rounds.len()).step_by(2) {
        let mut xs = Vec::new();
        let mut ns = Vec::new();
        for byte in state {
            let x: [Wire; 8] = std::array::from_fn(|j| conjugate(c, byte, j));
            let bits: [Wire; 4] = std::array::from_fn(|bit| {
                c.push(Op::AesHint {
                    input: vec![Term::Linear(Fe::ONE, x[0])].into(),
                    bit,
                    norm: true,
                })
            });
            let n: [Wire; 8] = std::array::from_fn(|j| {
                c.linear(
                    (0..4)
                        .map(|i| (Fe::byte(pow(BASIS[i], 1 << j)), bits[i]))
                        .collect(),
                    Fe::ZERO,
                )
            });
            c.assert_zero(vec![
                Term::Cubic(Fe::ONE, n[0], x[1], x[4]),
                Term::Linear(Fe::ONE, x[0]),
            ]);
            // Canonical zero norm, without exceptional-case disclosure.
            c.assert_zero(vec![
                Term::Cubic(Fe::ONE, n[1], x[0], x[4]),
                Term::Linear(Fe::ONE, n[0]),
            ]);
            xs.push(x);
            ns.push(n);
        }
        let pairs: Vec<(Vec<Term>, Vec<Term>)> = (0..16)
            .map(|i| {
                let polynomials: [Vec<Term>; 2] = std::array::from_fn(|squared| {
                    let mut terms = Vec::new();
                    let mut constant = 0;
                    for column_byte in 0..4 {
                        let m = mix[i % 4][column_byte];
                        constant ^= byte_mul(m, 0x63);
                        // ShiftRows before MixColumns.
                        let source = ((i / 4 + column_byte) % 4) * 4 + column_byte;
                        for j in 0..8 {
                            let coefficient = pow(byte_mul(m, coeffs[j]), 1 << squared);
                            if coefficient != 0 {
                                terms.push(Term::Quadratic(
                                    Fe::byte(coefficient),
                                    ns[source][(j + squared) % 8],
                                    xs[source][(j + squared + 4) % 8],
                                ));
                            }
                        }
                    }
                    terms.push(Term::Constant(Fe::byte(pow(constant, 1 << squared))));
                    terms.push(Term::Linear(
                        Fe::ONE,
                        conjugate(c, key.rounds[round][i], squared),
                    ));
                    terms
                });
                let [x, x2] = polynomials;
                (x, x2)
            })
            .collect();
        state = std::array::from_fn(|i| {
            let input: std::sync::Arc<[Term]> = pairs[i].0.clone().into();
            let inverse = Byte(std::array::from_fn(|bit| {
                c.push(Op::AesHint {
                    input: input.clone(),
                    bit,
                    norm: false,
                })
            }));
            let y = c.lift(inverse);
            let y2 = conjugate(c, inverse, 1);
            let mut first = multiply_by_wire(&pairs[i].1, y);
            first.extend(pairs[i].0.clone());
            c.assert_zero(first);
            let mut second = multiply_by_wire(&pairs[i].0, y2);
            second.push(Term::Linear(Fe::ONE, y));
            c.assert_zero(second);
            c.byte_linear(
                inverse,
                std::array::from_fn(|j| {
                    let x = 1u8 << j;
                    x ^ x.rotate_left(1) ^ x.rotate_left(2) ^ x.rotate_left(3) ^ x.rotate_left(4)
                }),
                0x63,
            )
        });
        state = std::array::from_fn(|i| state[((i / 4 + i % 4) % 4) * 4 + i % 4]);
        if round + 2 != key.rounds.len() {
            state = crate::aes::mix_columns(c, state);
        }
        state = std::array::from_fn(|i| c.byte_xor(state[i], key.rounds[round + 1][i]));
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::byte_inputs;
    #[test]
    fn round_pairs_match_reference_and_reduce_commitments() {
        for length in [16, 32] {
            for seed in 0..8u8 {
                let key: Vec<_> = (0..length)
                    .map(|i| seed.wrapping_mul(17).wrapping_add(i as u8))
                    .collect();
                let mut c = Circuit::default();
                let refs: Vec<_> = (0..length).map(|_| c.commit_byte()).collect();
                let expanded = ExpandedKey::new(&mut c, &refs).unwrap();
                let input = std::array::from_fn(|i| c.public_byte(seed.wrapping_add(i as u8)));
                let old = expanded.encrypt(&mut c, input);
                let before = c.committed_bits();
                let new = encrypt(&expanded, &mut c, input);
                let after = c.committed_bits();
                let w = c.eval(&byte_inputs(&key)).unwrap();
                assert_eq!(old.map(|b| w.byte(b)), new.map(|b| w.byte(b)));
                let rounds = if length == 16 { 10 } else { 14 };
                assert_eq!(after - before, rounds / 2 * 16 * 12);
                let plan = c
                    .streaming_plan(&new.iter().flat_map(|b| b.0).collect::<Vec<_>>())
                    .unwrap();
                assert!(plan.eval(&byte_inputs(&key)).is_ok());
            }
        }
    }
    #[test]
    fn tampered_norm_and_inverse_hints_fail() {
        let mut c = Circuit::default();
        let refs: Vec<_> = (0..16).map(|_| c.commit_byte()).collect();
        let expanded = ExpandedKey::new(&mut c, &refs).unwrap();
        let input = [0; 16].map(|b| c.public_byte(b));
        encrypt(&expanded, &mut c, input);
        let mut w = c.eval(&byte_inputs(&[0; 16])).unwrap();
        for (index, op) in c.ops.iter().enumerate() {
            if matches!(op, Op::AesHint { .. }) {
                w.values[index] = w.values[index] ^ Fe::ONE;
                assert!(c.check(&w).is_err());
                w.values[index] = w.values[index] ^ Fe::ONE;
            }
        }
    }
}
