//! Zero-knowledge transcript predicates (zkfetch patch).
//!
//! Each predicate is a boolean circuit evaluated in the same QuickSilver VM
//! that authenticates the transcript plaintext, so the predicate is bound to
//! the TLS data directly. Only the verdict bit is decoded.

use std::{collections::HashMap, sync::Arc};

use mpz_circuits::{Circuit, CircuitBuilder, Feed, Node, ops::wrapping_add};
use mpz_memory_core::{
    DecodeFutureTyped, MemoryExt,
    binary::{Binary, U8},
};
use mpz_vm_core::{Call, Vm, VmError, prelude::*};
use tlsn_core::transcript::{
    Direction, TranscriptPredicate,
    predicate::{MAX_UINT_DIGITS, PredicateKind},
};

use crate::transcript_internal::TranscriptRefs;

/// Pending verdicts of predicates; all must decode to `1`.
pub(crate) struct PredicateFuture {
    futs: Vec<(
        TranscriptPredicate,
        DecodeFutureTyped<mpz_core::bitvec::BitVec, u8>,
    )>,
}

impl PredicateFuture {
    /// Returns the predicates if every verdict is true.
    pub(crate) fn try_recv(self) -> Result<Vec<TranscriptPredicate>, PredicateProofError> {
        let mut out = Vec::with_capacity(self.futs.len());
        for (predicate, mut fut) in self.futs {
            let verdict = fut
                .try_recv()
                .map_err(|_| PredicateProofError::Decode)?
                .ok_or(PredicateProofError::Decode)?;
            if verdict != 1 {
                return Err(PredicateProofError::False(predicate));
            }
            out.push(predicate);
        }
        Ok(out)
    }
}

/// Adds predicate circuits over authenticated plaintext references. Used by
/// both prover and verifier; the circuits only depend on public parameters.
pub(crate) fn predicate_circuits(
    vm: &mut dyn Vm<Binary>,
    refs: &TranscriptRefs,
    predicates: &[TranscriptPredicate],
) -> Result<PredicateFuture, PredicateProofError> {
    let mut cache: HashMap<(usize, PredicateKind), Arc<Circuit>> = HashMap::new();
    let mut futs = Vec::with_capacity(predicates.len());
    for predicate in predicates {
        let refs = match predicate.direction {
            Direction::Sent => &refs.sent,
            Direction::Received => &refs.recv,
        };
        let data = refs
            .get(predicate.range.clone())
            .ok_or_else(|| PredicateProofError::Unauthenticated(predicate.clone()))?;

        let circuit = cache
            .entry((predicate.range.len(), predicate.kind))
            .or_insert_with(|| Arc::new(build_circuit(predicate.range.len(), &predicate.kind)))
            .clone();

        let call = Call::builder(circuit)
            .arg(data)
            .build()
            .map_err(|e| PredicateProofError::Vm(VmError::call(e)))?;
        let verdict: U8 = vm.call(call).map_err(PredicateProofError::Vm)?;
        let fut = vm.decode(verdict).map_err(PredicateProofError::Vm)?;
        futs.push((predicate.clone(), fut));
    }
    Ok(PredicateFuture { futs })
}

/// Builds the circuit for `kind` over `len` input bytes. Inputs are the bytes'
/// bits, LSB first; the single `u8` output is `1` iff the predicate holds.
pub(crate) fn build_circuit(len: usize, kind: &PredicateKind) -> Circuit {
    match *kind {
        PredicateKind::UintGte { minimum } => uint_gte(len, minimum),
        PredicateKind::JsonStringContent => json_string_content(len),
        PredicateKind::JsonAtom => json_atom(len),
    }
}

type Byte = [Node<Feed>; 8];

fn input_bytes(b: &mut CircuitBuilder, len: usize) -> Vec<Byte> {
    (0..len)
        .map(|_| std::array::from_fn(|_| b.add_input()))
        .collect()
}

fn finish(mut b: CircuitBuilder, anchor: Node<Feed>, verdict: Node<Feed>) -> Circuit {
    // Outputs must be gate outputs, but the builder folds gates on constants
    // and a verdict can legitimately be constant (e.g. `>= 0`). Each output bit
    // is therefore XORed with its own fresh zero gate `!a & !!a` built from an
    // input bit `a`, which the builder cannot fold.
    let zero = b.get_const_zero();
    for bit in std::iter::once(verdict).chain(std::iter::repeat_n(zero, 7)) {
        let na = b.add_inv_gate(anchor);
        let nna = b.add_inv_gate(na);
        let fresh_zero = b.add_and_gate(na, nna);
        let out = b.add_xor_gate(bit, fresh_zero);
        b.add_output(out);
    }
    b.build().expect("predicate circuit is well-formed")
}

/// `x == k`.
fn eq_const(b: &mut CircuitBuilder, x: &Byte, k: u8) -> Node<Feed> {
    let bits: Vec<Node<Feed>> = (0..8)
        .map(|i| {
            if (k >> i) & 1 == 1 {
                x[i]
            } else {
                b.add_inv_gate(x[i])
            }
        })
        .collect();
    and_all(b, &bits)
}

/// `x >= k` as the carry out of `x + !k + 1`.
fn ge_const(b: &mut CircuitBuilder, x: &Byte, k: u8) -> Node<Feed> {
    let zero = b.get_const_zero();
    let one = b.get_const_one();
    let mut carry = one;
    for (i, &a) in x.iter().enumerate() {
        let m = if (k >> i) & 1 == 1 { zero } else { one };
        let a_c = b.add_xor_gate(a, carry);
        let m_c = b.add_xor_gate(m, carry);
        let t = b.add_and_gate(a_c, m_c);
        carry = b.add_xor_gate(t, carry);
    }
    carry
}

/// `lo <= x <= hi`.
fn in_range(b: &mut CircuitBuilder, x: &Byte, lo: u8, hi: u8) -> Node<Feed> {
    let ge = ge_const(b, x, lo);
    if hi == u8::MAX {
        return ge;
    }
    let gt = ge_const(b, x, hi + 1);
    let le = b.add_inv_gate(gt);
    b.add_and_gate(ge, le)
}

fn any_of(b: &mut CircuitBuilder, x: &Byte, set: &[u8]) -> Node<Feed> {
    let mut acc = b.get_const_zero();
    for &k in set {
        let e = eq_const(b, x, k);
        acc = or(b, acc, e);
    }
    acc
}

/// One-hot DFA step: `next[j] = OR over edges (i, cond, j) of state[i] & cond`.
fn dfa_step(
    b: &mut CircuitBuilder,
    state: &[Node<Feed>],
    edges: &[(usize, Node<Feed>, usize)],
) -> Vec<Node<Feed>> {
    let zero = b.get_const_zero();
    let mut next = vec![zero; state.len()];
    for &(from, cond, to) in edges {
        let t = b.add_and_gate(state[from], cond);
        next[to] = or(b, next[to], t);
    }
    next
}

fn dfa_start(b: &mut CircuitBuilder, states: usize) -> Vec<Node<Feed>> {
    let zero = b.get_const_zero();
    let one = b.get_const_one();
    (0..states)
        .map(|i| if i == 0 { one } else { zero })
        .collect()
}

fn json_string_content(len: usize) -> Circuit {
    let mut b = CircuitBuilder::new();
    let bytes = input_bytes(&mut b, len);
    // States encode JSON escapes, paired UTF-16 surrogates, and strict UTF-8.
    let mut state = dfa_start(&mut b, 22);
    for x in &bytes {
        let printable = in_range(&mut b, x, 0x20, 0x7f);
        let quote = eq_const(&mut b, x, b'"');
        let slash = eq_const(&mut b, x, b'\\');
        let nq = b.add_inv_gate(quote);
        let ns = b.add_inv_gate(slash);
        let normal = and_all(&mut b, &[printable, nq, ns]);
        let escaped = any_of(&mut b, x, b"\"\\/bfnrt");
        let u = eq_const(&mut b, x, b'u');
        let digit = in_range(&mut b, x, b'0', b'9');
        let upper = in_range(&mut b, x, b'A', b'F');
        let lower = in_range(&mut b, x, b'a', b'f');
        let du = or(&mut b, digit, upper);
        let hex = or(&mut b, du, lower);
        let d = any_of(&mut b, x, b"Dd");
        let nd = b.add_inv_gate(d);
        let non_d = and_all(&mut b, &[hex, nd]);
        let below_surrogate = in_range(&mut b, x, b'0', b'7');
        let high = any_of(&mut b, x, b"89ABab");
        let low = any_of(&mut b, x, b"CDEFcdef");
        let cont = in_range(&mut b, x, 0x80, 0xbf);
        let lead2 = in_range(&mut b, x, 0xc2, 0xdf);
        let lead3 = any_of(
            &mut b,
            x,
            &[
                0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xee, 0xef,
            ],
        );
        let e0 = eq_const(&mut b, x, 0xe0);
        let ed = eq_const(&mut b, x, 0xed);
        let f0 = eq_const(&mut b, x, 0xf0);
        let f4 = eq_const(&mut b, x, 0xf4);
        let lead4 = in_range(&mut b, x, 0xf1, 0xf3);
        let e0cont = in_range(&mut b, x, 0xa0, 0xbf);
        let edcont = in_range(&mut b, x, 0x80, 0x9f);
        let f0cont = in_range(&mut b, x, 0x90, 0xbf);
        let f4cont = in_range(&mut b, x, 0x80, 0x8f);
        state = dfa_step(
            &mut b,
            &state,
            &[
                (0, normal, 0),
                (0, slash, 1),
                (1, escaped, 0),
                (1, u, 2),
                (2, non_d, 3),
                (2, d, 6),
                (3, hex, 4),
                (4, hex, 5),
                (5, hex, 0),
                (6, below_surrogate, 4),
                (6, high, 7),
                (7, hex, 8),
                (8, hex, 9),
                (9, slash, 10),
                (10, u, 11),
                (11, d, 12),
                (12, low, 13),
                (13, hex, 14),
                (14, hex, 0),
                (0, lead2, 15),
                (15, cont, 0),
                (0, lead3, 16),
                (16, cont, 15),
                (0, lead4, 17),
                (17, cont, 16),
                (0, e0, 18),
                (18, e0cont, 15),
                (0, ed, 19),
                (19, edcont, 15),
                (0, f0, 20),
                (20, f0cont, 16),
                (0, f4, 21),
                (21, f4cont, 16),
            ],
        );
    }
    let verdict = state[0];
    finish(b, bytes[0][0], verdict)
}

fn json_atom(len: usize) -> Circuit {
    let mut b = CircuitBuilder::new();
    let bytes = input_bytes(&mut b, len);
    let mut state = dfa_start(&mut b, 9);
    for x in &bytes {
        let minus = eq_const(&mut b, x, b'-');
        let zero_c = eq_const(&mut b, x, b'0');
        let nonzero = in_range(&mut b, x, b'1', b'9');
        let digit = in_range(&mut b, x, b'0', b'9');
        let dot = eq_const(&mut b, x, b'.');
        let exp = any_of(&mut b, x, b"eE");
        let sign = any_of(&mut b, x, b"+-");
        state = dfa_step(
            &mut b,
            &state,
            &[
                (0, minus, 1),
                (0, zero_c, 2),
                (0, nonzero, 3),
                (1, zero_c, 2),
                (1, nonzero, 3),
                (2, dot, 4),
                (2, exp, 6),
                (3, digit, 3),
                (3, dot, 4),
                (3, exp, 6),
                (4, digit, 5),
                (5, digit, 5),
                (5, exp, 6),
                (6, sign, 7),
                (6, digit, 8),
                (7, digit, 8),
                (8, digit, 8),
            ],
        );
    }
    let s23 = or(&mut b, state[2], state[3]);
    let s58 = or(&mut b, state[5], state[8]);
    let mut verdict = or(&mut b, s23, s58);
    for literal in [b"true".as_slice(), b"false", b"null"] {
        if literal.len() == len {
            let eqs: Vec<_> = bytes
                .iter()
                .zip(literal)
                .map(|(x, &k)| eq_const(&mut b, x, k))
                .collect();
            let m = and_all(&mut b, &eqs);
            verdict = or(&mut b, verdict, m);
        }
    }
    finish(b, bytes[0][0], verdict)
}

fn uint_gte(len: usize, minimum: u64) -> Circuit {
    assert!((1..=MAX_UINT_DIGITS).contains(&len));
    let mut b = CircuitBuilder::new();
    let zero = b.get_const_zero();
    let one = b.get_const_one();

    let bytes: Vec<[Node<Feed>; 8]> = (0..len)
        .map(|_| std::array::from_fn(|_| b.add_input()))
        .collect();

    // Every byte is an ASCII digit: high nibble 0b0011, low nibble <= 9.
    let mut ok = one;
    for byte in &bytes {
        let not6 = b.add_inv_gate(byte[6]);
        let not7 = b.add_inv_gate(byte[7]);
        let hi = and_all(&mut b, &[byte[4], byte[5], not6, not7]);
        // low <= 9  <=>  !b3 | (!b2 & !b1)
        let not1 = b.add_inv_gate(byte[1]);
        let not2 = b.add_inv_gate(byte[2]);
        let not3 = b.add_inv_gate(byte[3]);
        let not12 = b.add_and_gate(not1, not2);
        let le9 = or(&mut b, not3, not12);
        let digit = b.add_and_gate(hi, le9);
        ok = b.add_and_gate(ok, digit);
    }

    // Canonical: no leading zero unless the number is a single digit.
    if len > 1 {
        let first = bytes[0];
        let nz01 = or(&mut b, first[0], first[1]);
        let nz23 = or(&mut b, first[2], first[3]);
        let nonzero = or(&mut b, nz01, nz23);
        ok = b.add_and_gate(ok, nonzero);
    }

    // acc = acc * 10 + digit, in 64 bits (19 digits cannot overflow).
    let mut acc: Vec<Node<Feed>> = vec![zero; 64];
    for byte in &bytes {
        let shl3: Vec<_> = (0..64)
            .map(|i| if i >= 3 { acc[i - 3] } else { zero })
            .collect();
        let shl1: Vec<_> = (0..64)
            .map(|i| if i >= 1 { acc[i - 1] } else { zero })
            .collect();
        let times10 = wrapping_add(&mut b, &shl3, &shl1);
        let digit: Vec<_> = (0..64)
            .map(|i| if i < 4 { byte[i] } else { zero })
            .collect();
        acc = wrapping_add(&mut b, &times10, &digit);
    }

    // acc >= minimum  <=>  carry out of acc + !minimum + 1.
    let mut carry = one;
    for (i, &a) in acc.iter().enumerate() {
        let m = if (minimum >> i) & 1 == 1 { zero } else { one };
        let a_c = b.add_xor_gate(a, carry);
        let m_c = b.add_xor_gate(m, carry);
        let t = b.add_and_gate(a_c, m_c);
        carry = b.add_xor_gate(t, carry);
    }

    let verdict = b.add_and_gate(ok, carry);
    finish(b, bytes[0][0], verdict)
}

fn and_all(b: &mut CircuitBuilder, nodes: &[Node<Feed>]) -> Node<Feed> {
    let mut acc = nodes[0];
    for &n in &nodes[1..] {
        acc = b.add_and_gate(acc, n);
    }
    acc
}

fn or(b: &mut CircuitBuilder, x: Node<Feed>, y: Node<Feed>) -> Node<Feed> {
    // x | y = !(!x & !y)
    let nx = b.add_inv_gate(x);
    let ny = b.add_inv_gate(y);
    let a = b.add_and_gate(nx, ny);
    b.add_inv_gate(a)
}

/// Error proving or verifying predicates.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PredicateProofError {
    #[error("VM error: {0}")]
    Vm(VmError),
    #[error("failed to decode predicate verdict")]
    Decode,
    #[error("predicate range is not authenticated: {0:?}")]
    Unauthenticated(TranscriptPredicate),
    #[error("predicate does not hold: {0:?}")]
    False(TranscriptPredicate),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tlsn_core::transcript::predicate::evaluate;

    fn eval(circ: &Circuit, data: &[u8]) -> bool {
        let input: Vec<bool> = data
            .iter()
            .flat_map(|b| (0..8).map(move |i| (b >> i) & 1 == 1))
            .collect();
        let out = circ.evaluate(input).expect("evaluates");
        out.iter()
            .enumerate()
            .fold(0u8, |acc, (i, &bit)| acc | (u8::from(bit) << i))
            == 1
    }

    #[test]
    fn uint_gte_matches_reference() {
        let cases: &[(&[u8], u64)] = &[
            (b"439", 365),
            (b"439", 439),
            (b"439", 440),
            (b"0", 0),
            (b"0", 1),
            (b"7", 7),
            (b"07", 0),
            (b"1a", 0),
            (b"9999999999999999999", 9999999999999999999),
            (b"9999999999999999999", u64::MAX),
            (b"1000000000000000000", 999999999999999999),
            (b"12:", 0),
            (b"/9", 0),
            (b" 5", 0),
        ];
        for &(data, minimum) in cases {
            let kind = PredicateKind::UintGte { minimum };
            let circ = build_circuit(data.len(), &kind);
            assert_eq!(
                eval(&circ, data),
                evaluate(&kind, data),
                "{:?} >= {minimum}",
                std::str::from_utf8(data).unwrap()
            );
        }
    }

    #[test]
    fn json_shapes_match_reference() {
        let strings: &[&[u8]] = &[
            b"hello",
            b"a\\\"b",
            b"\\\\",
            b"\\u00e9x",
            b"\\uZZZZ",
            b"\\",
            b"a\"b",
            b"\\x",
            b"tab\there",
            b"\\/\\b\\f\\n\\r\\t",
            "caf\u{e9}".as_bytes(),
            b"\\u12",
            b"\\uD800",
            b"\\uDC00",
            b"\\uD800\\uDC00",
            b"\\uD800x",
            b"\xff",
            b"\xc0\x80",
            b"\xed\xa0\x80",
            b"\xf4\x90\x80\x80",
            "😀".as_bytes(),
            b"\x01",
        ];
        for &data in strings {
            let kind = PredicateKind::JsonStringContent;
            let circ = build_circuit(data.len(), &kind);
            assert_eq!(eval(&circ, data), evaluate(&kind, data), "string {data:?}");
        }
        let atoms: &[&[u8]] = &[
            b"0", b"-0", b"12", b"012", b"1.5", b"1.", b".5", b"-", b"1e9", b"1E+9", b"1e-",
            b"2.5e-3", b"true", b"false", b"null", b"nul", b"truex", b"1-2", b"--1", b"9",
        ];
        for &data in atoms {
            let kind = PredicateKind::JsonAtom;
            let circ = build_circuit(data.len(), &kind);
            assert_eq!(
                eval(&circ, data),
                evaluate(&kind, data),
                "atom {:?}",
                std::str::from_utf8(data)
            );
        }
    }

    #[test]
    fn randomized_differential() {
        // Deterministic xorshift so failures reproduce.
        let mut seed = 0x9e3779b97f4a7c15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let alphabet = b"0123456789-+.eEtrufalsn\"\\/bu AFaf\x01\x7f\xc3\xa9";
        for _ in 0..3000 {
            let len = 1 + (next() % 12) as usize;
            let data: Vec<u8> = (0..len)
                .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
                .collect();
            let minimum = next() % 1000;
            for kind in [
                PredicateKind::UintGte { minimum },
                PredicateKind::JsonStringContent,
                PredicateKind::JsonAtom,
            ] {
                let circ = build_circuit(data.len(), &kind);
                assert_eq!(
                    eval(&circ, &data),
                    evaluate(&kind, &data),
                    "{data:?} {kind:?}"
                );
            }
        }
    }

    #[test]
    fn exhaustive_single_byte() {
        for byte in 0u8..=255 {
            for kind in [
                PredicateKind::UintGte { minimum: 0 },
                PredicateKind::UintGte { minimum: 5 },
                PredicateKind::UintGte { minimum: 10 },
                PredicateKind::JsonStringContent,
                PredicateKind::JsonAtom,
            ] {
                let circ = build_circuit(1, &kind);
                assert_eq!(
                    eval(&circ, &[byte]),
                    evaluate(&kind, &[byte]),
                    "{byte} {kind:?}"
                );
            }
        }
    }
}
