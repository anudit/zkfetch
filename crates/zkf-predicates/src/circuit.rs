//! Only the ZK prover/verifier APIs are used. Payloads and blinders are witnesses.
use anyhow::{Result, ensure};
use binius_circuits::blake3::blake3_fixed;
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};
use binius_hash::sha256::Sha256HashSuite;
use binius_prover::{OptimalPackedB128, zk_config::ZKProver};
use binius_verifier::{
    config::StdChallenger,
    transcript::{ProverTranscript, VerifierTranscript},
    zk_config::ZKVerifier,
};

use crate::{MAX_HIDDEN_BYTES, MAX_SCALARS, ScalarClaim, ScalarKind};

fn eq(b: &CircuitBuilder, x: Wire, n: u64) -> Wire {
    b.icmp_eq(x, b.add_constant_64(n))
}
fn any(b: &CircuitBuilder, values: impl IntoIterator<Item = Wire>) -> Wire {
    values
        .into_iter()
        .fold(b.add_constant_64(0), |a, c| b.bor(a, c))
}
fn between(b: &CircuitBuilder, x: Wire, low: u64, high: u64) -> Wire {
    b.band(
        b.icmp_uge(x, b.add_constant_64(low)),
        b.icmp_ule(x, b.add_constant_64(high)),
    )
}
fn transition(b: &CircuitBuilder, state: Wire, c: Wire, edges: &[(u64, Wire, u64)]) -> Wire {
    let mut next = b.add_constant_64(255);
    for &(from, condition, to) in edges {
        next = b.select(
            b.band(eq(b, state, from), condition),
            b.add_constant_64(to),
            next,
        );
    }
    // c is used by the caller to build the edge conditions.
    let _ = c;
    next
}

fn string_content(b: &CircuitBuilder, bytes: &[Wire]) {
    let mut state = b.add_constant_64(0);
    let mut utf8 = b.add_constant_64(0);
    for &c in bytes {
        let normal = b.band(
            between(b, c, 0x20, 0xff),
            b.band(
                b.bnot(eq(b, c, b'"' as u64)),
                b.bnot(eq(b, c, b'\\' as u64)),
            ),
        );
        let escaped = any(b, (*b"\"\\/bfnrt").map(|v| eq(b, c, v as u64)));
        let hex = any(
            b,
            [
                between(b, c, 48, 57),
                between(b, c, 65, 70),
                between(b, c, 97, 102),
            ],
        );
        state = transition(
            b,
            state,
            c,
            &[
                (0, normal, 0),
                (0, eq(b, c, 92), 1),
                (1, escaped, 0),
                (1, eq(b, c, 117), 2),
                (
                    2,
                    b.band(hex, b.bnot(any(b, [eq(b, c, 68), eq(b, c, 100)]))),
                    3,
                ),
                (2, any(b, [eq(b, c, 68), eq(b, c, 100)]), 6),
                (3, hex, 4),
                (4, hex, 5),
                (5, hex, 0),
                (6, between(b, c, 48, 55), 4),
                (
                    6,
                    any(
                        b,
                        [
                            between(b, c, 56, 57),
                            between(b, c, 65, 66),
                            between(b, c, 97, 98),
                        ],
                    ),
                    7,
                ),
                (7, hex, 8),
                (8, hex, 9),
                (9, eq(b, c, 92), 10),
                (10, eq(b, c, 117), 11),
                (11, any(b, [eq(b, c, 68), eq(b, c, 100)]), 12),
                (
                    12,
                    any(b, [between(b, c, 67, 70), between(b, c, 99, 102)]),
                    13,
                ),
                (13, hex, 14),
                (14, hex, 0),
            ],
        );
        // Strict UTF-8: reject overlong encodings, surrogates, > U+10FFFF,
        // lone continuation bytes and truncated multibyte sequences.
        let cont = between(b, c, 0x80, 0xbf);
        utf8 = transition(
            b,
            utf8,
            c,
            &[
                (0, between(b, c, 0, 0x7f), 0),
                (0, between(b, c, 0xc2, 0xdf), 1),
                (0, eq(b, c, 0xe0), 4),
                (0, between(b, c, 0xe1, 0xec), 2),
                (0, eq(b, c, 0xed), 5),
                (0, between(b, c, 0xee, 0xef), 2),
                (0, eq(b, c, 0xf0), 6),
                (0, between(b, c, 0xf1, 0xf3), 3),
                (0, eq(b, c, 0xf4), 7),
                (1, cont, 0),
                (2, cont, 1),
                (3, cont, 2),
                (4, between(b, c, 0xa0, 0xbf), 1),
                (5, between(b, c, 0x80, 0x9f), 1),
                (6, between(b, c, 0x90, 0xbf), 2),
                (7, between(b, c, 0x80, 0x8f), 2),
            ],
        );
    }
    b.assert_eq("complete JSON string content", state, b.add_constant_64(0));
    b.assert_eq("complete UTF-8 string", utf8, b.add_constant_64(0));
}

fn atom(b: &CircuitBuilder, bytes: &[Wire]) {
    let mut state = b.add_constant_64(0);
    for &c in bytes {
        let digit = between(b, c, 48, 57);
        let nonzero = between(b, c, 49, 57);
        let zero = eq(b, c, 48);
        let dot = eq(b, c, 46);
        let exp = b.bor(eq(b, c, 101), eq(b, c, 69));
        let sign = b.bor(eq(b, c, 43), eq(b, c, 45));
        state = transition(
            b,
            state,
            c,
            &[
                (0, eq(b, c, 45), 1),
                (0, zero, 2),
                (0, nonzero, 3),
                (1, zero, 2),
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
    let mut valid = any(b, [2, 3, 5, 8].map(|s| eq(b, state, s)));
    for literal in [b"null".as_slice(), b"true".as_slice(), b"false".as_slice()] {
        if literal.len() == bytes.len() {
            let matched = bytes
                .iter()
                .zip(literal)
                .fold(b.add_constant_64(1 << 63), |acc, (&c, &v)| {
                    b.band(acc, eq(b, c, v as u64))
                });
            valid = b.bor(valid, matched);
        }
    }
    b.assert_true("valid JSON atom", valid);
}

struct ScalarWires {
    /// `data || blinder` as 32-bit little-endian words, 4 bytes per wire.
    message: Vec<Wire>,
    digest: [Wire; 8],
    minimum: Option<Wire>,
}

fn build(b: &CircuitBuilder, claims: &[ScalarClaim]) -> Vec<ScalarWires> {
    claims
        .iter()
        .map(|claim| {
            let len = claim.len();
            // Length is public via the signed ranges, but the data and blinder are private.
            // The single-lane gadget hashes only each word's low 32 bits, which are
            // exactly the bytes extracted below.
            let message: Vec<Wire> = (0..(len + 16).div_ceil(4))
                .map(|_| b.add_witness())
                .collect();
            let computed = blake3_fixed(b, &message, len + 16);
            let digest = std::array::from_fn(|_| b.add_inout());
            for (a, c) in computed.into_iter().zip(digest) {
                b.assert_eq("BLAKE3(data || blinder)", a, c);
            }
            let bytes: Vec<_> = (0..len)
                .map(|i| b.extract_byte(message[i / 4], (i % 4) as u32))
                .collect();
            let minimum = match claim.kind {
                ScalarKind::StringContent => {
                    string_content(b, &bytes);
                    None
                }
                ScalarKind::Atom => {
                    atom(b, &bytes);
                    None
                }
                ScalarKind::UnsignedInteger => {
                    let minimum = b.add_inout();
                    let mut value = b.add_constant_64(0);
                    let ten = b.add_constant_64(10);
                    for (i, &c) in bytes.iter().enumerate() {
                        b.assert_true("ASCII decimal digit", between(b, c, 48, 57));
                        if i == 0 && len > 1 {
                            b.assert_true("no leading zeros", between(b, c, 49, 57));
                        }
                        let (digit, borrow) =
                            b.isub_bin_bout(c, b.add_constant_64(48), b.add_constant_64(0));
                        b.assert_false("digit subtraction", borrow);
                        let (hi, lo) = b.imul(value, ten);
                        b.assert_zero("decimal multiplication overflow", hi);
                        let (sum, carry) = b.iadd(lo, digit);
                        b.assert_false("decimal addition overflow", carry);
                        value = sum;
                    }
                    b.assert_true("value >= minimum", b.icmp_uge(value, minimum));
                    Some(minimum)
                }
            };
            ScalarWires {
                message,
                digest,
                minimum,
            }
        })
        .collect()
}

fn validate(claims: &[ScalarClaim]) -> Result<()> {
    ensure!(
        !claims.is_empty() && claims.len() <= MAX_SCALARS,
        "invalid hidden scalar count"
    );
    ensure!(
        claims.iter().map(ScalarClaim::len).sum::<usize>() <= MAX_HIDDEN_BYTES,
        "hidden data too large"
    );
    for c in claims {
        ensure!(
            !c.is_empty() && c.len() <= MAX_HIDDEN_BYTES,
            "invalid scalar length"
        );
        ensure!(
            (c.kind == ScalarKind::UnsignedInteger) == c.predicate.is_some(),
            "invalid predicate kind"
        );
        if let Some(spec) = &c.predicate {
            ensure!(c.len() <= 19, "predicates support at most 19 digits");
            spec.predicate.minimum().map_err(anyhow::Error::msg)?;
        }
    }
    Ok(())
}

fn public_inputs(
    w: &mut WitnessFiller<'_>,
    wires: &[ScalarWires],
    claims: &[ScalarClaim],
) -> Result<()> {
    for (wire, claim) in wires.iter().zip(claims) {
        for (i, chunk) in claim.digest.as_chunks::<4>().0.iter().enumerate() {
            w[wire.digest[i]] = Word(u32::from_le_bytes(*chunk) as u64);
        }
        if let Some(minimum) = wire.minimum {
            w[minimum] = Word(
                claim
                    .predicate
                    .as_ref()
                    .unwrap()
                    .predicate
                    .minimum()
                    .map_err(anyhow::Error::msg)?,
            );
        }
    }
    Ok(())
}

/// Digest of a leaf commitment opening (`payload || blinder`): BLAKE3, as
/// TLSNotary's `HashAlgId::BLAKE3` commitment computes it.
pub(crate) fn leaf_digest(witness: &[u8]) -> [u8; 32] {
    *blake3::hash(witness).as_bytes()
}

/// AND constraints of the circuit for `claims` (benchmarks).
#[cfg(test)]
pub(crate) fn and_constraints(claims: &[ScalarClaim]) -> usize {
    let b = CircuitBuilder::new();
    build(&b, claims);
    binius_frontend::CircuitStat::collect(&b.build()).n_and_constraints
}

pub fn prove(claims: &[ScalarClaim], witnesses: &[Vec<u8>], message: &[u8]) -> Result<Vec<u8>> {
    validate(claims)?;
    ensure!(claims.len() == witnesses.len(), "witness count mismatch");
    let b = CircuitBuilder::new();
    let wires = build(&b, claims);
    let circuit = b.build();
    let mut w = circuit.new_witness_filler();
    public_inputs(&mut w, &wires, claims)?;
    for ((wire, claim), witness) in wires.iter().zip(claims).zip(witnesses) {
        ensure!(witness.len() == claim.len() + 16, "invalid witness length");
        ensure!(
            leaf_digest(witness) == claim.digest,
            "commitment witness mismatch"
        );
        for (wire, chunk) in wire.message.iter().zip(witness.chunks(4)) {
            let mut word = [0u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            w[*wire] = Word(u32::from_le_bytes(word) as u64);
        }
    }
    circuit.populate_wire_witness(&mut w)?;
    let values = w.into_value_vec();
    circuit.constraint_system().verify(&values)?;
    let verifier = ZKVerifier::<Sha256HashSuite>::setup(circuit.constraint_system().clone(), 1)?;
    let prover = ZKProver::<OptimalPackedB128, Sha256HashSuite>::setup(&verifier)?;
    let mut transcript = ProverTranscript::new(StdChallenger::default());
    prover.prove_sig(&values, message, rand_binius::rng(), &mut transcript)?;
    Ok(transcript.finalize())
}

pub fn verify(claims: &[ScalarClaim], proof: Vec<u8>, message: &[u8]) -> Result<()> {
    validate(claims)?;
    let b = CircuitBuilder::new();
    let wires = build(&b, claims);
    let circuit = b.build();
    let mut w = circuit.new_witness_filler();
    public_inputs(&mut w, &wires, claims)?;
    let values = w.into_value_vec();
    let verifier = ZKVerifier::<Sha256HashSuite>::setup(circuit.constraint_system().clone(), 1)?;
    let mut transcript = VerifierTranscript::new(StdChallenger::default(), proof);
    verifier.verify_sig(values.inout(), message, &mut transcript)?;
    transcript.finalize()?;
    Ok(())
}
