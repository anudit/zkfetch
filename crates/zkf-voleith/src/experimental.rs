//! General degree-3 relation protocol using FAEST-128 BAVC/VOLE masks.
//! This is an experimental adaptation, not a FAEST signature and not an
//! independently reviewed claim of inheriting its full security theorem.
use crate::primitives::{self, Parameters};
use anyhow::{Result, anyhow, ensure};
use rand::RngCore;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sha3::{
    TurboShake128, TurboShake128Core, TurboShake128Reader,
    digest::{ExtendableOutput, Update, XofReader},
};
use spongefish::{VerifierState, instantiations::XOF};
use zeroize::Zeroizing;
use zkf_ir::{CheckedWitness, Circuit, Witness, field::Fe};

const MAGIC: &[u8; 8] = b"zkfVI\0\x03\0";
const MAX_GRIND: u32 = 1 << 24;

/// Proof-of-work bits added to each Fiat–Shamir challenge, on hash output
/// independent of the challenge itself. Every accepted challenge then costs an
/// adversary 2^bits random-oracle queries, which divides that round's
/// round-by-round error by 2^bits. `scripts/soundness.py` derives these values;
/// see `docs/v2-soundness.md` (offline margin).
pub const POW_IV_BITS: u32 = 7;
pub const POW_CONSISTENCY_BITS: u32 = 2;
pub const POW_WEIGHTS_BITS: u32 = 2;
pub const POW_OPENING_BITS: u32 = 3;

/// All three bindings are supplied by the integrating verifier. `statement`
/// must be a canonical encoding, not an unchecked client description.
pub struct Context<'a> {
    pub attestation_digest: [u8; 32],
    pub statement: &'a [u8],
    pub presentation_nonce: [u8; 32],
}

#[derive(Clone)]
struct Turbo(TurboShake128);
impl Default for Turbo {
    fn default() -> Self {
        Self(TurboShake128::from_core(TurboShake128Core::new(0x1f)))
    }
}
impl Update for Turbo {
    fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
}
impl ExtendableOutput for Turbo {
    type Reader = TurboShake128Reader;
    fn finalize_xof(self) -> Self::Reader {
        self.0.finalize_xof()
    }
}
type Transcript = VerifierState<'static, XOF<Turbo>>;

fn transcript(
    context: &Context<'_>,
    circuit: &Circuit,
    params: Parameters,
    profiled: bool,
) -> Transcript {
    let mut instance = Vec::new();
    instance.extend_from_slice(&context.attestation_digest);
    instance.extend_from_slice(&context.presentation_nonce);
    let identity = if profiled {
        circuit.transcript_identity()
    } else {
        let mut identity = b"circuit-digest\0".to_vec();
        identity.extend_from_slice(&circuit.digest());
        identity
    };
    instance.extend_from_slice(&(identity.len() as u64).to_le_bytes());
    instance.extend_from_slice(&identity);
    instance.push(params.label());
    instance.extend_from_slice(&(circuit.committed_bits() as u64).to_le_bytes());
    instance.extend_from_slice(&(context.statement.len() as u64).to_le_bytes());
    instance.extend_from_slice(context.statement);
    spongefish::domain_separator!("zkf/2/present; general-degree-3; pow-margin-2")
        .instance(&instance)
        .to_verifier(XOF::<Turbo>::default(), &[])
}

fn absorb(t: &mut Transcript, label: &[u8], bytes: &[u8]) {
    t.public_message(label);
    t.public_message(&(bytes.len() as u64));
    t.public_message(bytes);
}
fn challenge<const N: usize>(t: &mut Transcript, label: &[u8]) -> [u8; N] {
    t.public_message(label);
    t.verifier_message::<[u8; N]>()
}
fn vector_bytes(c: &Circuit) -> Result<usize> {
    let bytes = c
        .committed_bits()
        .div_ceil(8)
        .checked_add(50)
        .ok_or_else(|| anyhow!("witness overflow"))?;
    ensure!(bytes <= primitives::MAX_VECTOR_BYTES, "witness exceeds cap");
    Ok(bytes)
}
fn pack(c: &Circuit, witness: &CheckedWitness<'_>) -> Result<Zeroizing<Vec<u8>>> {
    let values = c.commitment_values_checked(witness)?;
    let widths = c.commitment_widths();
    let mut bits = Zeroizing::new(vec![0u8; c.committed_bits().div_ceil(8)]);
    let mut at = 0;
    for (value, width) in values.iter().zip(widths) {
        for bit in 0..width {
            bits[at / 8] |= (((value.0 >> bit) & 1) as u8) << (at % 8);
            at += 1;
        }
    }
    Ok(bits)
}
fn row(columns: &[Vec<u8>], at: usize) -> Fe {
    let mut value = 0u128;
    for (i, col) in columns.iter().enumerate() {
        value |= u128::from((col[at / 8] >> (at % 8)) & 1) << i;
    }
    Fe(value)
}
fn authenticated_values(c: &Circuit, columns: &[Vec<u8>]) -> Zeroizing<Vec<Fe>> {
    let mut at = 0;
    let positions: Vec<_> = c
        .commitment_widths()
        .into_iter()
        .map(|width| {
            let start = at;
            at += width;
            (start, width)
        })
        .collect();
    let lift = |(start, width): &(usize, usize)| {
        (0..*width).fold(Fe::ZERO, |value, bit| {
            value ^ row(columns, start + bit).scale_public(Fe(1u128 << bit))
        })
    };
    #[cfg(feature = "parallel")]
    let values = positions.par_iter().map(lift).collect();
    #[cfg(not(feature = "parallel"))]
    let values = positions.iter().map(lift).collect();
    Zeroizing::new(values)
}
fn mask(columns: &[Vec<u8>], start: usize) -> Fe {
    (0..128).fold(Fe::ZERO, |value, bit| {
        value ^ (row(columns, start + bit) * Fe(1u128 << bit))
    })
}
fn weights(seed: &[u8; 32]) -> TurboShake128Reader {
    let mut hash = Turbo::default();
    hash.update(b"zkf/2/check-weights");
    hash.update(seed);
    hash.finalize_xof()
}
fn next_weight(reader: &mut TurboShake128Reader) -> Fe {
    let mut bytes = [0; 16];
    reader.read(&mut bytes);
    Fe(u128::from_le_bytes(bytes))
}
fn low_bits_zero(bytes: [u8; 4], bits: u32) -> bool {
    u32::from_le_bytes(bytes) & ((1u32 << bits) - 1) == 0
}
/// One random-oracle query: the opening challenge Δ and, from independent
/// output bits, its proof-of-work predicate.
fn grind(seed: &[u8; 32], counter: u32) -> ([u8; 16], bool) {
    let mut hash = Turbo::default();
    hash.update(b"zkf/2/check-opening");
    hash.update(seed);
    hash.update(&counter.to_le_bytes());
    let mut output = [0; 20];
    hash.finalize_xof().read(&mut output);
    let pow = low_bits_zero(output[16..].try_into().unwrap(), POW_OPENING_BITS);
    (output[..16].try_into().unwrap(), pow)
}
fn pow_hash(label: &[u8], seed: &[u8], nonce: u32) -> [u8; 4] {
    let mut hash = Turbo::default();
    hash.update(b"zkf/2/pow");
    hash.update(&(label.len() as u64).to_le_bytes());
    hash.update(label);
    hash.update(seed);
    hash.update(&nonce.to_le_bytes());
    let mut output = [0; 4];
    hash.finalize_xof().read(&mut output);
    output
}
fn iv_ok(iv: &[u8; 16]) -> bool {
    low_bits_zero(pow_hash(b"iv", iv, 0), POW_IV_BITS)
}
/// Bind a proof-of-work to the current transcript state before a challenge.
fn pow_prove(t: &mut Transcript, label: &[u8], bits: u32) -> Result<u32> {
    let seed = challenge::<32>(t, label);
    let nonce = (0..MAX_GRIND)
        .find(|n| low_bits_zero(pow_hash(label, &seed, *n), bits))
        .ok_or_else(|| anyhow!("proof-of-work budget exhausted"))?;
    absorb(t, label, &nonce.to_le_bytes());
    Ok(nonce)
}
fn pow_verify(t: &mut Transcript, label: &[u8], bits: u32, nonce: u32) -> Result<()> {
    let seed = challenge::<32>(t, label);
    ensure!(
        nonce < MAX_GRIND && low_bits_zero(pow_hash(label, &seed, nonce), bits),
        "invalid proof-of-work"
    );
    absorb(t, label, &nonce.to_le_bytes());
    Ok(())
}

/// Prove an already checked IR relation. This API deliberately requires a
/// caller-supplied nonce; replay policy is not silently supplied by the backend.
pub fn prove(
    c: &Circuit,
    witness: &Witness,
    params: Parameters,
    context: &Context<'_>,
) -> Result<Vec<u8>> {
    prove_checked_inner(&c.checked(witness)?, params, context, false)
}
pub(crate) fn prove_checked(
    checked: &CheckedWitness<'_>,
    params: Parameters,
    context: &Context<'_>,
) -> Result<Vec<u8>> {
    ensure!(
        checked.circuit().profile().is_some(),
        "registered profile required"
    );
    prove_checked_inner(checked, params, context, true)
}
fn prove_checked_inner(
    checked: &CheckedWitness<'_>,
    params: Parameters,
    context: &Context<'_>,
    profiled: bool,
) -> Result<Vec<u8>> {
    let mut profile = crate::profile::Lap::new();
    let c = checked.circuit();
    profile.mark("prove.checked-witness-reuse");
    let length = vector_bytes(c)?;
    let mut seed = Zeroizing::new([0u8; 16]);
    let mut iv = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(seed.as_mut());
    // The leaf-commitment hash key derives from iv; grinding iv bounds the
    // number of keys an adversary can try (FAEST v2 Thm 9.24, third term).
    loop {
        rand::rngs::OsRng.fill_bytes(&mut iv);
        if iv_ok(&iv) {
            break;
        }
    }
    let material = primitives::commit(params, &seed, &iv, length)
        .ok_or_else(|| anyhow!("VOLE commitment failed"))?;
    profile.mark("prove.vole-commit");
    let mut t = transcript(context, c, params, profiled);
    absorb(&mut t, b"iv", &iv);
    absorb(&mut t, b"bavc", &material.com);
    absorb(&mut t, b"corrections", &material.corrections);
    profile.mark("transcript.binding");
    let pow_consistency = pow_prove(&mut t, b"pow-consistency", POW_CONSISTENCY_BITS)?;
    let check_seed = challenge::<88>(&mut t, b"vole-consistency");
    let u_tilde = primitives::hash_vector(&check_seed, &material.u).unwrap();
    absorb(&mut t, b"u-tilde", &u_tilde);
    for column in material.columns.iter() {
        absorb(
            &mut t,
            b"v-hash",
            &primitives::hash_vector(&check_seed, column).unwrap(),
        );
    }
    let mut correction = pack(c, checked)?;
    for (byte, u) in correction.iter_mut().zip(material.u.iter()) {
        *byte ^= u;
    }
    absorb(&mut t, b"witness-correction", &correction);
    let pow_weights = pow_prove(&mut t, b"pow-weights", POW_WEIGHTS_BITS)?;
    let weight_seed = challenge::<32>(&mut t, b"check-weights");
    profile.mark("prove.transcript-and-consistency");
    let tags = authenticated_values(c, &material.columns);
    profile.mark("prove.authenticated-rows");
    let polynomials = c.constraint_polynomials_checked(checked, &tags)?;
    profile.mark("prove.constraint-polynomials");
    let wbytes = correction.len();
    let mask_start = wbytes * 8;
    let mut a0 = mask(&material.columns, mask_start);
    let u0 = Zeroizing::new(Fe(u128::from_le_bytes(
        material.u[wbytes..wbytes + 16].try_into().unwrap(),
    )));
    let u1 = Zeroizing::new(Fe(u128::from_le_bytes(
        material.u[wbytes + 16..wbytes + 32].try_into().unwrap(),
    )));
    let mut a1 = *u0 ^ mask(&material.columns, mask_start + 128);
    let mut a2 = *u1;
    let mut reader = weights(&weight_seed);
    for polynomial in &polynomials.0 {
        ensure!(polynomial.0[3] == Fe::ZERO, "invalid relation polynomial");
        let weight = next_weight(&mut reader);
        a0 = a0 ^ (weight * polynomial.0[0]);
        a1 = a1 ^ (weight * polynomial.0[1]);
        a2 = a2 ^ (weight * polynomial.0[2]);
    }
    absorb(&mut t, b"a0", &a0.0.to_le_bytes());
    absorb(&mut t, b"a1", &a1.0.to_le_bytes());
    absorb(&mut t, b"a2", &a2.0.to_le_bytes());
    profile.mark("prove.weighted-check");
    let opening_seed = challenge::<32>(&mut t, b"opening-seed");
    let mut selected = None;
    for counter in 0..MAX_GRIND {
        let (delta, pow) = grind(&opening_seed, counter);
        if !pow || !params.valid_challenge(&delta) {
            continue;
        }
        if let Some(opening) = material.open(&delta) {
            selected = Some((counter, delta, opening));
            break;
        }
    }
    let (counter, delta, opening) = selected.ok_or_else(|| anyhow!("grinding budget exhausted"))?;
    profile.mark("prove.grind-and-open");
    let mut proof = Vec::new();
    proof.extend_from_slice(MAGIC);
    proof.push(params.label());
    proof.extend_from_slice(&(c.committed_bits() as u64).to_le_bytes());
    proof.extend_from_slice(&iv);
    proof.extend_from_slice(&material.corrections);
    proof.extend_from_slice(&pow_consistency.to_le_bytes());
    proof.extend_from_slice(&u_tilde);
    proof.extend_from_slice(&correction);
    proof.extend_from_slice(&pow_weights.to_le_bytes());
    proof.extend_from_slice(&a1.0.to_le_bytes());
    proof.extend_from_slice(&a2.0.to_le_bytes());
    proof.extend_from_slice(&opening);
    proof.extend_from_slice(&delta);
    proof.extend_from_slice(&counter.to_le_bytes());
    profile.mark("prove.encoding");
    Ok(proof)
}

struct Parsed<'a> {
    params: Parameters,
    iv: &'a [u8; 16],
    corrections: &'a [u8],
    pow_consistency: u32,
    u_tilde: &'a [u8; 18],
    correction: &'a [u8],
    pow_weights: u32,
    a1: Fe,
    a2: Fe,
    opening: &'a [u8],
    delta: &'a [u8; 16],
    counter: u32,
}
fn parse<'a>(c: &Circuit, proof: &'a [u8]) -> Result<Parsed<'a>> {
    ensure!(
        proof.len() >= 17 && &proof[..8] == MAGIC,
        "invalid proof header"
    );
    let params = match proof[8] {
        8 => Parameters::Fast,
        11 => Parameters::Small,
        _ => return Err(anyhow!("unsupported parameter set")),
    };
    ensure!(
        u64::from_le_bytes(proof[9..17].try_into().unwrap()) == c.committed_bits() as u64,
        "wrong witness size"
    );
    let length = vector_bytes(c)?;
    let wbytes = length - 50;
    let cbytes = (params.tau() - 1) * length;
    let expected = 17 + 16 + cbytes + 4 + 18 + wbytes + 4 + 32 + params.opening_bytes() + 16 + 4;
    ensure!(
        proof.len() == expected,
        "incorrect proof length or trailing bytes"
    );
    let mut at = 17;
    let mut take = |n| {
        let value = &proof[at..at + n];
        at += n;
        value
    };
    let iv = take(16).try_into().unwrap();
    let corrections = take(cbytes);
    let pow_consistency = u32::from_le_bytes(take(4).try_into().unwrap());
    let u_tilde = take(18).try_into().unwrap();
    let correction = take(wbytes);
    let pow_weights = u32::from_le_bytes(take(4).try_into().unwrap());
    let a1 = Fe(u128::from_le_bytes(take(16).try_into().unwrap()));
    let a2 = Fe(u128::from_le_bytes(take(16).try_into().unwrap()));
    let opening = take(params.opening_bytes());
    let delta = take(16).try_into().unwrap();
    let counter = u32::from_le_bytes(take(4).try_into().unwrap());
    ensure!(
        counter < MAX_GRIND && params.valid_challenge(delta),
        "invalid grinding challenge"
    );
    ensure!(iv_ok(iv), "invalid iv proof-of-work");
    Ok(Parsed {
        params,
        iv,
        corrections,
        pow_consistency,
        u_tilde,
        correction,
        pow_weights,
        a1,
        a2,
        opening,
        delta,
        counter,
    })
}

/// Verify only the caller-rebuilt relation; policy, Bao authentication and
/// attestation signature verification precede this call in a presentation.
pub fn verify(c: &Circuit, proof: &[u8], context: &Context<'_>) -> Result<()> {
    verify_inner(c, proof, context, false)
}
pub(crate) fn verify_profiled(c: &Circuit, proof: &[u8], context: &Context<'_>) -> Result<()> {
    ensure!(c.profile().is_some(), "registered profile required");
    verify_inner(c, proof, context, true)
}
fn verify_inner(c: &Circuit, proof: &[u8], context: &Context<'_>, profiled: bool) -> Result<()> {
    let mut profile = crate::profile::Lap::new();
    let p = parse(c, proof)?;
    profile.mark("verify.proof-decode");
    let length = vector_bytes(c)?;
    let mut material =
        primitives::reconstruct(p.params, p.delta, p.opening, p.corrections, p.iv, length)
            .ok_or_else(|| anyhow!("invalid BAVC opening"))?;
    profile.mark("verify.vole-reconstruct");
    let mut t = transcript(context, c, p.params, profiled);
    absorb(&mut t, b"iv", p.iv);
    absorb(&mut t, b"bavc", &material.com);
    absorb(&mut t, b"corrections", p.corrections);
    profile.mark("transcript.binding");
    pow_verify(&mut t, b"pow-consistency", POW_CONSISTENCY_BITS, p.pow_consistency)?;
    let check_seed = challenge::<88>(&mut t, b"vole-consistency");
    absorb(&mut t, b"u-tilde", p.u_tilde);
    for (i, column) in material.columns.iter().enumerate() {
        let mut hash = primitives::hash_vector(&check_seed, column).unwrap();
        if (p.delta[i / 8] >> (i % 8)) & 1 != 0 {
            for (a, b) in hash.iter_mut().zip(p.u_tilde) {
                *a ^= b;
            }
        }
        absorb(&mut t, b"v-hash", &hash);
    }
    absorb(&mut t, b"witness-correction", p.correction);
    pow_verify(&mut t, b"pow-weights", POW_WEIGHTS_BITS, p.pow_weights)?;
    let weight_seed = challenge::<32>(&mut t, b"check-weights");
    for (i, column) in material.columns.iter_mut().enumerate() {
        if (p.delta[i / 8] >> (i % 8)) & 1 != 0 {
            for (q, d) in column.iter_mut().zip(p.correction) {
                *q ^= d;
            }
        }
    }
    profile.mark("verify.transcript-and-consistency");
    let keys = authenticated_values(c, &material.columns);
    profile.mark("verify.authenticated-rows");
    let delta = Fe(u128::from_le_bytes(*p.delta));
    let checks = c.verifier_constraints(&keys, delta)?;
    profile.mark("verify.constraints");
    let mask_start = p.correction.len() * 8;
    let mut a0 = mask(&material.columns, mask_start)
        ^ (delta * mask(&material.columns, mask_start + 128))
        ^ (delta * p.a1)
        ^ (delta * delta * p.a2);
    let mut reader = weights(&weight_seed);
    for check in checks {
        a0 = a0 ^ (next_weight(&mut reader) * check);
    }
    absorb(&mut t, b"a0", &a0.0.to_le_bytes());
    absorb(&mut t, b"a1", &p.a1.0.to_le_bytes());
    absorb(&mut t, b"a2", &p.a2.0.to_le_bytes());
    let opening_seed = challenge::<32>(&mut t, b"opening-seed");
    profile.mark("verify.weighted-check");
    ensure!(
        grind(&opening_seed, p.counter) == (*p.delta, true),
        "invalid relation/transcript"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_ir::{Term, aes::sbox, byte_inputs};
    fn context() -> Context<'static> {
        Context {
            attestation_digest: [1; 32],
            statement: b"test relation",
            presentation_nonce: [2; 32],
        }
    }
    #[test]
    fn honest_cubic_and_nonce_statement_binding() {
        let mut c = Circuit::default();
        let x = c.commit_fe();
        let y = c.commit_fe();
        let z = c.commit_fe();
        c.assert_zero(vec![Term::Cubic(Fe::ONE, x, y, z), Term::Constant(Fe(8))]);
        let w = c.eval(&[Fe(2); 3]).unwrap();
        for params in [Parameters::Fast, Parameters::Small] {
            let proof = prove(&c, &w, params, &context()).unwrap();
            verify(&c, &proof, &context()).unwrap();
            let mut changed = context();
            changed.presentation_nonce[0] ^= 1;
            assert!(verify(&c, &proof, &changed).is_err());
            changed = context();
            changed.attestation_digest[0] ^= 1;
            assert!(verify(&c, &proof, &changed).is_err());
            changed = context();
            changed.statement = b"other";
            assert!(verify(&c, &proof, &changed).is_err());
            let mut trailing = proof.clone();
            trailing.push(0);
            assert!(verify(&c, &trailing, &context()).is_err());
            assert!(verify(&c, &proof[..proof.len() - 1], &context()).is_err());
        }
    }
    #[test]
    fn sbox_bit_rows_and_mutated_check() {
        let mut c = Circuit::default();
        let byte = c.commit_byte();
        let out = sbox(&mut c, byte);
        c.assert_byte(out, 0x63);
        let w = c.eval(&byte_inputs(&[0])).unwrap();
        let proof = prove(&c, &w, Parameters::Fast, &context()).unwrap();
        verify(&c, &proof, &context()).unwrap();
        // Check each public component, including the two transmitted masked
        // coefficients. Full byte-flip sweeps belong to the longer test budget.
        let parsed = parse(&c, &proof).unwrap();
        let lengths = [
            8,
            1,
            8,
            16,
            parsed.corrections.len(),
            4,
            18,
            parsed.correction.len(),
            4,
            16,
            16,
            parsed.opening.len(),
            16,
            4,
        ];
        let mut at = 0;
        for length in lengths {
            for offset in [0, length - 1] {
                let mut changed = proof.clone();
                changed[at + offset] ^= 1;
                assert!(
                    verify(&c, &changed, &context()).is_err(),
                    "component at {}",
                    at + offset
                );
            }
            at += length;
        }
        assert_eq!(at, proof.len());
    }

    #[test]
    #[ignore = "explicit malicious-proof byte-flip budget"]
    fn every_proof_byte_is_bound() {
        let mut c = Circuit::default();
        let bit = c.commit_bit();
        c.assert_zero(vec![Term::Linear(Fe::ONE, bit), Term::Constant(Fe::ONE)]);
        let w = c.eval(&[Fe::ONE]).unwrap();
        let proof = prove(&c, &w, Parameters::Fast, &context()).unwrap();
        for index in 0..proof.len() {
            let mut changed = proof.clone();
            changed[index] ^= 1;
            assert!(
                verify(&c, &changed, &context()).is_err(),
                "accepted mutation {index}"
            );
        }
    }
}
