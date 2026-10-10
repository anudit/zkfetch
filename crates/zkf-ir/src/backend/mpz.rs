//! Authenticated degree-three checks over MPZ's existing bit MACs.
//!
//! The borrowed prefix is the existing VM reference (for example, an ORIGO
//! application key), never a newly assigned copy. All other committed values
//! and two independent masks use fresh correlations from that same VM. This
//! bridge supports an interactive reference flow and a negotiated combined
//! Fiat--Shamir flow. See docs/v2-presentation-optimizations.md for the binding
//! and soundness conditions.
use super::check::Polynomial;
use crate::{CheckedWitness, Circuit, Witness, field::Fe};
use anyhow::{Result, ensure};
use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_ot::rcot::{RCOTReceiver, RCOTSender};
use mpz_vm_core::{
    Execute,
    memory::{
        MemoryExt, Repr, ViewExt,
        binary::{Binary, U8},
    },
};
use mpz_zk::{Prover, Verifier};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serio::{SinkExt, stream::IoStreamExt};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const MAX_BITS: usize = 8 << 20;

fn binding(c: &Circuit, statement: &[u8], profiled: bool) -> Vec<u8> {
    let mut out = b"zkf/2/mpz/degree-three/chacha8/v2\0".to_vec();
    let identity = if profiled {
        c.transcript_identity()
    } else {
        let mut out = b"circuit-digest\0".to_vec();
        out.extend_from_slice(&c.digest());
        out
    };
    out.extend_from_slice(&(identity.len() as u64).to_le_bytes());
    out.extend_from_slice(&identity);
    out.extend_from_slice(&(c.committed_bits() as u64).to_le_bytes());
    out.extend_from_slice(&(statement.len() as u64).to_le_bytes());
    out.extend_from_slice(statement);
    out
}
/// Independent pseudorandom coefficients, not powers of a field seed.
/// Hash the complete public binding once; expanding the PRG then costs O(n)
/// without rehashing a potentially large binding for every constraint.
struct Weights(ChaCha8Rng);
impl Weights {
    fn new(seed: &[u8; 32], binding: &[u8]) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"zkf/2/mpz/check-weights/chacha8/v2");
        hash.update(seed);
        hash.update((binding.len() as u64).to_le_bytes());
        hash.update(binding);
        Self(ChaCha8Rng::from_seed(hash.finalize().into()))
    }
    fn next(&mut self) -> Fe {
        let mut bytes = [0; 16];
        self.0.fill_bytes(&mut bytes);
        Fe(u128::from_le_bytes(bytes))
    }
}
fn layout(c: &Circuit, prefix_bits: usize) -> Result<usize> {
    ensure!(c.committed_bits() <= MAX_BITS, "circuit exceeds bridge cap");
    ensure!(
        prefix_bits <= c.committed_bits() && prefix_bits.is_multiple_of(8),
        "borrowed prefix must end on a byte boundary within commitments"
    );
    // A prefix may not split a field commitment.
    let mut at = 0;
    for width in c.commitment_widths() {
        ensure!(
            !(at < prefix_bits && at + width > prefix_bits),
            "prefix splits a commitment"
        );
        at += width;
    }
    Ok(c.committed_bits().div_ceil(8))
}
fn pack(c: &Circuit, w: &CheckedWitness<'_>) -> Result<Zeroizing<Vec<u8>>> {
    let values = c.commitment_values_checked(w)?;
    let mut out = Zeroizing::new(vec![0u8; c.committed_bits().div_ceil(8)]);
    let mut at = 0;
    for (value, width) in values.iter().zip(c.commitment_widths()) {
        for bit in 0..width {
            out[at / 8] |= (((value.0 >> bit) & 1) as u8) << (at % 8);
            at += 1;
        }
    }
    Ok(out)
}
fn lift_rows(c: &Circuit, rows: &[Fe]) -> Zeroizing<Vec<Fe>> {
    let mut at = 0;
    Zeroizing::new(
        c.commitment_widths()
            .into_iter()
            .map(|width| {
                let mut value = Fe::ZERO;
                for bit in 0..width {
                    value = value ^ (rows[at] * Fe(1u128 << bit));
                    at += 1;
                }
                value
            })
            .collect(),
    )
}
fn field_rows(rows: &[Fe]) -> Fe {
    assert_eq!(rows.len(), 128);
    rows.iter().enumerate().fold(Fe::ZERO, |value, (bit, row)| {
        value ^ (*row * Fe(1u128 << bit))
    })
}

/// Prove a relation using a prefix already authenticated by the same VM.
/// Callers must await acceptance before signing any derived commitment.
/// On any failure, discard the session; masks and correlations are single-use.
pub async fn prove<OT, R>(
    vm: &mut Prover<OT>,
    ctx: &mut Context,
    c: &Circuit,
    witness: &Witness,
    prefix: R,
    statement: &[u8],
) -> Result<()>
where
    OT: RCOTReceiver<bool, Block> + Flush + Send + 'static,
    R: Repr<Binary> + Copy,
{
    prove_prefixes(vm, ctx, c, witness, &[prefix], statement, false).await
}

pub async fn prove_prefixes<OT, R>(
    vm: &mut Prover<OT>,
    ctx: &mut Context,
    c: &Circuit,
    witness: &Witness,
    prefixes: &[R],
    statement: &[u8],
    fiat_shamir: bool,
) -> Result<()>
where
    OT: RCOTReceiver<bool, Block> + Flush + Send + 'static,
    R: Repr<Binary> + Copy,
{
    prove_prefixes_inner(vm, ctx, c, witness, prefixes, statement, fiat_shamir, false).await
}

pub async fn prove_profiled_prefixes<OT, R>(
    vm: &mut Prover<OT>,
    ctx: &mut Context,
    c: &Circuit,
    witness: &Witness,
    prefixes: &[R],
    statement: &[u8],
    fiat_shamir: bool,
) -> Result<()>
where
    OT: RCOTReceiver<bool, Block> + Flush + Send + 'static,
    R: Repr<Binary> + Copy,
{
    ensure!(c.profile().is_some(), "registered profile required");
    prove_prefixes_inner(vm, ctx, c, witness, prefixes, statement, fiat_shamir, true).await
}

async fn prove_prefixes_inner<OT, R>(
    vm: &mut Prover<OT>,
    ctx: &mut Context,
    c: &Circuit,
    witness: &Witness,
    prefixes: &[R],
    statement: &[u8],
    fiat_shamir: bool,
    profiled: bool,
) -> Result<()>
where
    OT: RCOTReceiver<bool, Block> + Flush + Send + 'static,
    R: Repr<Binary> + Copy,
{
    let checked = c.checked(witness)?;
    let prefix_bits = prefixes.iter().map(|prefix| prefix.to_raw().len()).sum();
    let bytes = layout(c, prefix_bits)?;
    let mut values = pack(c, &checked)?;
    let mut masks = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(masks.as_mut());
    values.extend_from_slice(masks.as_ref());
    let extra = vm.alloc_vec::<U8>(values.len() - prefix_bits / 8)?;
    vm.mark_private(extra)?;
    vm.assign(extra, values[prefix_bits / 8..].to_vec())?;
    vm.commit(extra)?;
    let binding = binding(c, statement, profiled);
    vm.bind_statement(&binding);
    vm.flush(ctx).await?;
    let rows = Zeroizing::new(
        prefixes
            .iter()
            .map(|prefix| vm.get_macs(*prefix))
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .chain(vm.get_macs(extra)?)
            .map(|mac| Fe(u128::from_le_bytes(mac.as_block().to_bytes())))
            .collect::<Vec<_>>(),
    );
    ensure!(
        rows.len() == (bytes + 32) * 8,
        "wrong authenticated row count"
    );
    let tags = lift_rows(c, &rows);
    let seed = if fiat_shamir {
        vm.field_challenge()
    } else {
        let (digest, seed): ([u8; 32], [u8; 32]) = ctx.io_mut().expect_next().await?;
        ensure!(digest == c.digest(), "verifier circuit differs");
        seed
    };
    let mut coefficients = Zeroizing::new([Fe::ZERO; 3]);
    let mut weights = Weights::new(&seed, &binding);
    if c.edge_count() >= 32_768 {
        // The schedule can execute checks in a different order. Expand the
        // public coefficient stream once in transcript order and index it by
        // original constraint ID; no relation/profile/wire-format change.
        let weights: Vec<_> = (0..c.constraint_count()).map(|_| weights.next()).collect();
        let plan = c.streaming_plan(&[])?;
        let mut valid = true;
        plan.prover_constraints(&checked, &tags, |index, poly| {
            valid &= poly.0[3] == Fe::ZERO;
            for j in 0..3 {
                coefficients[j] = coefficients[j] ^ (weights[index] * poly.0[j]);
            }
        })?;
        ensure!(valid, "unsatisfied relation");
    } else {
        let polynomials = c.constraint_polynomials_checked(&checked, &tags)?;
        for poly in &polynomials.0 {
            ensure!(poly.0[3] == Fe::ZERO, "unsatisfied relation");
            let chi = weights.next();
            for j in 0..3 {
                coefficients[j] = coefficients[j] ^ (chi * poly.0[j]);
            }
        }
    }
    coefficients[0] = coefficients[0] ^ field_rows(&rows[bytes * 8..bytes * 8 + 128]);
    coefficients[1] = coefficients[1]
        ^ Fe(u128::from_le_bytes(masks[..16].try_into().unwrap()))
        ^ field_rows(&rows[bytes * 8 + 128..]);
    coefficients[2] = coefficients[2] ^ Fe(u128::from_le_bytes(masks[16..].try_into().unwrap()));
    let message = coefficients.map(|v| v.0.to_le_bytes());
    ctx.io_mut().send(message).await?;
    Ok(())
}

/// Check the identical public circuit using the notary's MAC keys and secret
/// delta. A successful result proves the borrowed prefix and new commitments
/// satisfy the relation; no plaintext or inverse witness is received.
pub async fn verify<OT, R>(
    vm: &mut Verifier<OT>,
    ctx: &mut Context,
    c: &Circuit,
    prefix: R,
    statement: &[u8],
) -> Result<()>
where
    OT: RCOTSender<Block> + Flush + Send + 'static,
    R: Repr<Binary> + Copy,
{
    verify_prefixes(vm, ctx, c, &[prefix], statement, false).await
}

pub async fn verify_prefixes<OT, R>(
    vm: &mut Verifier<OT>,
    ctx: &mut Context,
    c: &Circuit,
    prefixes: &[R],
    statement: &[u8],
    fiat_shamir: bool,
) -> Result<()>
where
    OT: RCOTSender<Block> + Flush + Send + 'static,
    R: Repr<Binary> + Copy,
{
    verify_prefixes_inner(vm, ctx, c, prefixes, statement, fiat_shamir, false).await
}

pub async fn verify_profiled_prefixes<OT, R>(
    vm: &mut Verifier<OT>,
    ctx: &mut Context,
    c: &Circuit,
    prefixes: &[R],
    statement: &[u8],
    fiat_shamir: bool,
) -> Result<()>
where
    OT: RCOTSender<Block> + Flush + Send + 'static,
    R: Repr<Binary> + Copy,
{
    ensure!(c.profile().is_some(), "registered profile required");
    verify_prefixes_inner(vm, ctx, c, prefixes, statement, fiat_shamir, true).await
}

async fn verify_prefixes_inner<OT, R>(
    vm: &mut Verifier<OT>,
    ctx: &mut Context,
    c: &Circuit,
    prefixes: &[R],
    statement: &[u8],
    fiat_shamir: bool,
    profiled: bool,
) -> Result<()>
where
    OT: RCOTSender<Block> + Flush + Send + 'static,
    R: Repr<Binary> + Copy,
{
    let prefix_bits = prefixes.iter().map(|prefix| prefix.to_raw().len()).sum();
    let bytes = layout(c, prefix_bits)?;
    let extra = vm.alloc_vec::<U8>(bytes + 32 - prefix_bits / 8)?;
    vm.mark_blind(extra)?;
    vm.commit(extra)?;
    let binding = binding(c, statement, profiled);
    vm.bind_statement(&binding);
    vm.flush(ctx).await?;
    let rows = Zeroizing::new(
        prefixes
            .iter()
            .map(|prefix| vm.get_keys(*prefix))
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .chain(vm.get_keys(extra)?)
            .map(|key| Fe(u128::from_le_bytes(key.as_block().to_bytes())))
            .collect::<Vec<_>>(),
    );
    ensure!(
        rows.len() == (bytes + 32) * 8,
        "wrong authenticated row count"
    );
    let commitments = lift_rows(c, &rows);
    let delta = Fe(u128::from_le_bytes(vm.delta().as_block().to_bytes()));
    let seed = if fiat_shamir {
        vm.field_challenge()
    } else {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        ctx.io_mut().send((c.digest(), seed)).await?;
        seed
    };
    let mut expected = field_rows(&rows[bytes * 8..bytes * 8 + 128])
        ^ (delta * field_rows(&rows[bytes * 8 + 128..]));
    let mut weights = Weights::new(&seed, &binding);
    // A verifier wire is only one field element, versus four for a prover
    // polynomial. Until schedule metadata is smaller than that wire array,
    // materialization uses less peak memory on the memory-constrained notary.
    let checks = Zeroizing::new(c.verifier_constraints(&commitments, delta)?);
    for check in checks.iter() {
        expected = expected ^ (weights.next() * *check);
    }
    let message: [[u8; 16]; 3] = ctx.io_mut().expect_next().await?;
    let poly = Polynomial([
        Fe(u128::from_le_bytes(message[0])),
        Fe(u128::from_le_bytes(message[1])),
        Fe(u128::from_le_bytes(message[2])),
        Fe::ZERO,
    ]);
    ensure!(
        poly.at(delta) == expected,
        "degree-three authenticated check failed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Term, aes::ExpandedKey, byte_inputs, tls};
    use aes::{
        Aes128,
        cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
    };
    use mpz_common::context::test_st_context;
    use mpz_ot::ideal::rcot::ideal_rcot;
    use mpz_vm_core::memory::{Array, correlated::Delta};
    use mpz_zk::{ProverConfig, VerifierConfig};

    #[test]
    fn coefficient_stream_is_bound_and_reproducible() {
        let mut a = Weights::new(&[11; 32], b"statement A");
        let mut b = Weights::new(&[11; 32], b"statement A");
        let mut other_statement = Weights::new(&[11; 32], b"statement B");
        let mut other_seed = Weights::new(&[12; 32], b"statement A");
        let coefficients: Vec<_> = (0..128).map(|_| a.next()).collect();
        assert_eq!(coefficients, (0..128).map(|_| b.next()).collect::<Vec<_>>());
        assert_ne!(
            coefficients,
            (0..128).map(|_| other_statement.next()).collect::<Vec<_>>()
        );
        assert_ne!(
            coefficients,
            (0..128).map(|_| other_seed.next()).collect::<Vec<_>>()
        );
        assert_ne!(coefficients[2], coefficients[1] * coefficients[1]);
    }

    #[test]
    fn guessing_the_secret_delta_can_pass_a_false_constant_relation() {
        let map = |raw: u128| {
            u128::from_le_bytes(
                Delta::new(Block::new(raw.to_le_bytes()))
                    .as_block()
                    .to_bytes(),
            )
        };
        assert_eq!(map(0), 1);
        assert_eq!(map(1), 1);
        for bit in 1..128 {
            assert_eq!(map(1u128 << bit), (1u128 << bit) | 1);
        }
        // An unsatisfiable degree-three relation: homogenizing 1 = 0 gives
        // Delta^3 = 0. A malicious prover need not use the checked-witness API;
        // it can submit the constant guessed_delta^3 instead. Masks translate
        // both sides by the same honest lower-degree polynomial and do not
        // remove this attack. The real Delta has only 127 random bits.
        let mut c = Circuit::default();
        c.assert_zero(vec![Term::Constant(Fe::ONE)]);
        let guess = Fe(83); // Odd, hence within MPZ's challenge support.
        let message = Polynomial([guess * guess * guess, Fe::ZERO, Fe::ZERO, Fe::ZERO]);
        let mut accepted = 0;
        for raw in (1..256u128).step_by(2) {
            let delta = Fe(raw);
            let expected = c.verifier_constraints(&[], delta).unwrap()[0];
            if message.at(delta) == expected {
                accepted += 1;
            }
        }
        assert!(accepted >= 1 && accepted <= 3);
        assert_eq!(
            message.at(guess),
            c.verifier_constraints(&[], guess).unwrap()[0]
        );
        // Additional public weights at the same Delta preserve the common root.
        for weight in [Fe(1), Fe(19), Fe(97)] {
            assert_eq!(
                weight * message.at(guess),
                weight * c.verifier_constraints(&[], guess).unwrap()[0]
            );
        }
    }

    #[tokio::test]
    async fn gcm_tag_borrows_the_authenticated_session_key() {
        use aes_gcm::{
            Aes128Gcm,
            aead::{Aead, KeyInit, Payload},
        };
        let key = [43; 16];
        let nonce = [19; 12];
        let aad = [23, 3, 3, 0, 32];
        let sealed = Aes128Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: b"split test body!",
                    aad: &aad,
                },
            )
            .unwrap();
        let (ct, tag) = sealed.split_at(sealed.len() - 16);
        let c = crate::gcm::tag_statement(16, nonce, &aad, ct, tag.try_into().unwrap()).unwrap();
        let w = c.eval(&byte_inputs(&key)).unwrap();
        let (p, v) = run(&c, &w, &key, b"captured record", b"captured record").await;
        p.unwrap();
        v.unwrap();
        let (p, v) = run(&c, &w, &[44; 16], b"captured record", b"captured record").await;
        assert!(p.is_err() || v.is_err(), "replacement key accepted");
        let (p, v) = run(&c, &w, &key, b"captured record", b"substituted record").await;
        assert!(p.is_err() || v.is_err(), "replacement binding accepted");
    }

    async fn run(
        c: &Circuit,
        w: &Witness,
        actual: &[u8],
        p_statement: &[u8],
        v_statement: &[u8],
    ) -> (Result<()>, Result<()>) {
        run_mode(c, w, actual, p_statement, v_statement, false).await
    }

    async fn run_mode(
        c: &Circuit,
        w: &Witness,
        actual: &[u8],
        p_statement: &[u8],
        v_statement: &[u8],
        fiat_shamir: bool,
    ) -> (Result<()>, Result<()>) {
        let (mut ctx_p, mut ctx_v) = test_st_context(8);
        let delta = Delta::new(Block::new([97; 16]));
        let (send, recv) = ideal_rcot(Block::new([41; 16]), delta.into_inner());
        let mut p = Prover::new(ProverConfig::default(), recv);
        let mut v = Verifier::new(VerifierConfig::default(), delta, send);
        let mut prefixes_p = Vec::new();
        let mut prefixes_v = Vec::new();
        for chunk in actual.chunks(16) {
            let prefix_p = p.alloc_vec::<U8>(chunk.len()).unwrap();
            let prefix_v = v.alloc_vec::<U8>(chunk.len()).unwrap();
            p.mark_private(prefix_p).unwrap();
            p.assign(prefix_p, chunk.to_vec()).unwrap();
            p.commit(prefix_p).unwrap();
            v.mark_blind(prefix_v).unwrap();
            v.commit(prefix_v).unwrap();
            prefixes_p.push(prefix_p);
            prefixes_v.push(prefix_v);
        }
        futures::join!(
            prove_prefixes_inner(
                &mut p,
                &mut ctx_p,
                c,
                w,
                &prefixes_p,
                p_statement,
                fiat_shamir,
                c.profile().is_some()
            ),
            verify_prefixes_inner(
                &mut v,
                &mut ctx_v,
                c,
                &prefixes_v,
                v_statement,
                fiat_shamir,
                c.profile().is_some()
            )
        )
    }

    #[tokio::test]
    async fn cubic_relation_over_real_mpz_macs() {
        let mut c = Circuit::default();
        let bytes: [_; 16] = std::array::from_fn(|_| c.commit_byte());
        let x = c.lift(bytes[0]);
        // A genuine cubic constraint, not a boolean gate translated to XOR.
        let seven = Fe::byte(7);
        c.assert_zero(vec![
            Term::Cubic(Fe::ONE, x, x, x),
            Term::Constant(seven * seven * seven),
        ]);
        let mut raw = [0u8; 16];
        raw[0] = 7;
        let w = c.eval(&byte_inputs(&raw)).unwrap();
        let (p, v) = run(&c, &w, &raw, b"cubic", b"cubic").await;
        p.unwrap();
        v.unwrap();
        let (p, v) = run(&c, &w, &raw, b"different", b"cubic").await;
        p.unwrap();
        assert!(v.is_err());
        raw[0] = 8;
        let (p, v) = run(&c, &w, &raw, b"cubic", b"cubic").await;
        p.unwrap();
        assert!(
            v.is_err(),
            "new witness must not replace the borrowed VM value"
        );
    }

    #[tokio::test]
    async fn aes_commitment_borrows_authenticated_key() {
        let raw = [7u8; 16];
        let native = Aes128::new_from_slice(&raw).unwrap();
        let mut c = Circuit::default();
        let key: Vec<_> = (0..16).map(|_| c.commit_byte()).collect();
        let expanded = ExpandedKey::new(&mut c, &key).unwrap();
        let ck = tls::key_commitment(&mut c, &expanded);
        for index in 1..=2 {
            let mut block = GenericArray::clone_from_slice(&tls::commitment_block(index).unwrap());
            native.encrypt_block(&mut block);
            for i in 0..16 {
                c.assert_byte(ck[(index as usize - 1) * 16 + i], block[i]);
            }
        }
        let w = c.eval(&byte_inputs(&raw)).unwrap();
        let (p, v) = run(&c, &w, &raw, b"AES key commitment", b"AES key commitment").await;
        p.unwrap();
        v.unwrap();
        let (p, v) = run(
            &c,
            &w,
            &[8; 16],
            b"AES key commitment",
            b"AES key commitment",
        )
        .await;
        p.unwrap();
        assert!(v.is_err());
    }

    /// Compare encodings through real MAC checks, with ideal OT so preprocessing
    /// and network latency do not obscure constraint evaluation. Uses registered
    /// benchmark profiles, matching production's omission of the circuit hash.
    #[tokio::test]
    #[ignore = "manual release benchmark; prints encoding tradeoff"]
    async fn benchmark_session_aes_encodings() {
        let raw = [37; 16];
        for compact in [false, true] {
            let mut c = Circuit::default();
            let refs: Vec<_> = (0..16).map(|_| c.commit_byte()).collect();
            let expanded = ExpandedKey::new(&mut c, &refs).unwrap();
            // Two C_k blocks plus a representative 800-byte response head.
            for index in 0..52u32 {
                let input = tls::counter_block([23; 12], 0, index).unwrap();
                let block = input.map(|b| c.public_byte(b));
                let output = if compact {
                    expanded.encrypt_norm(&mut c, block)
                } else {
                    expanded.encrypt(&mut c, block)
                };
                let mut native = GenericArray::clone_from_slice(&input);
                Aes128::new_from_slice(&raw)
                    .unwrap()
                    .encrypt_block(&mut native);
                for (wire, expected) in output.into_iter().zip(native) {
                    c.assert_byte(wire, expected);
                }
            }
            c.register_profile(if compact {
                "zkf/bench/mpz/compact-aes/v1"
            } else {
                "zkf/bench/mpz/standard-aes/v1"
            });
            let w = c.eval(&byte_inputs(&raw)).unwrap();
            let mut elapsed = Vec::new();
            for _ in 0..5 {
                let start = std::time::Instant::now();
                let (p, v) = run_mode(
                    &c,
                    &w,
                    &raw,
                    b"encoding benchmark",
                    b"encoding benchmark",
                    true,
                )
                .await;
                p.unwrap();
                v.unwrap();
                elapsed.push(start.elapsed().as_secs_f64() * 1000.0);
            }
            elapsed.sort_by(f64::total_cmp);
            println!(
                "encoding={} blocks=52 committed_bits={} constraints={} median_ms={:.3}",
                if compact { "compact" } else { "standard" },
                c.committed_bits(),
                c.constraint_count(),
                elapsed[2]
            );
            let plan_start = std::time::Instant::now();
            let plan = c.streaming_plan(&[]).unwrap();
            let plan_ms = plan_start.elapsed().as_secs_f64() * 1000.0;
            let tags: Vec<_> = (0..c.commitment_count())
                .map(|i| Fe(i as u128 + 19))
                .collect();
            let checked = c.checked(&w).unwrap();
            let keys = c.correlated_keys(&w, &tags, Fe(83)).unwrap();
            let start = std::time::Instant::now();
            let full = c.constraint_polynomials_checked(&checked, &tags).unwrap();
            let full_ms = start.elapsed().as_secs_f64() * 1000.0;
            let start = std::time::Instant::now();
            plan.prover_constraints(&checked, &tags, |i, p| assert_eq!(p, full.0[i]))
                .unwrap();
            let stream_ms = start.elapsed().as_secs_f64() * 1000.0;
            let full_v = c.verifier_constraints(&keys, Fe(83)).unwrap();
            plan.verifier_constraints(&keys, Fe(83), |i, v| assert_eq!(v, full_v[i]))
                .unwrap();
            println!(
                "authenticated_wire_values_full={} authenticated_wire_values_stream={} prover_check_full_ms={:.3} prover_check_stream_ms={:.3}",
                c.edge_count(),
                plan.resident_values(),
                full_ms,
                stream_ms
            );
            println!(
                "public_schedule_bytes={} schedule_build_ms={:.3}",
                plan.allocated_bytes(),
                plan_ms
            );
        }
    }

    #[tokio::test]
    async fn combined_fiat_shamir_binds_both_prefixes_and_statement() {
        let mut c = Circuit::default();
        let keys: Vec<_> = (0..32).map(|_| c.commit_byte()).collect();
        c.assert_byte(keys[0], 7);
        c.assert_byte(keys[16], 9);
        let mut raw = [7; 32];
        raw[16..].fill(9);
        let w = c.eval(&byte_inputs(&raw)).unwrap();
        let (p, v) = run_mode(&c, &w, &raw, b"head+claim+nonce", b"head+claim+nonce", true).await;
        p.unwrap();
        v.unwrap();
        let (p, v) = run_mode(&c, &w, &raw, b"old nonce", b"new nonce", true).await;
        p.unwrap();
        assert!(v.is_err());
        raw[16] ^= 1;
        let (p, v) = run_mode(&c, &w, &raw, b"head", b"head", true).await;
        p.unwrap();
        assert!(v.is_err());
    }

    #[test]
    fn mpz_field_encoding_matches_reference_field() {
        for a in [0, 1, 7, u128::MAX, 1 << 127] {
            for b in [0, 1, 11, u128::MAX, 1 << 127] {
                assert_eq!(
                    (Fe(a) * Fe(b)).0.to_le_bytes(),
                    Block::new(a.to_le_bytes())
                        .gfmul(Block::new(b.to_le_bytes()))
                        .to_bytes()
                );
            }
        }
        // Type check the session's usual fixed-size key reference as well.
        fn accepts<R: Repr<Binary> + Copy>() {}
        accepts::<Array<U8, 16>>();
    }
}
