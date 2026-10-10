//! Bounded dynamic-length adapter. The relation check and Fiat--Shamir
//! transcript belong to the caller, not the FAEST signature API.
use crate::{
    bavc::{BatchVectorCommitment, BavcDecommitment, BavcOpenResult},
    fields::GF128,
    parameter::{BAVC128Fast, BAVC128Small, TauParameters},
    prg::{IV, PseudoRandomGenerator},
    universal_hashing::{VoleHasher, VoleHasherInit, VoleHasherProcess},
    utils::{Reader, decode_all_chall_3},
};
use hybrid_array::{
    Array,
    typenum::{U3, U16},
};
use zeroize::{Zeroize, Zeroizing};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Hard cap on encoded VOLE vector bytes. Callers may impose a smaller cap.
pub const MAX_VECTOR_BYTES: usize = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Selected upstream FAEST-128 parameter family.
pub enum Parameters {
    /// FAEST-128f: sixteen shallow trees and eight grinding bits.
    Fast,
    /// FAEST-128s: eleven deeper trees and seven grinding bits.
    Small,
}
impl Parameters {
    /// Protocol label identifying the family, rather than upstream's K value.
    pub fn label(self) -> u8 {
        match self {
            Self::Fast => 8,
            Self::Small => 11,
        }
    }
    /// Number of combined small-field VOLE instances.
    pub fn tau(self) -> usize {
        match self {
            Self::Fast => 16,
            Self::Small => 11,
        }
    }
    /// Required zero bits in the final opening challenge.
    pub fn grinding_bits(self) -> usize {
        match self {
            Self::Fast => 8,
            Self::Small => 7,
        }
    }
    /// Fixed encoded BAVC opening size, including zero padding.
    pub fn opening_bytes(self) -> usize {
        self.tau() * 48
            + match self {
                Self::Fast => 110,
                Self::Small => 102,
            } * 16
    }
    /// Check the family's challenge grinding restriction.
    pub fn valid_challenge(self, delta: &[u8; 16]) -> bool {
        match self {
            Self::Fast => delta[15] == 0,
            Self::Small => delta[15] & 0xfe == 0,
        }
    }
}

/// Secret correlation material; intentionally lacks Clone/Debug/serialization.
pub struct Commitment {
    /// Public BAVC root commitment.
    pub com: [u8; 32],
    /// Public corrections combining the small-field VOLE vectors.
    pub corrections: Vec<u8>,
    /// Secret VOLE value vector, erased on drop.
    pub u: Zeroizing<Vec<u8>>,
    /// Secret VOLE MAC columns, erased on drop.
    pub columns: Zeroizing<Vec<Vec<u8>>>,
    decom: BavcDecommitment<U16, U3>,
    params: Parameters,
}

impl Drop for Commitment {
    fn drop(&mut self) {
        self.decom.erase();
    }
}

// This impl is in the primitive adapter so upstream signing semantics are
// unchanged. Only seed/commitment buffers held by this adapter are erased.
impl BavcDecommitment<U16, U3> {
    fn erase(&mut self) {
        for key in &mut self.keys {
            key.as_mut_slice().zeroize();
        }
        for com in &mut self.coms {
            com.as_mut_slice().zeroize();
        }
    }
}

/// Verifier's reconstructed commitment and correlation columns.
pub struct Reconstruction {
    /// Reconstructed public BAVC root commitment.
    pub com: [u8; 32],
    /// Verifier's correlation columns. These contain no prover witness.
    pub columns: Vec<Vec<u8>>,
}

fn xor(dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len());
    for (a, b) in dst.iter_mut().zip(src) {
        *a ^= b;
    }
}

// Same streaming tree reduction as upstream convert_to_vole, with Vec storage
// replacing only the compile-time LHatBytes arrays.
fn convert<B: BatchVectorCommitment<LambdaBytes = U16>>(
    columns: &mut [Vec<u8>],
    seeds: &[Array<u8, U16>],
    iv: &IV,
    round: usize,
    length: usize,
) -> Zeroizing<Vec<u8>> {
    let ni = B::TAU::bavc_max_node_index(round);
    assert_eq!(seeds.len(), ni);
    let mut scratch = Zeroizing::new(vec![vec![0; length]; B::TAU::vole_array_length(round)]);
    let mut right = Zeroizing::new(vec![0; length]);
    let mut next = 0;
    for i in 0..ni / 2 {
        B::PRG::new_prg(&seeds[2 * i], iv, round as u32 + (1 << 31)).read(&mut scratch[next]);
        B::PRG::new_prg(&seeds[2 * i + 1], iv, round as u32 + (1 << 31)).read(&mut right);
        xor(&mut columns[0], &right);
        xor(&mut scratch[next], &right);
        next += 1;
        right.fill(0);
        for (d, column) in columns[1..].iter_mut().enumerate() {
            if (i + 1) % (1 << (d + 1)) != 0 {
                break;
            }
            let (l, r) = scratch.split_at_mut(next - 1);
            let left = l.last_mut().unwrap();
            xor(column, &r[0]);
            xor(left, &r[0]);
            r[0].fill(0);
            next -= 1;
        }
    }
    Zeroizing::new(std::mem::take(&mut scratch[0]))
}

/// Generate bounded dynamic-length correlations with upstream FAEST primitives.
/// Seed material is private; callers must provide fresh randomness every time.
pub fn commit(
    params: Parameters,
    seed: &[u8; 16],
    iv: &[u8; 16],
    length: usize,
) -> Option<Commitment> {
    if !(19..=MAX_VECTOR_BYTES).contains(&length) {
        return None;
    }
    match params {
        Parameters::Fast => commit_inner::<BAVC128Fast<GF128>>(params, seed, iv, length),
        Parameters::Small => commit_inner::<BAVC128Small<GF128>>(params, seed, iv, length),
    }
}

fn commit_inner<
    B: BatchVectorCommitment<
            LambdaBytes = U16,
            NLeafCommit = U3,
            LambdaBytesTimes2 = hybrid_array::typenum::U32,
        >,
>(
    params: Parameters,
    seed: &[u8; 16],
    iv: &[u8; 16],
    length: usize,
) -> Option<Commitment> {
    let iv: IV = (*iv).into();
    let mut result = B::commit(&(*seed).into(), &iv);
    let mut columns = Zeroizing::new(Vec::with_capacity(128));
    let mut corrections = vec![0; (params.tau() - 1) * length];
    let mut seed_at = 0;
    let offsets: Vec<_> = (0..params.tau()).map(|round| {
        let start=seed_at; seed_at+=B::TAU::bavc_max_node_index(round); start
    }).collect();
    let expand = |round: usize| {
        let ni=B::TAU::bavc_max_node_index(round);
        let ki=B::TAU::bavc_max_node_depth(round);
        let mut columns=Zeroizing::new(vec![vec![0;length];ki]);
        let current=convert::<B>(&mut columns,&result.seeds[offsets[round]..offsets[round]+ni],&iv,round,length);
        (current,columns)
    };
    // Indexed collection preserves the transcript order regardless of thread
    // scheduling. The initialized WASM Rayon pool bounds parallelism.
    #[cfg(feature = "parallel")]
    let rounds:Vec<_>=(0..params.tau()).into_par_iter().map(expand).collect();
    #[cfg(not(feature = "parallel"))]
    let rounds:Vec<_>=(0..params.tau()).map(expand).collect();
    let mut u = Zeroizing::new(Vec::new());
    for (round,(current,mut expanded)) in rounds.into_iter().enumerate() {
        let ki = B::TAU::bavc_max_node_depth(round);
        for column in expanded.iter_mut() { columns.push(std::mem::take(column)); }
        if round == 0 {
            u = current;
        } else {
            let c = &mut corrections[(round - 1) * length..round * length];
            c.copy_from_slice(&current);
            xor(c, &u);
        }
        debug_assert_eq!(expanded.len(),ki);
    }
    for seed in &mut result.seeds {
        seed.as_mut_slice().zeroize();
    }
    Some(Commitment {
        com: result.com.as_slice().try_into().ok()?,
        corrections,
        u,
        columns,
        decom: result.decom,
        params,
    })
}

impl Commitment {
    /// Returns the fixed-size, zero-padded upstream BAVC opening, or None if
    /// the challenge exceeds the opening-node bound (continue grinding).
    pub fn open(&self, delta: &[u8; 16]) -> Option<Vec<u8>> {
        if !self.params.valid_challenge(delta) {
            return None;
        }
        match self.params {
            Parameters::Fast => self.open_inner::<BAVC128Fast<GF128>>(delta),
            Parameters::Small => self.open_inner::<BAVC128Small<GF128>>(delta),
        }
    }
    fn open_inner<B: BatchVectorCommitment<LambdaBytes = U16, NLeafCommit = U3>>(
        &self,
        delta: &[u8; 16],
    ) -> Option<Vec<u8>> {
        let indexes = decode_all_chall_3::<B::TAU>(delta);
        let opening = B::open(&self.decom, &indexes)?;
        let mut bytes = Vec::with_capacity(self.params.opening_bytes());
        for value in opening.coms.iter().chain(&opening.nodes) {
            bytes.extend_from_slice(value);
        }
        if bytes.len() > self.params.opening_bytes() {
            return None;
        }
        bytes.resize(self.params.opening_bytes(), 0);
        Some(bytes)
    }
}

/// Reconstruct verifier correlations from a fixed-width opening and corrections.
/// Reject unsupported lengths, grinding restrictions and noncanonical widths.
pub fn reconstruct(
    params: Parameters,
    delta: &[u8; 16],
    opening: &[u8],
    corrections: &[u8],
    iv: &[u8; 16],
    length: usize,
) -> Option<Reconstruction> {
    if !(19..=MAX_VECTOR_BYTES).contains(&length)
        || !params.valid_challenge(delta)
        || opening.len() != params.opening_bytes()
        || corrections.len() != (params.tau() - 1) * length
    {
        return None;
    }
    match params {
        Parameters::Fast => {
            reconstruct_inner::<BAVC128Fast<GF128>>(params, delta, opening, corrections, iv, length)
        }
        Parameters::Small => reconstruct_inner::<BAVC128Small<GF128>>(
            params,
            delta,
            opening,
            corrections,
            iv,
            length,
        ),
    }
}

fn reconstruct_inner<
    B: BatchVectorCommitment<LambdaBytes = U16, LambdaBytesTimes2 = hybrid_array::typenum::U32>,
>(
    params: Parameters,
    delta: &[u8; 16],
    opening: &[u8],
    corrections: &[u8],
    iv: &[u8; 16],
    length: usize,
) -> Option<Reconstruction> {
    let (coms, nodes) = opening.split_at(params.tau() * 48);
    let opening = BavcOpenResult {
        coms: coms.chunks_exact(48).collect(),
        nodes: nodes.chunks_exact(16).collect(),
    };
    let indexes = decode_all_chall_3::<B::TAU>(delta);
    let iv: IV = (*iv).into();
    let mut result = B::reconstruct(&opening, &indexes, &iv)?;
    let mut seed_at = 0;
    let offsets: Vec<_> = (0..params.tau()).map(|round| {
        let start = seed_at;
        seed_at += B::TAU::bavc_max_node_index(round) - 1;
        start
    }).collect();
    let expand = |round: usize| {
        let ni = B::TAU::bavc_max_node_index(round);
        let ki = B::TAU::bavc_max_node_depth(round);
        let index = indexes[round] as usize;
        let mut seeds = vec![Array::<u8,U16>::default(); ni];
        for (j, seed) in seeds.iter_mut().enumerate().skip(1) {
            let original = j ^ index;
            seed.copy_from_slice(&result.seeds[offsets[round] + original - usize::from(original > index)]);
        }
        let mut columns = vec![vec![0;length];ki];
        let _ = convert::<B>(&mut columns, &seeds, &iv, round, length);
        for seed in &mut seeds { seed.as_mut_slice().zeroize(); }
        if round != 0 {
            for (j, column) in columns.iter_mut().enumerate() {
                if index & (1 << j) != 0 {
                    xor(column, &corrections[(round - 1) * length..round * length]);
                }
            }
        }
        columns
    };
    #[cfg(feature = "parallel")]
    let rounds:Vec<_>=(0..params.tau()).into_par_iter().map(expand).collect();
    #[cfg(not(feature = "parallel"))]
    let rounds:Vec<_>=(0..params.tau()).map(expand).collect();
    let columns = rounds.into_iter().flatten().collect();
    for seed in &mut result.seeds {
        seed.as_mut_slice().zeroize();
    }
    Some(Reconstruction {
        com: result.com.as_slice().try_into().ok()?,
        columns,
    })
}

/// FAEST's 88-byte-seeded VOLE universal hash, including its 18-byte pad.
pub fn hash_vector(seed: &[u8; 88], vector: &[u8]) -> Option<[u8; 18]> {
    if !(19..=MAX_VECTOR_BYTES).contains(&vector.len()) {
        return None;
    }
    let hasher = VoleHasher::<GF128>::new_vole_hasher(&(*seed).into());
    Some(hasher.process(vector).as_slice().try_into().ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vole::{VoleCommitmentCRefMut, volecommit};
    use hybrid_array::typenum::U256;

    fn differential<
        B: BatchVectorCommitment<
                LambdaBytes = U16,
                NLeafCommit = U3,
                LambdaBytesTimes2 = hybrid_array::typenum::U32,
            >,
    >(
        params: Parameters,
    ) {
        let seed = [1u8; 16];
        let iv = [3u8; 16];
        let mut c = vec![0; (params.tau() - 1) * 256];
        let reference =
            volecommit::<B, U256>(VoleCommitmentCRefMut::new(&mut c), &seed.into(), &iv.into());
        let adapted = commit(params, &seed, &iv, 256).unwrap();
        assert_eq!(adapted.com.as_slice(), reference.com.as_slice());
        assert_eq!(adapted.corrections, c);
        assert_eq!(adapted.u.as_slice(), reference.u.as_slice());
        for (a, b) in adapted.columns.iter().zip(reference.v.iter()) {
            assert_eq!(a.as_slice(), b.as_slice());
        }
        let mut challenge = [0u8; 16];
        let opening = (0u32..10000)
            .find_map(|i| {
                challenge[..4].copy_from_slice(&i.to_le_bytes());
                adapted.open(&challenge)
            })
            .unwrap();
        let reconstructed =
            reconstruct(params, &challenge, &opening, &adapted.corrections, &iv, 256).unwrap();
        assert_eq!(reconstructed.com, adapted.com);
        for col in 0..128 {
            for row in 0..256 {
                let expected = adapted.columns[col][row]
                    ^ if (challenge[col / 8] >> (col % 8)) & 1 != 0 {
                        adapted.u[row]
                    } else {
                        0
                    };
                assert_eq!(reconstructed.columns[col][row], expected);
            }
        }
        let mut bad = opening.clone();
        bad[0] ^= 1;
        if let Some(reconstructed) =
            reconstruct(params, &challenge, &bad, &adapted.corrections, &iv, 256)
        {
            assert_ne!(reconstructed.com, adapted.com);
        }
    }

    #[test]
    fn dynamic_fast_matches_upstream() {
        differential::<BAVC128Fast<GF128>>(Parameters::Fast);
    }
    #[test]
    fn dynamic_small_matches_upstream() {
        differential::<BAVC128Small<GF128>>(Parameters::Small);
    }
}
