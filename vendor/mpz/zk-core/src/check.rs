//! QuickSilver consistency check.

use std::mem;

use blake3::Hasher;
use cfg_if::cfg_if;
use mpz_core::{
    Block,
    bitvec::{BitSlice, BitVec},
};
use rand_chacha::{ChaCha12Rng, rand_core::SeedableRng};
use serde::{Deserialize, Serialize};
use zerocopy::IntoBytes;

use crate::vole::{vole_receiver, vole_sender};

type Result<T> = core::result::Result<T, CheckError>;

/// Chunk size for parallel processing of consistency check.
/// Large enough to saturate caches, small enough for effective work stealing.
const SEGMENT_SIZE: usize = 512;

/// Values sent from the prover to the verifier for the consistency check.
#[derive(Debug, Serialize, Deserialize)]
pub struct UV {
    u: Block,
    v: Block,
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Triple {
    pub(crate) x: Block,
    pub(crate) y: Block,
    pub(crate) z: Block,
}

#[derive(Debug, Default)]
pub(crate) struct Check {
    triples: Vec<Triple>,
    adjust: BitVec,
}

impl Check {
    /// Reserves capacity for at least `n` AND gates, returns the starting
    /// index.
    pub(crate) fn reserve(&mut self, n: usize) -> usize {
        let idx = self.triples.len();
        self.triples.resize_with(idx + n, Default::default);
        self.adjust.resize_with(idx + n, |_| Default::default());
        idx
    }

    pub(crate) fn write(&mut self, idx: usize, triples: &[Triple], adjust: &BitSlice) {
        self.triples[idx..idx + triples.len()].copy_from_slice(triples);
        self.adjust[idx..idx + triples.len()].copy_from_bitslice(adjust);
    }

    /// Returns `true` if there are gates to check.
    #[inline]
    pub(crate) fn wants_check(&self) -> bool {
        !self.triples.is_empty()
    }

    /// Executes the prover check, returning `U` and `V` defined in Figure 5,
    /// Step 7.b.
    pub(crate) fn check_prover(
        &mut self,
        transcript: &mut Hasher,
        svole_choices: &[bool],
        svole_ev: &[Block],
    ) -> Result<UV> {
        // Returns the unreduced products for `u` and `v`. Reduction is linear,
        // so each segment reduces its accumulated sums once.
        #[inline]
        fn compute_terms(triple: Triple, chi: Block) -> ((Block, Block), (Block, Block)) {
            let Triple { x, y, z } = triple;

            let u = x.gfmul(y).clmul(chi);

            // (Note that the LSB of a MAC contains the authenticated bit).
            let a_10 = if x.lsb() { y } else { Block::ZERO };
            let a_11 = if y.lsb() { x } else { Block::ZERO };
            let v = (a_10 ^ a_11 ^ z).clmul(chi);

            (u, v)
        }

        let adjust_len = self.adjust.len();
        transcript.update(&self.adjust.as_raw_slice().as_bytes()[..adjust_len.div_ceil(8)]);

        let macs = mem::take(&mut self.triples);

        let seed = *transcript.finalize().as_bytes();
        let rng = ChaCha12Rng::from_seed(seed);

        let process_segment = |rng: &mut ChaCha12Rng, segment: &[Triple]| {
            use rand_chacha::rand_core::RngCore;

            let mut u_acc = (Block::ZERO, Block::ZERO);
            let mut v_acc = (Block::ZERO, Block::ZERO);
            let mut chi = Block::ZERO;

            for &triple in segment {
                rng.fill_bytes(chi.as_mut());

                let (u, v) = compute_terms(triple, chi);
                u_acc = (u_acc.0 ^ u.0, u_acc.1 ^ u.1);
                v_acc = (v_acc.0 ^ v.0, v_acc.1 ^ v.1);
            }
            (
                Block::reduce_gcm(u_acc.0, u_acc.1),
                Block::reduce_gcm(v_acc.0, v_acc.1),
            )
        };

        cfg_if! {
            if #[cfg(feature = "rayon")] {
                use rayon::prelude::*;

                let (mut u, mut v) = macs
                    .par_chunks(SEGMENT_SIZE)
                    .enumerate()
                    .map(
                        |(stream_id, segment)| {
                            let mut rng = rng.clone();
                            rng.set_stream(stream_id as u64);
                            process_segment(&mut rng, segment)
                        }
                    )
                    .reduce(
                        || (Block::ZERO, Block::ZERO),
                        |(u1, v1), (u2, v2)| (u1 ^ u2, v1 ^ v2),
                    );
            } else {
                let (mut u, mut v) = macs
                    .chunks(SEGMENT_SIZE)
                    .enumerate()
                    .map(|(stream_id, segment)| {
                        let mut rng = rng.clone();
                        rng.set_stream(stream_id as u64);
                        process_segment(&mut rng, segment)
                    })
                    .fold(
                        (Block::ZERO, Block::ZERO),
                        |(u1, v1), (u2, v2)| (u1 ^ u2, v1 ^ v2),
                    );
            }
        }

        let (a_0, a_1) = vole_receiver(
            svole_choices.try_into().map_err(|_| CheckError::SVole)?,
            svole_ev.try_into().map_err(|_| CheckError::SVole)?,
        );

        u ^= a_0;
        v ^= a_1;

        transcript.update(&u.to_bytes());
        transcript.update(&v.to_bytes());

        self.adjust.clear();

        Ok(UV { u, v })
    }

    /// Executes the verifier check, returning `W` defined in Figure 5, Step
    /// 7.c.
    pub(crate) fn check_verifier(
        &mut self,
        transcript: &mut Hasher,
        delta: &Block,
        svole_keys: &[Block],
        uv: UV,
    ) -> Result<()> {
        // Returns the unreduced product. Reduction is linear, so `x * y` and
        // `delta * z` share one reduction and each segment reduces its sum once.
        #[inline]
        fn compute_term(triple: Triple, chi: Block, delta: &Block) -> (Block, Block) {
            let Triple { x, y, z } = triple;
            let (xy_0, xy_1) = x.clmul(y);
            let (dz_0, dz_1) = delta.clmul(z);
            let b = Block::reduce_gcm(xy_0 ^ dz_0, xy_1 ^ dz_1);
            b.clmul(chi)
        }

        let adjust_len = self.adjust.len();
        transcript.update(&self.adjust.as_raw_slice().as_bytes()[..adjust_len.div_ceil(8)]);

        let keys = mem::take(&mut self.triples);

        let seed = *transcript.finalize().as_bytes();
        let rng = ChaCha12Rng::from_seed(seed);

        let process_segment = |rng: &mut ChaCha12Rng, segment: &[Triple]| {
            use rand_chacha::rand_core::RngCore;

            let mut w_acc = (Block::ZERO, Block::ZERO);
            let mut chi = Block::ZERO;

            for &triple in segment {
                rng.fill_bytes(chi.as_mut());

                let w = compute_term(triple, chi, delta);
                w_acc = (w_acc.0 ^ w.0, w_acc.1 ^ w.1);
            }

            Block::reduce_gcm(w_acc.0, w_acc.1)
        };

        cfg_if! {
            if #[cfg(feature = "rayon")] {
                use rayon::prelude::*;

                let mut w = keys
                    .par_chunks(SEGMENT_SIZE)
                    .enumerate()
                    .map(
                        |(stream_id, segment)| {
                            let mut rng = rng.clone();
                            rng.set_stream(stream_id as u64);
                            process_segment(&mut rng, segment)
                        }
                    )
                    .reduce(
                        || Block::ZERO,
                        |w1, w2| w1 ^ w2,
                    );
            } else {
                let mut w = keys
                    .chunks(SEGMENT_SIZE)
                    .enumerate()
                    .map(|(stream_id, segment)| {
                        let mut rng = rng.clone();
                        rng.set_stream(stream_id as u64);
                        process_segment(&mut rng, segment)
                    })
                    .fold(Block::ZERO, |w1, w2| w1 ^ w2);
            }
        }

        let b = vole_sender(svole_keys.try_into().map_err(|_| CheckError::SVole)?);

        w ^= b;

        let UV { u, v } = uv;
        transcript.update(&u.to_bytes());
        transcript.update(&v.to_bytes());

        self.adjust.clear();

        if w != u ^ delta.gfmul(v) {
            // Invalid! Call the police.
            return Err(CheckError::Invalid);
        }

        Ok(())
    }

    /// Returns the total number of triples that need to be checked.
    pub(crate) fn total(&self) -> usize {
        self.triples.len()
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CheckError {
    #[error("incorrect number of sVOLE instances provided")]
    SVole,
    #[error("invalid consistency check")]
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use rand_chacha::rand_core::RngCore;

    // The original upstream computation, reducing every product.
    fn reference(
        triples: &[Triple],
        seed: [u8; 32],
        delta: &Block,
    ) -> (Block, Block, Block) {
        let (mut u, mut v, mut w) = (Block::ZERO, Block::ZERO, Block::ZERO);
        for (stream_id, segment) in triples.chunks(SEGMENT_SIZE).enumerate() {
            let mut rng = ChaCha12Rng::from_seed(seed);
            rng.set_stream(stream_id as u64);
            let mut chi = Block::ZERO;
            for &Triple { x, y, z } in segment {
                rng.fill_bytes(chi.as_mut());
                u ^= x.gfmul(y).gfmul(chi);
                let a_10 = if x.lsb() { y } else { Block::ZERO };
                let a_11 = if y.lsb() { x } else { Block::ZERO };
                v ^= (a_10 ^ a_11 ^ z).gfmul(chi);
                w ^= (x.gfmul(y) ^ delta.gfmul(z)).gfmul(chi);
            }
        }
        (u, v, w)
    }

    #[test]
    fn lazy_reduction_matches_reference() {
        let mut rng = StdRng::seed_from_u64(20261008);
        for n in [1, 2, SEGMENT_SIZE - 1, SEGMENT_SIZE, SEGMENT_SIZE + 1, 3 * SEGMENT_SIZE + 17] {
            let triples: Vec<Triple> = (0..n)
                .map(|_| Triple {
                    x: Block::new(rng.random()),
                    y: Block::new(rng.random()),
                    z: Block::new(rng.random()),
                })
                .collect();
            let adjust: BitVec = (0..n).map(|_| rng.random::<bool>()).collect();
            let delta = Block::new(rng.random());
            let choices: Vec<bool> = (0..128).map(|_| rng.random()).collect();
            let ev: Vec<Block> = (0..128).map(|_| Block::new(rng.random())).collect();
            let keys: Vec<Block> = (0..128).map(|_| Block::new(rng.random())).collect();

            let fill = |check: &mut Check| {
                let idx = check.reserve(n);
                check.write(idx, &triples, &adjust);
            };

            let mut prover = Check::default();
            fill(&mut prover);
            let mut transcript = Hasher::new();
            transcript.update(b"lazy-reduction");
            let mut seed_transcript = transcript.clone();
            let UV { u, v } = prover.check_prover(&mut transcript, &choices, &ev).unwrap();

            seed_transcript
                .update(&adjust.as_raw_slice().as_bytes()[..n.div_ceil(8)]);
            let seed = *seed_transcript.finalize().as_bytes();
            let (ref_u, ref_v, ref_w) = reference(&triples, seed, &delta);
            let (a_0, a_1) = vole_receiver(
                choices.as_slice().try_into().unwrap(),
                ev.as_slice().try_into().unwrap(),
            );
            assert_eq!((u, v), (ref_u ^ a_0, ref_v ^ a_1), "prover n={n}");

            // The verifier accepts only if its lazily reduced W matches the
            // reference W; choose U accordingly.
            let b = vole_sender(keys.as_slice().try_into().unwrap());
            let mut verifier = Check::default();
            fill(&mut verifier);
            let mut transcript = Hasher::new();
            transcript.update(b"lazy-reduction");
            let v = Block::new(rng.random());
            let u = ref_w ^ b ^ delta.gfmul(v);
            verifier
                .check_verifier(&mut transcript, &delta, &keys, UV { u, v })
                .unwrap();
            let mut verifier = Check::default();
            fill(&mut verifier);
            let mut transcript = Hasher::new();
            transcript.update(b"lazy-reduction");
            assert!(
                verifier
                    .check_verifier(&mut transcript, &delta, &keys, UV { u: u ^ Block::ONE, v })
                    .is_err(),
                "verifier n={n}"
            );
        }
    }
}
