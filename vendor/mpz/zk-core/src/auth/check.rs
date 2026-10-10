//! Joint-transcript, independently weighted multiplication checks.
//! This kernel is deliberately separate from the legacy pointer-bit check.
use super::{ZkDelta, ZkKey, ZkMac, multiplication_keys, multiplication_terms};
use blake3::Hasher;
use mpz_core::Block;
use rand_chacha::{
    ChaCha12Rng,
    rand_core::{RngCore, SeedableRng},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckProof {
    pub u: Vec<Block>,
    pub v: Vec<Block>,
}
#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    #[error("incorrect authentication lane or mask count")]
    Shape,
    #[error("authentication lane {0} rejected the consistency check")]
    Invalid(usize),
}

fn weights(transcript: &Hasher, lane: usize) -> ChaCha12Rng {
    let mut t = transcript.clone();
    t.update(b"zkfetch/strict-quicksilver/independent-weight-lane/v1\0");
    t.update(&(lane as u64).to_le_bytes());
    ChaCha12Rng::from_seed(*t.finalize().as_bytes())
}
fn absorb(t: &mut Hasher, p: &CheckProof) {
    t.update(b"zkfetch/strict-quicksilver/check/v1\0");
    t.update(&(p.u.len() as u64).to_le_bytes());
    for i in 0..p.u.len() {
        t.update(p.u[i].as_bytes());
        t.update(p.v[i].as_bytes());
    }
}

/// Mask every lane with 128 fresh correlations. Reusing these masks reveals
/// linear combinations of private witness bits and is forbidden.
pub fn prove<const L: usize>(
    transcript: &mut Hasher,
    triples: &[(ZkMac<L>, ZkMac<L>, ZkMac<L>)],
    mask_choices: &[[bool; 128]; L],
    mask_tags: &[[Block; 128]; L],
) -> Result<CheckProof, CheckError> {
    if L == 0 {
        return Err(CheckError::Shape);
    }
    let mut p = CheckProof {
        u: vec![Block::ZERO; L],
        v: vec![Block::ZERO; L],
    };
    transcript.update(b"zkf/strict/multiplication-count/v1");
    transcript.update(&(triples.len() as u64).to_le_bytes());
    let mut rngs: [ChaCha12Rng; L] = std::array::from_fn(|lane| weights(transcript, lane));
    for &(x, y, z) in triples {
        let (u, v) = multiplication_terms(x, y, z);
        for lane in 0..L {
            let mut chi = [0; 16];
            rngs[lane].fill_bytes(&mut chi);
            let chi = Block::from(chi);
            p.u[lane] ^= u[lane].gfmul(chi);
            p.v[lane] ^= v[lane].gfmul(chi);
        }
    }
    for lane in 0..L {
        let (u, v) = crate::vole::vole_receiver(&mask_choices[lane], &mask_tags[lane]);
        p.u[lane] ^= u;
        p.v[lane] ^= v;
    }
    absorb(transcript, &p);
    Ok(p)
}

pub fn verify<const L: usize>(
    transcript: &mut Hasher,
    triples: &[(ZkKey<L>, ZkKey<L>, ZkKey<L>)],
    deltas: &[ZkDelta; L],
    mask_keys: &[[Block; 128]; L],
    p: &CheckProof,
) -> Result<(), CheckError> {
    if L == 0 || p.u.len() != L || p.v.len() != L {
        return Err(CheckError::Shape);
    }
    transcript.update(b"zkf/strict/multiplication-count/v1");
    transcript.update(&(triples.len() as u64).to_le_bytes());
    let mut rngs: [ChaCha12Rng; L] = std::array::from_fn(|lane| weights(transcript, lane));
    let mut w = [Block::ZERO; L];
    for &(x, y, z) in triples {
        let values = multiplication_keys(x, y, z, deltas);
        for lane in 0..L {
            let mut chi = [0; 16];
            rngs[lane].fill_bytes(&mut chi);
            w[lane] ^= values[lane].gfmul(Block::from(chi));
        }
    }
    let mut failed = None;
    for lane in 0..L {
        w[lane] ^= crate::vole::vole_sender(&mask_keys[lane]);
        if w[lane] != p.u[lane] ^ deltas[lane].as_block().gfmul(p.v[lane]) {
            failed = Some(lane);
        }
    }
    if let Some(lane) = failed {
        return Err(CheckError::Invalid(lane));
    }
    absorb(transcript, p);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn block(v: u128) -> Block {
        Block::from(v.to_le_bytes())
    }
    #[test]
    fn dual_checks_bind_both_lanes_and_the_joint_transcript() {
        let deltas = [ZkDelta::new(block(18)), ZkDelta::new(block(37))];
        let make = |value, n| {
            let keys = [block(n), block(n + 1)];
            let choices = [true, false];
            let tags = std::array::from_fn(|i| {
                keys[i]
                    ^ if choices[i] {
                        *deltas[i].as_block()
                    } else {
                        Block::ZERO
                    }
            });
            let (mac, adjust) = ZkMac::from_rcot(value, choices, tags);
            (mac, ZkKey::from_rcot(keys, adjust, &deltas))
        };
        let (x, kx) = make(true, 100);
        let (y, ky) = make(true, 200);
        let (z, kz) = make(true, 300);
        let choices = std::array::from_fn(|lane| std::array::from_fn(|i| (lane + i) % 3 == 0));
        let keys = std::array::from_fn(|lane| {
            std::array::from_fn(|i| block((400 + 128 * lane + i) as u128))
        });
        let tags = std::array::from_fn(|lane| {
            std::array::from_fn(|i| {
                keys[lane][i]
                    ^ if choices[lane][i] {
                        *deltas[lane].as_block()
                    } else {
                        Block::ZERO
                    }
            })
        });
        let mut t = Hasher::new();
        t.update(b"joint statement and both correction flights");
        let p = prove(&mut t.clone(), &[(x, y, z)], &choices, &tags).unwrap();
        verify(&mut t.clone(), &[(kx, ky, kz)], &deltas, &keys, &p).unwrap();
        // A forged message can be made to pass lane 0 by guessing delta 0;
        // accepting that lane alone must never accept the complete check.
        let mut forged = p.clone();
        forged.u[1] ^= block(1);
        assert!(matches!(
            verify(&mut t.clone(), &[(kx, ky, kz)], &deltas, &keys, &forged),
            Err(CheckError::Invalid(1))
        ));
        let mut truncated = p.clone();
        truncated.v.pop();
        assert!(matches!(
            verify(&mut t.clone(), &[(kx, ky, kz)], &deltas, &keys, &truncated),
            Err(CheckError::Shape)
        ));
        let mut changed = t.clone();
        changed.update(b"changed second lane corrections");
        assert!(verify(&mut changed, &[(kx, ky, kz)], &deltas, &keys, &p).is_err());
    }
}
