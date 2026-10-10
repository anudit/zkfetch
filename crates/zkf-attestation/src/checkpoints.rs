//! Signed Merkle root over JSON parser checkpoint commitments.
//!
//! The notary signs `Claim::Reveal { selector: "zkf/2/json-checkpoints/v1/
//! <spacing>/<count>", revealed_digest: root }`. A presentation carries only
//! the commitments it opens, each with an RFC 6962 audit path. Leaves bind
//! their index, so a commitment cannot be replayed at another position.
use crate::{Bytes, Claim};
use sha2::{Digest, Sha256};

pub const COMMITMENT_BYTES: usize = 32;
pub const SELECTOR_PREFIX: &str = "zkf/2/json-checkpoints/v1/";

fn leaf(index: usize, commitment: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(b"zkf/2/json-checkpoint");
    h.update((index as u32).to_le_bytes());
    h.update(commitment);
    h.finalize().into()
}
fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}
fn split(n: usize) -> usize {
    debug_assert!(n > 1);
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}
/// Leaves are 1-indexed checkpoints `first..first + leaves.len()`.
fn mth(first: usize, leaves: &[&[u8]]) -> [u8; 32] {
    match leaves.len() {
        0 => Sha256::digest(b"zkf/2/json-checkpoints/empty").into(),
        1 => leaf(first, leaves[0]),
        n => {
            let k = split(n);
            node(&mth(first, &leaves[..k]), &mth(first + k, &leaves[k..]))
        }
    }
}

/// Merkle root over commitments of checkpoints 1..=n.
pub fn root(commitments: &[[u8; COMMITMENT_BYTES]]) -> [u8; 32] {
    let leaves: Vec<&[u8]> = commitments.iter().map(|c| c.as_slice()).collect();
    mth(1, &leaves)
}

/// Audit path for checkpoint `index` (1-based), leaf to root.
pub fn path(commitments: &[[u8; COMMITMENT_BYTES]], index: usize) -> Vec<[u8; 32]> {
    fn go(first: usize, leaves: &[&[u8]], at: usize, out: &mut Vec<[u8; 32]>) {
        if leaves.len() <= 1 {
            return;
        }
        let k = split(leaves.len());
        if at < k {
            go(first, &leaves[..k], at, out);
            out.push(mth(first + k, &leaves[k..]));
        } else {
            go(first + k, &leaves[k..], at - k, out);
            out.push(mth(first, &leaves[..k]));
        }
    }
    assert!((1..=commitments.len()).contains(&index));
    let leaves: Vec<&[u8]> = commitments.iter().map(|c| c.as_slice()).collect();
    let mut out = Vec::new();
    go(1, &leaves, index - 1, &mut out);
    out
}

/// Verify an audit path for checkpoint `index` of `count` against `root`.
pub fn verify(
    root_hash: &[u8; 32],
    count: usize,
    index: usize,
    commitment: &[u8; COMMITMENT_BYTES],
    proof: &[[u8; 32]],
) -> bool {
    fn go(first: usize, n: usize, at: usize, hash: [u8; 32], proof: &[[u8; 32]]) -> Option<([u8; 32], usize)> {
        if n == 1 {
            return Some((hash, 0));
        }
        let k = split(n);
        let (sub, used) = if at < k {
            go(first, k, at, hash, proof)?
        } else {
            go(first + k, n - k, at - k, hash, proof)?
        };
        let sibling = proof.get(used)?;
        Some((if at < k { node(&sub, sibling) } else { node(sibling, &sub) }, used + 1))
    }
    if !(1..=count).contains(&index) {
        return false;
    }
    match go(1, count, index - 1, leaf(index, commitment), proof) {
        Some((computed, used)) => used == proof.len() && computed == *root_hash,
        None => false,
    }
}

pub fn claim(spacing: usize, commitments: &[[u8; COMMITMENT_BYTES]]) -> Claim {
    Claim::Reveal {
        selector: format!("{SELECTOR_PREFIX}{spacing}/{}", commitments.len()),
        revealed_digest: Bytes(root(commitments)),
    }
}

/// The signed (spacing, count, root), if the attestation carries checkpoints.
pub fn signed(claims: &[Claim]) -> Option<(usize, usize, [u8; 32])> {
    let mut found = claims.iter().filter_map(|c| match c {
        Claim::Reveal { selector, revealed_digest } => {
            let rest = selector.strip_prefix(SELECTOR_PREFIX)?;
            let (spacing, count) = rest.split_once('/')?;
            Some((spacing.parse().ok()?, count.parse().ok()?, revealed_digest.0))
        }
        _ => None,
    });
    let first = found.next()?;
    found.next().is_none().then_some(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audit_paths_verify_for_every_size_and_reject_substitutions() {
        for n in 1..=37usize {
            let commitments: Vec<[u8; 32]> = (0..n).map(|i| [i as u8 + 1; 32]).collect();
            let r = root(&commitments);
            for index in 1..=n {
                let p = path(&commitments, index);
                assert!(verify(&r, n, index, &commitments[index - 1], &p));
                if n > 1 {
                    let other = if index == 1 { 2 } else { index - 1 };
                    assert!(!verify(&r, n, other, &commitments[index - 1], &p));
                    let mut changed = commitments[index - 1];
                    changed[0] ^= 1;
                    assert!(!verify(&r, n, index, &changed, &p));
                }
                let mut long = p.clone();
                long.push([0; 32]);
                assert!(!verify(&r, n, index, &commitments[index - 1], &long));
            }
        }
        let commitments = vec![[3u8; 32]; 4];
        let claims = vec![claim(32, &commitments)];
        assert_eq!(signed(&claims), Some((32, 4, root(&commitments))));
        assert_eq!(signed(&[claim(32, &commitments), claim(32, &commitments)]), None);
    }
}
