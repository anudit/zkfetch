//! Dual-lane memory authentication. Openings bind the shared bit, address and lane.
mod prover;
mod verifier;
use super::{ZkDelta, ZkKey, ZkMac};
use crate::view::FlushView;
use blake3::{Hash, Hasher};
use mpz_core::bitvec::{BitSlice, BitVec};
use mpz_memory_core::{
    Slice,
    store::{Store, StoreError},
};
pub use prover::{ProverStore, ProverStoreError};
use serde::{Deserialize, Serialize};
pub use verifier::{VerifierStore, VerifierStoreError};
type RangeSet = rangeset::set::RangeSet<usize>;
type Mac = ZkMac<2>;
type Key = ZkKey<2>;
type Delta = ZkDelta;

#[derive(Debug, thiserror::Error)]
enum MacStoreError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("authentication length mismatch")]
    Length,
}
#[derive(Debug, thiserror::Error)]
enum KeyStoreError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("authentication length mismatch")]
    Length,
    #[error("invalid dual-lane opening")]
    Opening,
}
impl Default for Mac {
    fn default() -> Self {
        Self::public(false)
    }
}
impl Default for Key {
    fn default() -> Self {
        Self([mpz_core::Block::ZERO; 2])
    }
}
fn opening_hasher(lane: usize, ranges: &RangeSet) -> Hasher {
    let mut h = Hasher::new();
    h.update(b"zkf/strict/dual-lane/memory-opening/v1");
    h.update(&(lane as u64).to_le_bytes());
    h.update(&(ranges.len() as u64).to_le_bytes());
    for range in ranges.iter() {
        h.update(&(range.start as u64).to_le_bytes());
        h.update(&(range.end as u64).to_le_bytes());
    }
    h
}
#[derive(Debug, Default)]
struct MacStore(Store<Mac>);
impl MacStore {
    fn alloc(&mut self, n: usize) -> Slice {
        self.0.alloc(n)
    }
    fn is_set(&self, s: Slice) -> bool {
        self.0.is_set(s)
    }
    fn try_get(&self, s: Slice) -> Result<&[Mac], MacStoreError> {
        Ok(self.0.try_get(s)?)
    }
    fn try_set(&mut self, s: Slice, data: &[Mac]) -> Result<(), MacStoreError> {
        if s.len() != data.len() {
            return Err(MacStoreError::Length);
        }
        Ok(self.0.try_set(s, data)?)
    }
    fn try_set_public(&mut self, s: Slice, bits: &BitSlice) -> Result<(), MacStoreError> {
        self.try_set(s, &bits.iter().map(|b| Mac::public(*b)).collect::<Vec<_>>())
    }
    fn adjust(&mut self, s: Slice, bits: &BitSlice) -> Result<(), MacStoreError> {
        if s.len() != bits.len() {
            return Err(MacStoreError::Length);
        }
        for (mac, bit) in self.0.try_get_slice_mut(s)?.iter_mut().zip(bits) {
            mac.set_value(*bit);
        }
        Ok(())
    }
    fn prove(&self, ranges: &RangeSet) -> Result<(BitVec, [Hash; 2]), MacStoreError> {
        let mut hashers = std::array::from_fn(|lane| opening_hasher(lane, ranges));
        let mut bits = BitVec::with_capacity(ranges.len());
        for range in ranges.iter() {
            for mac in self.try_get(Slice::from_range_unchecked(range))? {
                bits.push(mac.value());
                for lane in 0..2 {
                    hashers[lane].update(&[u8::from(mac.value())]);
                    hashers[lane].update(&mac.tags()[lane].to_bytes());
                }
            }
        }
        Ok((bits, hashers.map(|h| h.finalize())))
    }
}
#[derive(Debug)]
struct KeyStore {
    store: Store<Key>,
    deltas: [Delta; 2],
}
impl KeyStore {
    fn new(deltas: [Delta; 2]) -> Self {
        Self {
            store: Store::new(),
            deltas,
        }
    }
    fn deltas(&self) -> &[Delta; 2] {
        &self.deltas
    }
    fn alloc(&mut self, n: usize) -> Slice {
        self.store.alloc(n)
    }
    fn try_get(&self, s: Slice) -> Result<&[Key], KeyStoreError> {
        Ok(self.store.try_get(s)?)
    }
    fn try_set(&mut self, s: Slice, data: &[Key]) -> Result<(), KeyStoreError> {
        if s.len() != data.len() {
            return Err(KeyStoreError::Length);
        }
        Ok(self.store.try_set(s, data)?)
    }
    fn try_set_public(&mut self, s: Slice, bits: &BitSlice) -> Result<(), KeyStoreError> {
        self.try_set(
            s,
            &bits
                .iter()
                .map(|b| Key::public(*b, &self.deltas))
                .collect::<Vec<_>>(),
        )
    }
    fn adjust(&mut self, s: Slice, bits: [&BitSlice; 2]) -> Result<(), KeyStoreError> {
        if bits.iter().any(|b| b.len() != s.len()) {
            return Err(KeyStoreError::Length);
        }
        for (i, key) in self.store.try_get_slice_mut(s)?.iter_mut().enumerate() {
            *key = Key::from_rcot(*key.tags(), [bits[0][i], bits[1][i]], &self.deltas);
        }
        Ok(())
    }
    fn verify(
        &self,
        ranges: &RangeSet,
        bits: &BitSlice,
        proof: [Hash; 2],
    ) -> Result<(), KeyStoreError> {
        if bits.len() != ranges.len() {
            return Err(KeyStoreError::Length);
        }
        let mut hashers = std::array::from_fn(|lane| opening_hasher(lane, ranges));
        let mut i = 0;
        for range in ranges.iter() {
            for key in self.try_get(Slice::from_range_unchecked(range))? {
                for lane in 0..2 {
                    let tag = key.tags()[lane]
                        ^ if bits[i] {
                            *self.deltas[lane].as_block()
                        } else {
                            mpz_core::Block::ZERO
                        };
                    hashers[lane].update(&[u8::from(bits[i])]);
                    hashers[lane].update(&tag.to_bytes());
                }
                i += 1;
            }
        }
        if hashers.map(|h| h.finalize()) != proof {
            return Err(KeyStoreError::Opening);
        }
        Ok(())
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(try_from = "UncheckedFlush")]
pub struct ProverFlush {
    view: FlushView,
    adjust: [BitVec; 2],
    mac_proof: Option<(BitVec, [Hash; 2])>,
}
#[derive(Debug, Deserialize)]
struct UncheckedFlush {
    view: FlushView,
    adjust: [BitVec; 2],
    mac_proof: Option<(BitVec, [Hash; 2])>,
}
impl TryFrom<UncheckedFlush> for ProverFlush {
    type Error = String;
    fn try_from(f: UncheckedFlush) -> Result<Self, String> {
        if f.adjust.iter().any(|b| b.len() != f.view.commit.len()) {
            return Err("invalid dual-lane adjustment length".into());
        }
        if f.mac_proof.as_ref().map_or(0, |p| p.0.len()) != f.view.prove.len() {
            return Err("invalid opening length".into());
        }
        Ok(Self {
            view: f.view,
            adjust: f.adjust,
            mac_proof: f.mac_proof,
        })
    }
}
#[cfg(test)]
mod tests {
    use blake3::Hasher;
    use mpz_core::Block;
    use mpz_memory_core::{Array, MemoryExt, ViewExt, binary::U8};
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;

    #[test]
    fn shared_opening_round_trip() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = [Delta::random(&mut rng), Delta::random(&mut rng)];
        let mut prover_transcript = Hasher::default();
        let mut verifier_transcript = Hasher::default();

        let mut verifier = VerifierStore::new(delta);
        let mut prover = ProverStore::new();

        let raw_keys: Vec<[Block; 2]> = (0..128)
            .map(|_| [Block::random(&mut rng), Block::random(&mut rng)])
            .collect();
        let masks: Vec<[bool; 2]> = (0..128).map(|i| [i % 2 == 0, i % 3 == 0]).collect();
        let keys: Vec<_> = raw_keys
            .iter()
            .map(|k| Key::from_rcot(*k, [false; 2], &delta))
            .collect();
        let macs: Vec<_> = raw_keys
            .iter()
            .zip(&masks)
            .map(|(k, c)| {
                let tags = std::array::from_fn(|lane| {
                    k[lane]
                        ^ if c[lane] {
                            *delta[lane].as_block()
                        } else {
                            Block::ZERO
                        }
                });
                Mac::from_rcot(false, *c, tags).0
            })
            .collect();

        let a_v: Array<U8, 16> = verifier.alloc().unwrap();
        let b_v: Array<U8, 16> = verifier.alloc().unwrap();

        let a_p: Array<U8, 16> = prover.alloc().unwrap();
        let b_p: Array<U8, 16> = prover.alloc().unwrap();

        verifier.mark_public(a_v).unwrap();
        verifier.mark_blind(b_v).unwrap();
        verifier.assign(a_v, [42u8; 16]).unwrap();
        verifier.commit(a_v).unwrap();
        verifier.commit(b_v).unwrap();

        prover.mark_public(a_p).unwrap();
        prover.mark_private(b_p).unwrap();
        prover.assign(a_p, [42u8; 16]).unwrap();
        prover.assign(b_p, [69u8; 16]).unwrap();
        prover.commit(a_p).unwrap();
        prover.commit(b_p).unwrap();

        let mut b_v = verifier.decode(b_v).unwrap();
        std::mem::drop(prover.decode(b_p).unwrap());

        assert!(verifier.wants_keys());
        assert!(prover.wants_macs());

        assert_eq!(verifier.key_count(), prover.mac_count());

        verifier.set_keys(&keys).unwrap();
        prover.set_macs(&masks, &macs).unwrap();

        // Commit
        assert!(verifier.wants_flush());
        assert!(prover.wants_flush());

        verifier.mark_flush_pending().unwrap();
        let flush_p = prover.send_flush(&mut prover_transcript).unwrap();

        verifier
            .receive_flush(flush_p, &mut verifier_transcript)
            .unwrap();
        prover.complete_flush().unwrap();

        // Prove
        assert!(verifier.wants_flush());
        assert!(prover.wants_flush());

        verifier.mark_flush_pending().unwrap();
        let flush_p = prover.send_flush(&mut prover_transcript).unwrap();

        verifier
            .receive_flush(flush_p, &mut verifier_transcript)
            .unwrap();
        prover.complete_flush().unwrap();

        let b_v = b_v.try_recv().unwrap().unwrap();

        assert_eq!(b_v, [69u8; 16]);
    }
    #[test]
    fn openings_reject_changed_lanes_bits_and_addresses() {
        let deltas = [
            Delta::new(Block::new([42; 16])),
            Delta::new(Block::new([97; 16])),
        ];
        let mut p = MacStore::default();
        let mut v = KeyStore::new(deltas);
        let ps = p.alloc(2);
        let vs = v.alloc(2);
        assert_eq!(ps, vs);
        let values = [true, false];
        let keys = [
            [Block::new([11; 16]), Block::new([12; 16])],
            [Block::new([13; 16]), Block::new([14; 16])],
        ];
        let macs: Vec<_> = keys
            .iter()
            .zip(values)
            .map(|(k, value)| {
                let tags = std::array::from_fn(|lane| {
                    k[lane]
                        ^ if value {
                            *deltas[lane].as_block()
                        } else {
                            Block::ZERO
                        }
                });
                Mac::from_rcot(value, [value; 2], tags).0
            })
            .collect();
        p.try_set(ps, &macs).unwrap();
        v.try_set(vs, &keys.map(|k| Key::from_rcot(k, [false; 2], &deltas)))
            .unwrap();
        let ranges = RangeSet::from(ps.to_range());
        let (bits, proof) = p.prove(&ranges).unwrap();
        v.verify(&ranges, &bits, proof).unwrap();
        let mut corrupted = proof;
        corrupted[1] = blake3::hash(b"wrong second lane");
        assert!(v.verify(&ranges, &bits, corrupted).is_err());
        let mut changed = bits.clone();
        changed.set(0, false);
        assert!(v.verify(&ranges, &changed, proof).is_err());
        let other = RangeSet::from(1..2);
        assert!(v.verify(&other, &bits[1..], proof).is_err());
        assert!(
            p.try_set(ps, &macs).is_err(),
            "initialization must not overwrite a live authentication"
        );
        assert!(v.adjust(vs, [&bits[..1], &bits]).is_err());
    }
}
