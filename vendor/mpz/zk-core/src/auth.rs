//! Full-entropy authentication for the strict zkfetch VM.
//!
//! Unlike garbling's pointer-bit MAC, the truth value is stored separately
//! from the tag. No operation truncates a correlation or authentication tag.
//! The lane count is a type parameter; strict sessions use two independent
//! RCOT streams. This module supplies the algebra, not an OT security proof.
pub mod check;
pub mod circuit;
pub mod store;
use mpz_core::Block;
use rand_chacha::rand_core::{CryptoRng, RngCore};

/// ZK correlation. Deliberately has no conversion from garbling's `Delta`.
#[derive(Clone, Copy, PartialEq)]
pub struct ZkDelta(Block);
impl std::fmt::Debug for ZkDelta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ZkDelta([redacted])")
    }
}
impl ZkDelta {
    pub fn new(value: Block) -> Self {
        Self(value)
    }
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut bytes = [0; 16];
        rng.fill_bytes(&mut bytes);
        Self(Block::from(bytes))
    }
    pub fn as_block(&self) -> &Block {
        &self.0
    }
}

/// Tags and their single shared witness bit. Tags do not encode that bit.
#[derive(Clone, Copy, PartialEq)]
pub struct ZkMac<const LANES: usize> {
    tags: [Block; LANES],
    value: bool,
}
#[derive(Clone, Copy, PartialEq)]
pub struct ZkKey<const LANES: usize>([Block; LANES]);

impl<const L: usize> std::fmt::Debug for ZkMac<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ZkMac([redacted])")
    }
}
impl<const L: usize> std::fmt::Debug for ZkKey<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ZkKey([redacted])")
    }
}

impl<const L: usize> ZkMac<L> {
    /// Derandomize independent correlations onto ONE common witness bit.
    pub fn from_rcot(value: bool, choices: [bool; L], tags: [Block; L]) -> (Self, [bool; L]) {
        assert!(L > 0);
        (Self { tags, value }, choices.map(|r| r ^ value))
    }
    pub(crate) fn set_value(&mut self, value: bool) {
        self.value = value;
    }
    pub fn value(&self) -> bool {
        self.value
    }
    pub fn tags(&self) -> &[Block; L] {
        &self.tags
    }
    pub fn xor(self, rhs: Self) -> Self {
        Self {
            tags: std::array::from_fn(|i| self.tags[i] ^ rhs.tags[i]),
            value: self.value ^ rhs.value,
        }
    }
    pub fn invert(self) -> Self {
        Self {
            value: !self.value,
            ..self
        }
    }
    /// Allocate a fresh output correlation for each AND; never reuse an input tag.
    pub fn and(self, rhs: Self, choices: [bool; L], tags: [Block; L]) -> (Self, [bool; L]) {
        Self::from_rcot(self.value & rhs.value, choices, tags)
    }
    pub fn public(value: bool) -> Self {
        Self {
            tags: [Block::ZERO; L],
            value,
        }
    }
}
impl<const L: usize> ZkKey<L> {
    pub fn from_rcot(keys: [Block; L], corrections: [bool; L], deltas: &[ZkDelta; L]) -> Self {
        assert!(L > 0);
        Self(std::array::from_fn(|i| {
            keys[i]
                ^ if corrections[i] {
                    *deltas[i].as_block()
                } else {
                    Block::ZERO
                }
        }))
    }
    pub fn tags(&self) -> &[Block; L] {
        &self.0
    }
    pub fn xor(self, rhs: Self) -> Self {
        Self(std::array::from_fn(|i| self.0[i] ^ rhs.0[i]))
    }
    pub fn invert(self, deltas: &[ZkDelta; L]) -> Self {
        Self(std::array::from_fn(|i| self.0[i] ^ *deltas[i].as_block()))
    }
    pub fn public(value: bool, deltas: &[ZkDelta; L]) -> Self {
        Self(std::array::from_fn(|i| {
            if value {
                *deltas[i].as_block()
            } else {
                Block::ZERO
            }
        }))
    }
    pub fn authenticates(&self, mac: &ZkMac<L>, deltas: &[ZkDelta; L]) -> bool {
        (0..L).all(|i| {
            mac.tags[i]
                == self.0[i]
                    ^ if mac.value {
                        *deltas[i].as_block()
                    } else {
                        Block::ZERO
                    }
        })
    }
}

/// Quadratic QuickSilver terms for an AND relation, with explicit witness bits.
/// Verifier identity: w = u + delta*v for a valid multiplication.
pub fn multiplication_terms<const L: usize>(
    x: ZkMac<L>,
    y: ZkMac<L>,
    z: ZkMac<L>,
) -> ([Block; L], [Block; L]) {
    let u = std::array::from_fn(|i| x.tags[i].gfmul(y.tags[i]));
    let v = std::array::from_fn(|i| {
        z.tags[i]
            ^ if x.value { y.tags[i] } else { Block::ZERO }
            ^ if y.value { x.tags[i] } else { Block::ZERO }
    });
    (u, v)
}
pub fn multiplication_keys<const L: usize>(
    x: ZkKey<L>,
    y: ZkKey<L>,
    z: ZkKey<L>,
    deltas: &[ZkDelta; L],
) -> [Block; L] {
    std::array::from_fn(|i| x.0[i].gfmul(y.0[i]) ^ deltas[i].as_block().gfmul(z.0[i]))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn block(n: u128) -> Block {
        Block::from(n.to_le_bytes())
    }
    fn correlated(
        value: bool,
        keys: [Block; 2],
        choices: [bool; 2],
        deltas: &[ZkDelta; 2],
    ) -> (ZkMac<2>, ZkKey<2>) {
        let tags = std::array::from_fn(|i| {
            keys[i]
                ^ if choices[i] {
                    *deltas[i].as_block()
                } else {
                    Block::ZERO
                }
        });
        let (mac, corrections) = ZkMac::from_rcot(value, choices, tags);
        (mac, ZkKey::from_rcot(keys, corrections, deltas))
    }
    #[test]
    fn zk_delta_preserves_the_entire_support() {
        for n in [0, 1, 2, 3, u128::MAX - 1, u128::MAX] {
            assert_eq!(
                ZkDelta::new(block(n)).as_block().to_bytes(),
                n.to_le_bytes()
            );
        }
    }
    #[test]
    fn full_entropy_lanes_preserve_boolean_arithmetic() {
        for d1 in 0..4 {
            for d2 in 4..8 {
                for a in [false, true] {
                    for b in [false, true] {
                        let deltas = [ZkDelta::new(block(d1)), ZkDelta::new(block(d2))];
                        let (x, kx) = correlated(a, [block(17), block(38)], [true, false], &deltas);
                        let (y, ky) = correlated(b, [block(72), block(91)], [false, true], &deltas);
                        let (z, kz) =
                            correlated(a & b, [block(101), block(122)], [true, false], &deltas);
                        assert!(kx.authenticates(&x, &deltas));
                        assert!(kx.xor(ky).authenticates(&x.xor(y), &deltas));
                        assert!(kx.invert(&deltas).authenticates(&x.invert(), &deltas));
                        assert!(
                            ZkKey::public(a, &deltas).authenticates(&ZkMac::public(a), &deltas)
                        );
                        let (u, v) = multiplication_terms(x, y, z);
                        let w = multiplication_keys(kx, ky, kz, &deltas);
                        for i in 0..2 {
                            assert_eq!(w[i], u[i] ^ deltas[i].as_block().gfmul(v[i]));
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn guessing_one_lane_does_not_forge_the_other() {
        let deltas = [ZkDelta::new(block(14)), ZkDelta::new(block(27))];
        let (mut mac, key) = correlated(false, [block(31), block(42)], [false, true], &deltas);
        // Flip the witness bit and compensate using only the correctly guessed first delta.
        mac.value = true;
        mac.tags[0] ^= *deltas[0].as_block();
        assert_eq!(mac.tags[0], key.0[0] ^ *deltas[0].as_block());
        assert!(!key.authenticates(&mac, &deltas));
    }
}
