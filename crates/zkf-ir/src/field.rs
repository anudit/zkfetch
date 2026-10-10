//! FAEST's polynomial basis, not the big-endian GHASH wire convention.
use core::ops::{BitXor, Mul};
use zeroize::Zeroize;

/// GF(2^128), reduced modulo z^128 + z^7 + z^2 + z + 1.
/// This scalar reference implementation is not a production proving backend.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Zeroize)]
pub struct Fe(pub u128);

impl Fe {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);
    /// FAEST v2 Appendix A.1, in little-endian polynomial order.
    pub const ALPHA: Self = Self(0x053d8555a9979a1ca13fe8ac5560ce0d);

    /// Scaling by a public circuit coefficient. Branches depend only on that
    /// coefficient; secret field multiplication continues to use fixed loops.
    pub fn scale_public(self, coefficient: Self) -> Self {
        match coefficient {
            Self::ZERO => Self::ZERO,
            Self::ONE => self,
            _ => self * coefficient,
        }
    }

    pub fn pow(self, mut exponent: u128) -> Self {
        let mut base = self;
        let mut out = Self::ONE;
        while exponent != 0 {
            if exponent & 1 != 0 {
                out = out * base;
            }
            base = base * base;
            exponent >>= 1;
        }
        out
    }

    /// Linear embedding of the AES field GF(2)[x]/(x^8+x^4+x^3+x+1).
    pub fn byte(value: u8) -> Self {
        static BASIS: std::sync::OnceLock<[Fe; 8]> = std::sync::OnceLock::new();
        let basis = BASIS.get_or_init(|| {
            let mut value = Self::ONE;
            std::array::from_fn(|_| {
                let out = value;
                value = value * Self::ALPHA;
                out
            })
        });
        let mut out = Self::ZERO;
        for (i, basis) in basis.iter().enumerate() {
            out = out ^ Self(basis.0 & 0u128.wrapping_sub(((value >> i) & 1) as u128));
        }
        out
    }
}

impl BitXor for Fe {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl Mul for Fe {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        use mpz_core::Block;
        Self(u128::from_le_bytes(
            Block::new(self.0.to_le_bytes())
                .gfmul(Block::new(rhs.0.to_le_bytes()))
                .to_bytes(),
        ))
    }
}

pub fn byte_mul(mut a: u8, mut b: u8) -> u8 {
    let mut out = 0;
    for _ in 0..8 {
        out ^= a & 0u8.wrapping_sub(b & 1);
        a = (a << 1) ^ (0x1b & 0u8.wrapping_sub(a >> 7));
        b >>= 1;
    }
    out
}

pub fn byte_inverse(x: u8) -> u8 {
    let mut out = 1;
    let mut base = x;
    let mut exponent = 254;
    while exponent != 0 {
        if exponent & 1 != 0 {
            out = byte_mul(out, base);
        }
        base = byte_mul(base, base);
        exponent >>= 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accelerated_product_matches_bit_serial_reference() {
        for x in [0, 1, 7, u128::MAX, 1 << 127, 0x123456789abcdef] {
            for y in [0, 1, 17, u128::MAX, 1 << 126, 0xfedcba987654321] {
                let mut a = x;
                let mut b = y;
                let mut out = 0;
                for _ in 0..128 {
                    out ^= a & 0u128.wrapping_sub(b & 1);
                    let carry = a >> 127;
                    a = (a << 1) ^ (0x87 & 0u128.wrapping_sub(carry));
                    b >>= 1;
                }
                assert_eq!(Fe(x) * Fe(y), Fe(out));
            }
        }
    }
    #[test]
    fn embedding_preserves_all_byte_products() {
        let table: Vec<_> = (0..=255).map(Fe::byte).collect();
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(
                    table[a as usize] * table[b as usize],
                    table[byte_mul(a, b) as usize]
                );
                assert_eq!(
                    table[a as usize] ^ table[b as usize],
                    table[(a ^ b) as usize]
                );
            }
        }
    }

    #[test]
    fn zero_safe_inverse_is_unique() {
        for x in 0..=255u8 {
            for y in 0..=255u8 {
                let valid = byte_mul(byte_mul(x, x), y) == x && byte_mul(x, byte_mul(y, y)) == y;
                assert_eq!(valid, y == byte_inverse(x), "x={x}, y={y}");
            }
        }
    }
}
