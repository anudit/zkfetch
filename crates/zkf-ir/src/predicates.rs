//! Boolean scalar gadgets, with overflow checked instead of wrapping.
use crate::{Byte, Circuit, Term, Wire, field::Fe};

#[derive(Clone, Copy)]
pub struct U64([Wire; 64]);

#[derive(Clone, Copy, Debug)]
pub enum Comparison {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl U64 {
    pub fn public(c: &mut Circuit, value: u64) -> Self {
        Self(std::array::from_fn(|i| c.public_bit((value >> i) & 1 != 0)))
    }
    pub fn from_le_bytes(bytes: [Byte; 8]) -> Self {
        Self(std::array::from_fn(|i| bytes[i / 8].0[i % 8]))
    }
    pub fn compare(self, c: &mut Circuit, rhs: Self, comparison: Comparison) -> Wire {
        let mut lt = c.public_bit(false);
        let mut equal = c.public_bit(true);
        // The last (most significant) differing bit determines comparison.
        for i in 0..64 {
            let a_not = c.not_bit(self.0[i]);
            let a_lt_b = c.and_bit(a_not, rhs.0[i]);
            let difference = c.xor_bit(self.0[i], rhs.0[i]);
            let bit_equal = c.not_bit(difference);
            let previous_lt = c.and_bit(bit_equal, lt);
            lt = c.xor_bit(a_lt_b, previous_lt);
            equal = c.and_bit(equal, bit_equal);
        }
        match comparison {
            Comparison::Eq => equal,
            Comparison::Ne => c.not_bit(equal),
            Comparison::Lt => lt,
            Comparison::Le => c.xor_bit(lt, equal),
            Comparison::Gt => {
                let le = c.xor_bit(lt, equal);
                c.not_bit(le)
            }
            Comparison::Ge => c.not_bit(lt),
        }
    }
    /// Restrict a relation to true, so a claim cannot simply report a computed
    /// result without proving that it is the result requested by its statement.
    pub fn assert_compare(self, c: &mut Circuit, rhs: Self, comparison: Comparison) {
        let result = self.compare(c, rhs, comparison);
        c.assert_zero(vec![Term::Linear(Fe::ONE, result), Term::Constant(Fe::ONE)]);
    }
    fn shift_checked(self, c: &mut Circuit, shift: usize) -> Self {
        for bit in &self.0[64 - shift..] {
            c.assert_zero(vec![Term::Linear(Fe::ONE, *bit)]);
        }
        let zero = c.public_bit(false);
        Self(std::array::from_fn(|i| {
            if i < shift { zero } else { self.0[i - shift] }
        }))
    }
    fn add_checked(self, c: &mut Circuit, rhs: Self) -> Self {
        let mut carry = c.public_bit(false);
        let output = std::array::from_fn(|i| {
            let pair = c.xor_bit(self.0[i], rhs.0[i]);
            let sum = c.xor_bit(pair, carry);
            let ab = c.and_bit(self.0[i], rhs.0[i]);
            let pc = c.and_bit(pair, carry);
            carry = c.xor_bit(ab, pc);
            sum
        });
        c.assert_zero(vec![Term::Linear(Fe::ONE, carry)]);
        Self(output)
    }
}

/// Parse a public-length byte window as an unsigned decimal u64. Every byte
/// must be ASCII 0..9. JSON grammar/canonical-number checks belong to its lexer.
pub fn ascii_u64(c: &mut Circuit, bytes: &[Byte]) -> Result<U64, DecimalError> {
    if bytes.is_empty() || bytes.len() > 20 {
        return Err(DecimalError);
    }
    let mut acc = U64::public(c, 0);
    let zero = c.public_bit(false);
    for byte in bytes {
        // ASCII digit high nibble is 0x3; low nibble must be <= 9.
        for i in 4..8 {
            c.assert_zero(vec![
                Term::Linear(Fe::ONE, byte.0[i]),
                Term::Constant(Fe(((0x30 >> i) & 1) as u128)),
            ]);
        }
        let digit = U64(std::array::from_fn(
            |i| if i < 4 { byte.0[i] } else { zero },
        ));
        let nine = U64::public(c, 9);
        digit.assert_compare(c, nine, Comparison::Le);
        let x8 = acc.shift_checked(c, 3);
        let x2 = acc.shift_checked(c, 1);
        let x10 = x8.add_checked(c, x2);
        acc = x10.add_checked(c, digit);
    }
    Ok(acc)
}

pub fn assert_bytes_equal(c: &mut Circuit, a: &[Byte], b: &[Byte]) -> Result<(), EqualityError> {
    if a.len() != b.len() {
        return Err(EqualityError);
    }
    for (&a, &b) in a.iter().zip(b) {
        let (a, b) = (c.lift(a), c.lift(b));
        c.assert_equal(a, b);
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
#[error("decimal window must contain 1 to 20 bytes")]
pub struct DecimalError;
#[derive(Debug, thiserror::Error)]
#[error("byte equality length mismatch")]
pub struct EqualityError;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::byte_inputs;
    #[test]
    fn comparators_cover_unsigned_boundaries() {
        for a in [0, 1, 7, u64::MAX / 2, u64::MAX] {
            for b in [0, 1, 7, u64::MAX / 2, u64::MAX] {
                for (comparison, expected) in [
                    (Comparison::Eq, a == b),
                    (Comparison::Ne, a != b),
                    (Comparison::Lt, a < b),
                    (Comparison::Le, a <= b),
                    (Comparison::Gt, a > b),
                    (Comparison::Ge, a >= b),
                ] {
                    let mut c = Circuit::default();
                    let refs = std::array::from_fn(|_| c.commit_byte());
                    let scalar_a = a;
                    let a = U64::from_le_bytes(refs);
                    let b = U64::public(&mut c, b);
                    let output = a.compare(&mut c, b, comparison);
                    let witness = c.eval(&byte_inputs(&scalar_a.to_le_bytes())).unwrap();
                    assert_eq!(witness.value(output), Fe(expected as u128));
                }
            }
        }
    }
    #[test]
    fn decimal_parser_rejects_overflow_and_non_digits() {
        for text in [
            "0",
            "9",
            "10",
            "18446744073709551615",
            "18446744073709551616",
            "-1",
            ":",
            "1a",
        ] {
            let mut c = Circuit::default();
            let refs: Vec<_> = text.bytes().map(|_| c.commit_byte()).collect();
            let parsed = ascii_u64(&mut c, &refs).unwrap();
            if let Ok(value) = text.parse::<u64>() {
                let expected = U64::public(&mut c, value);
                parsed.assert_compare(&mut c, expected, Comparison::Eq);
                assert!(c.eval(&byte_inputs(text.as_bytes())).is_ok(), "{text}");
            } else {
                assert!(c.eval(&byte_inputs(text.as_bytes())).is_err(), "{text}");
            }
        }
    }
}
