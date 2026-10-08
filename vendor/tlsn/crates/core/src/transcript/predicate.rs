//! Predicates over transcript plaintext, proven to the verifier in zero
//! knowledge (QuickSilver) during the proving phase. (zkfetch patch)
//!
//! A predicate names a byte range of the transcript and a property of those
//! bytes. The verifier learns only that the property holds, not the bytes.

use std::ops::Range;

use serde::{Deserialize, Serialize};

use crate::transcript::Direction;

/// Maximum number of ASCII digits in a [`PredicateKind::UintGte`] operand.
///
/// 19 decimal digits always fit in a `u64` without overflow.
pub const MAX_UINT_DIGITS: usize = 19;

/// Maximum number of predicates in a single proving request.
pub const MAX_PREDICATES: usize = 1024;

/// Maximum operand bytes summed over all predicates in one request. Each
/// predicate is a separate circuit evaluation, so repeating or overlapping
/// long operands must not multiply the notary's work (zkfetch P7).
pub const MAX_PREDICATE_BYTES: usize = 1 << 18;

/// Maximum length of a [`PredicateKind::JsonStringContent`] operand.
pub const MAX_STRING_CONTENT: usize = 1 << 16;

/// Maximum length of a [`PredicateKind::JsonAtom`] operand.
pub const MAX_ATOM: usize = 64;

/// Property proven about a plaintext range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PredicateKind {
    /// The range is a canonical unsigned decimal integer (ASCII digits, no
    /// leading zero unless the value is `0`) whose value is `>= minimum`.
    UintGte {
        /// Inclusive lower bound.
        minimum: u64,
    },
    /// The range is the content of a JSON string (between the quotes): every
    /// quote and backslash belongs to a valid escape sequence, there are no
    /// control characters, and no escape is left open. Hiding such a range
    /// cannot change how the surrounding JSON parses.
    JsonStringContent,
    /// The range is a JSON number or one of `true`, `false`, `null`.
    JsonAtom,
}

/// A predicate over a contiguous range of the transcript.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TranscriptPredicate {
    /// Direction of the plaintext.
    pub direction: Direction,
    /// Byte range of the plaintext.
    pub range: Range<usize>,
    /// Property proven about the range.
    pub kind: PredicateKind,
}

impl TranscriptPredicate {
    /// Checks the predicate is well-formed for a transcript with the given
    /// lengths of sent and received data.
    pub fn validate(&self, len_sent: usize, len_received: usize) -> Result<(), PredicateError> {
        let len = match self.direction {
            Direction::Sent => len_sent,
            Direction::Received => len_received,
        };
        if self.range.start >= self.range.end || self.range.end > len {
            return Err(PredicateError::Range {
                range: self.range.clone(),
                len,
            });
        }
        let max = match self.kind {
            PredicateKind::UintGte { .. } => MAX_UINT_DIGITS,
            PredicateKind::JsonStringContent => MAX_STRING_CONTENT,
            PredicateKind::JsonAtom => MAX_ATOM,
        };
        if self.range.len() > max {
            return Err(PredicateError::TooLong {
                len: self.range.len(),
                max,
            });
        }
        Ok(())
    }
}

/// Error for a malformed predicate.
#[derive(Debug, thiserror::Error)]
pub enum PredicateError {
    /// Range is empty or out of bounds.
    #[error("predicate range {range:?} is empty or exceeds transcript length {len}")]
    Range {
        /// The range.
        range: Range<usize>,
        /// Transcript length.
        len: usize,
    },
    /// Operand is too long.
    #[error("predicate operand is {len} bytes; at most {max} are supported")]
    TooLong {
        /// Operand length.
        len: usize,
        /// Maximum length.
        max: usize,
    },
    /// Too many predicates.
    #[error("too many predicates: {0} > {MAX_PREDICATES}")]
    TooMany(usize),
}

/// Evaluates a predicate on plaintext in the clear (used by the prover to fail
/// fast and by tests as the reference).
pub fn evaluate(kind: &PredicateKind, data: &[u8]) -> bool {
    match *kind {
        PredicateKind::UintGte { minimum } => {
            if data.is_empty() || data.len() > MAX_UINT_DIGITS {
                return false;
            }
            if !data.iter().all(u8::is_ascii_digit) {
                return false;
            }
            if data.len() > 1 && data[0] == b'0' {
                return false;
            }
            let value = data
                .iter()
                .fold(0u64, |acc, d| acc * 10 + u64::from(d - b'0'));
            value >= minimum
        }
        PredicateKind::JsonStringContent => json_string_content(data),
        PredicateKind::JsonAtom => json_atom(data),
    }
}

fn json_string_content(data: &[u8]) -> bool {
    // 0: normal, 1: after `\`, 2..=5: inside `\u` expecting hex digits.
    let mut state = 0u8;
    for &c in data {
        state = match (state, c) {
            (0, b'\\') => 1,
            (0, b'"') => return false,
            (0, c) if c >= 0x20 => 0,
            (1, b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => 0,
            (1, b'u') => 2,
            (2..=4, c) if c.is_ascii_hexdigit() => state + 1,
            (5, c) if c.is_ascii_hexdigit() => 0,
            _ => return false,
        };
    }
    state == 0
}

fn json_atom(data: &[u8]) -> bool {
    if matches!(data, b"true" | b"false" | b"null") {
        return true;
    }
    // RFC 8259 number grammar.
    let mut state = 0u8;
    for &c in data {
        state = match (state, c) {
            (0, b'-') => 1,
            (0 | 1, b'0') => 2,
            (0 | 1, b'1'..=b'9') => 3,
            (3, b'0'..=b'9') => 3,
            (2 | 3, b'.') => 4,
            (4 | 5, b'0'..=b'9') => 5,
            (2 | 3 | 5, b'e' | b'E') => 6,
            (6, b'+' | b'-') => 7,
            (6..=8, b'0'..=b'9') => 8,
            _ => return false,
        };
    }
    matches!(state, 2 | 3 | 5 | 8)
}
