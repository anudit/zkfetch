//! Hidden parser context for T2 membership. Parses the entire authenticated
//! JSON document with a bounded private stack; no parser trace or skeleton is
//! public. The caller must authenticate document boundaries (e.g. HTTP body)
//! and connect every byte to its ciphertext decryption relation.
use crate::{Byte, Circuit, Term, Wire, field::Fe};
use std::ops::Range;

const ROOT: usize = 0;
const DONE: usize = 1;
const OKEND: usize = 2;
const OKEY: usize = 3;
const COLON: usize = 4;
const OVAL: usize = 5;
const OCOMMA: usize = 6;
const AVEND: usize = 7;
const AVAL: usize = 8;
const ACOMMA: usize = 9;
const NONE: usize = 0;
const STRING: usize = 1;
const ESC: usize = 2;
const U1: usize = 3;
const U2: usize = 4;
const U3: usize = 5;
const U4: usize = 6;
const PAIRSLASH: usize = 7;
const PAIRU: usize = 8;
const C1: usize = 9;
const C2: usize = 10;
const C3: usize = 11;
const E0: usize = 12;
const ED: usize = 13;
const F0: usize = 14;
const F4: usize = 15;
const MINUS: usize = 16;
const ZERO: usize = 17;
const DIGITS: usize = 18;
const DOT: usize = 19;
const FRAC: usize = 20;
const EXP: usize = 21;
const EXPSIGN: usize = 22;
const EXPDIGITS: usize = 23;
const T1: usize = 24;
const T2: usize = 25;
const T3: usize = 26;
const F1: usize = 27;
const F2: usize = 28;
const F3: usize = 29;
const FEND: usize = 30;
const N1: usize = 31;
const N2: usize = 32;
const N3: usize = 33;
const NSTATES: usize = 34;
pub const MAX_DEPTH: usize = 64;
pub const MAX_DOCUMENT_BYTES: usize = 64 << 10;

fn and(c: &mut Circuit, a: Wire, b: Wire) -> Wire {
    c.and_bit(a, b)
}
fn not(c: &mut Circuit, a: Wire) -> Wire {
    c.not_bit(a)
}
fn or(c: &mut Circuit, a: Wire, b: Wire) -> Wire {
    let both = and(c, a, b);
    let either = c.xor_bit(a, b);
    c.xor_bit(either, both)
}
fn any(c: &mut Circuit, items: &[Wire]) -> Wire {
    let mut out = c.public_bit(false);
    for item in items {
        out = or(c, out, *item);
    }
    out
}
fn eq(c: &mut Circuit, byte: Byte, value: u8) -> Wire {
    let mut out = c.public_bit(true);
    for i in 0..8 {
        let bit = if (value >> i) & 1 != 0 {
            byte.0[i]
        } else {
            not(c, byte.0[i])
        };
        out = and(c, out, bit);
    }
    out
}
fn range(c: &mut Circuit, byte: Byte, low: u8, high: u8) -> Wire {
    fn lt(c: &mut Circuit, byte: Byte, bound: u8) -> Wire {
        let mut less = c.public_bit(false);
        let mut equal = c.public_bit(true);
        for i in (0..8).rev() {
            let bit = byte.0[i];
            let inv = not(c, bit);
            if (bound >> i) & 1 != 0 {
                let term = and(c, equal, inv);
                less = or(c, less, term);
                equal = and(c, equal, bit);
            } else {
                equal = and(c, equal, inv);
            }
        }
        less
    }
    let below = lt(c, byte, low);
    let above = if high == 255 {
        c.public_bit(false)
    } else {
        let within = lt(c, byte, high + 1);
        not(c, within)
    };
    let outside = or(c, below, above);
    not(c, outside)
}
fn equals_any(c: &mut Circuit, byte: Byte, values: &[u8]) -> Wire {
    let values: Vec<_> = values.iter().map(|v| eq(c, byte, *v)).collect();
    any(c, &values)
}
fn emit(c: &mut Circuit, next: &mut [Wire], dest: usize, source: Wire, condition: Wire) {
    let term = and(c, source, condition);
    next[dest] = c.xor_bit(next[dest], term);
}
fn assert_true(c: &mut Circuit, wire: Wire) {
    c.assert_zero(vec![Term::Linear(Fe::ONE, wire), Term::Constant(Fe::ONE)]);
}
fn assert_false(c: &mut Circuit, wire: Wire) {
    c.assert_zero(vec![Term::Linear(Fe::ONE, wire)]);
}

#[derive(Debug, thiserror::Error)]
pub enum JsonCircuitError {
    #[error("JSON document or selected spans exceed limits")]
    Bounds,
    #[error("selected key is not a valid encoded JSON string")]
    Key,
}

/// Public member selection contains only the requested key encoding and its
/// spans, not a full parse trace. The integrating verifier checks the decoded
/// encoded key against its requested key before building this relation.
pub struct Selection<'a> {
    pub encoded_key: &'a [u8],
    pub key: Range<usize>,
    pub colon: usize,
    pub value: Range<usize>,
}

/// Authenticate grammar and the exact extent of one selected member. Other
/// key/value bytes and all parser/stack states remain private circuit wires.
/// Returns the selected encoded value wires for revelation or predicates.
pub fn member(
    c: &mut Circuit,
    document: &[Byte],
    selection: &Selection<'_>,
) -> Result<Vec<Byte>, JsonCircuitError> {
    let s = selection;
    if document.is_empty()
        || document.len() > MAX_DOCUMENT_BYTES
        || s.key.start >= s.key.end
        || s.key.end > s.colon
        || s.colon >= s.value.start
        || s.value.start >= s.value.end
        || s.value.end > document.len()
        || s.key.len() != s.encoded_key.len()
    {
        return Err(JsonCircuitError::Bounds);
    }
    serde_json::from_slice::<String>(s.encoded_key).map_err(|_| JsonCircuitError::Key)?;
    for (i, value) in s.encoded_key.iter().enumerate() {
        c.assert_byte(document[s.key.start + i], *value);
    }
    for (i, byte) in document
        .iter()
        .enumerate()
        .take(s.value.start)
        .skip(s.key.end)
    {
        if i == s.colon {
            c.assert_byte(*byte, b':');
        } else {
            let ws = equals_any(c, *byte, b" \t\n\r");
            assert_true(c, ws);
        }
    }
    let one = c.public_bit(true);
    let zero = c.public_bit(false);
    let mut grammar = [zero; 10];
    grammar[ROOT] = one;
    let mut lex = [zero; NSTATES];
    lex[NONE] = one;
    let mut depth = vec![zero; MAX_DEPTH + 1];
    depth[0] = one;
    let mut kind = vec![zero; MAX_DEPTH];
    let mut selected_depth = Vec::new();
    let mut unicode_d = zero;
    let mut unicode_high = zero;
    let mut unicode_low = zero;
    let mut pair_required = zero;
    for (position, byte) in document.iter().copied().enumerate() {
        let ws = equals_any(c, byte, b" \t\n\r");
        let quote = eq(c, byte, b'"');
        let slash = eq(c, byte, b'\\');
        let open_obj = eq(c, byte, b'{');
        let close_obj = eq(c, byte, b'}');
        let open_arr = eq(c, byte, b'[');
        let close_arr = eq(c, byte, b']');
        let comma = eq(c, byte, b',');
        let colon = eq(c, byte, b':');
        let digit = range(c, byte, b'0', b'9');
        let digit0 = eq(c, byte, b'0');
        let nonzero = range(c, byte, b'1', b'9');
        let minus = eq(c, byte, b'-');
        let plus = eq(c, byte, b'+');
        let dot = eq(c, byte, b'.');
        let exponent = equals_any(c, byte, b"eE");
        let t = eq(c, byte, b't');
        let f = eq(c, byte, b'f');
        let n = eq(c, byte, b'n');
        let delimiter = any(c, &[ws, comma, close_obj, close_arr]);
        let numeric = any(c, &[lex[ZERO], lex[DIGITS], lex[FRAC], lex[EXPDIGITS]]);
        let num_end = and(c, numeric, delimiter);
        let base = or(c, lex[NONE], num_end);
        if position == s.value.start {
            selected_depth = depth.clone();
        }
        if position > s.value.start && position <= s.value.end {
            let mut same = one;
            for (a, b) in depth.iter().zip(&selected_depth) {
                let neq = c.xor_bit(*a, *b);
                let equal = not(c, neq);
                same = and(c, same, equal);
            }
            let after = any(c, &[grammar[DONE], grammar[OCOMMA], grammar[ACOMMA]]);
            let lex_done = or(c, lex[NONE], num_end);
            let complete = and(c, same, after);
            let complete = and(c, complete, lex_done);
            if position == s.value.end {
                assert_true(c, complete);
            } else {
                assert_false(c, complete);
            }
        }
        let mut next = [zero; 10];
        let hold = not(c, base);
        for i in 0..10 {
            next[i] = and(c, grammar[i], hold);
            let src = and(c, grammar[i], base);
            emit(c, &mut next, i, src, ws);
        }
        let active: Vec<_> = grammar.iter().map(|g| and(c, *g, base)).collect();
        let value_src = any(
            c,
            &[active[ROOT], active[OVAL], active[AVEND], active[AVAL]],
        );
        let key_src = any(c, &[active[OKEND], active[OKEY]]);
        let key_start = and(c, key_src, quote);
        let string_start = and(c, value_src, quote);
        let strings = or(c, key_start, string_start);
        let scalar = any(c, &[quote, minus, digit, t, f, n]);
        let scalar_start = and(c, value_src, scalar);
        let container = or(c, open_obj, open_arr);
        let push = and(c, value_src, container);
        let value_start = or(c, scalar_start, push);
        if position == s.key.start {
            assert_true(c, key_start);
        }
        if position == s.value.start {
            assert_true(c, value_start);
        }
        for (src, dest) in [
            (ROOT, DONE),
            (OVAL, OCOMMA),
            (AVEND, ACOMMA),
            (AVAL, ACOMMA),
        ] {
            emit(c, &mut next, dest, active[src], scalar);
            emit(c, &mut next, OKEND, active[src], open_obj);
            emit(c, &mut next, AVEND, active[src], open_arr);
        }
        emit(c, &mut next, COLON, key_src, quote);
        emit(c, &mut next, OVAL, active[COLON], colon);
        emit(c, &mut next, OKEY, active[OCOMMA], comma);
        emit(c, &mut next, AVAL, active[ACOMMA], comma);
        let obj_end_src = any(c, &[active[OKEND], active[OCOMMA]]);
        let arr_end_src = any(c, &[active[AVEND], active[ACOMMA]]);
        let obj_end = and(c, obj_end_src, close_obj);
        let arr_end = and(c, arr_end_src, close_arr);
        let pop = or(c, obj_end, arr_end);
        let mut parent_obj = zero;
        for i in 2..=MAX_DEPTH {
            let bit = and(c, depth[i], kind[i - 2]);
            parent_obj = c.xor_bit(parent_obj, bit);
        }
        let parent_root = depth[1];
        let parent_nonroot = not(c, parent_root);
        let not_obj = not(c, parent_obj);
        let parent_arr = and(c, parent_nonroot, not_obj);
        emit(c, &mut next, DONE, pop, parent_root);
        emit(c, &mut next, OCOMMA, pop, parent_obj);
        emit(c, &mut next, ACOMMA, pop, parent_arr);
        let overflow = and(c, push, depth[MAX_DEPTH]);
        assert_false(c, overflow);
        let movement = or(c, push, pop);
        let stationary = not(c, movement);
        let mut new_depth = vec![zero; MAX_DEPTH + 1];
        for i in 0..=MAX_DEPTH {
            let stay = and(c, depth[i], stationary);
            let up = if i > 0 {
                and(c, depth[i - 1], push)
            } else {
                zero
            };
            let down = if i < MAX_DEPTH {
                and(c, depth[i + 1], pop)
            } else {
                zero
            };
            let a = c.xor_bit(stay, up);
            new_depth[i] = c.xor_bit(a, down);
            if i < MAX_DEPTH {
                let write = and(c, depth[i], push);
                let difference = c.xor_bit(kind[i], open_obj);
                let change = and(c, write, difference);
                kind[i] = c.xor_bit(kind[i], change);
            }
        }
        let mut nl = [zero; NSTATES];
        let numeric_or_literal = any(c, &[minus, digit, t, f, n]);
        let numeric_or_literal = and(c, value_src, numeric_or_literal);
        let token = or(c, strings, numeric_or_literal);
        let not_token = not(c, token);
        nl[NONE] = and(c, base, not_token);
        nl[STRING] = strings;
        for (symbol, dest) in [
            (minus, MINUS),
            (digit0, ZERO),
            (nonzero, DIGITS),
            (t, T1),
            (f, F1),
            (n, N1),
        ] {
            emit(c, &mut nl, dest, value_src, symbol);
        }
        // Strings: full UTF-8 byte validity and strict surrogate pairing.
        let normal = range(c, byte, 0x20, 0x7f);
        let special = or(c, quote, slash);
        let nonspecial = not(c, special);
        let normal = and(c, normal, nonspecial);
        emit(c, &mut nl, STRING, lex[STRING], normal);
        emit(c, &mut nl, NONE, lex[STRING], quote);
        emit(c, &mut nl, ESC, lex[STRING], slash);
        let escaped = equals_any(c, byte, b"\"\\/bfnrt");
        emit(c, &mut nl, STRING, lex[ESC], escaped);
        let u = eq(c, byte, b'u');
        emit(c, &mut nl, U1, lex[ESC], u);
        let hex_lower = range(c, byte, b'a', b'f');
        let hex_upper = range(c, byte, b'A', b'F');
        let hex = any(c, &[digit, hex_lower, hex_upper]);
        emit(c, &mut nl, U2, lex[U1], hex);
        emit(c, &mut nl, U3, lex[U2], hex);
        emit(c, &mut nl, U4, lex[U3], hex);
        let d = equals_any(c, byte, b"dD");
        let first_change = c.xor_bit(unicode_d, d);
        let first_change = and(c, lex[U1], first_change);
        unicode_d = c.xor_bit(unicode_d, first_change);
        let high_char = equals_any(c, byte, b"89aAbB");
        let low_char = equals_any(c, byte, b"cCdDeEfF");
        let high = and(c, unicode_d, high_char);
        let low = and(c, unicode_d, low_char);
        let change = c.xor_bit(unicode_high, high);
        let change = and(c, lex[U2], change);
        unicode_high = c.xor_bit(unicode_high, change);
        let change = c.xor_bit(unicode_low, low);
        let change = and(c, lex[U2], change);
        unicode_low = c.xor_bit(unicode_low, change);
        let not_required = not(c, pair_required);
        let not_high = not(c, unicode_high);
        let not_low = not(c, unicode_low);
        let ordinary = and(c, not_high, not_low);
        let ordinary = and(c, ordinary, not_required);
        let paired = and(c, pair_required, unicode_low);
        let allowed = or(c, ordinary, paired);
        let allowed = and(c, allowed, hex);
        emit(c, &mut nl, STRING, lex[U4], allowed);
        let high_first = and(c, unicode_high, not_required);
        let high_first = and(c, high_first, hex);
        emit(c, &mut nl, PAIRSLASH, lex[U4], high_first);
        emit(c, &mut nl, PAIRU, lex[PAIRSLASH], slash);
        emit(c, &mut nl, U1, lex[PAIRU], u);
        let pair_set = and(c, lex[PAIRU], u);
        let pair_hold = not(c, lex[U4]);
        let pair_old = and(c, pair_required, pair_hold);
        pair_required = or(c, pair_old, pair_set);
        for (src, lo, hi, dest) in [
            (STRING, 0xc2, 0xdf, C1),
            (STRING, 0xe1, 0xec, C2),
            (STRING, 0xee, 0xef, C2),
            (STRING, 0xf1, 0xf3, C3),
            (C1, 0x80, 0xbf, STRING),
            (C2, 0x80, 0xbf, C1),
            (C3, 0x80, 0xbf, C2),
            (E0, 0xa0, 0xbf, C1),
            (ED, 0x80, 0x9f, C1),
            (F0, 0x90, 0xbf, C2),
            (F4, 0x80, 0x8f, C2),
        ] {
            let condition = range(c, byte, lo, hi);
            emit(c, &mut nl, dest, lex[src], condition);
        }
        for (value, dest) in [(0xe0, E0), (0xed, ED), (0xf0, F0), (0xf4, F4)] {
            let condition = eq(c, byte, value);
            emit(c, &mut nl, dest, lex[STRING], condition);
        }
        // JSON number grammar; terminal states reprocess delimiters above.
        for (src, condition, dest) in [
            (MINUS, digit0, ZERO),
            (MINUS, nonzero, DIGITS),
            (DIGITS, digit, DIGITS),
            (ZERO, dot, DOT),
            (DIGITS, dot, DOT),
            (DOT, digit, FRAC),
            (FRAC, digit, FRAC),
            (ZERO, exponent, EXP),
            (DIGITS, exponent, EXP),
            (FRAC, exponent, EXP),
            (EXP, digit, EXPDIGITS),
            (EXPSIGN, digit, EXPDIGITS),
            (EXPDIGITS, digit, EXPDIGITS),
        ] {
            emit(c, &mut nl, dest, lex[src], condition);
        }
        let sign = or(c, plus, minus);
        emit(c, &mut nl, EXPSIGN, lex[EXP], sign);
        for (src, symbol, dest) in [
            (T1, b'r', T2),
            (T2, b'u', T3),
            (T3, b'e', NONE),
            (F1, b'a', F2),
            (F2, b'l', F3),
            (F3, b's', FEND),
            (FEND, b'e', NONE),
            (N1, b'u', N2),
            (N2, b'l', N3),
            (N3, b'l', NONE),
        ] {
            let condition = eq(c, byte, symbol);
            emit(c, &mut nl, dest, lex[src], condition);
        }
        grammar = next;
        lex = nl;
        depth = new_depth;
    }
    let endlex = any(
        c,
        &[lex[NONE], lex[ZERO], lex[DIGITS], lex[FRAC], lex[EXPDIGITS]],
    );
    assert_true(c, endlex);
    assert_true(c, grammar[DONE]);
    assert_true(c, depth[0]);
    if s.value.end == document.len() {
        for (a, b) in depth.iter().zip(selected_depth) {
            c.assert_equal(*a, b);
        }
        let after = any(c, &[grammar[DONE], grammar[OCOMMA], grammar[ACOMMA]]);
        assert_true(c, after);
    }
    Ok(document[s.value.clone()].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::byte_inputs;
    fn accepts(
        body: &[u8],
        key: Range<usize>,
        colon: usize,
        value: Range<usize>,
        encoded_key: &[u8],
    ) -> bool {
        let mut c = Circuit::default();
        let doc: Vec<_> = body.iter().map(|_| c.commit_byte()).collect();
        member(
            &mut c,
            &doc,
            &Selection {
                encoded_key,
                key,
                colon,
                value,
            },
        )
        .unwrap();
        c.eval(&byte_inputs(body)).is_ok()
    }
    #[test]
    fn member_context_and_exact_extent() {
        assert!(accepts(br#"{"id":123}"#, 1..5, 5, 6..9, br#""id""#));
        assert!(!accepts(br#"{"id":123}"#, 1..5, 5, 6..8, br#""id""#));
        assert!(!accepts(br#"{"id":123,"x":1}"#, 1..5, 5, 6..14, br#""id""#));
        assert!(accepts(
            br#"{"id":[{"a":1},2]}"#,
            1..5,
            5,
            6..17,
            br#""id""#
        ));
        assert!(!accepts(
            br#"{"id":[{"a":1},2]}"#,
            1..5,
            5,
            6..14,
            br#""id""#
        ));
    }
    #[test]
    fn fake_local_key_and_invalid_grammar_fail() {
        let body = br#"{"a":"x", ": 7, hidden":0}"#;
        let start = body.windows(8).position(|w| w == b"\", \": 7,").unwrap();
        assert!(!accepts(
            body,
            start..start + 4,
            start + 4,
            start + 6..start + 7,
            b"\", \""
        ));
        for body in [
            br#"{"id":01}"#.as_slice(),
            br#"{"id":1,}"#,
            br#"{"id":1]"#,
            br#"{"id":1}false"#,
            br#"{"id":1e}"#,
        ] {
            assert!(!accepts(body, 1..5, 5, 6..7, br#""id""#));
        }
    }
    #[test]
    fn escapes_utf8_and_surrogate_pairs() {
        for value in [
            r#""a\"b""#,
            r#""\ud83d\ude00""#,
            r#""é😀""#,
            r#"-12.3e+2"#,
            r#"true"#,
            r#"null"#,
        ] {
            let body = format!("{{\"id\":{value}}}");
            assert!(accepts(
                body.as_bytes(),
                1..5,
                5,
                6..body.len() - 1,
                br#""id""#
            ));
        }
        for value in [
            r#""\ud83d""#,
            r#""\ude00""#,
            r#""\ud83d\u0041""#,
            r#""\q""#,
            r#"1."#,
        ] {
            let body = format!("{{\"id\":{value}}}");
            assert!(!accepts(
                body.as_bytes(),
                1..5,
                5,
                6..body.len() - 1,
                br#""id""#
            ));
        }
    }
}
