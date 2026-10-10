//! Hidden parser context for T2 membership. Parses the entire authenticated
//! JSON document with a bounded private stack; no parser trace or skeleton is
//! public. The caller must authenticate document boundaries (e.g. HTTP body)
//! and connect every byte to its ciphertext decryption relation.
use crate::json_circuit::{JsonCircuitError, MAX_DEPTH, MAX_DOCUMENT_BYTES, Selection};
use crate::{
    Byte, Circuit,
    algebra::{Algebra, Bit as Wire},
};

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

fn and(c: &mut Algebra<'_>, a: Wire, b: Wire) -> Wire {
    c.and_bit(a, b)
}
fn not(c: &mut Algebra<'_>, a: Wire) -> Wire {
    c.not_bit(a)
}
fn or(c: &mut Algebra<'_>, a: Wire, b: Wire) -> Wire {
    // Every union below combines disjoint byte classes or mutually exclusive
    // deterministic states. XOR is their Boolean union without an AND hint.
    c.xor_bit(a, b)
}
fn any(c: &mut Algebra<'_>, items: &[Wire]) -> Wire {
    let mut out = c.public_bit(false);
    for item in items {
        out = c.xor_bit(out, *item);
    }
    out
}
fn eq(c: &mut Algebra<'_>, byte: Byte, value: u8) -> Wire {
    c.range(byte, value, value)
}
fn range(c: &mut Algebra<'_>, byte: Byte, low: u8, high: u8) -> Wire {
    c.range(byte, low, high)
}
fn equals_any(c: &mut Algebra<'_>, byte: Byte, values: &[u8]) -> Wire {
    let values: Vec<_> = values.iter().map(|v| eq(c, byte, *v)).collect();
    any(c, &values)
}
fn emit(c: &mut Algebra<'_>, next: &mut [Wire], dest: usize, source: Wire, condition: Wire) {
    let term = and(c, source, condition);
    next[dest] = c.xor_bit(next[dest], term);
}
fn assert_true(c: &mut Algebra<'_>, wire: Wire) {
    c.assert_true(wire);
}
fn assert_false(c: &mut Algebra<'_>, wire: Wire) {
    c.assert_false(wire);
}

/// Authenticate grammar and the exact extent of one selected member. Other
/// key/value bytes and all parser/stack states remain private circuit wires.
/// Returns the selected encoded value wires for revelation or predicates.
pub fn member(
    circuit: &mut Circuit,
    document: &[Byte],
    selection: &Selection<'_>,
) -> Result<Vec<Byte>, JsonCircuitError> {
    member_bounded(circuit, document, selection, MAX_DEPTH, false)
}

pub fn member_bounded(
    circuit: &mut Circuit,
    document: &[Byte],
    selection: &Selection<'_>,
    max_depth: usize,
    prefix_only: bool,
) -> Result<Vec<Byte>, JsonCircuitError> {
    member_profile(circuit, document, selection, max_depth, prefix_only, false)
}

/// Authenticate a member of the root object, with the same prefix grammar checks.
pub fn top_level_member(
    circuit: &mut Circuit,
    document: &[Byte],
    selection: &Selection<'_>,
    max_depth: usize,
    prefix_only: bool,
) -> Result<Vec<Byte>, JsonCircuitError> {
    member_profile(circuit, document, selection, max_depth, prefix_only, true)
}

fn member_profile(
    circuit: &mut Circuit,
    document: &[Byte],
    selection: &Selection<'_>,
    max_depth: usize,
    prefix_only: bool,
    top_level: bool,
) -> Result<Vec<Byte>, JsonCircuitError> {
    let mut compiler = Algebra::new(circuit);
    let c = &mut compiler;
    let s = selection;
    if max_depth == 0 || max_depth > MAX_DEPTH {
        return Err(JsonCircuitError::Bounds);
    }
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
    let mut one = c.public_bit(true);
    let mut zero = c.public_bit(false);
    let mut grammar = [zero; 10];
    grammar[ROOT] = one;
    let mut lex = [zero; NSTATES];
    lex[NONE] = one;
    let mut depth = vec![zero; max_depth + 1];
    depth[0] = one;
    let mut kind = vec![zero; max_depth];
    let mut selected_depth = Vec::new();
    let mut unicode_d = zero;
    let mut unicode_high = zero;
    let mut unicode_low = zero;
    let mut pair_required = zero;
    let through = if prefix_only {
        s.value.end.saturating_add(1).min(document.len())
    } else {
        document.len()
    };
    for (position, byte) in document.iter().copied().enumerate().take(through) {
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
            if top_level {
                assert_true(c, depth[1]);
                assert_true(c, kind[0]);
            }
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
        for i in 2..=max_depth {
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
        let overflow = and(c, push, depth[max_depth]);
        assert_false(c, overflow);
        let movement = or(c, push, pop);
        let stationary = not(c, movement);
        let mut new_depth = vec![zero; max_depth + 1];
        for i in 0..=max_depth {
            let stay = and(c, depth[i], stationary);
            let up = if i > 0 {
                and(c, depth[i - 1], push)
            } else {
                zero
            };
            let down = if i < max_depth {
                and(c, depth[i + 1], pop)
            } else {
                zero
            };
            let a = c.xor_bit(stay, up);
            new_depth[i] = c.xor_bit(a, down);
            if i < max_depth {
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
        let mut unicode = [
            unicode_d,
            unicode_high,
            unicode_low,
            pair_required,
            one,
            zero,
        ];
        c.checkpoint(&mut [
            &mut grammar,
            &mut lex,
            &mut depth,
            &mut kind,
            &mut selected_depth,
            &mut unicode,
        ]);
        [
            unicode_d,
            unicode_high,
            unicode_low,
            pair_required,
            one,
            zero,
        ] = unicode;
    }
    let endlex = any(
        c,
        &[lex[NONE], lex[ZERO], lex[DIGITS], lex[FRAC], lex[EXPDIGITS]],
    );
    assert_true(c, endlex);
    if !prefix_only {
        assert_true(c, grammar[DONE]);
        assert_true(c, depth[0]);
    }
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
    use std::ops::Range;
    #[test]
    fn measured_membership_cost() {
        let body = br#"{"userId":1,"id":1,"title":"delectus aut autem","completed":false}"#;
        let selection = Selection {
            encoded_key: br#""userId""#,
            key: 1..9,
            colon: 9,
            value: 10..11,
        };
        for (label, optimized, prefix) in [
            ("boolean", false, false),
            ("algebraic-full", true, false),
            ("algebraic-prefix", true, true),
        ] {
            let mut c = Circuit::default();
            let bytes: Vec<_> = body.iter().map(|_| c.commit_byte()).collect();
            let before = c.committed_bits();
            if optimized {
                member_bounded(&mut c, &bytes, &selection, 4, prefix).unwrap();
            } else {
                crate::json_circuit::member(&mut c, &bytes, &selection).unwrap();
            }
            c.eval(&byte_inputs(body)).unwrap();
            println!(
                "{label}: bytes={} parser_bits={} constraints={}",
                body.len(),
                c.committed_bits() - before,
                c.constraint_count()
            );
        }
    }

    #[test]
    fn polynomial_state_hints_cannot_be_changed() {
        let body = br#"{"id":123}"#;
        let mut c = Circuit::default();
        let bytes: Vec<_> = body.iter().map(|_| c.commit_byte()).collect();
        member_bounded(
            &mut c,
            &bytes,
            &Selection {
                encoded_key: br#""id""#,
                key: 1..5,
                colon: 5,
                value: 6..9,
            },
            4,
            false,
        )
        .unwrap();
        for index in c
            .ops
            .iter()
            .enumerate()
            .filter(|(_, op)| matches!(op, crate::Op::PolynomialBit(_)))
            .map(|(i, _)| i)
            .take(64)
        {
            let mut witness = c.eval(&byte_inputs(body)).unwrap();
            witness.values[index] = witness.values[index] ^ crate::field::Fe::ONE;
            assert!(c.check(&witness).is_err());
        }
    }
    #[test]
    fn mutation_differential_against_boolean_parser() {
        let original = br#"{"id":123,"x":[true,null,"\ud83d\ude00",{"x":-1.3e+2}]}"#;
        let selection = Selection {
            encoded_key: br#""id""#,
            key: 1..5,
            colon: 5,
            value: 6..9,
        };
        for (index, value) in [
            (0, b'['),
            (9, b']'),
            (10, b','),
            (14, b'['),
            (20, b'\"'),
            (24, b'\"'),
            (29, b'q'),
            (32, b'z'),
            (35, b'0'),
            (46, b']'),
            (50, b'e'),
            (52, b']'),
        ]
        .into_iter()
        .filter(|(i, _)| *i < original.len())
        {
            let mut body = original.to_vec();
            body[index] = value;
            let mut reference = Circuit::default();
            let bytes: Vec<_> = body.iter().map(|_| reference.commit_byte()).collect();
            crate::json_circuit::member(&mut reference, &bytes, &selection).unwrap();
            let expected = reference.eval(&byte_inputs(&body)).is_ok();
            let mut optimized = Circuit::default();
            let bytes: Vec<_> = body.iter().map(|_| optimized.commit_byte()).collect();
            member(&mut optimized, &bytes, &selection).unwrap();
            assert_eq!(
                optimized.eval(&byte_inputs(&body)).is_ok(),
                expected,
                "mutation at {index}"
            );
        }
    }
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
