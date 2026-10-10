//! Hidden parser context for T2 membership. Parses the entire authenticated
//! JSON document with a bounded private stack; no parser trace or skeleton is
//! public. The caller must authenticate document boundaries (e.g. HTTP body)
//! and connect every byte to its ciphertext decryption relation.
use crate::json::{JsonPathSegment, PathAnchor};
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

fn bind_key(
    c: &mut Algebra<'_>,
    document: &[Byte],
    encoded: &[u8],
    key: std::ops::Range<usize>,
    colon: usize,
    value_start: usize,
) -> Result<(), JsonCircuitError> {
    if key.start >= key.end
        || key.end > colon
        || colon >= value_start
        || value_start >= document.len()
        || key.len() != encoded.len()
    {
        return Err(JsonCircuitError::Bounds);
    }
    serde_json::from_slice::<String>(encoded).map_err(|_| JsonCircuitError::Key)?;
    for (i, value) in encoded.iter().enumerate() {
        c.assert_byte(document[key.start + i], *value);
    }
    for (i, byte) in document.iter().enumerate().take(value_start).skip(key.end) {
        if i == colon {
            c.assert_byte(*byte, b':');
        } else {
            let ws = equals_any(c, *byte, b" \t\n\r");
            assert_true(c, ws);
        }
    }
    Ok(())
}

/// Match a decoded member name at every possible opening quote. The grammar
/// authenticates strings independently. This DP accepts literal UTF-8, short
/// escapes and case-insensitive Unicode/surrogate escapes, so uniqueness cannot
/// be bypassed with e.g. "a" versus "\u0061".
fn decoded_key_matches(c: &mut Algebra<'_>, document: &[Byte], name: &str) -> Vec<Wire> {
    let mut zero = c.public_bit(false);
    let mut suffix: Vec<_> = document.iter().map(|b| eq(c, *b, b'"')).collect();
    suffix.push(zero);
    for ch in name.chars().rev() {
        let mut alternatives: Vec<(Vec<u8>, bool)> = Vec::new();
        if ch >= ' ' && ch != '"' && ch != '\\' {
            alternatives.push((ch.to_string().into_bytes(), false));
        }
        let short = match ch {
            '"' => Some(b'"'),
            '\\' => Some(b'\\'),
            '/' => Some(b'/'),
            '\x08' => Some(b'b'),
            '\x0c' => Some(b'f'),
            '\n' => Some(b'n'),
            '\r' => Some(b'r'),
            '\t' => Some(b't'),
            _ => None,
        };
        if let Some(short) = short {
            alternatives.push((vec![b'\\', short], false));
        }
        let mut units = [0u16; 2];
        let unicode: Vec<u8> = ch
            .encode_utf16(&mut units)
            .iter()
            .flat_map(|unit| format!("\\u{unit:04x}").into_bytes())
            .collect();
        alternatives.push((unicode, true));
        let mut next = vec![zero; document.len() + 1];
        for (position, slot) in next.iter_mut().enumerate().take(document.len()) {
            for (encoding, hex) in &alternatives {
                if position + encoding.len() > document.len() {
                    continue;
                }
                let mut matches = suffix[position + encoding.len()];
                for (offset, expected) in encoding.iter().enumerate() {
                    let byte = document[position + offset];
                    let class = if *hex && offset % 6 >= 2 && expected.is_ascii_alphabetic() {
                        equals_any(c, byte, &[*expected, expected.to_ascii_uppercase()])
                    } else {
                        eq(c, byte, *expected)
                    };
                    matches = and(c, matches, class);
                }
                *slot = or(c, *slot, matches);
            }
        }
        let mut constants = [zero];
        c.checkpoint(&mut [&mut next, &mut constants]);
        zero = constants[0];
        suffix = next;
    }
    (0..document.len())
        .map(|position| suffix.get(position + 1).copied().unwrap_or(zero))
        .collect()
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
    member_profile(
        circuit,
        document,
        selection,
        max_depth,
        prefix_only,
        false,
        None,
    )
}

/// Authenticate a member of the root object, with the same prefix grammar checks.
pub fn top_level_member(
    circuit: &mut Circuit,
    document: &[Byte],
    selection: &Selection<'_>,
    max_depth: usize,
    prefix_only: bool,
) -> Result<Vec<Byte>, JsonCircuitError> {
    member_profile(
        circuit,
        document,
        selection,
        max_depth,
        prefix_only,
        true,
        None,
    )
}

/// Authenticate each edge from the root, including direct array indices.
/// Unique proofs parse the full document and reject duplicate names along
/// the selected path, including alternative JSON escape encodings.
pub fn path_member(
    circuit: &mut Circuit,
    document: &[Byte],
    path: &[JsonPathSegment],
    anchors: &[PathAnchor],
    unique: bool,
) -> Result<Vec<Byte>, JsonCircuitError> {
    if path.is_empty() || path.len() > 8 || path.len() != anchors.len() {
        return Err(JsonCircuitError::Bounds);
    }
    let last = anchors.last().unwrap();
    let selection = Selection {
        encoded_key: &last.encoded_key,
        key: last.key.clone(),
        colon: last.colon,
        value: last.value.clone(),
    };
    member_profile(
        circuit,
        document,
        &selection,
        8,
        !unique,
        false,
        Some((path, anchors, unique)),
    )
}

fn member_profile(
    circuit: &mut Circuit,
    document: &[Byte],
    selection: &Selection<'_>,
    max_depth: usize,
    prefix_only: bool,
    top_level: bool,
    path: Option<(&[JsonPathSegment], &[PathAnchor], bool)>,
) -> Result<Vec<Byte>, JsonCircuitError> {
    let mut compiler = Algebra::new(circuit);
    let c = &mut compiler;
    let s = selection;
    if max_depth == 0 || max_depth > MAX_DEPTH {
        return Err(JsonCircuitError::Bounds);
    }
    if document.is_empty()
        || document.len() > MAX_DOCUMENT_BYTES
        || s.value.start >= s.value.end
        || s.value.end > document.len()
    {
        return Err(JsonCircuitError::Bounds);
    }
    if let Some((steps, anchors, _)) = path {
        for (level, (step, anchor)) in steps.iter().zip(anchors).enumerate() {
            if anchor.value.start >= anchor.value.end
                || anchor.value.end > MAX_DOCUMENT_BYTES
                || anchor.value.start >= document.len()
                || (level > 0
                    && (anchor.value.start <= anchors[level - 1].value.start
                        || anchor.value.end > anchors[level - 1].value.end))
            {
                return Err(JsonCircuitError::Bounds);
            }
            match step {
                JsonPathSegment::Member(name) => {
                    if name.len() > 1024
                        || serde_json::from_slice::<String>(&anchor.encoded_key)
                            .map_err(|_| JsonCircuitError::Key)?
                            != *name
                    {
                        return Err(JsonCircuitError::Key);
                    }
                    bind_key(
                        c,
                        document,
                        &anchor.encoded_key,
                        anchor.key.clone(),
                        anchor.colon,
                        anchor.value.start,
                    )?;
                }
                JsonPathSegment::Index(index) => {
                    if *index >= MAX_DOCUMENT_BYTES
                        || !anchor.encoded_key.is_empty()
                        || anchor.key != (0..0)
                        || anchor.colon != 0
                    {
                        return Err(JsonCircuitError::Bounds);
                    }
                }
            }
            if let Some(next) = steps.get(level + 1) {
                c.assert_byte(
                    document[anchor.value.start],
                    match next {
                        JsonPathSegment::Member(_) => b'{',
                        JsonPathSegment::Index(_) => b'[',
                    },
                );
            }
        }
    } else {
        bind_key(
            c,
            document,
            s.encoded_key,
            s.key.clone(),
            s.colon,
            s.value.start,
        )?;
    }
    let unique_matches: Vec<_> = if let Some((steps, _, true)) = path {
        steps
            .iter()
            .map(|step| match step {
                JsonPathSegment::Member(name) => {
                    let matches = decoded_key_matches(c, document, name);
                    matches
                        .into_iter()
                        .map(|b| c.export_bit(b))
                        .collect::<Vec<_>>()
                }
                JsonPathSegment::Index(_) => Vec::new(),
            })
            .collect()
    } else {
        Vec::new()
    };
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
    let mut indices = path
        .map(|(steps, _, _)| vec![vec![zero; 16]; steps.len()])
        .unwrap_or_default();
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
        if path.is_none() && position == s.key.start {
            assert_true(c, key_start);
        }
        if position == s.value.start {
            assert_true(c, value_start);
            if top_level {
                assert_true(c, depth[1]);
                assert_true(c, kind[0]);
            }
        }
        if let Some((steps, anchors, unique)) = path {
            for (level, (step, anchor)) in steps.iter().zip(anchors).enumerate() {
                // Never leave the selected parent and re-enter a sibling.
                if level > 0
                    && position > anchors[level - 1].value.start
                    && position <= anchor.value.start
                {
                    let outside = any(c, &depth[..=level]);
                    assert_false(c, outside);
                }
                if position == anchor.value.start {
                    assert_true(c, value_start);
                    assert_true(c, depth[level + 1]);
                    match step {
                        JsonPathSegment::Member(_) => assert_true(c, kind[level]),
                        JsonPathSegment::Index(index) => {
                            assert_false(c, kind[level]);
                            for (bit, count) in indices[level].iter().enumerate() {
                                if index >> bit & 1 == 1 {
                                    assert_true(c, *count);
                                } else {
                                    assert_false(c, *count);
                                }
                            }
                        }
                    }
                }
                if matches!(step, JsonPathSegment::Member(_)) && position == anchor.key.start {
                    assert_true(c, key_start);
                    assert_true(c, depth[level + 1]);
                }
                if matches!(step, JsonPathSegment::Index(_))
                    && position < anchor.value.start
                    && (level == 0 || position > anchors[level - 1].value.start)
                {
                    let event = and(c, value_start, depth[level + 1]);
                    let mut carry = event;
                    for count in &mut indices[level] {
                        let next_carry = and(c, *count, carry);
                        *count = c.xor_bit(*count, carry);
                        carry = next_carry;
                    }
                    assert_false(c, carry);
                }
                if unique
                    && matches!(step, JsonPathSegment::Member(_))
                    && position != anchor.key.start
                    && (level == 0
                        || (position > anchors[level - 1].value.start
                            && position < anchors[level - 1].value.end))
                {
                    let direct = and(c, key_start, depth[level + 1]);
                    let matches = c.import_bit(unique_matches[level][position]);
                    let duplicate = and(c, direct, matches);
                    assert_false(c, duplicate);
                }
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
        if let Some((_, anchors, true)) = path {
            for (level, anchor) in anchors.iter().enumerate().take(anchors.len() - 1) {
                if position + 1 == anchor.value.end {
                    assert_true(c, pop);
                    assert_true(c, depth[level + 2]);
                }
            }
        }
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
        let mut sections: Vec<&mut [Wire]> = vec![
            &mut grammar,
            &mut lex,
            &mut depth,
            &mut kind,
            &mut selected_depth,
            &mut unicode,
        ];
        sections.extend(indices.iter_mut().map(|v| v.as_mut_slice()));
        c.checkpoint(&mut sections);
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

    fn accepts_path(
        body: &[u8],
        steps: &[JsonPathSegment],
        anchors: &[PathAnchor],
        unique: bool,
    ) -> bool {
        let mut c = Circuit::default();
        let bytes: Vec<_> = body.iter().map(|_| c.commit_byte()).collect();
        if path_member(&mut c, &bytes, steps, anchors, unique).is_err() {
            return false;
        }
        c.eval(&byte_inputs(body)).is_ok()
    }
    fn selection(body: &[u8], path: &[JsonPathSegment]) -> Vec<PathAnchor> {
        crate::json::values(body)
            .unwrap()
            .into_iter()
            .find(|v| v.path == path)
            .unwrap()
            .anchors
    }
    fn names(names: &[&str]) -> Vec<JsonPathSegment> {
        names
            .iter()
            .map(|n| JsonPathSegment::Member((*n).into()))
            .collect()
    }
    #[test]
    fn exact_paths_reject_sibling_and_nested_substitutions() {
        let body = br#"{"streakData":{"longestStreak":{"length":123}},"other":{"longestStreak":{"length":999}},"length":888}"#;
        let path = names(&["streakData", "longestStreak", "length"]);
        let anchors = selection(body, &path);
        assert!(accepts_path(body, &path, &anchors, false));
        assert!(accepts_path(body, &path, &anchors, true));
        let mut wrong = anchors.clone();
        let sibling = selection(body, &names(&["other", "longestStreak", "length"]));
        wrong[1..].clone_from_slice(&sibling[1..]);
        assert!(!accepts_path(body, &path, &wrong, false));
        let wrong = selection(body, &names(&["length"]));
        assert!(!accepts_path(body, &path, &wrong, false));
    }
    #[test]
    fn array_indices_count_only_direct_elements() {
        let body = br#"{"rows":[{"v":1,"junk":[1,2,3]},[3,4],{"v":123}]}"#;
        let path = vec![
            JsonPathSegment::Member("rows".into()),
            JsonPathSegment::Index(2),
            JsonPathSegment::Member("v".into()),
        ];
        let anchors = selection(body, &path);
        assert!(accepts_path(body, &path, &anchors, false));
        let mut wrong = path.clone();
        wrong[1] = JsonPathSegment::Index(0);
        assert!(!accepts_path(body, &wrong, &anchors, false));
        let array = br#"[0,{"junk":[1,2]},123]"#;
        let path = vec![JsonPathSegment::Index(2)];
        let anchors = selection(array, &path);
        assert!(accepts_path(array, &path, &anchors, true));
    }
    #[test]
    fn uniqueness_checks_escaped_duplicates_and_ancestors() {
        for body in [
            br#"{"a":{"v":1},"a":{"v":2}}"#.as_slice(),
            br#"{"a":{"v":1,"\u0076":2}}"#,
            br#"{"a":{"v":1},"\u0061":{"v":2}}"#,
        ] {
            let path = names(&["a", "v"]);
            let anchors = selection(body, &path);
            assert!(accepts_path(body, &path, &anchors, false));
            assert!(!accepts_path(body, &path, &anchors, true));
        }
        for body in [
            br#"{"\u0061":{"\u0076":1}}"#.as_slice(),
            br#"{"a":{"v":1},"other":{"v":2}}"#,
        ] {
            let path = names(&["a", "v"]);
            assert!(accepts_path(body, &path, &selection(body, &path), true));
        }
        let body = "{\"😀\":1,\"\\ud83d\\uDe00\":2}".as_bytes();
        let path = names(&["😀"]);
        assert!(!accepts_path(body, &path, &selection(body, &path), true));
    }
    #[test]
    fn path_depth_eight_and_malformed_grammar() {
        let body = br#"{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":1}}}}}}}}"#;
        let path = names(&["a", "b", "c", "d", "e", "f", "g", "h"]);
        assert!(accepts_path(body, &path, &selection(body, &path), true));
        let mut bad = body.to_vec();
        bad[5] = b']';
        assert!(!accepts_path(&bad, &path, &selection(body, &path), false));
        let body = br#"{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":1}}}}}}}}}"#;
        let path = names(&["a", "b", "c", "d", "e", "f", "g", "h", "i"]);
        assert!(!accepts_path(body, &path, &selection(body, &path), false));
    }
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
