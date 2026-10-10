//! Query-independent JSON parsing in resumable segments.
//!
//! The session parses the whole response body once and exports the parser
//! state every [`CHECKPOINT_SPACING`] bytes. The notary signs hiding AES
//! commitments to those states (see `checkpoint`), so an offline proof can
//! resume from the checkpoint before a window and parse only the window.
//!
//! The state machine is the one in `json_algebra` (same grammar, lexer,
//! UTF-8 and surrogate rules, bounded depth). Two additions make windows
//! composable without re-parsing what lies between them:
//!
//! - `stack[d]` holds `position + 1` of the byte that opened the container at
//!   depth `d` (entries at or above the current depth are stale). A key's
//!   enclosing container is therefore identified by a public position, which
//!   is how an offline path proof links each edge to its parent.
//! - Stack updates use "last write wins" chains per segment instead of a
//!   per-byte multiplexer: one committed write bit and one committed
//!   "no later write" bit per level and byte.
use crate::algebra::{Algebra, Bit};
use crate::{Byte, Circuit, Wire};

pub const CHECKPOINT_SPACING: usize = 32;
pub const LEVELS: usize = 8;
pub const POSITION_BITS: usize = 14;
pub const MAX_BODY: usize = (1 << POSITION_BITS) - 1;

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
pub(crate) const NSTATES: usize = 34;

/// Bits of the query-independent parser state, in canonical order.
pub const STATE_BITS: usize = 10 + NSTATES + (LEVELS + 1) + LEVELS + 4 + LEVELS * POSITION_BITS;

/// A parser state as circuit wires (bits), valid across compiler checkpoints.
#[derive(Clone)]
pub struct State {
    pub grammar: [Wire; 10],
    pub lex: [Wire; NSTATES],
    /// One-hot current depth 0..=LEVELS.
    pub depth: [Wire; LEVELS + 1],
    /// kind[d] = 1 for an object at depth d + 1.
    pub kind: [Wire; LEVELS],
    /// unicode_d, unicode_high, unicode_low, pair_required.
    pub unicode: [Wire; 4],
    /// Little-endian `position + 1` of each level's opening byte.
    pub stack: [[Wire; POSITION_BITS]; LEVELS],
}

impl State {
    /// The parser state before the first byte of a document.
    pub fn initial(c: &mut Circuit) -> Self {
        let zero = c.public_bit(false);
        let one = c.public_bit(true);
        let mut grammar = [zero; 10];
        grammar[ROOT] = one;
        let mut lex = [zero; NSTATES];
        lex[NONE] = one;
        let mut depth = [zero; LEVELS + 1];
        depth[0] = one;
        Self {
            grammar,
            lex,
            depth,
            kind: [zero; LEVELS],
            unicode: [zero; 4],
            stack: [[zero; POSITION_BITS]; LEVELS],
        }
    }
    /// A committed (witness) state, e.g. one opened from a checkpoint.
    pub fn committed(c: &mut Circuit) -> Self {
        Self::from_bits(&(0..STATE_BITS).map(|_| c.commit_bit()).collect::<Vec<_>>())
    }
    pub fn bits(&self) -> Vec<Wire> {
        let mut out = Vec::with_capacity(STATE_BITS);
        out.extend(self.grammar);
        out.extend(self.lex);
        out.extend(self.depth);
        out.extend(self.kind);
        out.extend(self.unicode);
        for level in &self.stack {
            out.extend(level);
        }
        out
    }
    pub fn from_bits(bits: &[Wire]) -> Self {
        assert_eq!(bits.len(), STATE_BITS);
        let mut at = 0;
        let mut take = |n: usize| {
            let slice = &bits[at..at + n];
            at += n;
            slice.to_vec()
        };
        let grammar = take(10).try_into().unwrap();
        let lex = take(NSTATES).try_into().unwrap();
        let depth = take(LEVELS + 1).try_into().unwrap();
        let kind = take(LEVELS).try_into().unwrap();
        let unicode = take(4).try_into().unwrap();
        let stack = std::array::from_fn(|_| take(POSITION_BITS).try_into().unwrap());
        Self {
            grammar,
            lex,
            depth,
            kind,
            unicode,
            stack,
        }
    }
    /// Committed states must be well formed: one-hot grammar, lexer and
    /// depth, and Boolean bits. (Bits are Boolean by construction of the
    /// committed-bit encoding; one-hotness is asserted here.)
    pub fn assert_well_formed(&self, c: &mut Circuit) {
        let mut a = Algebra::new(c);
        for group in [&self.grammar[..], &self.lex[..], &self.depth[..]] {
            let bits: Vec<_> = group.iter().map(|w| a.import_bit(*w)).collect();
            let mut sum = a.public_bit(false);
            for b in &bits {
                sum = a.xor_bit(sum, *b);
            }
            a.assert_true(sum);
            for i in 0..bits.len() {
                for j in i + 1..bits.len() {
                    let both = a.and_bit(bits[i], bits[j]);
                    a.assert_false(both);
                }
            }
        }
    }
}

/// Per-byte public events, valid until the byte's state transition.
pub struct Events {
    pub key_start: Bit,
    pub value_start: Bit,
    pub push: Bit,
    pub pop: Bit,
    /// Depth before this byte (one-hot).
    pub depth: Vec<Bit>,
    pub kind: Vec<Bit>,
    /// The previous value ended at or before this byte (value-extent check).
    pub value_complete: Bit,
}

/// Resumable parser over authenticated bytes at known absolute positions.
pub struct Parser<'c, 'a> {
    pub c: &'c mut Algebra<'a>,
    grammar: [Bit; 10],
    lex: [Bit; NSTATES],
    depth: Vec<Bit>,
    kind: Vec<Bit>,
    unicode: [Bit; 4],
    /// Stack at the start of the current segment, and the write bits since.
    stack_base: [[Wire; POSITION_BITS]; LEVELS],
    writes: Vec<(usize, [Wire; LEVELS])>,
    max_depth: usize,
    /// When set, the current state is these wires (template steps) and the
    /// symbolic bits above are stale until `materialize`.
    pending: Option<Vec<Wire>>,
    constants: Option<(Wire, Wire)>,
}

/// Inputs and outputs of the cached step template: grammar, lexer, depth,
/// kind and unicode bits (in that order), then the byte; outputs the same
/// state bits followed by the eight stack-write bits.
const CORE_BITS: usize = 10 + NSTATES + (LEVELS + 1) + LEVELS + 4;

fn step_template() -> &'static crate::template::Template {
    static TEMPLATE: std::sync::OnceLock<crate::template::Template> = std::sync::OnceLock::new();
    TEMPLATE.get_or_init(|| {
        let mut g = Circuit::default();
        let core: Vec<Wire> = (0..CORE_BITS).map(|_| g.commit_bit()).collect();
        let byte = g.commit_byte();
        let zero = g.public_bit(false);
        let mut bits = core.clone();
        bits.extend(std::iter::repeat_n(zero, LEVELS * POSITION_BITS));
        let state = State::from_bits(&bits);
        let mut a = Algebra::new(&mut g);
        let mut p = Parser::new(&mut a, &state, LEVELS);
        p.step(byte, 0, |_, _| {});
        let mut outputs = p.core_wires();
        outputs.extend(p.writes[0].1);
        drop(p);
        drop(a);
        crate::template::Template::new(g, outputs)
    })
}

impl<'c, 'a> Parser<'c, 'a> {
    pub fn new(c: &'c mut Algebra<'a>, state: &State, max_depth: usize) -> Self {
        assert!((1..=LEVELS).contains(&max_depth));
        let grammar = state.grammar.map(|w| c.import_bit(w));
        let lex = state.lex.map(|w| c.import_bit(w));
        let depth = state.depth[..=max_depth]
            .iter()
            .map(|w| c.import_bit(*w))
            .collect();
        let kind = state.kind[..max_depth]
            .iter()
            .map(|w| c.import_bit(*w))
            .collect();
        let unicode = state.unicode.map(|w| c.import_bit(w));
        if max_depth < LEVELS {
            // A shallower bound may only resume a state within it.
            for w in &state.depth[max_depth + 1..] {
                let bit = c.import_bit(*w);
                c.assert_false(bit);
            }
        }
        Self {
            c,
            grammar,
            lex,
            depth,
            kind,
            unicode,
            stack_base: state.stack,
            writes: Vec::new(),
            max_depth,
            pending: None,
            constants: None,
        }
    }

    fn constants(&mut self) -> (Wire, Wire) {
        if self.constants.is_none() {
            let zero = self.c.circuit().public_bit(false);
            let one = self.c.circuit().public_bit(true);
            self.constants = Some((zero, one));
        }
        self.constants.unwrap()
    }

    /// The current core state (grammar, lex, depth, kind, unicode) as wires.
    fn core_wires(&mut self) -> Vec<Wire> {
        if let Some(wires) = &self.pending {
            return wires.clone();
        }
        let (zero, one) = self.constants();
        let mut bits: Vec<Bit> = Vec::with_capacity(CORE_BITS);
        bits.extend(self.grammar);
        bits.extend(self.lex);
        bits.extend(self.depth.iter().copied());
        bits.extend(self.kind.iter().copied());
        bits.extend(self.unicode);
        let mut out: Vec<Wire> = bits.into_iter().map(|b| self.c.wire_of(b, zero, one)).collect();
        // Shallower parsers pad depth/kind to the full layout with zeros.
        if self.max_depth < LEVELS {
            let (g, rest) = out.split_at(10 + NSTATES);
            let (d, rest) = rest.split_at(self.max_depth + 1);
            let (k, u) = rest.split_at(self.max_depth);
            let mut full = g.to_vec();
            full.extend(d);
            full.extend(std::iter::repeat_n(zero, LEVELS - self.max_depth));
            full.extend(k);
            full.extend(std::iter::repeat_n(zero, LEVELS - self.max_depth));
            full.extend(u);
            out = full;
        }
        out
    }

    /// Re-import pending wires as symbolic bits for a hooked step or check.
    fn materialize(&mut self) {
        let Some(wires) = self.pending.take() else { return };
        let mut at = 0;
        let mut take = |n: usize| {
            let slice = wires[at..at + n].to_vec();
            at += n;
            slice
        };
        let grammar = take(10);
        let lex = take(NSTATES);
        let depth = take(LEVELS + 1);
        let kind = take(LEVELS);
        let unicode = take(4);
        for (i, w) in grammar.iter().enumerate() {
            self.grammar[i] = self.c.import_bit(*w);
        }
        for (i, w) in lex.iter().enumerate() {
            self.lex[i] = self.c.import_bit(*w);
        }
        self.depth = depth[..=self.max_depth].iter().map(|w| self.c.import_bit(*w)).collect();
        self.kind = kind[..self.max_depth].iter().map(|w| self.c.import_bit(*w)).collect();
        for (i, w) in unicode.iter().enumerate() {
            self.unicode[i] = self.c.import_bit(*w);
        }
    }

    /// Process one byte with no assertions: instantiate the cached step
    /// template (same relation as `step`) instead of recompiling it.
    pub fn step_plain(&mut self, byte: Byte, position: usize) {
        assert!(position < MAX_BODY);
        if self.max_depth != LEVELS {
            return self.step(byte, position, |_, _| {});
        }
        let mut inputs = self.core_wires();
        inputs.extend(byte.0);
        let outputs = step_template().instantiate(self.c.circuit(), &inputs);
        self.writes
            .push((position, outputs[CORE_BITS..].try_into().unwrap()));
        self.pending = Some(outputs[..CORE_BITS].to_vec());
    }

    fn eq(&mut self, byte: Byte, value: u8) -> Bit {
        self.c.range(byte, value, value)
    }
    fn any(&mut self, items: &[Bit]) -> Bit {
        let mut out = self.c.public_bit(false);
        for item in items {
            out = self.c.xor_bit(out, *item);
        }
        out
    }
    fn equals_any(&mut self, byte: Byte, values: &[u8]) -> Bit {
        let bits: Vec<_> = values.iter().map(|v| self.eq(byte, *v)).collect();
        self.any(&bits)
    }
    fn emit(&mut self, next: &mut [Bit], dest: usize, source: Bit, condition: Bit) {
        let term = self.c.and_bit(source, condition);
        next[dest] = self.c.xor_bit(next[dest], term);
    }

    /// Process one byte at absolute `position`. `hook` sees the byte's events
    /// before the transition (assert there); it must export anything it keeps.
    pub fn step(
        &mut self,
        byte: Byte,
        position: usize,
        hook: impl FnOnce(&mut Algebra<'a>, &Events),
    ) {
        assert!(position < MAX_BODY);
        self.materialize();
        let max_depth = self.max_depth;
        let ws = self.equals_any(byte, b" \t\n\r");
        let quote = self.eq(byte, b'"');
        let slash = self.eq(byte, b'\\');
        let open_obj = self.eq(byte, b'{');
        let close_obj = self.eq(byte, b'}');
        let open_arr = self.eq(byte, b'[');
        let close_arr = self.eq(byte, b']');
        let comma = self.eq(byte, b',');
        let colon = self.eq(byte, b':');
        let digit = self.c.range(byte, b'0', b'9');
        let digit0 = self.eq(byte, b'0');
        let nonzero = self.c.range(byte, b'1', b'9');
        let minus = self.eq(byte, b'-');
        let plus = self.eq(byte, b'+');
        let dot = self.eq(byte, b'.');
        let exponent = self.equals_any(byte, b"eE");
        let t = self.eq(byte, b't');
        let f = self.eq(byte, b'f');
        let n = self.eq(byte, b'n');
        let lex = self.lex;
        let grammar = self.grammar;
        let delimiter = self.any(&[ws, comma, close_obj, close_arr]);
        let numeric = self.any(&[lex[ZERO], lex[DIGITS], lex[FRAC], lex[EXPDIGITS]]);
        let num_end = self.c.and_bit(numeric, delimiter);
        let base = self.c.xor_bit(lex[NONE], num_end);

        let after = self.any(&[grammar[DONE], grammar[OCOMMA], grammar[ACOMMA]]);
        let value_complete = self.c.and_bit(after, base);

        let zero = self.c.public_bit(false);
        let mut next = [zero; 10];
        let hold = self.c.not_bit(base);
        for i in 0..10 {
            next[i] = self.c.and_bit(grammar[i], hold);
            let src = self.c.and_bit(grammar[i], base);
            self.emit(&mut next, i, src, ws);
        }
        let active: Vec<_> = grammar.iter().map(|g| self.c.and_bit(*g, base)).collect();
        let value_src = self.any(&[active[ROOT], active[OVAL], active[AVEND], active[AVAL]]);
        let key_src = self.any(&[active[OKEND], active[OKEY]]);
        let key_start = self.c.and_bit(key_src, quote);
        let string_start = self.c.and_bit(value_src, quote);
        let strings = self.c.xor_bit(key_start, string_start);
        let scalar = self.any(&[quote, minus, digit, t, f, n]);
        let scalar_start = self.c.and_bit(value_src, scalar);
        let container = self.c.xor_bit(open_obj, open_arr);
        let push = self.c.and_bit(value_src, container);
        let value_start = self.c.xor_bit(scalar_start, push);

        for (src, dest) in [(ROOT, DONE), (OVAL, OCOMMA), (AVEND, ACOMMA), (AVAL, ACOMMA)] {
            self.emit(&mut next, dest, active[src], scalar);
            self.emit(&mut next, OKEND, active[src], open_obj);
            self.emit(&mut next, AVEND, active[src], open_arr);
        }
        self.emit(&mut next, COLON, key_src, quote);
        self.emit(&mut next, OVAL, active[COLON], colon);
        self.emit(&mut next, OKEY, active[OCOMMA], comma);
        self.emit(&mut next, AVAL, active[ACOMMA], comma);
        let obj_end_src = self.any(&[active[OKEND], active[OCOMMA]]);
        let arr_end_src = self.any(&[active[AVEND], active[ACOMMA]]);
        let obj_end = self.c.and_bit(obj_end_src, close_obj);
        let arr_end = self.c.and_bit(arr_end_src, close_arr);
        let pop = self.c.xor_bit(obj_end, arr_end);

        let events = Events {
            key_start,
            value_start,
            push,
            pop,
            depth: self.depth.clone(),
            kind: self.kind.clone(),
            value_complete,
        };
        hook(self.c, &events);

        // Stack writes: level d receives `position + 1` on a push at depth d.
        let mut write = [zero; LEVELS];
        for d in 0..max_depth {
            write[d] = self.c.and_bit(push, self.depth[d]);
        }
        let write = write.map(|w| self.c.export_bit(w));
        self.writes.push((position, write));

        let depth = &self.depth;
        let mut parent_obj = zero;
        for i in 2..=max_depth {
            let bit = self.c.and_bit(depth[i], self.kind[i - 2]);
            parent_obj = self.c.xor_bit(parent_obj, bit);
        }
        let parent_root = depth[1];
        let parent_nonroot = self.c.not_bit(parent_root);
        let not_obj = self.c.not_bit(parent_obj);
        let parent_arr = self.c.and_bit(parent_nonroot, not_obj);
        self.emit(&mut next, DONE, pop, parent_root);
        self.emit(&mut next, OCOMMA, pop, parent_obj);
        self.emit(&mut next, ACOMMA, pop, parent_arr);
        let overflow = self.c.and_bit(push, self.depth[max_depth]);
        self.c.assert_false(overflow);
        let movement = self.c.xor_bit(push, pop);
        let stationary = self.c.not_bit(movement);
        let mut new_depth = vec![zero; max_depth + 1];
        for i in 0..=max_depth {
            let stay = self.c.and_bit(self.depth[i], stationary);
            let up = if i > 0 { self.c.and_bit(self.depth[i - 1], push) } else { zero };
            let down = if i < max_depth { self.c.and_bit(self.depth[i + 1], pop) } else { zero };
            let a = self.c.xor_bit(stay, up);
            new_depth[i] = self.c.xor_bit(a, down);
            if i < max_depth {
                let w = self.c.and_bit(self.depth[i], push);
                let difference = self.c.xor_bit(self.kind[i], open_obj);
                let change = self.c.and_bit(w, difference);
                self.kind[i] = self.c.xor_bit(self.kind[i], change);
            }
        }

        let mut nl = [zero; NSTATES];
        let numeric_or_literal = self.any(&[minus, digit, t, f, n]);
        let numeric_or_literal = self.c.and_bit(value_src, numeric_or_literal);
        let token = self.c.xor_bit(strings, numeric_or_literal);
        let not_token = self.c.not_bit(token);
        nl[NONE] = self.c.and_bit(base, not_token);
        nl[STRING] = strings;
        for (symbol, dest) in [(minus, MINUS), (digit0, ZERO), (nonzero, DIGITS), (t, T1), (f, F1), (n, N1)] {
            self.emit(&mut nl, dest, value_src, symbol);
        }
        let normal = self.c.range(byte, 0x20, 0x7f);
        let special = self.c.xor_bit(quote, slash);
        let nonspecial = self.c.not_bit(special);
        let normal = self.c.and_bit(normal, nonspecial);
        self.emit(&mut nl, STRING, lex[STRING], normal);
        self.emit(&mut nl, NONE, lex[STRING], quote);
        self.emit(&mut nl, ESC, lex[STRING], slash);
        let escaped = self.equals_any(byte, b"\"\\/bfnrt");
        self.emit(&mut nl, STRING, lex[ESC], escaped);
        let u = self.eq(byte, b'u');
        self.emit(&mut nl, U1, lex[ESC], u);
        let hex_lower = self.c.range(byte, b'a', b'f');
        let hex_upper = self.c.range(byte, b'A', b'F');
        let hex = self.any(&[digit, hex_lower, hex_upper]);
        self.emit(&mut nl, U2, lex[U1], hex);
        self.emit(&mut nl, U3, lex[U2], hex);
        self.emit(&mut nl, U4, lex[U3], hex);
        let [mut unicode_d, mut unicode_high, mut unicode_low, mut pair_required] = self.unicode;
        let d = self.equals_any(byte, b"dD");
        let first_change = self.c.xor_bit(unicode_d, d);
        let first_change = self.c.and_bit(lex[U1], first_change);
        unicode_d = self.c.xor_bit(unicode_d, first_change);
        let high_char = self.equals_any(byte, b"89aAbB");
        let low_char = self.equals_any(byte, b"cCdDeEfF");
        let high = self.c.and_bit(unicode_d, high_char);
        let low = self.c.and_bit(unicode_d, low_char);
        let change = self.c.xor_bit(unicode_high, high);
        let change = self.c.and_bit(lex[U2], change);
        unicode_high = self.c.xor_bit(unicode_high, change);
        let change = self.c.xor_bit(unicode_low, low);
        let change = self.c.and_bit(lex[U2], change);
        unicode_low = self.c.xor_bit(unicode_low, change);
        let not_required = self.c.not_bit(pair_required);
        let not_high = self.c.not_bit(unicode_high);
        let not_low = self.c.not_bit(unicode_low);
        let ordinary = self.c.and_bit(not_high, not_low);
        let ordinary = self.c.and_bit(ordinary, not_required);
        let paired = self.c.and_bit(pair_required, unicode_low);
        let allowed = self.c.xor_bit(ordinary, paired);
        let allowed = self.c.and_bit(allowed, hex);
        self.emit(&mut nl, STRING, lex[U4], allowed);
        let high_first = self.c.and_bit(unicode_high, not_required);
        let high_first = self.c.and_bit(high_first, hex);
        self.emit(&mut nl, PAIRSLASH, lex[U4], high_first);
        self.emit(&mut nl, PAIRU, lex[PAIRSLASH], slash);
        self.emit(&mut nl, U1, lex[PAIRU], u);
        let pair_set = self.c.and_bit(lex[PAIRU], u);
        let pair_hold = self.c.not_bit(lex[U4]);
        let pair_old = self.c.and_bit(pair_required, pair_hold);
        pair_required = self.c.xor_bit(pair_old, pair_set);
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
            let condition = self.c.range(byte, lo, hi);
            self.emit(&mut nl, dest, lex[src], condition);
        }
        for (value, dest) in [(0xe0, E0), (0xed, ED), (0xf0, F0), (0xf4, F4)] {
            let condition = self.eq(byte, value);
            self.emit(&mut nl, dest, lex[STRING], condition);
        }
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
            self.emit(&mut nl, dest, lex[src], condition);
        }
        let sign = self.c.xor_bit(plus, minus);
        self.emit(&mut nl, EXPSIGN, lex[EXP], sign);
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
            let condition = self.eq(byte, symbol);
            self.emit(&mut nl, dest, lex[src], condition);
        }
        self.grammar = next;
        self.lex = nl;
        self.depth = new_depth;
        self.unicode = [unicode_d, unicode_high, unicode_low, pair_required];
        let mut sections: Vec<&mut [Bit]> = vec![
            &mut self.grammar,
            &mut self.lex,
            &mut self.depth,
            &mut self.kind,
            &mut self.unicode,
        ];
        self.c.checkpoint(&mut sections);
    }

    /// The stack entry of `level` after the bytes processed so far, as
    /// committed bits ("last write wins" over this segment's writes).
    fn stack_level(&mut self, level: usize) -> [Wire; POSITION_BITS] {
        if level >= self.max_depth {
            return self.stack_base[level];
        }
        // later[i] = no write at this level after writes[i].
        let mut later = Vec::with_capacity(self.writes.len());
        let mut none_after = self.c.public_bit(true);
        for (_, write) in self.writes.iter().rev() {
            later.push(none_after);
            let w = self.c.import_bit(write[level]);
            let not_w = self.c.not_bit(w);
            let both = self.c.and_bit(none_after, not_w);
            none_after = self.c.commit(both);
        }
        later.reverse();
        let untouched = none_after;
        std::array::from_fn(|bit| {
            let old = self.c.import_bit(self.stack_base[level][bit]);
            let mut value = self.c.and_bit(old, untouched);
            for ((position, write), keep) in self.writes.iter().zip(&later) {
                if (position + 1) >> bit & 1 == 1 {
                    let w = self.c.import_bit(write[level]);
                    let last = self.c.and_bit(w, *keep);
                    value = self.c.xor_bit(value, last);
                }
            }
            let value = self.c.commit(value);
            self.c.export_bit(value)
        })
    }

    /// Assert that the stack entry of `level` equals `position + 1` now,
    /// without committing the whole stack.
    pub fn assert_stack(&mut self, level: usize, opened_at: usize) {
        let value = self.stack_level(level);
        for (bit, wire) in value.iter().enumerate() {
            let b = self.c.import_bit(*wire);
            if (opened_at + 1) >> bit & 1 == 1 {
                self.c.assert_true(b);
            } else {
                self.c.assert_false(b);
            }
        }
    }

    /// The full state after the bytes processed so far; starts a new segment.
    pub fn export(&mut self) -> State {
        if self.pending.is_some() {
            let core = self.core_wires();
            let stack = std::array::from_fn(|level| self.stack_level(level));
            self.stack_base = stack;
            self.writes.clear();
            let mut bits = core;
            for level in &stack {
                bits.extend(level);
            }
            return State::from_bits(&bits);
        }
        let zero = self.c.public_bit(false);
        let mut depth = vec![zero; LEVELS + 1];
        depth[..=self.max_depth].copy_from_slice(&self.depth);
        let mut kind = vec![zero; LEVELS];
        kind[..self.max_depth].copy_from_slice(&self.kind);
        let stack = std::array::from_fn(|level| self.stack_level(level));
        let grammar = self.grammar.map(|b| self.c.export_bit(b));
        let lex = self.lex.map(|b| self.c.export_bit(b));
        let depth: Vec<_> = depth.into_iter().map(|b| self.c.export_bit(b)).collect();
        let kind: Vec<_> = kind.into_iter().map(|b| self.c.export_bit(b)).collect();
        let unicode = self.unicode.map(|b| self.c.export_bit(b));
        self.stack_base = stack;
        self.writes.clear();
        State {
            grammar,
            lex,
            depth: depth.try_into().unwrap(),
            kind: kind.try_into().unwrap(),
            unicode,
            stack,
        }
    }

    /// The document is complete here: one top-level value, closed, no token open.
    pub fn assert_complete(&mut self) {
        self.materialize();
        let lex = self.lex;
        let endlex = self.any(&[lex[NONE], lex[ZERO], lex[DIGITS], lex[FRAC], lex[EXPDIGITS]]);
        self.c.assert_true(endlex);
        self.c.assert_true(self.grammar[DONE]);
        self.c.assert_true(self.depth[0]);
    }
}

/// Session relation: parse the whole body from the document start and return
/// the state at every checkpoint boundary (positions SPACING, 2·SPACING, …
/// strictly inside the body). Asserts a complete JSON document of bounded depth.
pub fn checkpoint_states(c: &mut Circuit, body: &[Byte]) -> Vec<State> {
    assert!(!body.is_empty() && body.len() <= MAX_BODY);
    let initial = State::initial(c);
    let mut a = Algebra::new(c);
    a.cache_byte_classes();
    let mut p = Parser::new(&mut a, &initial, LEVELS);
    let mut states = Vec::new();
    for (position, byte) in body.iter().enumerate() {
        if position > 0 && position % CHECKPOINT_SPACING == 0 {
            states.push(p.export());
        }
        p.step_plain(*byte, position);
    }
    p.assert_complete();
    states
}

/// Native values of checkpoint states from an evaluated witness.
pub fn state_values(w: &crate::Witness, state: &State) -> Vec<bool> {
    state.bits().into_iter().map(|b| w.value(b) == crate::field::Fe::ONE).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::byte_inputs;

    fn accepts(document: &[u8]) -> bool {
        let mut c = Circuit::default();
        let bytes: Vec<_> = (0..document.len()).map(|_| c.commit_byte()).collect();
        checkpoint_states(&mut c, &bytes);
        c.eval(&byte_inputs(document)).is_ok()
    }

    #[test]
    fn grammar_agrees_with_serde_on_valid_and_invalid_documents() {
        let cases: &[&[u8]] = &[
            br#"{"a":1}"#,
            br#"{"a":[1,2,{"b":"x\"y"}],"c":true,"d":null,"e":-1.5e+3}"#,
            b" { \"k\" : \"\\u00e9\\ud83d\\ude00\" } ",
            br#"[1,2,3]"#,
            br#"{"a":1,}"#,
            br#"{"a":01}"#,
            br#"{"a":"\ud83d"}"#,
            br#"{"a" 1}"#,
            br#"{"a":1}}"#,
            br#"{"a":[1,2}"#,
            br#"{"a":tru}"#,
            "{\"a\":\"\u{e9}\"}".as_bytes(),
            b"{\"a\":\"\xff\"}",
            br#"{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":1}}}}}}}}"#,
            br#"{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":1}}}}}}}}}"#,
        ];
        for document in cases {
            let serde = serde_json::from_slice::<serde_json::Value>(document).is_ok()
                && crate::json::required_depth(document) <= LEVELS;
            assert_eq!(accepts(document), serde, "{}", String::from_utf8_lossy(document));
        }
    }

    #[test]
    fn exported_stack_names_each_open_container() {
        let document = br#"{"padding":"0123456789012345678901","x":{"y":[1,{"z":2,"w":[[3],{"v":"]}"}]},4]},"t":[{"u":{}}]}"#;
        let mut c = Circuit::default();
        let bytes: Vec<_> = (0..document.len()).map(|_| c.commit_byte()).collect();
        let states = checkpoint_states(&mut c, &bytes);
        let w = c.eval(&byte_inputs(document)).unwrap();
        assert_eq!(states.len(), (document.len() - 1) / CHECKPOINT_SPACING);
        let one = crate::field::Fe::ONE;
        for (index, state) in states.iter().enumerate() {
            let at = (index + 1) * CHECKPOINT_SPACING;
            let mut opened = Vec::new();
            let (mut quoted, mut escaped) = (false, false);
            for (i, &b) in document[..at].iter().enumerate() {
                if quoted {
                    if escaped { escaped = false } else if b == b'\\' { escaped = true } else if b == b'"' { quoted = false }
                    continue;
                }
                match b {
                    b'"' => quoted = true,
                    b'{' | b'[' => opened.push(i),
                    b'}' | b']' => { opened.pop(); }
                    _ => {}
                }
            }
            let depth = state.depth.iter().position(|b| w.value(*b) == one).unwrap();
            assert_eq!(depth, opened.len(), "checkpoint {at}");
            for (level, position) in opened.iter().enumerate() {
                let value: usize = state.stack[level]
                    .iter()
                    .enumerate()
                    .map(|(i, b)| usize::from(w.value(*b) == one) << i)
                    .sum();
                assert_eq!(value, position + 1, "checkpoint {at} level {level}");
            }
        }
    }
}

#[cfg(test)]
mod cost {
    use super::*;
    #[test]
    #[ignore = "diagnostic"]
    fn session_checkpoint_cost_per_byte() {
        let body = format!(r#"{{"pad":"{}","streakData":{{"longestStreak":{{"length":123}}}}}}"#, "x".repeat(950));
        let mut c = Circuit::default();
        let bytes: Vec<_> = (0..body.len()).map(|_| c.commit_byte()).collect();
        let base = c.committed_bits();
        for _ in 1..std::env::var("ZKF_REPEAT").ok().and_then(|v| v.parse().ok()).unwrap_or(1usize) {
            let mut c2 = Circuit::default();
            let bytes2: Vec<_> = (0..body.len()).map(|_| c2.commit_byte()).collect();
            checkpoint_states(&mut c2, &bytes2);
        }
        let started = std::time::Instant::now();
        let states = checkpoint_states(&mut c, &bytes);
        println!(
            "checkpoint-cost bytes={} states={} bits_per_byte={:.1} constraints={} build_ms={:.1}",
            body.len(),
            states.len(),
            (c.committed_bits() - base) as f64 / body.len() as f64,
            c.constraint_count(),
            started.elapsed().as_secs_f64() * 1000.0
        );
    }
}
