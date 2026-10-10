//! Boolean polynomials over authenticated bits. Linear expressions are free;
//! products stay inside degree-three constraints until an auxiliary bit is
//! necessary. Parser states are explicitly materialized at byte boundaries.
use crate::{Byte, Circuit, Term, Wire, field::Fe};
use rustc_hash::FxHashMap;
use std::collections::BTreeMap;
use std::rc::Rc;

#[derive(Clone, Copy)]
pub(crate) struct Bit(usize);
/// A monomial of degree <= 3: wire ids + 1 in ascending order, zero padded.
/// Lexicographic order on this array equals the order of the id vectors it
/// replaces (a proper prefix sorts first), so emitted terms are unchanged.
type Mono = [u32; 3];
/// Sorted, duplicate-free XOR of monomials.
type Polynomial = Vec<Mono>;
const CONSTANT: Mono = [0; 3];
pub(crate) struct Algebra<'a> {
    circuit: &'a mut Circuit,
    expressions: Vec<Rc<[Mono]>>,
    cache_classes: bool,
    stable_classes: BTreeMap<[usize; 8], ([Wire; 16], [Wire; 16])>,
    classes: BTreeMap<[usize; 8], ([Bit; 16], [Bit; 16])>,
    materialized: FxHashMap<usize, Bit>,
    interned: FxHashMap<Rc<[Mono]>, Bit>,
    ranges: FxHashMap<([usize; 8], u8, u8), Bit>,
}

fn mono_degree(m: &Mono) -> usize {
    m.iter().take_while(|&&x| x != 0).count()
}
fn mono_of(wire: Wire) -> Mono {
    [u32::try_from(wire.0 + 1).expect("wire id fits u32"), 0, 0]
}
/// Product of two monomials over Boolean bits (x² = x). The caller keeps the
/// total degree at most three.
fn mono_mul(a: &Mono, b: &Mono) -> Mono {
    let mut ids = [0u32; 6];
    let mut n = 0;
    for &x in a.iter().chain(b).filter(|&&x| x != 0) {
        ids[n] = x;
        n += 1;
    }
    let ids = &mut ids[..n];
    ids.sort_unstable();
    let mut out = [0u32; 3];
    let mut k = 0;
    for &x in ids.iter() {
        if k == 0 || out[k - 1] != x {
            assert!(k < 3, "degree capped before multiplication");
            out[k] = x;
            k += 1;
        }
    }
    out
}
/// XOR of two sorted, duplicate-free polynomials (sorted merge with cancellation).
fn xor_sorted(a: &[Mono], b: &[Mono]) -> Polynomial {
    let mut out = Vec::with_capacity(a.len() + b.len());
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => {
                out.push(a[i]);
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                out.push(b[j]);
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                i += 1;
                j += 1;
            }
        }
    }
    out.extend_from_slice(&a[i..]);
    out.extend_from_slice(&b[j..]);
    out
}
/// Sort an arbitrary monomial list and cancel equal pairs.
fn normalize(mut monos: Vec<Mono>) -> Polynomial {
    monos.sort_unstable();
    let mut out = Vec::with_capacity(monos.len());
    for m in monos {
        if out.last() == Some(&m) {
            out.pop();
        } else {
            out.push(m);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::byte_inputs;
    #[test]
    fn classes_match_every_byte() {
        let ranges = [
            (0, 255),
            (b'0', b'9'),
            (b'1', b'9'),
            (b'a', b'f'),
            (b'A', b'F'),
            (0x20, 0x7f),
            (0x80, 0xbf),
            (0xc2, 0xdf),
            (0xe1, 0xec),
            (0xee, 0xef),
            (0xf1, 0xf3),
            (0x90, 0xbf),
        ];
        for value in 0..=255u8 {
            let mut c = Circuit::default();
            let input = c.commit_byte();
            let mut a = Algebra::new(&mut c);
            for (low, high) in ranges {
                let class = a.range(input, low, high);
                if low <= value && value <= high {
                    a.assert_true(class);
                } else {
                    a.assert_false(class);
                }
            }
            drop(a);
            c.eval(&byte_inputs(&[value])).unwrap();
        }
    }
}
impl<'a> Algebra<'a> {
    pub fn new(circuit: &'a mut Circuit) -> Self {
        Self {
            circuit,
            expressions: Vec::new(),
            cache_classes: false,
            stable_classes: BTreeMap::new(),
            classes: BTreeMap::new(),
            materialized: FxHashMap::default(),
            interned: FxHashMap::default(),
            ranges: FxHashMap::default(),
        }
    }
    /// Reuse authenticated nibble indicators across compiler checkpoints.
    /// Keys are circuit wire IDs, never private byte values or expression IDs.
    pub fn cache_byte_classes(&mut self) {
        self.cache_classes = true;
    }
    fn wire(&self, id: u32) -> Wire {
        Wire(id as usize - 1, self.circuit.owner)
    }
    fn push(&mut self, polynomial: Polynomial) -> Bit {
        if let Some(id) = self.interned.get(polynomial.as_slice()) {
            return *id;
        }
        let id = Bit(self.expressions.len());
        let shared: Rc<[Mono]> = polynomial.into();
        self.expressions.push(shared.clone());
        self.interned.insert(shared, id);
        id
    }
    fn input(&mut self, wire: Wire) -> Bit {
        if let crate::Op::Public(value) = self.circuit.ops[wire.0] {
            assert!(value == Fe::ZERO || value == Fe::ONE);
            return self.public_bit(value == Fe::ONE);
        }
        if let crate::Op::Linear {
            ref terms,
            constant,
            ..
        } = self.circuit.ops[wire.0]
        {
            if terms.is_empty() && (constant == Fe::ZERO || constant == Fe::ONE) {
                return self.public_bit(constant == Fe::ONE);
            }
        }
        self.push(vec![mono_of(wire)])
    }
    pub fn public_bit(&mut self, bit: bool) -> Bit {
        self.push(if bit { vec![CONSTANT] } else { vec![] })
    }
    /// Retain a circuit wire across compiler checkpoints, without retaining an
    /// expression-table index that a checkpoint will invalidate.
    pub fn export_bit(&mut self, bit: Bit) -> Wire {
        let bit = self.commit(bit);
        match &self.expressions[bit.0][..] {
            [] => self.circuit.public_bit(false),
            [term] if *term == CONSTANT => self.circuit.public_bit(true),
            [term] if mono_degree(term) == 1 => self.wire(term[0]),
            _ => unreachable!("committed bit is constant or a single wire"),
        }
    }
    /// The wire behind a bit that is already a single wire or a constant,
    /// without adding ops (committing first if it is a larger polynomial).
    pub fn wire_of(&mut self, bit: Bit, zero: Wire, one: Wire) -> Wire {
        match &self.expressions[bit.0][..] {
            [] => zero,
            [m] if *m == CONSTANT => one,
            [m] if mono_degree(m) == 1 => self.wire(m[0]),
            _ => self.export_bit(bit),
        }
    }
    pub fn circuit(&mut self) -> &mut Circuit {
        self.circuit
    }
    pub fn import_bit(&mut self, wire: Wire) -> Bit {
        self.input(wire)
    }
    pub fn xor_bit(&mut self, a: Bit, b: Bit) -> Bit {
        let sum = xor_sorted(&self.expressions[a.0], &self.expressions[b.0]);
        self.push(sum)
    }
    pub fn not_bit(&mut self, a: Bit) -> Bit {
        let one = self.public_bit(true);
        self.xor_bit(a, one)
    }
    fn degree(&self, a: Bit) -> usize {
        self.expressions[a.0].iter().map(mono_degree).max().unwrap_or(0)
    }
    fn terms(&self, a: Bit) -> Vec<Term> {
        self.expressions[a.0]
            .iter()
            .map(|m| match mono_degree(m) {
                0 => Term::Constant(Fe::ONE),
                1 => Term::Linear(Fe::ONE, self.wire(m[0])),
                2 => Term::Quadratic(Fe::ONE, self.wire(m[0]), self.wire(m[1])),
                _ => Term::Cubic(Fe::ONE, self.wire(m[0]), self.wire(m[1]), self.wire(m[2])),
            })
            .collect()
    }
    pub fn commit(&mut self, a: Bit) -> Bit {
        if let Some(value) = self.materialized.get(&a.0) {
            return *value;
        }
        let degree = self.degree(a);
        if degree == 0 {
            return a;
        }
        let wire = if degree < 2 {
            let mut constant = Fe::ZERO;
            let mut terms = Vec::new();
            for m in self.expressions[a.0].iter() {
                if *m == CONSTANT {
                    constant = constant ^ Fe::ONE;
                } else {
                    terms.push((Fe::ONE, self.wire(m[0])));
                }
            }
            self.circuit.linear_kind(terms, constant, true)
        } else {
            self.circuit.polynomial_bit(self.terms(a))
        };
        let value = self.input(wire);
        self.materialized.insert(a.0, value);
        value
    }
    pub fn and_bit(&mut self, mut a: Bit, mut b: Bit) -> Bit {
        if self.degree(a) + self.degree(b) > 3
            || self.expressions[a.0].len() * self.expressions[b.0].len() > 64
        {
            if self.degree(a) >= self.degree(b) {
                a = self.commit(a);
            } else {
                b = self.commit(b);
            }
        }
        if self.degree(a) + self.degree(b) > 3
            || self.expressions[a.0].len() * self.expressions[b.0].len() > 64
        {
            a = self.commit(a);
            b = self.commit(b);
        }
        let (left, right) = (&self.expressions[a.0], &self.expressions[b.0]);
        let mut products = Vec::with_capacity(left.len() * right.len());
        for l in left.iter() {
            for r in right.iter() {
                products.push(mono_mul(l, r));
            }
        }
        let product = normalize(products);
        self.push(product)
    }
    pub fn assert_true(&mut self, a: Bit) {
        let one = self.public_bit(true);
        let difference = self.xor_bit(a, one);
        self.assert_false(difference);
    }
    pub fn assert_false(&mut self, a: Bit) {
        self.circuit.assert_zero(self.terms(a));
    }
    pub fn assert_equal(&mut self, a: Bit, b: Bit) {
        let difference = self.xor_bit(a, b);
        self.assert_false(difference);
    }
    pub fn assert_byte(&mut self, byte: Byte, value: u8) {
        self.circuit.assert_byte(byte, value);
    }
    /// Drop compiler expressions at each byte boundary. Only parser/stack
    /// states survive; this does not retain a secret trace in the builder.
    pub fn checkpoint(&mut self, sections: &mut [&mut [Bit]]) {
        let mut live = Vec::new();
        let mut materialized = FxHashMap::default();
        for section in sections.iter_mut() {
            for bit in section.iter_mut() {
                let value = *materialized
                    .entry(bit.0)
                    .or_insert_with(|| self.commit(*bit));
                live.push(self.expressions[value.0].clone());
            }
        }
        self.expressions = live;
        self.classes.clear();
        self.ranges.clear();
        self.materialized.clear();
        self.interned.clear();
        for (index, polynomial) in self.expressions.iter().enumerate() {
            self.interned.entry(polynomial.clone()).or_insert(Bit(index));
        }
        let mut index = 0;
        for section in sections {
            for bit in section.iter_mut() {
                *bit = Bit(index);
                index += 1;
            }
        }
    }

    fn nibble(&mut self, bits: &[Wire]) -> [Bit; 16] {
        let input: Vec<_> = bits.iter().map(|w| self.input(*w)).collect();
        let zero = self.public_bit(false);
        let mut pairs = [zero; 4];
        for (value, pair) in pairs.iter_mut().enumerate() {
            let a = if value & 1 == 0 {
                self.not_bit(input[0])
            } else {
                input[0]
            };
            let b = if value & 2 == 0 {
                self.not_bit(input[1])
            } else {
                input[1]
            };
            let expr = self.and_bit(a, b);
            *pair = self.commit(expr);
        }
        std::array::from_fn(|value| {
            let a = if value & 4 == 0 {
                self.not_bit(input[2])
            } else {
                input[2]
            };
            let b = if value & 8 == 0 {
                self.not_bit(input[3])
            } else {
                input[3]
            };
            let pair = self.and_bit(a, b);
            let expr = self.and_bit(pairs[value & 3], pair);
            self.commit(expr)
        })
    }
    /// Shared nibble indicators authenticate all byte classes without
    /// rebuilding Boolean comparators for every punctuation/range test.
    pub fn range(&mut self, byte: Byte, low: u8, high: u8) -> Bit {
        let key = byte.0.map(|w| w.0);
        if let Some(bit) = self.ranges.get(&(key, low, high)) {
            return *bit;
        }
        let result = self.range_uncached(byte, key, low, high);
        self.ranges.insert((key, low, high), result);
        result
    }
    fn range_uncached(&mut self, _byte: Byte, key: [usize; 8], low: u8, high: u8) -> Bit {
        let byte = _byte;
        let (lo, hi) = if let Some(classes) = self.classes.get(&key) {
            *classes
        } else {
            let (lo, hi) = if let Some((lo, hi)) = self.stable_classes.get(&key).copied() {
                (lo.map(|w| self.import_bit(w)), hi.map(|w| self.import_bit(w)))
            } else {
                let lo = self.nibble(&byte.0[..4]);
                let hi = self.nibble(&byte.0[4..]);
                if self.cache_classes {
                    let wires = (lo.map(|b| self.export_bit(b)), hi.map(|b| self.export_bit(b)));
                    self.stable_classes.insert(key, wires);
                }
                (lo, hi)
            };
            self.classes.insert(key, (lo, hi));
            (lo, hi)
        };
        let mut result = self.public_bit(false);
        for h in 0..16 {
            let mut lows = self.public_bit(false);
            for l in 0..16 {
                let value = (h * 16 + l) as u8;
                if low <= value && value <= high {
                    lows = self.xor_bit(lows, lo[l]);
                }
            }
            let class = self.and_bit(hi[h], lows);
            result = self.xor_bit(result, class);
        }
        result
    }
}
