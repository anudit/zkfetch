//! Boolean polynomials over authenticated bits. Linear expressions are free;
//! products stay inside degree-three constraints until an auxiliary bit is
//! necessary. Parser states are explicitly materialized at byte boundaries.
use crate::{Byte, Circuit, Term, Wire, field::Fe};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy)]
pub(crate) struct Bit(usize);
type Polynomial = Vec<Vec<Wire>>;
pub(crate) struct Algebra<'a> {
    circuit: &'a mut Circuit,
    expressions: Vec<Polynomial>,
    classes: BTreeMap<[usize; 8], ([Bit; 16], [Bit; 16])>,
    materialized: BTreeMap<usize, Bit>,
    interned: BTreeMap<Vec<Vec<usize>>, Bit>,
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
            classes: BTreeMap::new(),
            materialized: BTreeMap::new(),
            interned: BTreeMap::new(),
        }
    }
    fn push(&mut self, polynomial: Polynomial) -> Bit {
        let key: Vec<Vec<usize>> = polynomial
            .iter()
            .map(|m| m.iter().map(|w| w.0).collect())
            .collect();
        if let Some(id) = self.interned.get(&key) {
            return *id;
        }
        let id = Bit(self.expressions.len());
        self.expressions.push(polynomial);
        self.interned.insert(key, id);
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
        self.push(vec![vec![wire]])
    }
    pub fn public_bit(&mut self, bit: bool) -> Bit {
        self.push(if bit { vec![vec![]] } else { vec![] })
    }
    /// Retain a circuit wire across compiler checkpoints, without retaining an
    /// expression-table index that a checkpoint will invalidate.
    pub fn export_bit(&mut self, bit: Bit) -> Wire {
        let bit = self.commit(bit);
        match self.expressions[bit.0].as_slice() {
            [] => self.circuit.public_bit(false),
            [term] if term.is_empty() => self.circuit.public_bit(true),
            [term] if term.len() == 1 => term[0],
            _ => unreachable!("committed bit is constant or a single wire"),
        }
    }
    pub fn import_bit(&mut self, wire: Wire) -> Bit {
        self.input(wire)
    }
    pub fn xor_bit(&mut self, a: Bit, b: Bit) -> Bit {
        let mut terms = BTreeSet::new();
        for term in self.expressions[a.0].iter().chain(&self.expressions[b.0]) {
            let key: Vec<_> = term.iter().map(|w| w.0).collect();
            if !terms.insert(key.clone()) {
                terms.remove(&key);
            }
        }
        let owner = self.circuit.owner;
        self.push(
            terms
                .into_iter()
                .map(|ids| ids.into_iter().map(|id| Wire(id, owner)).collect())
                .collect(),
        )
    }
    pub fn not_bit(&mut self, a: Bit) -> Bit {
        let one = self.public_bit(true);
        self.xor_bit(a, one)
    }
    fn degree(&self, a: Bit) -> usize {
        self.expressions[a.0]
            .iter()
            .map(Vec::len)
            .max()
            .unwrap_or(0)
    }
    fn terms(&self, a: Bit) -> Vec<Term> {
        self.expressions[a.0]
            .iter()
            .map(|m| match m.as_slice() {
                [] => Term::Constant(Fe::ONE),
                [a] => Term::Linear(Fe::ONE, *a),
                [a, b] => Term::Quadratic(Fe::ONE, *a, *b),
                [a, b, c] => Term::Cubic(Fe::ONE, *a, *b, *c),
                _ => unreachable!("degree capped before materialization"),
            })
            .collect()
    }
    pub fn commit(&mut self, a: Bit) -> Bit {
        if let Some(value) = self.materialized.get(&a.0) {
            return *value;
        }
        if self.degree(a) == 0 {
            return a;
        }
        if self.degree(a) < 2 {
            let mut constant = Fe::ZERO;
            let mut terms = Vec::new();
            for m in &self.expressions[a.0] {
                if m.is_empty() {
                    constant = constant ^ Fe::ONE;
                } else {
                    terms.push((Fe::ONE, m[0]));
                }
            }
            let wire = self.circuit.linear_kind(terms, constant, true);
            let value = self.input(wire);
            self.materialized.insert(a.0, value);
            return value;
        }
        let wire = self.circuit.polynomial_bit(self.terms(a));
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
        let mut terms = BTreeSet::new();
        for left in &self.expressions[a.0] {
            for right in &self.expressions[b.0] {
                let mut monomial: Vec<_> = left.iter().chain(right).map(|w| w.0).collect();
                monomial.sort_unstable();
                monomial.dedup(); // x² = x for authenticated Boolean bits.
                if !terms.insert(monomial.clone()) {
                    terms.remove(&monomial);
                }
            }
        }
        let owner = self.circuit.owner;
        self.push(
            terms
                .into_iter()
                .map(|m| m.into_iter().map(|id| Wire(id, owner)).collect())
                .collect(),
        )
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
        let mut materialized = BTreeMap::new();
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
        self.materialized.clear();
        self.interned.clear();
        for (index, polynomial) in self.expressions.iter().enumerate() {
            let key = polynomial
                .iter()
                .map(|m| m.iter().map(|w| w.0).collect())
                .collect();
            self.interned.entry(key).or_insert(Bit(index));
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
        let (lo, hi) = if let Some(classes) = self.classes.get(&key) {
            *classes
        } else {
            let lo = self.nibble(&byte.0[..4]);
            let hi = self.nibble(&byte.0[4..]);
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
