//! Reference IR for D1/D3. No proof-system API is exposed until a backend
//! authenticates every input and enforces every constraint.
pub mod aes;
mod aes_norm;
mod algebra;
pub mod backend;
pub mod checkpoint;
pub mod field;
pub mod gcm;
pub mod json;
pub mod json_algebra;
pub mod json_circuit;
pub mod json_segment;
pub mod json_window;
pub mod predicates;
pub mod response;
pub mod sha256;
pub mod sha512;
pub mod stream;
mod template;
pub mod tls;

use field::{Fe, byte_inverse};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Opaque, topologically ordered edge. Edges must belong to their builder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wire(usize, u64);

/// A byte is eight committed/derived GF(2) edges, least significant bit first.
#[derive(Clone, Copy, Debug)]
pub struct Byte([Wire; 8]);

#[derive(Clone, Debug)]
enum Op {
    Input {
        index: usize,
        bit: bool,
    },
    Public(Fe),
    Linear {
        terms: Vec<(Fe, Wire)>,
        constant: Fe,
        bit: bool,
    },
    Product(Wire, Wire),
    BitProduct(Wire, Wire),
    /// A Boolean auxiliary hint constrained by a polynomial of degree <= 3.
    PolynomialBit(Vec<Term>),
    AesHint {
        input: std::sync::Arc<[Term]>,
        bit: usize,
        norm: bool,
    },
    InverseBit {
        input: Byte,
        bit: usize,
    },
}

/// One monomial of degree at most three. Fixed arity avoids arbitrary degrees.
#[derive(Clone, Debug)]
pub enum Term {
    Constant(Fe),
    Linear(Fe, Wire),
    Quadratic(Fe, Wire, Wire),
    Cubic(Fe, Wire, Wire, Wire),
}

impl Term {
    fn eval(&self, values: &[Fe]) -> Fe {
        match *self {
            Self::Constant(c) => c,
            Self::Linear(c, x) => values[x.0].scale_public(c),
            Self::Quadratic(c, x, y) => (values[x.0] * values[y.0]).scale_public(c),
            Self::Cubic(c, x, y, z) => (values[x.0] * values[y.0] * values[z.0]).scale_public(c),
        }
    }
}

/// Immutable validation capability. Holding it borrows both the circuit and
/// witness, so neither can change between validation and backend use.
pub struct EvaluatedWitness<'a> {
    circuit: &'a Circuit,
    witness: Witness,
}
impl EvaluatedWitness<'_> {
    pub fn checked(&self) -> CheckedWitness<'_> {
        CheckedWitness {
            circuit: self.circuit,
            witness: &self.witness,
        }
    }
}
impl CheckedWitness<'_> {
    pub fn circuit(&self) -> &Circuit {
        self.circuit
    }
    pub fn witness(&self) -> &Witness {
        self.witness
    }
}
pub struct CheckedWitness<'a> {
    circuit: &'a Circuit,
    witness: &'a Witness,
}

/// Secret assignment, excluded from the circuit and erased on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Witness {
    values: Vec<Fe>,
    owner: u64,
}

impl Witness {
    pub fn value(&self, wire: Wire) -> Fe {
        assert_eq!(wire.1, self.owner, "edge belongs to another circuit");
        self.values[wire.0]
    }
    pub fn byte(&self, byte: Byte) -> u8 {
        byte.0
            .iter()
            .enumerate()
            .fold(0, |v, (i, w)| v | ((self.value(*w).0 as u8) << i))
    }
}

/// Public circuit graph, containing no witness values.
#[derive(Debug)]
pub struct Circuit {
    ops: Vec<Op>,
    constraints: Vec<Vec<Term>>,
    inputs: usize,
    owner: u64,
    profile: Option<&'static str>,
}

impl Default for Circuit {
    fn default() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let owner = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .expect("circuit identifiers exhausted");
        Self {
            ops: Vec::new(),
            constraints: Vec::new(),
            inputs: 0,
            profile: None,
            owner,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("wrong private input count")]
    InputCount,
    #[error("wrong witness length")]
    WitnessLength,
    #[error("witness belongs to another circuit")]
    ForeignCircuit,
    #[error("non-boolean bit at edge {0}")]
    BitDomain(usize),
    #[error("inconsistent edge {0}")]
    Edge(usize),
    #[error("constraint {0} failed")]
    Constraint(usize),
}

impl Circuit {
    /// Registered builders alone can set a versioned profile. Any mutation
    /// invalidates it, so generic or extended relations retain the full digest.
    pub(crate) fn register_profile(&mut self, profile: &'static str) {
        self.profile = Some(profile);
    }
    pub fn profile(&self) -> Option<&'static str> {
        self.profile
    }
    pub fn transcript_identity(&self) -> Vec<u8> {
        match self.profile {
            Some(profile) => {
                let mut out = b"profile\0".to_vec();
                out.extend_from_slice(profile.as_bytes());
                out
            }
            None => {
                let mut out = b"circuit-digest\0".to_vec();
                out.extend_from_slice(&self.digest());
                out
            }
        }
    }
    fn require_wire(&self, wire: Wire) {
        assert!(
            wire.0 < self.ops.len() && wire.1 == self.owner,
            "unknown or foreign edge"
        );
    }
    fn require_bit(&self, wire: Wire) {
        self.require_wire(wire);
        assert!(
            matches!(
                self.ops[wire.0],
                Op::Input { bit: true, .. }
                    | Op::Linear { bit: true, .. }
                    | Op::BitProduct(..)
                    | Op::PolynomialBit(..)
                    | Op::AesHint { .. }
                    | Op::InverseBit { .. }
            ) || matches!(self.ops[wire.0], Op::Public(Fe::ZERO | Fe::ONE)),
            "operation requires bit edges"
        );
    }
    fn push(&mut self, op: Op) -> Wire {
        self.profile = None;
        let wire = Wire(self.ops.len(), self.owner);
        self.ops.push(op);
        wire
    }
    pub fn commit_bit(&mut self) -> Wire {
        let index = self.inputs;
        self.inputs += 1;
        self.push(Op::Input { index, bit: true })
    }
    pub fn commit_byte(&mut self) -> Byte {
        Byte(std::array::from_fn(|_| self.commit_bit()))
    }
    pub fn commit_fe(&mut self) -> Wire {
        let index = self.inputs;
        self.inputs += 1;
        self.push(Op::Input { index, bit: false })
    }
    pub fn public_fe(&mut self, value: Fe) -> Wire {
        self.push(Op::Public(value))
    }
    pub fn public_bit(&mut self, bit: bool) -> Wire {
        self.public_fe(Fe(bit as u128))
    }
    pub fn public_byte(&mut self, value: u8) -> Byte {
        Byte(std::array::from_fn(|i| {
            self.public_bit((value >> i) & 1 != 0)
        }))
    }
    fn linear_kind(&mut self, terms: Vec<(Fe, Wire)>, constant: Fe, bit: bool) -> Wire {
        for (_, w) in &terms {
            self.require_wire(*w);
        }
        self.push(Op::Linear {
            terms,
            constant,
            bit,
        })
    }
    pub fn linear(&mut self, terms: Vec<(Fe, Wire)>, constant: Fe) -> Wire {
        self.linear_kind(terms, constant, false)
    }
    pub fn xor(&mut self, a: Wire, b: Wire) -> Wire {
        self.linear(vec![(Fe::ONE, a), (Fe::ONE, b)], Fe::ZERO)
    }
    pub fn byte_xor(&mut self, a: Byte, b: Byte) -> Byte {
        Byte(std::array::from_fn(|i| {
            self.linear_kind(vec![(Fe::ONE, a.0[i]), (Fe::ONE, b.0[i])], Fe::ZERO, true)
        }))
    }
    /// Arbitrary GF(2)-linear byte map specified by its eight basis images.
    pub fn byte_linear(&mut self, input: Byte, basis: [u8; 8], constant: u8) -> Byte {
        Byte(std::array::from_fn(|j| {
            let terms = (0..8)
                .filter(|&i| (basis[i] >> j) & 1 != 0)
                .map(|i| (Fe::ONE, input.0[i]))
                .collect();
            self.linear_kind(terms, Fe(((constant >> j) & 1) as u128), true)
        }))
    }
    pub fn lift(&mut self, byte: Byte) -> Wire {
        let terms = (0..8).map(|i| (Fe::byte(1 << i), byte.0[i])).collect();
        self.linear(terms, Fe::ZERO)
    }
    /// A product output is a new commitment with a quadratic consistency check.
    pub fn mul(&mut self, a: Wire, b: Wire) -> Wire {
        self.require_wire(a);
        self.require_wire(b);
        let out = self.push(Op::Product(a, b));
        self.assert_zero(vec![
            Term::Quadratic(Fe::ONE, a, b),
            Term::Linear(Fe::ONE, out),
        ]);
        out
    }
    pub(crate) fn and_bit(&mut self, a: Wire, b: Wire) -> Wire {
        self.require_bit(a);
        self.require_bit(b);
        let out = self.push(Op::BitProduct(a, b));
        self.assert_zero(vec![
            Term::Quadratic(Fe::ONE, a, b),
            Term::Linear(Fe::ONE, out),
        ]);
        out
    }
    /// Commit only the result of a degree-2/3 equation, without allocating
    /// intermediate AND gates. Evaluation supplies a hint; verification uses
    /// the equation and the backend's authenticated Boolean commitment.
    pub fn polynomial_bit(&mut self, terms: Vec<Term>) -> Wire {
        let out = self.push(Op::PolynomialBit(terms.clone()));
        let mut equation = terms;
        equation.push(Term::Linear(Fe::ONE, out));
        self.assert_zero(equation);
        out
    }
    pub(crate) fn xor_bit(&mut self, a: Wire, b: Wire) -> Wire {
        self.require_bit(a);
        self.require_bit(b);
        self.linear_kind(vec![(Fe::ONE, a), (Fe::ONE, b)], Fe::ZERO, true)
    }
    pub(crate) fn not_bit(&mut self, a: Wire) -> Wire {
        self.require_bit(a);
        self.linear_kind(vec![(Fe::ONE, a)], Fe::ONE, true)
    }
    pub fn assert_zero(&mut self, terms: Vec<Term>) {
        self.profile = None;
        for term in &terms {
            let refs: &[Wire] = match term {
                Term::Constant(_) => &[],
                Term::Linear(_, a) => std::slice::from_ref(a),
                _ => &[],
            };
            for w in refs {
                self.require_wire(*w);
            }
            match term {
                Term::Quadratic(_, a, b) => {
                    self.require_wire(*a);
                    self.require_wire(*b);
                }
                Term::Cubic(_, a, b, c) => {
                    self.require_wire(*a);
                    self.require_wire(*b);
                    self.require_wire(*c);
                }
                _ => {}
            }
        }
        self.constraints.push(terms);
    }
    pub fn assert_equal(&mut self, a: Wire, b: Wire) {
        self.assert_zero(vec![Term::Linear(Fe::ONE, a), Term::Linear(Fe::ONE, b)]);
    }
    pub fn assert_byte(&mut self, a: Byte, value: u8) {
        let actual = self.lift(a);
        self.assert_zero(vec![
            Term::Linear(Fe::ONE, actual),
            Term::Constant(Fe::byte(value)),
        ]);
    }
    /// Auxiliary inverse bits are hints only. Both zero-safe equations are
    /// enforced independently; squaring in the byte field is a linear map.
    pub fn inverse_byte(&mut self, input: Byte) -> Byte {
        for wire in input.0 {
            self.require_wire(wire);
        }
        let out = Byte(std::array::from_fn(|bit| {
            self.push(Op::InverseBit { input, bit })
        }));
        let square = std::array::from_fn(|i| field::byte_mul(1 << i, 1 << i));
        let input_sq = self.byte_linear(input, square, 0);
        let output_sq = self.byte_linear(out, square, 0);
        let (x, y, x2, y2) = (
            self.lift(input),
            self.lift(out),
            self.lift(input_sq),
            self.lift(output_sq),
        );
        self.assert_zero(vec![
            Term::Quadratic(Fe::ONE, x2, y),
            Term::Linear(Fe::ONE, x),
        ]);
        self.assert_zero(vec![
            Term::Quadratic(Fe::ONE, x, y2),
            Term::Linear(Fe::ONE, y),
        ]);
        out
    }
    /// Counts only authenticated bits/field elements, excluding linear edges.
    pub fn committed_bits(&self) -> usize {
        self.ops
            .iter()
            .map(|op| match op {
                Op::Input { bit: true, .. }
                | Op::InverseBit { .. }
                | Op::BitProduct(..)
                | Op::PolynomialBit(..)
                | Op::AesHint { .. } => 1,
                Op::Input { bit: false, .. } | Op::Product(..) => 128,
                _ => 0,
            })
            .sum()
    }
    pub fn constraint_count(&self) -> usize {
        self.constraints.len()
    }
    pub fn edge_count(&self) -> usize {
        self.ops.len()
    }
    /// Number of authenticated values, distinct from their bit-VOLE cost.
    pub fn commitment_count(&self) -> usize {
        self.ops
            .iter()
            .filter(|op| {
                matches!(
                    op,
                    Op::Input { .. }
                        | Op::Product(..)
                        | Op::BitProduct(..)
                        | Op::PolynomialBit(..)
                        | Op::AesHint { .. }
                        | Op::InverseBit { .. }
                )
            })
            .count()
    }

    /// Width of each authenticated value in commitment order. A field input
    /// is a linear combination of 128 authenticated bits; a bit uses one.
    pub fn commitment_widths(&self) -> Vec<usize> {
        self.ops
            .iter()
            .filter_map(|op| match op {
                Op::Input { bit: true, .. }
                | Op::BitProduct(..)
                | Op::PolynomialBit(..)
                | Op::AesHint { .. }
                | Op::InverseBit { .. } => Some(1),
                Op::Input { bit: false, .. } | Op::Product(..) => Some(128),
                _ => None,
            })
            .collect()
    }

    pub fn checked<'a>(&'a self, witness: &'a Witness) -> Result<CheckedWitness<'a>, Error> {
        self.check(witness)?;
        Ok(CheckedWitness {
            circuit: self,
            witness,
        })
    }

    /// Secret committed values for a backend. Erased on drop; not a wire
    /// format. Auxiliary hints are checked before they enter a protocol.
    pub fn commitment_values(&self, witness: &Witness) -> Result<Zeroizing<Vec<Fe>>, Error> {
        self.commitment_values_checked(&self.checked(witness)?)
    }
    pub fn commitment_values_checked(
        &self,
        checked: &CheckedWitness<'_>,
    ) -> Result<Zeroizing<Vec<Fe>>, Error> {
        if !std::ptr::eq(self, checked.circuit) {
            return Err(Error::ForeignCircuit);
        }
        let witness = checked.witness;
        Ok(Zeroizing::new(
            self.ops
                .iter()
                .enumerate()
                .filter_map(|(i, op)| {
                    matches!(
                        op,
                        Op::Input { .. }
                            | Op::Product(..)
                            | Op::BitProduct(..)
                            | Op::PolynomialBit(..)
                            | Op::AesHint { .. }
                            | Op::InverseBit { .. }
                    )
                    .then_some(witness.values[i])
                })
                .collect(),
        ))
    }

    /// Canonical digest of the entire public graph, including every constant,
    /// edge, input kind and constraint. Runtime owner IDs are deliberately
    /// excluded. A verifier must rebuild the graph from its statement policy;
    /// accepting an arbitrary client graph does not authenticate any claim.
    pub fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"zkf/2/ir");
        fn number(hash: &mut Sha256, value: usize) {
            hash.update((value as u64).to_le_bytes());
        }
        fn wire(hash: &mut Sha256, value: Wire) {
            number(hash, value.0);
        }
        number(&mut hash, self.inputs);
        number(&mut hash, self.ops.len());
        for op in &self.ops {
            match op {
                Op::Input { index, bit } => {
                    hash.update([0, u8::from(*bit)]);
                    number(&mut hash, *index);
                }
                Op::Public(value) => {
                    hash.update([1]);
                    hash.update(value.0.to_le_bytes());
                }
                Op::Linear {
                    terms,
                    constant,
                    bit,
                } => {
                    hash.update([2, u8::from(*bit)]);
                    hash.update(constant.0.to_le_bytes());
                    number(&mut hash, terms.len());
                    for (coefficient, input) in terms {
                        hash.update(coefficient.0.to_le_bytes());
                        wire(&mut hash, *input);
                    }
                }
                Op::Product(a, b) | Op::BitProduct(a, b) => {
                    hash.update([if matches!(op, Op::Product(..)) { 3 } else { 4 }]);
                    wire(&mut hash, *a);
                    wire(&mut hash, *b);
                }
                Op::InverseBit { input, bit } => {
                    hash.update([5]);
                    number(&mut hash, *bit);
                    for input in input.0 {
                        wire(&mut hash, input);
                    }
                }
                Op::AesHint { input, bit, norm } => {
                    hash.update([7, u8::from(*norm)]);
                    number(&mut hash, *bit);
                    number(&mut hash, input.len());
                    for term in input.iter() {
                        let (degree, coefficient, refs) = match *term {
                            Term::Constant(c) => (0, c, Vec::new()),
                            Term::Linear(c, x) => (1, c, vec![x]),
                            Term::Quadratic(c, x, y) => (2, c, vec![x, y]),
                            Term::Cubic(c, x, y, z) => (3, c, vec![x, y, z]),
                        };
                        hash.update([degree]);
                        hash.update(coefficient.0.to_le_bytes());
                        for input in refs {
                            wire(&mut hash, input);
                        }
                    }
                }
                Op::PolynomialBit(terms) => {
                    hash.update([6]);
                    number(&mut hash, terms.len());
                    for term in terms {
                        let (degree, coefficient, refs) = match *term {
                            Term::Constant(c) => (0, c, Vec::new()),
                            Term::Linear(c, x) => (1, c, vec![x]),
                            Term::Quadratic(c, x, y) => (2, c, vec![x, y]),
                            Term::Cubic(c, x, y, z) => (3, c, vec![x, y, z]),
                        };
                        hash.update([degree]);
                        hash.update(coefficient.0.to_le_bytes());
                        for input in refs {
                            wire(&mut hash, input);
                        }
                    }
                }
            }
        }
        number(&mut hash, self.constraints.len());
        for terms in &self.constraints {
            number(&mut hash, terms.len());
            for term in terms {
                let (degree, coefficient, refs) = match *term {
                    Term::Constant(c) => (0, c, Vec::new()),
                    Term::Linear(c, x) => (1, c, vec![x]),
                    Term::Quadratic(c, x, y) => (2, c, vec![x, y]),
                    Term::Cubic(c, x, y, z) => (3, c, vec![x, y, z]),
                };
                hash.update([degree]);
                hash.update(coefficient.0.to_le_bytes());
                for input in refs {
                    wire(&mut hash, input);
                }
            }
        }
        hash.finalize().into()
    }

    /// Plain reference evaluation; never serialize the returned witness.
    pub fn eval_checked(&self, inputs: &[Fe]) -> Result<EvaluatedWitness<'_>, Error> {
        Ok(EvaluatedWitness {
            circuit: self,
            witness: self.eval(inputs)?,
        })
    }
    pub fn eval(&self, inputs: &[Fe]) -> Result<Witness, Error> {
        if inputs.len() != self.inputs {
            return Err(Error::InputCount);
        }
        let mut witness = Witness {
            values: Vec::with_capacity(self.ops.len()),
            owner: self.owner,
        };
        for op in &self.ops {
            let values = &witness.values;
            let value = match op {
                Op::Input { index, .. } => inputs[*index],
                Op::Public(v) => *v,
                Op::Linear {
                    terms, constant, ..
                } => terms
                    .iter()
                    .fold(*constant, |v, (c, w)| v ^ values[w.0].scale_public(*c)),
                Op::Product(a, b) => values[a.0] * values[b.0],
                Op::BitProduct(a, b) => Fe(values[a.0].0 & values[b.0].0),
                Op::PolynomialBit(terms) => terms.iter().fold(Fe::ZERO, |v, t| v ^ t.eval(values)),
                Op::AesHint { input, bit, norm } => aes::hint(
                    input.iter().fold(Fe::ZERO, |v, t| v ^ t.eval(values)),
                    *bit,
                    *norm,
                ),
                Op::InverseBit { input, bit } => {
                    let x = witness.byte(*input);
                    Fe(((byte_inverse(x) >> bit) & 1) as u128)
                }
            };
            witness.values.push(value);
        }
        self.check(&witness)?;
        Ok(witness)
    }

    /// Checks an arbitrary witness without trusting auxiliary inverse hints.
    pub fn check(&self, witness: &Witness) -> Result<(), Error> {
        if witness.owner != self.owner {
            return Err(Error::ForeignCircuit);
        }
        let values = &witness.values;
        if values.len() != self.ops.len() {
            return Err(Error::WitnessLength);
        }
        for (i, op) in self.ops.iter().enumerate() {
            let bit = matches!(
                op,
                Op::Input { bit: true, .. }
                    | Op::InverseBit { .. }
                    | Op::Linear { bit: true, .. }
                    | Op::BitProduct(..)
                    | Op::PolynomialBit(..)
                    | Op::AesHint { .. }
            );
            if bit && values[i] != Fe::ZERO && values[i] != Fe::ONE {
                return Err(Error::BitDomain(i));
            }
            let expected = match op {
                Op::Public(v) => Some(*v),
                Op::Linear {
                    terms, constant, ..
                } => Some(
                    terms
                        .iter()
                        .fold(*constant, |v, (c, w)| v ^ values[w.0].scale_public(*c)),
                ),
                // Private inputs and auxiliary products/inverses are checked
                // through their domains and constraints, not reference hints.
                _ => None,
            };
            if expected.is_some_and(|v| v != values[i]) {
                return Err(Error::Edge(i));
            }
        }
        for (i, terms) in self.constraints.iter().enumerate() {
            if terms.iter().fold(Fe::ZERO, |v, t| v ^ t.eval(values)) != Fe::ZERO {
                return Err(Error::Constraint(i));
            }
        }
        Ok(())
    }
}

/// Turn bytes into input bit values in the IR's little-endian bit order.
pub fn byte_inputs(bytes: &[u8]) -> Vec<Fe> {
    bytes
        .iter()
        .flat_map(|byte| (0..8).map(move |i| Fe(((byte >> i) & 1) as u128)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn changing_a_registered_relation_restores_the_full_digest_binding() {
        let mut c = crate::tls::keys_commitment_statement([1; 32], [2; 32]);
        assert_eq!(c.profile(), Some(crate::tls::KEYS_PROFILE));
        c.public_bit(true);
        assert_eq!(c.profile(), None);
        let mut c = crate::tls::keys_commitment_statement([1; 32], [2; 32]);
        c.assert_zero(vec![Term::Constant(Fe::ZERO)]);
        assert_eq!(c.profile(), None);
        let mut other = Circuit::default();
        other.commit_bit();
        assert_ne!(c.transcript_identity(), other.transcript_identity());
    }
    #[test]
    fn foreign_edges_and_witnesses_are_rejected() {
        let mut a = Circuit::default();
        let mut b = Circuit::default();
        let x = a.commit_fe();
        let y = b.commit_fe();
        let w = a.eval(&[Fe::ONE]).unwrap();
        assert_eq!(b.check(&w), Err(Error::ForeignCircuit));
        let checked = a.checked(&w).unwrap();
        assert_eq!(&*a.commitment_values_checked(&checked).unwrap(), &[Fe::ONE]);
        assert!(matches!(
            b.commitment_values_checked(&checked),
            Err(Error::ForeignCircuit)
        ));
        assert!(matches!(
            b.constraint_polynomials_checked(&checked, &[Fe::ONE]),
            Err(Error::ForeignCircuit)
        ));
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| b.xor(x, y))).is_err());
    }
    #[test]
    fn malicious_auxiliary_product_and_domain_rejected() {
        let mut c = Circuit::default();
        let bit = c.commit_bit();
        let x = c.commit_fe();
        let product = c.mul(bit, x);
        let mut w = c.eval(&[Fe::ONE, Fe(42)]).unwrap();
        w.values[product.0] = Fe(43);
        assert!(matches!(c.check(&w), Err(Error::Constraint(_))));
        assert!(matches!(c.eval(&[Fe(2), Fe(42)]), Err(Error::BitDomain(_))));
    }
    #[test]
    fn cubic_constraint_is_enforced() {
        let mut c = Circuit::default();
        let x = c.commit_fe();
        let y = c.commit_fe();
        let z = c.commit_fe();
        c.assert_zero(vec![Term::Cubic(Fe::ONE, x, y, z), Term::Constant(Fe(8))]);
        assert!(c.eval(&[Fe(2), Fe(2), Fe(2)]).is_ok());
        assert!(c.eval(&[Fe(2), Fe(2), Fe(3)]).is_err());
    }
    #[test]
    fn tampered_inverse_bits_are_not_trusted() {
        for x in 0..=255u8 {
            let mut c = Circuit::default();
            let byte = c.commit_byte();
            let inverse = c.inverse_byte(byte);
            let mut w = c.eval(&byte_inputs(&[x])).unwrap();
            for bit in inverse.0 {
                w.values[bit.0] = w.values[bit.0] ^ Fe::ONE;
                assert!(c.check(&w).is_err());
                w.values[bit.0] = w.values[bit.0] ^ Fe::ONE;
            }
        }
    }
}
