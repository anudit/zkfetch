//! Liveness-based streaming of the reference graph. This reduces secret-value
//! storage to the live frontier. Public graph/slot metadata still scales with
//! the circuit size; authenticated backends must apply the same schedule to
//! their own tags/keys before claiming bounded protocol memory.
use crate::{
    Circuit, Error, Op, Term, Wire,
    field::{Fe, byte_inverse},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Public allocation schedule. Each operation is an explicit single-output
/// node; constraints run as soon as all their input edges exist.
pub struct Plan<'a> {
    pub(crate) circuit: &'a Circuit,
    pub(crate) slots: Vec<usize>,
    pub(crate) checks: Events,
    pub(crate) release: Events,
    outputs: Vec<Wire>,
    pub(crate) slot_count: usize,
}

/// Only requested output values survive streaming evaluation. Outputs may
/// contain secrets and are erased on drop. Never serialize this assignment.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Output {
    values: Vec<Fe>,
}

impl Output {
    pub fn values(&self) -> &[Fe] {
        &self.values
    }
}

/// Compact CSR schedule: no per-operation heap allocation for event lists.
pub(crate) struct Events {
    offsets: Vec<usize>,
    values: Vec<usize>,
}
impl Events {
    fn new(steps: usize, assignments: impl Iterator<Item = (usize, usize)> + Clone) -> Self {
        let mut offsets = vec![0; steps + 1];
        for (step, _) in assignments.clone() {
            offsets[step + 1] += 1;
        }
        for step in 1..=steps {
            offsets[step] += offsets[step - 1];
        }
        let mut cursors = offsets[..steps].to_vec();
        let mut values = vec![0; offsets[steps]];
        for (step, value) in assignments {
            values[cursors[step]] = value;
            cursors[step] += 1;
        }
        Self { offsets, values }
    }
    pub(crate) fn steps(&self) -> usize {
        self.offsets.len() - 1
    }
    pub(crate) fn at(&self, step: usize) -> &[usize] {
        &self.values[self.offsets[step]..self.offsets[step + 1]]
    }
    fn allocated_bytes(&self) -> usize {
        (self.offsets.capacity() + self.values.capacity()) * std::mem::size_of::<usize>()
    }
}

fn visit_term_inputs(term: &Term, consume: &mut impl FnMut(Wire)) {
    match *term {
        Term::Constant(_) => {}
        Term::Linear(_, a) => consume(a),
        Term::Quadratic(_, a, b) => {
            consume(a);
            consume(b);
        }
        Term::Cubic(_, a, b, c) => {
            consume(a);
            consume(b);
            consume(c);
        }
    }
}
fn visit_op_inputs(op: &Op, consume: &mut impl FnMut(Wire)) {
    match op {
        Op::Input { .. } | Op::Public(_) => {}
        Op::Linear { terms, .. } => {
            for (_, wire) in terms {
                consume(*wire);
            }
        }
        Op::Product(a, b) | Op::BitProduct(a, b) => {
            consume(*a);
            consume(*b);
        }
        Op::InverseBit { input, .. } => {
            for wire in input.0 {
                consume(wire);
            }
        }
        Op::PolynomialBit(terms) => {
            for term in terms {
                visit_term_inputs(term, consume);
            }
        }
        Op::AesHint { input: terms, .. } => {
            for term in terms.iter() {
                visit_term_inputs(term, consume);
            }
        }
    }
}

impl Circuit {
    /// Compile a schedule retaining only selected output edges. A full
    /// requested witness naturally defeats streaming, so backends should
    /// consume node intermediates during their scheduled checks instead.
    pub fn streaming_plan(&self, outputs: &[Wire]) -> Result<Plan<'_>, Error> {
        for wire in outputs {
            if wire.1 != self.owner || wire.0 >= self.ops.len() {
                return Err(Error::ForeignCircuit);
            }
        }
        let n = self.ops.len();
        // An empty graph still needs one step for constant-only constraints.
        let steps = n.max(1);
        let mut last: Vec<_> = (0..n).collect();
        for (step, op) in self.ops.iter().enumerate() {
            visit_op_inputs(op, &mut |wire| last[wire.0] = last[wire.0].max(step));
        }
        let mut check_steps = Vec::with_capacity(self.constraints.len());
        for terms in &self.constraints {
            let mut step = 0;
            for term in terms {
                visit_term_inputs(term, &mut |wire| step = step.max(wire.0));
            }
            for term in terms {
                visit_term_inputs(term, &mut |wire| last[wire.0] = last[wire.0].max(step));
            }
            check_steps.push(step);
        }
        let checks = Events::new(
            steps,
            check_steps
                .iter()
                .enumerate()
                .map(|(index, step)| (*step, index)),
        );
        for wire in outputs {
            last[wire.0] = steps - 1;
        }
        let release = Events::new(
            steps,
            last.iter().enumerate().map(|(edge, step)| (*step, edge)),
        );
        let mut slots = Vec::with_capacity(n);
        let mut free = Vec::new();
        let mut slot_count = 0;
        for step in 0..n {
            // Allocate before freeing this step's inputs.
            let slot = free.pop().unwrap_or_else(|| {
                let slot = slot_count;
                slot_count += 1;
                slot
            });
            slots.push(slot);
            for edge in release.at(step) {
                free.push(slots[*edge]);
            }
        }
        Ok(Plan {
            circuit: self,
            slots,
            checks,
            release,
            outputs: outputs.to_vec(),
            slot_count,
        })
    }
}

impl Plan<'_> {
    /// Maximum simultaneously resident field values; excludes caller inputs
    /// and the small final output buffer. Each value occupies 16 bytes.
    pub fn resident_values(&self) -> usize {
        self.slot_count
    }

    /// Allocated public schedule metadata, excluding the circuit graph.
    pub fn allocated_bytes(&self) -> usize {
        self.slots.capacity() * std::mem::size_of::<usize>()
            + self.outputs.capacity() * std::mem::size_of::<Wire>()
            + self.checks.allocated_bytes()
            + self.release.allocated_bytes()
    }

    /// Evaluate and enforce every constraint without keeping a full witness.
    /// Input buffers remain caller-owned, just as for `Circuit::eval`.
    pub fn eval(&self, inputs: &[Fe]) -> Result<Output, Error> {
        if inputs.len() != self.circuit.inputs {
            return Err(Error::InputCount);
        }
        let mut storage = Zeroizing::new(vec![Fe::ZERO; self.slot_count]);
        let mut output = Output {
            values: Vec::with_capacity(self.outputs.len()),
        };
        for step in 0..self.checks.steps() {
            if let Some(op) = self.circuit.ops.get(step) {
                let get = |wire: Wire| storage[self.slots[wire.0]];
                let value = match op {
                    Op::Input { index, .. } => inputs[*index],
                    Op::Public(value) => *value,
                    Op::Linear {
                        terms, constant, ..
                    } => terms
                        .iter()
                        .fold(*constant, |acc, (c, wire)| acc ^ (*c * get(*wire))),
                    Op::Product(a, b) | Op::BitProduct(a, b) => get(*a) * get(*b),
                    Op::PolynomialBit(terms) => terms.iter().fold(Fe::ZERO, |acc, term| {
                        acc ^ match *term {
                            Term::Constant(c) => c,
                            Term::Linear(c, x) => get(x).scale_public(c),
                            Term::Quadratic(c, x, y) => (get(x) * get(y)).scale_public(c),
                            Term::Cubic(c, x, y, z) => (get(x) * get(y) * get(z)).scale_public(c),
                        }
                    }),
                    Op::AesHint { input, bit, norm } => {
                        let value = input.iter().fold(Fe::ZERO, |v, t| {
                            v ^ match *t {
                                Term::Constant(c) => c,
                                Term::Linear(c, x) => get(x).scale_public(c),
                                Term::Quadratic(c, x, y) => (get(x) * get(y)).scale_public(c),
                                Term::Cubic(c, x, y, z) => {
                                    (get(x) * get(y) * get(z)).scale_public(c)
                                }
                            }
                        });
                        crate::aes::hint(value, *bit, *norm)
                    }
                    Op::InverseBit { input, bit } => {
                        let byte = input
                            .0
                            .iter()
                            .enumerate()
                            .fold(0u8, |acc, (i, wire)| acc | ((get(*wire).0 as u8) << i));
                        Fe(((byte_inverse(byte) >> bit) & 1) as u128)
                    }
                };
                let is_bit = matches!(
                    op,
                    Op::Input { bit: true, .. }
                        | Op::Linear { bit: true, .. }
                        | Op::BitProduct(..)
                        | Op::PolynomialBit(..)
                        | Op::AesHint { .. }
                        | Op::InverseBit { .. }
                );
                if is_bit && value != Fe::ZERO && value != Fe::ONE {
                    return Err(Error::BitDomain(step));
                }
                storage[self.slots[step]] = value;
            }
            for index in self.checks.at(step) {
                let get = |wire: Wire| storage[self.slots[wire.0]];
                let value = self.circuit.constraints[*index]
                    .iter()
                    .fold(Fe::ZERO, |acc, term| {
                        acc ^ match *term {
                            Term::Constant(c) => c,
                            Term::Linear(c, x) => c * get(x),
                            Term::Quadratic(c, x, y) => c * get(x) * get(y),
                            Term::Cubic(c, x, y, z) => c * get(x) * get(y) * get(z),
                        }
                    });
                if value != Fe::ZERO {
                    return Err(Error::Constraint(*index));
                }
            }
            if step + 1 == self.checks.steps() {
                output
                    .values
                    .extend(self.outputs.iter().map(|wire| storage[self.slots[wire.0]]));
            }
            for edge in self.release.at(step) {
                storage[self.slots[*edge]].zeroize();
            }
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{aes::ExpandedKey, byte_inputs};

    #[test]
    fn aes_stream_matches_full_evaluator() {
        let mut circuit = Circuit::default();
        let key = (0..16).map(|_| circuit.commit_byte()).collect::<Vec<_>>();
        let expanded = ExpandedKey::new(&mut circuit, &key).unwrap();
        let input = std::array::from_fn(|i| circuit.public_byte(i as u8));
        let encrypted = expanded.encrypt(&mut circuit, input);
        let wires: Vec<_> = encrypted.iter().flat_map(|byte| byte.0).collect();
        let inputs = byte_inputs(&[0; 16]);
        let full = circuit.eval(&inputs).unwrap();
        let plan = circuit.streaming_plan(&wires).unwrap();
        let streamed = plan.eval(&inputs).unwrap();
        for (wire, value) in wires.iter().zip(streamed.values()) {
            assert_eq!(full.value(*wire), *value);
        }
        assert!(plan.resident_values() < circuit.edge_count() / 2);
    }

    #[test]
    fn long_chain_reuses_two_slots_and_retains_outputs() {
        let mut circuit = Circuit::default();
        let first = circuit.commit_fe();
        let mut last = first;
        for _ in 0..10000 {
            last = circuit.linear(vec![(Fe::ONE, last)], Fe::ONE);
        }
        let plan = circuit.streaming_plan(&[last]).unwrap();
        assert_eq!(plan.resident_values(), 2);
        assert_eq!(plan.eval(&[Fe(7)]).unwrap().values(), &[Fe(7)]);
        let plan = circuit.streaming_plan(&[first, last, first]).unwrap();
        assert_eq!(plan.resident_values(), 3);
        assert_eq!(plan.eval(&[Fe(7)]).unwrap().values(), &[Fe(7); 3]);
    }

    #[test]
    fn future_constraints_keep_inputs_alive_and_invalid_assignments_fail() {
        let mut circuit = Circuit::default();
        let x = circuit.commit_bit();
        let y = circuit.commit_fe();
        let z = circuit.mul(x, y);
        circuit.assert_zero(vec![Term::Cubic(Fe::ONE, x, y, z), Term::Constant(Fe(4))]);
        let plan = circuit.streaming_plan(&[]).unwrap();
        assert!(plan.eval(&[Fe::ONE, Fe(2)]).is_ok());
        assert!(matches!(
            plan.eval(&[Fe(2), Fe(2)]),
            Err(Error::BitDomain(0))
        ));
        assert!(matches!(
            plan.eval(&[Fe::ONE, Fe(3)]),
            Err(Error::Constraint(_))
        ));
        assert!(matches!(plan.eval(&[]), Err(Error::InputCount)));
    }

    #[test]
    fn constant_only_constraints_and_foreign_outputs() {
        let mut circuit = Circuit::default();
        circuit.assert_zero(vec![Term::Constant(Fe::ONE)]);
        assert!(matches!(
            circuit.streaming_plan(&[]).unwrap().eval(&[]),
            Err(Error::Constraint(0))
        ));
        let mut other = Circuit::default();
        let wire = other.commit_bit();
        assert!(matches!(
            circuit.streaming_plan(&[wire]),
            Err(Error::ForeignCircuit)
        ));
    }
}
