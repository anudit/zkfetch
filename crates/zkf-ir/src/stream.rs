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
    circuit: &'a Circuit,
    slots: Vec<usize>,
    checks: Vec<Vec<usize>>,
    release: Vec<Vec<usize>>,
    outputs: Vec<Wire>,
    slot_count: usize,
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

fn op_inputs(op: &Op) -> Vec<Wire> {
    match op {
        Op::Input { .. } | Op::Public(_) => Vec::new(),
        Op::Linear { terms, .. } => terms.iter().map(|(_, wire)| *wire).collect(),
        Op::Product(a, b) | Op::BitProduct(a, b) => vec![*a, *b],
        Op::InverseBit { input, .. } => input.0.to_vec(),
        Op::PolynomialBit(terms) => terms.iter().flat_map(term_inputs).collect(),
        Op::AesHint {input:terms,..} => terms.iter().flat_map(term_inputs).collect(),
    }
}

fn term_inputs(term: &Term) -> Vec<Wire> {
    match term {
        Term::Constant(_) => Vec::new(),
        Term::Linear(_, a) => vec![*a],
        Term::Quadratic(_, a, b) => vec![*a, *b],
        Term::Cubic(_, a, b, c) => vec![*a, *b, *c],
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
            for wire in op_inputs(op) {
                last[wire.0] = last[wire.0].max(step);
            }
        }
        let mut checks = vec![Vec::new(); steps];
        for (index, terms) in self.constraints.iter().enumerate() {
            let inputs: Vec<_> = terms.iter().flat_map(term_inputs).collect();
            let step = inputs.iter().map(|wire| wire.0).max().unwrap_or(0);
            for wire in inputs {
                last[wire.0] = last[wire.0].max(step);
            }
            checks[step].push(index);
        }
        for wire in outputs {
            last[wire.0] = steps - 1;
        }
        let mut release = vec![Vec::new(); steps];
        for (edge, step) in last.iter().enumerate() {
            release[*step].push(edge);
        }
        let mut slots = Vec::with_capacity(n);
        let mut free = Vec::new();
        let mut slot_count = 0;
        for (step, edges) in release.iter().enumerate().take(n) {
            // Allocate before freeing this step's inputs: outputs may depend
            // on every live input, including the slot that dies at this step.
            let slot = free.pop().unwrap_or_else(|| {
                let slot = slot_count;
                slot_count += 1;
                slot
            });
            slots.push(slot);
            for edge in edges {
                if last[*edge] == step {
                    free.push(slots[*edge]);
                }
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
        for step in 0..self.checks.len() {
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
                    Op::PolynomialBit(terms) => terms.iter().fold(Fe::ZERO, |acc,term| acc ^ match *term {
                        Term::Constant(c) => c,
                        Term::Linear(c,x) => get(x).scale_public(c),
                        Term::Quadratic(c,x,y) => (get(x)*get(y)).scale_public(c),
                        Term::Cubic(c,x,y,z) => (get(x)*get(y)*get(z)).scale_public(c),
                    }),
                    Op::AesHint {input,bit,norm} => {
                        let value = input.iter().fold(Fe::ZERO, |v,t|v ^ match *t {
                            Term::Constant(c)=>c,Term::Linear(c,x)=>get(x).scale_public(c),
                            Term::Quadratic(c,x,y)=>(get(x)*get(y)).scale_public(c),
                            Term::Cubic(c,x,y,z)=>(get(x)*get(y)*get(z)).scale_public(c),
                        });
                        crate::aes::hint(value,*bit,*norm)
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
                        | Op::PolynomialBit(..) | Op::AesHint { .. }
                        | Op::InverseBit { .. }
                );
                if is_bit && value != Fe::ZERO && value != Fe::ONE {
                    return Err(Error::BitDomain(step));
                }
                storage[self.slots[step]] = value;
            }
            for index in &self.checks[step] {
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
            if step + 1 == self.checks.len() {
                output
                    .values
                    .extend(self.outputs.iter().map(|wire| storage[self.slots[wire.0]]));
            }
            for edge in &self.release[step] {
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
