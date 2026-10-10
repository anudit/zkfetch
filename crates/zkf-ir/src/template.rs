//! Immutable public graph templates. No witness assignments are cached.
use crate::{Byte, Circuit, Op, Term, Wire};
use std::{collections::HashMap, sync::Arc};
pub(crate) struct Template {
    circuit: Circuit,
    outputs: Vec<Wire>,
}
impl Template {
    pub fn new(circuit: Circuit, outputs: Vec<Wire>) -> Self {
        Self { circuit, outputs }
    }
    pub fn instantiate(&self, c: &mut Circuit, inputs: &[Wire]) -> Vec<Wire> {
        assert_eq!(inputs.len(), self.circuit.inputs);
        c.ops.reserve(self.circuit.ops.len() - inputs.len());
        c.constraints.reserve(self.circuit.constraints.len());
        c.profile = None;
        let mut mapping = Vec::<Wire>::with_capacity(self.circuit.ops.len());
        let mut hints = HashMap::<usize, Arc<[Term]>>::new();
        let mut bytes = HashMap::<usize, Arc<Byte>>::new();
        fn term(t: &Term, m: &[Wire]) -> Term {
            match *t {
                Term::Constant(k) => Term::Constant(k),
                Term::Linear(k, x) => Term::Linear(k, m[x.0]),
                Term::Quadratic(k, x, y) => Term::Quadratic(k, m[x.0], m[y.0]),
                Term::Cubic(k, x, y, z) => Term::Cubic(k, m[x.0], m[y.0], m[z.0]),
            }
        }
        for op in &self.circuit.ops {
            if let Op::Input { index, bit } = op {
                let wire = inputs[*index];
                if *bit {
                    c.require_bit(wire)
                } else {
                    c.require_wire(wire)
                };
                mapping.push(wire);
                continue;
            }
            let mapped = match op {
                Op::Public(v) => Op::Public(*v),
                Op::Linear {
                    terms,
                    constant,
                    bit,
                } => Op::Linear {
                    terms: terms.iter().map(|(k, w)| (*k, mapping[w.0])).collect(),
                    constant: *constant,
                    bit: *bit,
                },
                Op::Product(x, y) => Op::Product(mapping[x.0], mapping[y.0]),
                Op::BitProduct(x, y) => Op::BitProduct(mapping[x.0], mapping[y.0]),
                Op::PolynomialBit(terms) => {
                    Op::PolynomialBit(terms.iter().map(|t| term(t, &mapping)).collect())
                }
                Op::AesHint { input, bit, norm } => Op::AesHint {
                    input: hints
                        .entry(input.as_ptr() as usize)
                        .or_insert_with(|| input.iter().map(|t| term(t, &mapping)).collect())
                        .clone(),
                    bit: *bit,
                    norm: *norm,
                },
                Op::InverseBit { input, bit } => Op::InverseBit {
                    input: bytes
                        .entry(Arc::as_ptr(input) as usize)
                        .or_insert_with(|| Arc::new(Byte(input.0.map(|w| mapping[w.0]))))
                        .clone(),
                    bit: *bit,
                },
                Op::Input { .. } => unreachable!(),
            };
            mapping.push(c.push(mapped));
        }
        // Templates originate from checked builders. Remapping preserves the
        // canonical term order and domains; do not rebuild the same BTreeMaps.
        c.constraints.extend(
            self.circuit
                .constraints
                .iter()
                .map(|terms| terms.iter().map(|t| term(t, &mapping)).collect()),
        );
        self.outputs.iter().map(|w| mapping[w.0]).collect()
    }
}
