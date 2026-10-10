//! QuickSilver's homogeneous constraint polynomials, degree at most three.
//! Authentication convention: verifier key q = m + delta * witness value.
//! Challenges and the degree-dependent VOLE masks must be supplied by an
//! authenticated protocol; this module deliberately has no prove/verify API.
use crate::{CheckedWitness, Circuit, Error, Op, Term, Witness, field::Fe};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub struct Polynomial(pub [Fe; 4]);

impl Polynomial {
    fn zero() -> Self {
        Self([Fe::ZERO; 4])
    }
    fn linear(value: Fe, tag: Fe) -> Self {
        Self([tag, value, Fe::ZERO, Fe::ZERO])
    }
    fn shift(self, by: usize) -> Self {
        let mut output = Self::zero();
        for i in 0..4 - by {
            output.0[i + by] = self.0[i];
        }
        output
    }
    // Every graph wire is an authenticated degree-one polynomial. Products
    // below have public, known degrees; skip only structurally zero terms.
    fn linear_product(self, rhs: Self) -> Self {
        Self([
            self.0[0] * rhs.0[0],
            self.0[0] * rhs.0[1] ^ self.0[1] * rhs.0[0],
            self.0[1] * rhs.0[1],
            Fe::ZERO,
        ])
    }
    fn quadratic_times_linear(self, rhs: Self) -> Self {
        Self([
            self.0[0] * rhs.0[0],
            self.0[0] * rhs.0[1] ^ self.0[1] * rhs.0[0],
            self.0[1] * rhs.0[1] ^ self.0[2] * rhs.0[0],
            self.0[2] * rhs.0[1],
        ])
    }
    fn scale(self, c: Fe) -> Self {
        Self(self.0.map(|v| v.scale_public(c)))
    }
    fn xor(self, rhs: Self) -> Self {
        Self(std::array::from_fn(|i| self.0[i] ^ rhs.0[i]))
    }
    pub fn at(self, delta: Fe) -> Fe {
        self.0
            .into_iter()
            .rev()
            .fold(Fe::ZERO, |acc, coefficient| (acc * delta) ^ coefficient)
    }
}

/// Polynomials contain witness values and must never be sent to a verifier.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ProverPolynomials(pub Vec<Polynomial>);

impl Circuit {
    /// Construct authenticated wires from independently supplied commitment
    /// tags. Public constants have zero tags and linear maps are free.
    pub fn constraint_polynomials(
        &self,
        witness: &Witness,
        tags: &[Fe],
    ) -> Result<ProverPolynomials, Error> {
        self.constraint_polynomials_checked(&self.checked(witness)?, tags)
    }
    pub fn constraint_polynomials_checked(
        &self,
        checked: &CheckedWitness<'_>,
        tags: &[Fe],
    ) -> Result<ProverPolynomials, Error> {
        if !std::ptr::eq(self, checked.circuit) {
            return Err(Error::ForeignCircuit);
        }
        let witness = checked.witness;
        if tags.len() != self.commitment_count() {
            return Err(Error::InputCount);
        }
        let mut tags = tags.iter();
        let mut polynomials = Zeroizing::new(Vec::<Polynomial>::with_capacity(self.ops.len()));
        for (i, op) in self.ops.iter().enumerate() {
            let p = match op {
                Op::Input { .. }
                | Op::Product(..)
                | Op::BitProduct(..)
                | Op::PolynomialBit(..)
                | Op::AesHint { .. }
                | Op::InverseBit { .. } => {
                    Polynomial::linear(witness.values[i], *tags.next().unwrap())
                }
                Op::Public(value) => Polynomial::linear(*value, Fe::ZERO),
                Op::Linear {
                    terms, constant, ..
                } => terms
                    .iter()
                    .fold(Polynomial::linear(*constant, Fe::ZERO), |acc, (c, w)| {
                        acc.xor(polynomials[w.0].scale(*c))
                    }),
            };
            polynomials.push(p);
        }
        #[cfg(feature = "parallel")]
        let constraints = self.constraints.par_iter();
        #[cfg(not(feature = "parallel"))]
        let constraints = self.constraints.iter();
        let output = constraints
            .map(|terms| {
                // Lift every constraint to degree 3. Lower-degree constraints get
                // multiplied by X^(3-d), exactly as in FAEST's check batching.
                terms.iter().fold(Polynomial::zero(), |acc, term| {
                    acc.xor(match *term {
                        Term::Constant(c) => Polynomial([Fe::ZERO, Fe::ZERO, Fe::ZERO, c]),
                        Term::Linear(c, x) => polynomials[x.0].shift(2).scale(c),
                        Term::Quadratic(c, x, y) => polynomials[x.0]
                            .linear_product(polynomials[y.0])
                            .shift(1)
                            .scale(c),
                        Term::Cubic(c, x, y, z) => polynomials[x.0]
                            .linear_product(polynomials[y.0])
                            .quadratic_times_linear(polynomials[z.0])
                            .scale(c),
                    })
                })
            })
            .collect();
        // Clear copies of authenticated witness values before returning only
        // the constraint polynomials needed by the check implementation.
        polynomials.zeroize();
        Ok(ProverPolynomials(output))
    }

    /// The verifier evaluates the same graph using only q values and delta.
    /// It never receives an S-box inverse or plaintext assignment.
    pub fn verifier_constraints(&self, commitments: &[Fe], delta: Fe) -> Result<Vec<Fe>, Error> {
        if commitments.len() != self.commitment_count() {
            return Err(Error::InputCount);
        }
        let mut keys = commitments.iter();
        let mut wires: Vec<Fe> = Vec::with_capacity(self.ops.len());
        for op in &self.ops {
            let q = match op {
                Op::Input { .. }
                | Op::Product(..)
                | Op::BitProduct(..)
                | Op::PolynomialBit(..)
                | Op::AesHint { .. }
                | Op::InverseBit { .. } => *keys.next().unwrap(),
                Op::Public(value) => *value * delta,
                Op::Linear {
                    terms, constant, ..
                } => terms
                    .iter()
                    .fold(delta.scale_public(*constant), |acc, (c, w)| {
                        acc ^ wires[w.0].scale_public(*c)
                    }),
            };
            wires.push(q);
        }
        let delta2 = delta * delta;
        let delta3 = delta2 * delta;
        #[cfg(feature = "parallel")]
        let constraints = self.constraints.par_iter();
        #[cfg(not(feature = "parallel"))]
        let constraints = self.constraints.iter();
        Ok(constraints
            .map(|terms| {
                terms.iter().fold(Fe::ZERO, |acc, term| {
                    acc ^ match *term {
                        Term::Constant(c) => delta3.scale_public(c),
                        Term::Linear(c, x) => (wires[x.0] * delta2).scale_public(c),
                        Term::Quadratic(c, x, y) => {
                            (wires[x.0] * wires[y.0] * delta).scale_public(c)
                        }
                        Term::Cubic(c, x, y, z) => {
                            (wires[x.0] * wires[y.0] * wires[z.0]).scale_public(c)
                        }
                    }
                })
            })
            .collect())
    }

    /// Build q from a known correlation for reference/differential tests.
    /// Production verifier backends must get q directly from their VOLE.
    pub fn correlated_keys(
        &self,
        witness: &Witness,
        tags: &[Fe],
        delta: Fe,
    ) -> Result<Vec<Fe>, Error> {
        self.check(witness)?;
        if tags.len() != self.commitment_count() {
            return Err(Error::InputCount);
        }
        Ok(self
            .ops
            .iter()
            .enumerate()
            .filter(|(_, op)| {
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
            .zip(tags)
            .map(|((i, _), tag)| *tag ^ (witness.values[i] * delta))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{aes::sbox, byte_inputs};
    use proptest::prelude::*;
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]
        fn prover_and_verifier_equations_match(x in any::<u8>(), delta in 1u128..=u128::MAX, seed in any::<u128>()) {
            let mut c = Circuit::default();
            let byte = c.commit_byte();
            sbox(&mut c, byte);
            let witness = c.eval(&byte_inputs(&[x])).unwrap();
            let tags: Vec<_> = (0..c.commitment_count()).map(|i| Fe(seed.wrapping_add(i as u128))).collect();
            let delta = Fe(delta);
            let polys = c.constraint_polynomials(&witness, &tags).unwrap();
            let keys = c.correlated_keys(&witness, &tags, delta).unwrap();
            let checks = c.verifier_constraints(&keys, delta).unwrap();
            for (poly, check) in polys.0.iter().zip(checks) {
                prop_assert_eq!(poly.0[3], Fe::ZERO);
                prop_assert_eq!(poly.at(delta), check);
            }
        }
    }
    #[test]
    fn genuine_cubic_term_and_public_constants_match() {
        let mut c = Circuit::default();
        let x = c.commit_fe();
        let y = c.commit_fe();
        let z = c.commit_fe();
        c.assert_zero(vec![Term::Cubic(Fe::ONE, x, y, z), Term::Constant(Fe(8))]);
        let witness = c.eval(&[Fe(2), Fe(2), Fe(2)]).unwrap();
        let tags = [Fe(0x1234), Fe(0x5678), Fe(0x9999)];
        let delta = Fe(0xaabbcc);
        let polys = c.constraint_polynomials(&witness, &tags).unwrap();
        let mut keys = c.correlated_keys(&witness, &tags, delta).unwrap();
        assert_eq!(
            polys.0[0].at(delta),
            c.verifier_constraints(&keys, delta).unwrap()[0]
        );
        keys[0] = keys[0] ^ Fe::ONE;
        assert_ne!(
            polys.0[0].at(delta),
            c.verifier_constraints(&keys, delta).unwrap()[0]
        );
    }
}
