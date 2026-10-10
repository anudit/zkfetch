//! Boolean circuit execution with explicit bits and full-width tags.
use super::{ZkDelta, ZkKey, ZkMac};
use mpz_circuits::{Circuit, Gate};
use mpz_core::Block;

#[derive(Debug, thiserror::Error)]
pub enum CircuitError {
    #[error("circuit correlation, input or adjustment count differs")]
    Shape,
}

pub struct ProverExecution<const L: usize> {
    pub outputs: Vec<ZkMac<L>>,
    pub triples: Vec<(ZkMac<L>, ZkMac<L>, ZkMac<L>)>,
    pub adjustments: Vec<[bool; L]>,
}
pub struct VerifierExecution<const L: usize> {
    pub outputs: Vec<ZkKey<L>>,
    pub triples: Vec<(ZkKey<L>, ZkKey<L>, ZkKey<L>)>,
}

pub fn prove<const L: usize>(
    circuit: &Circuit,
    inputs: &[ZkMac<L>],
    gate_choices: &[[bool; L]],
    gate_tags: &[[Block; L]],
) -> Result<ProverExecution<L>, CircuitError> {
    if L == 0
        || inputs.len() != circuit.inputs().len()
        || gate_choices.len() != circuit.and_count()
        || gate_tags.len() != circuit.and_count()
    {
        return Err(CircuitError::Shape);
    }
    let mut wires = vec![ZkMac::public(false); circuit.feed_count()];
    wires[..inputs.len()].copy_from_slice(inputs);
    let mut triples = Vec::with_capacity(circuit.and_count());
    let mut adjustments = Vec::with_capacity(circuit.and_count());
    for gate in circuit.gates() {
        match gate {
            Gate::Xor { x, y, z } => wires[z.id()] = wires[x.id()].xor(wires[y.id()]),
            Gate::Inv { x, z } => wires[z.id()] = wires[x.id()].invert(),
            Gate::Id { x, z } => wires[z.id()] = wires[x.id()],
            Gate::And { x, y, z } => {
                let i = triples.len();
                let (mac, adjust) = wires[x.id()].and(wires[y.id()], gate_choices[i], gate_tags[i]);
                wires[z.id()] = mac;
                triples.push((wires[x.id()], wires[y.id()], mac));
                adjustments.push(adjust);
            }
        }
    }
    Ok(ProverExecution {
        outputs: wires[circuit.outputs()].to_vec(),
        triples,
        adjustments,
    })
}

pub fn verify<const L: usize>(
    circuit: &Circuit,
    inputs: &[ZkKey<L>],
    gate_keys: &[[Block; L]],
    adjustments: &[[bool; L]],
    deltas: &[ZkDelta; L],
) -> Result<VerifierExecution<L>, CircuitError> {
    if L == 0
        || inputs.len() != circuit.inputs().len()
        || gate_keys.len() != circuit.and_count()
        || adjustments.len() != circuit.and_count()
    {
        return Err(CircuitError::Shape);
    }
    let mut wires = vec![ZkKey::public(false, deltas); circuit.feed_count()];
    wires[..inputs.len()].copy_from_slice(inputs);
    let mut triples = Vec::with_capacity(circuit.and_count());
    for gate in circuit.gates() {
        match gate {
            Gate::Xor { x, y, z } => wires[z.id()] = wires[x.id()].xor(wires[y.id()]),
            Gate::Inv { x, z } => wires[z.id()] = wires[x.id()].invert(deltas),
            Gate::Id { x, z } => wires[z.id()] = wires[x.id()],
            Gate::And { x, y, z } => {
                let i = triples.len();
                let key = ZkKey::from_rcot(gate_keys[i], adjustments[i], deltas);
                wires[z.id()] = key;
                triples.push((wires[x.id()], wires[y.id()], key));
            }
        }
    }
    Ok(VerifierExecution {
        outputs: wires[circuit.outputs()].to_vec(),
        triples,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{BlockCipherEncrypt, KeyInit};
    use mpz_circuits::AES128;
    fn block(v: u128) -> Block {
        Block::from(v.to_le_bytes())
    }
    #[test]
    fn aes_outputs_have_two_independent_full_width_authentications() {
        let key = [7u8; 16];
        let msg = [11u8; 16];
        let mut expected = msg.into();
        aes::Aes128::new(&key.into()).encrypt_block(&mut expected);
        let deltas = [ZkDelta::new(block(10)), ZkDelta::new(block(27))];
        let input_bits: Vec<_> = key
            .into_iter()
            .chain(msg)
            .flat_map(|byte| (0..8).map(move |bit| (byte >> bit) & 1 != 0))
            .collect();
        let mut macs = Vec::new();
        let mut keys = Vec::new();
        for (i, value) in input_bits.into_iter().enumerate() {
            let k = [block((1000 + 2 * i) as u128), block((1001 + 2 * i) as u128)];
            let choices = [i % 2 == 0, i % 3 == 0];
            let tags = std::array::from_fn(|lane| {
                k[lane]
                    ^ if choices[lane] {
                        *deltas[lane].as_block()
                    } else {
                        Block::ZERO
                    }
            });
            let (m, a) = ZkMac::from_rcot(value, choices, tags);
            macs.push(m);
            keys.push(ZkKey::from_rcot(k, a, &deltas));
        }
        let gate_keys: Vec<_> = (0..AES128.and_count())
            .map(|i| [block((2000 + 2 * i) as u128), block((2001 + 2 * i) as u128)])
            .collect();
        let choices: Vec<_> = (0..AES128.and_count())
            .map(|i| [i % 5 == 0, i % 7 == 0])
            .collect();
        let tags: Vec<_> = gate_keys
            .iter()
            .zip(&choices)
            .map(|(k, c)| {
                std::array::from_fn(|lane| {
                    k[lane]
                        ^ if c[lane] {
                            *deltas[lane].as_block()
                        } else {
                            Block::ZERO
                        }
                })
            })
            .collect();
        let p = prove(&AES128, &macs, &choices, &tags).unwrap();
        let v = verify(&AES128, &keys, &gate_keys, &p.adjustments, &deltas).unwrap();
        let mut actual = [0u8; 16];
        for (i, (m, k)) in p.outputs.iter().zip(&v.outputs).enumerate() {
            assert!(k.authenticates(m, &deltas));
            actual[i / 8] |= (m.value() as u8) << (i % 8);
        }
        assert_eq!(actual.as_slice(), expected.as_slice());
        assert_eq!(p.triples.len(), AES128.and_count());
        assert!(
            verify(
                &AES128,
                &keys,
                &gate_keys,
                &p.adjustments[..p.adjustments.len() - 1],
                &deltas
            )
            .is_err()
        );
    }
}
