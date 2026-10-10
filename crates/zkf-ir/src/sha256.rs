//! Adapter for the existing MPZ Bristol SHA-256 compression circuit.
//! State bytes use network order; Bristol U32 inputs use little-endian bits.
use crate::{Byte, Circuit, Wire};
use mpz_circuits::{Gate, SHA256_COMPRESS};

pub const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub fn compression(c: &mut Circuit, state: [Byte; 32], message: [Byte; 64]) -> [Byte; 32] {
    let bristol = &*SHA256_COMPRESS;
    let mut wires: Vec<Option<Wire>> = vec![None; bristol.feed_count()];
    let inputs = message.into_iter().flat_map(|b| b.0).chain(
        state
            .as_chunks::<4>()
            .0
            .iter()
            .flat_map(|word| word.iter().rev().flat_map(|b| b.0)),
    );
    assert_eq!(bristol.inputs().len(), 768);
    for (i, wire) in bristol.inputs().zip(inputs) {
        wires[i] = Some(wire);
    }
    for gate in bristol.gates() {
        let (out, value) = match *gate {
            Gate::Xor { x, y, z } => (
                z.id(),
                c.xor_bit(wires[x.id()].unwrap(), wires[y.id()].unwrap()),
            ),
            Gate::And { x, y, z } => (
                z.id(),
                c.and_bit(wires[x.id()].unwrap(), wires[y.id()].unwrap()),
            ),
            Gate::Inv { x, z } => (z.id(), c.not_bit(wires[x.id()].unwrap())),
            Gate::Id { x, z } => (z.id(), wires[x.id()].unwrap()),
        };
        assert!(wires[out].is_none(), "Bristol output assigned twice");
        wires[out] = Some(value);
    }
    let bits: Vec<_> = bristol.outputs().map(|i| wires[i].unwrap()).collect();
    assert_eq!(bits.len(), 256);
    std::array::from_fn(|byte| {
        let word = byte / 4;
        let little_byte = 3 - byte % 4;
        Byte(std::array::from_fn(|bit| {
            bits[word * 32 + little_byte * 8 + bit]
        }))
    })
}

pub fn public_state(c: &mut Circuit, state: [u32; 8]) -> [Byte; 32] {
    let bytes: Vec<_> = state.into_iter().flat_map(u32::to_be_bytes).collect();
    std::array::from_fn(|i| c.public_byte(bytes[i]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::byte_inputs;
    #[test]
    fn existing_bristol_matches_sha2_compressor() {
        for fill in [0, 69, 255] {
            let mut c = Circuit::default();
            let block = std::array::from_fn(|_| c.commit_byte());
            let state = public_state(&mut c, IV);
            let output = compression(&mut c, state, block);
            let witness = c.eval(&byte_inputs(&[fill; 64])).unwrap();
            let result = output.map(|b| witness.byte(b));
            let mut expected = IV;
            sha2::compress256(&mut expected, &[([fill; 64]).into()]);
            let expected: Vec<_> = expected.into_iter().flat_map(u32::to_be_bytes).collect();
            assert_eq!(result.as_slice(), expected);
            assert_eq!(c.committed_bits(), 512 + SHA256_COMPRESS.and_count());
        }
    }
}
