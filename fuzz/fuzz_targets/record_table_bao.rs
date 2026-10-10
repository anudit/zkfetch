#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zkf_attestation::records::{Direction, Opening};

fuzz_target!(|data: &[u8]| {
    if data.len() > 65536 {
        return;
    }
    // The encoded pair lets mutations explore table invariants as well as
    // authenticated Bao decoding. Production decoders also enforce canonical
    // presentation encoding, which is not implemented yet.
    if let Ok((direction, opening)) =
        ciborium::from_reader::<(Direction, Opening), _>(Cursor::new(data))
    {
        let _ = direction.validate();
        if let Ok(bytes) = opening.verify(&direction) {
            assert_eq!(bytes.len() as u64, opening.length);
        }
    }
});
