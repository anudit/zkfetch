#![no_main]
use libfuzzer_sys::fuzz_target;
use zkf_attestation::Attestation;

fuzz_target!(|data: &[u8]| {
    if let Ok(attestation) = Attestation::decode(data) {
        let encoded = attestation
            .encode()
            .expect("decoded attestation must encode");
        assert_eq!(encoded, data);
        let again = Attestation::decode(&encoded).unwrap();
        assert_eq!(attestation, again);
    }
});
