//! Deterministic mutation smoke tests; sustained coverage-guided fuzzing is separate.
use zkf_core::{RevealSpec, VerifyOptions, b64};
#[test]
fn bounded_session_presentation_and_json_mutations_do_not_panic() {
    let mut state = 0x9e3779b97f4a7c15u64;
    for len in 0..512 {
        let mut bytes = vec![0; len];
        for byte in &mut bytes {
            state ^= state << 13; state ^= state >> 7; state ^= state << 17;
            *byte = state as u8;
        }
        let encoded = b64::encode(&bytes);
        let _ = zkf_verifier::verify(&encoded, &VerifyOptions { allow_untrusted_notary: true, ..Default::default() });
        let _ = zkf_prover::present(&encoded, &encoded, &RevealSpec::default());
        if zkf_core::parsing::check_json_nesting(&bytes).is_ok() {
            if let Ok(doc) = tlsn_formats::spansy::json::parse(bytes.as_slice()) {
                let _ = zkf_predicates::validate_keys(&doc.root);
            }
        }
    }
    let encoded = "A".repeat(zkf_core::MAX_FRAME_LEN.div_ceil(3) * 4 + 4);
    assert!(zkf_prover::present(&encoded, "", &RevealSpec::default()).is_err());
}
