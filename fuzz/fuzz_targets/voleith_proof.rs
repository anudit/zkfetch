#![no_main]
use libfuzzer_sys::fuzz_target;
use zkf_ir::{Circuit, Term, field::Fe};
use zkf_voleith::experimental::{self, Context};

fuzz_target!(|data: &[u8]| {
    let mut circuit = Circuit::default();
    let x = circuit.commit_bit();
    circuit.assert_zero(vec![Term::Linear(Fe::ONE, x), Term::Constant(Fe::ONE)]);
    let context = Context {
        attestation_digest: [1; 32],
        statement: b"public fuzz seed relation",
        presentation_nonce: [2; 32],
    };
    if experimental::verify(&circuit, data, &context).is_ok() {
        let replay = Context {
            presentation_nonce: [3; 32],
            ..context
        };
        assert!(experimental::verify(&circuit, data, &replay).is_err());
    }
});
