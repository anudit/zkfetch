//! Synthetic relation benchmark, not a hosted TLS session or attestation.
use aes::{
    Aes128,
    cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
};
use std::time::Instant;
use zkf_ir::{
    Circuit,
    aes::ExpandedKey,
    byte_inputs,
    json_circuit::{self, Selection},
    predicates::{self, Comparison, U64},
    tls,
};
use zkf_voleith::{
    experimental::{self, Context},
    primitives::Parameters,
};

fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("json");
    anyhow::ensure!(
        matches!(mode, "json" | "key-ctr"),
        "mode must be json or key-ctr"
    );
    let padding: usize = args.get(2).map(|v| v.parse()).transpose()?.unwrap_or(32);
    anyhow::ensure!(padding <= 4096, "synthetic padding exceeds benchmark cap");
    let params = match args.get(3).map(String::as_str).unwrap_or("8") {
        "8" => Parameters::Fast,
        "11" => Parameters::Small,
        _ => anyhow::bail!("k must be 8 or 11"),
    };
    let raw_key = [7u8; 16];
    let native = Aes128::new_from_slice(&raw_key).unwrap();
    let build = Instant::now();
    let mut c = Circuit::default();
    let key: Vec<_> = (0..16).map(|_| c.commit_byte()).collect();
    let expanded = ExpandedKey::new(&mut c, &key)?;
    let ck = tls::key_commitment(&mut c, &expanded);
    for block in 0..2 {
        let mut expected = GenericArray::clone_from_slice(&tls::commitment_block(block as u8 + 1)?);
        native.encrypt_block(&mut expected);
        for i in 0..16 {
            c.assert_byte(ck[block * 16 + i], expected[i]);
        }
    }
    let body = if mode == "json" {
        format!("{{\"id\":123,\"padding\":\"{}\"}}", "x".repeat(padding)).into_bytes()
    } else {
        b"0123456789abcdef".to_vec()
    };
    let mut inner = body.clone();
    inner.push(0x17);
    let inner_len = inner.len();
    inner.resize(inner.len().div_ceil(16) * 16, 0);
    let mut plaintext = Vec::new();
    for (index, block) in inner.as_chunks::<16>().0.iter().enumerate() {
        let counter = tls::counter_block([0; 12], 0, index as u32)?;
        let mut encrypted = GenericArray::clone_from_slice(&counter);
        native.encrypt_block(&mut encrypted);
        let ciphertext = std::array::from_fn(|i| block[i] ^ encrypted[i]);
        plaintext.extend_from_slice(&tls::ctr_block(
            &mut c, &expanded, counter, ciphertext, [None; 16],
        )?);
    }
    // Only the actual TLSInnerPlaintext tail belongs to the suffix statement.
    tls::assert_application_suffix(&mut c, &plaintext[body.len()..inner_len])?;
    if mode == "json" {
        let selected = json_circuit::member(
            &mut c,
            &plaintext[..body.len()],
            &Selection {
                encoded_key: br#""id""#,
                key: 1..5,
                colon: 5,
                value: 6..9,
            },
        )?;
        let value = predicates::ascii_u64(&mut c, &selected)?;
        let minimum = U64::public(&mut c, 100);
        value.assert_compare(&mut c, minimum, Comparison::Ge);
    } else {
        for (wire, byte) in plaintext.iter().zip(&body) {
            c.assert_byte(*wire, *byte);
        }
    }
    let build_ms = build.elapsed().as_secs_f64() * 1000.;
    let start = Instant::now();
    let witness = c.eval(&byte_inputs(&raw_key))?;
    let witness_ms = start.elapsed().as_secs_f64() * 1000.;
    let context = Context {
        attestation_digest: [1; 32],
        statement: b"synthetic Ck/CTR/JSON benchmark only",
        presentation_nonce: [2; 32],
    };
    let start = Instant::now();
    let proof = experimental::prove(&c, &witness, params, &context)?;
    let prove_ms = start.elapsed().as_secs_f64() * 1000.;
    let start = Instant::now();
    experimental::verify(&c, &proof, &context)?;
    let verify_ms = start.elapsed().as_secs_f64() * 1000.;
    println!(
        "{{\"experimental\":true,\"scope\":\"synthetic relation only; no TLS session or attestation\",\"mode\":\"{mode}\",\"k\":{},\"json_body_bytes\":{},\"committed_bits\":{},\"edges\":{},\"constraints\":{},\"proof_bytes\":{},\"build_ms\":{build_ms},\"witness_ms\":{witness_ms},\"prove_ms\":{prove_ms},\"verify_ms\":{verify_ms}}}",
        params.label(),
        body.len(),
        c.committed_bits(),
        c.edge_count(),
        c.constraint_count(),
        proof.len()
    );
    Ok(())
}
