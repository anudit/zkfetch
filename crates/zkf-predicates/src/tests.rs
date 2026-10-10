use super::*;
use zkf_core::{Decimal, NumericPredicate};

fn integer(data: &[u8], minimum: u64) -> (ScalarClaim, Vec<u8>) {
    let mut witness = data.to_vec();
    witness.extend_from_slice(&[9; 16]);
    let claim = ScalarClaim {
        idx: (0..data.len()).into(),
        digest: *blake3::hash(&witness).as_bytes(),
        kind: ScalarKind::UnsignedInteger,
        predicate: Some(PredicateSpec {
            json_path: "streak".into(),
            predicate: NumericPredicate {
                gte: Some(Decimal::Number(minimum)),
                gt: None,
            },
        }),
    };
    (claim, witness)
}

#[test]
fn binary_envelope_preserves_public_claims() {
    let (claim, _) = integer(b"365", 365);
    let envelope = Envelope {
        presentation: vec![1, 2, 3],
        claims: vec![claim],
        proof: vec![4, 5],
    };
    let mut bytes = MAGIC.to_vec();
    bytes.extend(bincode::serialize(&envelope).unwrap());
    let decoded = decode(&bytes).unwrap().unwrap();
    assert_eq!(decoded.claims[0].predicate, envelope.claims[0].predicate);
    assert_eq!(decoded.proof, envelope.proof);
    bytes.push(0);
    assert!(decode(&bytes).is_err(), "trailing bytes accepted");
}

#[test]
#[cfg(feature = "legacy-binius")]
fn zk_integer_boundary_and_tampering() {
    let (claim, witness) = integer(b"365", 365);
    let proof = circuit::prove(std::slice::from_ref(&claim), &[witness], b"session A").unwrap();
    circuit::verify(std::slice::from_ref(&claim), proof.clone(), b"session A").unwrap();
    assert!(circuit::verify(std::slice::from_ref(&claim), proof.clone(), b"session B").is_err());
    let mut changed = claim.clone();
    changed.digest[0] ^= 1;
    assert!(circuit::verify(&[changed], proof.clone(), b"session A").is_err());
    let mut changed = claim;
    changed.predicate.as_mut().unwrap().predicate.gte = Some(Decimal::Number(366));
    assert!(circuit::verify(&[changed], proof.clone(), b"session A").is_err());
    let mut changed = proof;
    *changed.last_mut().unwrap() ^= 1;
    assert!(circuit::verify(&[integer(b"365", 365).0], changed, b"session A").is_err());
}

#[test]
#[cfg(feature = "legacy-binius")]
fn malformed_or_false_integer_rejected() {
    for data in [
        b"364".as_slice(),
        b"-365",
        b"0365",
        b"365.0",
        b"3e3",
        b"+365",
        b"365 ",
        b"1,2",
    ] {
        let (claim, witness) = integer(data, 365);
        assert!(
            circuit::prove(&[claim], &[witness], b"test").is_err(),
            "accepted {:?}",
            data
        );
    }
    let (claim, witness) = integer(b"9999999999999999999", 9999999999999999999);
    let proof = circuit::prove(std::slice::from_ref(&claim), &[witness], b"wide integer").unwrap();
    circuit::verify(&[claim], proof, b"wide integer").unwrap();
    let (claim, witness) = integer(b"18446744073709551616", 0);
    assert!(circuit::prove(&[claim], &[witness], b"overflow").is_err());
}

#[test]
#[cfg(feature = "legacy-binius")]
fn hidden_scalars_cannot_contain_structure() {
    for (kind, good, bad) in [
        (ScalarKind::Atom, b"1.2e-3".as_slice(), b"1,2".as_slice()),
        (ScalarKind::Atom, b"false".as_slice(), b"{}".as_slice()),
        (
            ScalarKind::StringContent,
            b"secret\\u0041\\\"".as_slice(),
            b"evil\",\"other\":7".as_slice(),
        ),
        (
            ScalarKind::StringContent,
            "😀é€".as_bytes(),
            b"\xc0\xaf".as_slice(),
        ),
        (
            ScalarKind::StringContent,
            b"escaped\\n".as_slice(),
            b"\xed\xa0\x80".as_slice(),
        ),
        (
            ScalarKind::StringContent,
            b"text".as_slice(),
            b"\xf4\x90\x80\x80".as_slice(),
        ),
        (
            ScalarKind::StringContent,
            b"text".as_slice(),
            b"\xe2\x82".as_slice(),
        ),
        (
            ScalarKind::StringContent,
            b"\\uD800\\uDC00".as_slice(),
            b"\\uD800".as_slice(),
        ),
        (
            ScalarKind::StringContent,
            b"\\u1234".as_slice(),
            b"\\uDC00".as_slice(),
        ),
    ] {
        for (data, valid) in [(good, true), (bad, false)] {
            let (mut claim, witness) = integer(data, 0);
            claim.kind = kind;
            claim.predicate = None;
            let proof = circuit::prove(&[claim.clone()], &[witness], b"shape");
            assert_eq!(proof.is_ok(), valid, "data {:?}", data);
            if let Ok(proof) = proof {
                circuit::verify(&[claim], proof, b"shape").unwrap();
            }
        }
    }
}

#[test]
fn ambiguous_json_rejected() {
    use tlsn_formats::spansy::json::parse;
    let doc = parse(b"{\"a\":1,\"\\u0061\":2}".as_slice()).unwrap();
    assert!(validate_keys(&doc.root).is_err());
    for json in [r#"{"a.b":1,"a":{"b":2}}"#, r#"{"a\u002eb":1}"#, r#"{"":1}"#] {
        let doc = parse(json.as_bytes()).unwrap();
        assert!(validate_keys(&doc.root).is_err());
    }
    let doc = parse(b"{\"items\":[{\"streak\":365}]}".as_slice()).unwrap();
    validate_keys(&doc.root).unwrap();
    assert!(resolve(&doc.root, "items.0.streak").is_ok());
    assert!(resolve(&doc.root, "items.00.streak").is_err());
    assert!(resolve(&doc.root, "items.1.streak").is_err());
}

/// Benchmark (run with `--ignored --nocapture`): Binius cost of hidden scalars.
#[test]
#[ignore]
#[cfg(feature = "legacy-binius")]
fn bench_leaf_hash() {
    let cases: [(&str, &[u8]); 3] = [
        ("3-digit integer", b"439"),
        ("10-digit integer", b"1234567890"),
        ("19-digit integer", b"1234567890123456789"),
    ];
    for (name, data) in cases {
        let (claim, witness) = integer(data, 1);
        let claims = vec![claim];
        let ands = circuit::and_constraints(&claims);
        let started = std::time::Instant::now();
        let proof = circuit::prove(&claims, &[witness], b"bench").unwrap();
        let prove_ms = started.elapsed().as_secs_f64() * 1e3;
        let started = std::time::Instant::now();
        circuit::verify(&claims, proof.clone(), b"bench").unwrap();
        let verify_ms = started.elapsed().as_secs_f64() * 1e3;
        println!(
            "BENCH {name}: and={ands} prove={prove_ms:.1}ms verify={verify_ms:.1}ms proof={}B",
            proof.len()
        );
    }
}

#[test]
fn production_quicksilver_unicode_matches_strict_json() {
    let cases: &[&[u8]] = &[
        b"X",
        b"hello",
        "café".as_bytes(),
        "😀".as_bytes(),
        b"\\uD800\\uDC00",
        b"\\uD800",
        b"\\uDC00",
        b"\\uD800x",
        b"\\uD800\\u1234",
        b"\\u1234",
        b"\\uZZZZ",
        b"\xff",
        b"\xc0\x80",
        b"\xed\xa0\x80",
        b"\xf4\x90\x80\x80",
        b"\xc2",
        b"\x80",
    ];
    for data in cases {
        let reference = std::str::from_utf8(data)
            .ok()
            .is_some_and(|s| serde_json::from_str::<String>(&format!("\"{s}\"")).is_ok());
        assert_eq!(
            tlsn::security_test_support::json_string(data),
            reference,
            "{data:?}"
        );
    }
    for byte in 0..=255 {
        let data = [byte];
        let reference = std::str::from_utf8(&data)
            .ok()
            .is_some_and(|s| serde_json::from_str::<String>(&format!("\"{s}\"")).is_ok());
        assert_eq!(tlsn::security_test_support::json_string(&data), reference);
    }
}

#[test]
fn production_mpc_handshake_substitution_and_truncation_are_rejected() {
    assert_eq!(
        tlsn::security_test_support::handshake_mutations(),
        vec![true; 8]
    );
}
#[test]
fn production_proxy_record_and_byte_budgets_fail_closed() {
    let record = |typ: u8, payload: usize| {
        let mut wire = vec![typ, 3, 3];
        wire.extend_from_slice(&(payload as u16).to_be_bytes());
        wire.resize(payload + 5, 0);
        wire
    };
    for limit in [1 << 17, 1 << 20] {
        let (accepted, captured) = tlsn::security_test_support::proxy_records(
            record(23, 1024).repeat(limit / 1024 + 2),
            limit,
        );
        assert!(!accepted);
        assert!(captured <= limit);
    }
    for wire in [
        record(23, 0).repeat(4097),
        record(22, 16384).repeat(9),
        vec![23, 3, 3, 255, 255],
        vec![255, 3, 3, 0, 0],
    ] {
        assert!(!tlsn::security_test_support::proxy_records(wire, 1 << 20).0);
    }
    assert!(tlsn::security_test_support::proxy_records(record(23, 1024), 1 << 20).0);
}

#[test]
fn production_commitment_budget_rejects_overlap_count_and_bounds() {
    use tlsn::transcript::Direction::Received;
    let check = tlsn::security_test_support::hash_budget;
    assert!(check(vec![(Received, 0..1024)], 0, 1024));
    assert!(!check(vec![(Received, 0..1024); 3], 0, 1024));
    assert!(!check(vec![(Received, 0..1); 2049], 0, 2049));
    assert!(!check(vec![(Received, 0..(1 << 20) + 1)], 0, (1 << 20) + 1));
    assert!(!check(vec![(Received, 0..1025)], 0, 1024));
}
