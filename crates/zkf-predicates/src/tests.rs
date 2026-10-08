use super::*;
use zkf_core::{Decimal, NumericPredicate};

fn integer(data: &[u8], minimum: u64) -> (ScalarClaim, Vec<u8>) {
    let mut witness = data.to_vec();
    witness.extend_from_slice(&[9; 16]);
    let claim = ScalarClaim {
        idx: (0..data.len()).into(),
        digest: crate::circuit::leaf_digest(&witness),
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
    let doc = parse(b"{\"items\":[{\"streak\":365}]}".as_slice()).unwrap();
    validate_keys(&doc.root).unwrap();
    assert!(resolve(&doc.root, "items.0.streak").is_ok());
    assert!(resolve(&doc.root, "items.00.streak").is_err());
    assert!(resolve(&doc.root, "items.1.streak").is_err());
}

/// Benchmark (run with `--ignored --nocapture`): Binius cost of hidden scalars.
#[test]
#[ignore]
fn bench_leaf_hash() {
    let cases: [(&str, &[u8]); 3] = [("3-digit integer", b"439"), ("10-digit integer", b"1234567890"), ("19-digit integer", b"1234567890123456789")];
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
        println!("BENCH {name}: and={ands} prove={prove_ms:.1}ms verify={verify_ms:.1}ms proof={}B", proof.len());
    }
}
