//! End-to-end: fixture HTTPS server + notary + prover + verifier, in-process.
//! Run with `cargo test --release` (MPC is slow unoptimized).

use std::sync::Arc;

use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncWriteCompatExt;
use zkf_core::{NotarizeParams, ResponseReveal, RevealSpec, VerifyOptions, b64};

fn gte(path: &str, minimum: u64) -> zkf_core::PredicateSpec {
    zkf_core::PredicateSpec {
        json_path: path.into(),
        predicate: zkf_core::NumericPredicate {
            gte: Some(zkf_core::Decimal::Number(minimum)),
            gt: None,
        },
    }
}

fn params(
    notary_url: String,
    fixture: String,
    predicates: Vec<zkf_core::PredicateSpec>,
) -> NotarizeParams {
    NotarizeParams {
        notary_url,
        url: format!("https://{SERVER_DOMAIN}/formats/json"),
        method: None,
        headers: vec![],
        body: None,
        connect_addr: Some(fixture),
        extra_root_certs: vec![b64::encode(CA_CERT_DER)],
        max_sent: None,
        max_recv: None,
        owner: None,
        context: None,
        predicates,
        binius: false,
        tls_version: Some("1.2".into()),
        mode: None,
    }
}

async fn spawn_fixture() -> String {
    spawn_fixture_version(false).await
}

async fn spawn_fixture_version(tls13_only: bool) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                if tls13_only {
                    tlsn_server_fixture::bind_tls13(socket.compat_write()).await
                } else {
                    tlsn_server_fixture::bind(socket.compat_write()).await
                }
            });
        }
    });
    addr
}

async fn spawn_notary() -> (String, String) {
    let config = Arc::new(zkf_notary::NotaryConfig {
        signing_key: [7u8; 32],
        extra_roots: vec![CA_CERT_DER.to_vec()],
    });
    let key = config.public_key_hex().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let connector = Arc::new(zkf_notary::TcpConnector { resolve: vec![] });
    tokio::spawn(zkf_notary::serve(listener, config, connector));
    (url, key)
}

#[tokio::test(flavor = "multi_thread")]
async fn notarize_present_verify() {
    let fixture = spawn_fixture().await;
    let (notary_url, notary_key) = spawn_notary().await;
    let ca = b64::encode(CA_CERT_DER);

    let out = zkf_prover::notarize(NotarizeParams {
        notary_url,
        url: format!("https://{SERVER_DOMAIN}/formats/json"),
        method: None,
        headers: vec![("Authorization".into(), "Bearer super-secret-token".into())],
        body: None,
        connect_addr: Some(fixture),
        extra_root_certs: vec![ca.clone()],
        max_sent: None,
        max_recv: None,
        owner: Some("0xowner".into()),
        context: Some("challenge-42".into()),
        // QuickSilver predicate attested at fetch time (default backend)...
        predicates: vec![gte("id", 1000)],
        // ...plus per-leaf commitments so Binius64 can prove more later.
        binius: true,
        tls_version: Some("1.2".into()),
        mode: None,
    })
    .await
    .expect("notarize");

    assert_eq!(out.response.status, 200);
    assert_eq!(
        out.notary_key.key, notary_key,
        "notary key reported by attestation"
    );
    let body: serde_json::Value = serde_json::from_str(&out.response.body).unwrap();
    assert_eq!(body["meta"]["version"], serde_json::json!(1.2));

    let spec = RevealSpec {
        response: ResponseReveal {
            json_paths: vec!["id".into(), "meta.version".into()],
            ..Default::default()
        },
        ..Default::default()
    };
    let presentation = zkf_prover::present(&out.attestation, &out.secrets, &spec).unwrap();

    let opts = VerifyOptions {
        trusted_notary_keys: vec![notary_key.clone()],
        extra_root_certs: vec![ca.clone()],
        expected_owner: Some("0xowner".into()),
        expected_context: Some("challenge-42".into()),
        ..Default::default()
    };
    let verified = zkf_verifier::verify(&presentation, &opts).expect("verify");

    assert_eq!(verified.server_name, SERVER_DOMAIN);
    assert!(verified.notary_trusted);
    assert!(verified.sent.starts_with("GET /formats/json HTTP/1.1"));
    assert!(
        !verified.sent.contains("super-secret-token"),
        "auth value must stay hidden"
    );
    assert!(
        verified
            .sent
            .to_ascii_lowercase()
            .contains("authorization: "),
        "header name revealed"
    );
    assert!(verified.recv.starts_with("HTTP/1.1 200 OK"));
    assert!(
        verified.recv.contains("\"id\":1234567890"),
        "{}",
        verified.recv
    );
    assert!(verified.recv.contains("\"version\":1.2"));
    // Only the selected key/value is disclosed from the body.
    assert!(!verified.recv.contains("John Doe"));

    // A field nested inside an array element can be revealed on its own.
    let nested = RevealSpec {
        response: ResponseReveal {
            json_paths: vec!["information.family.siblings.0.name".into()],
            ..Default::default()
        },
        ..Default::default()
    };
    let nested = zkf_prover::present(&out.attestation, &out.secrets, &nested).unwrap();
    let nested = zkf_verifier::verify(&nested, &opts).expect("verify nested");
    assert!(
        nested.recv.contains("\"name\":\"Jane Doe\""),
        "{}",
        nested.recv
    );
    assert!(!nested.recv.contains("John Doe"));

    // Tamper: change a revealed byte; verification must fail.
    let mut raw = b64::decode(&presentation).unwrap();
    let needle = b"1234567890";
    let pos = raw
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("revealed value present");
    raw[pos] ^= 0x01;
    assert!(
        zkf_verifier::verify(&b64::encode(&raw), &opts).is_err(),
        "tampered value accepted"
    );

    // Wrong notary key / context must be rejected.
    let bad_key = VerifyOptions {
        trusted_notary_keys: vec!["02".repeat(33)],
        ..opts.clone()
    };
    assert!(zkf_verifier::verify(&presentation, &bad_key).is_err());
    let bad_ctx = VerifyOptions {
        expected_context: Some("other".into()),
        ..opts.clone()
    };
    assert!(zkf_verifier::verify(&presentation, &bad_ctx).is_err());

    // A hidden number is proven against its signed commitment and JSON path.
    let predicate = zkf_core::PredicateSpec {
        json_path: "id".into(),
        predicate: zkf_core::NumericPredicate {
            gte: Some(zkf_core::Decimal::Number(1_000_000_000)),
            gt: None,
        },
    };
    let spec = RevealSpec {
        prove: vec![predicate.clone()],
        backend: zkf_core::PredicateBackend::Binius,
        ..Default::default()
    };
    let p = zkf_prover::present(&out.attestation, &out.secrets, &spec).expect("prove id");
    let opts = VerifyOptions {
        expected_predicates: vec![predicate.clone()],
        ..opts
    };
    let v = zkf_verifier::verify(&p, &opts).expect("verify hidden id");
    assert_eq!(v.predicates, vec![predicate]);
    assert!(!v.recv.contains("1234567890"));
    assert!(!v.recv.contains("John Doe"));
    assert!(!v.sent.contains("super-secret-token"));
    // Stripping the envelope does not satisfy the verifier's required claim.
    let bytes = b64::decode(&p).unwrap();
    let envelope = zkf_predicates::decode(&bytes).unwrap().unwrap();
    assert!(zkf_verifier::verify(&b64::encode(&envelope.presentation), &opts).is_err());
    let mut swapped = envelope;
    swapped
        .claims
        .iter_mut()
        .find(|c| c.predicate.is_some())
        .unwrap()
        .predicate
        .as_mut()
        .unwrap()
        .json_path = "information.age".into();
    let mut raw = zkf_predicates::MAGIC.to_vec();
    raw.extend(bincode::serialize(&swapped).unwrap());
    assert!(zkf_verifier::verify(&b64::encode(raw), &opts).is_err());

    let nested = zkf_core::PredicateSpec {
        json_path: "information.family.siblings.0.age".into(),
        predicate: zkf_core::NumericPredicate {
            gte: None,
            gt: Some(zkf_core::Decimal::String("23".into())),
        },
    };
    let claims = vec![spec.prove[0].clone(), nested];
    let p = zkf_prover::present(
        &out.attestation,
        &out.secrets,
        &RevealSpec {
            response: ResponseReveal {
                json_paths: vec!["information.name".into()],
                ..Default::default()
            },
            prove: claims.clone(),
            backend: zkf_core::PredicateBackend::Binius,
            ..Default::default()
        },
    )
    .expect("multiple predicates with disclosed sibling");
    let v = zkf_verifier::verify(
        &p,
        &VerifyOptions {
            expected_predicates: claims.clone(),
            ..opts.clone()
        },
    )
    .unwrap();
    assert_eq!(v.predicates, claims);
    assert!(v.recv.contains("John Doe"));
    assert!(!v.recv.contains("1234567890"));
    assert!(!v.recv.contains("\"age\":24"));
}

#[tokio::test(flavor = "multi_thread")]
async fn quicksilver_predicate_default() {
    let fixture = spawn_fixture().await;
    let (notary_url, notary_key) = spawn_notary().await;
    let ca = b64::encode(CA_CERT_DER);

    let out = zkf_prover::notarize(params(notary_url, fixture, vec![gte("id", 1000)]))
        .await
        .expect("notarize with QuickSilver predicate");

    // Disclose nothing but the JSON skeleton; the value stays hidden.
    let wanted = gte("id", 1000);
    let spec = RevealSpec {
        prove: vec![wanted.clone()],
        ..Default::default()
    };
    let p = zkf_prover::present(&out.attestation, &out.secrets, &spec).expect("present");
    assert!(
        zkf_predicates::decode(&b64::decode(&p).unwrap())
            .unwrap()
            .is_none(),
        "no Binius envelope"
    );

    let opts = VerifyOptions {
        trusted_notary_keys: vec![notary_key],
        extra_root_certs: vec![ca],
        expected_predicates: vec![wanted.clone()],
        ..Default::default()
    };
    let v = zkf_verifier::verify(&p, &opts).expect("verify QuickSilver predicate");
    assert_eq!(v.predicates.len(), 1);
    assert_eq!(v.predicates[0].json_path, "id");
    assert_eq!(v.predicates[0].predicate.minimum().unwrap(), 1000);
    assert!(!v.recv.contains("1234567890"), "{}", v.recv);
    assert!(!v.recv.contains("John Doe"));
    assert!(
        v.recv.contains("\"id\":"),
        "key is disclosed with the skeleton"
    );

    // A stronger requirement than was attested is rejected...
    let stronger = VerifyOptions {
        expected_predicates: vec![gte("id", 1_234_567_891)],
        ..opts.clone()
    };
    assert!(zkf_verifier::verify(&p, &stronger).is_err());
    // ...and so is asking to present one that was never attested.
    let spec = RevealSpec {
        prove: vec![gte("information.age", 1)],
        ..Default::default()
    };
    assert!(zkf_prover::present(&out.attestation, &out.secrets, &spec).is_err());

    // Without the skeleton the predicate cannot be path-bound, so it is not reported.
    let plain =
        zkf_prover::present(&out.attestation, &out.secrets, &RevealSpec::default()).unwrap();
    assert!(
        zkf_verifier::verify(&plain, &opts).is_err(),
        "expected predicate missing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn quicksilver_false_predicate_rejected() {
    let fixture = spawn_fixture().await;
    let (notary_url, _) = spawn_notary().await;
    let err = zkf_prover::notarize(params(notary_url, fixture, vec![gte("id", 9_999_999_999)]))
        .await
        .expect_err("false predicate must not notarize");
    assert!(format!("{err:#}").contains("does not hold"), "{err:#}");
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_falls_back_for_get_but_never_retries_post() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let connections = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fixture = listener.local_addr().unwrap().to_string();
    let counter = connections.clone();
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(tlsn_server_fixture::bind_tls12(socket.compat_write()));
        }
    });
    let (notary_url, _) = spawn_notary().await;
    let mut get = params(notary_url.clone(), fixture.clone(), vec![]);
    get.tls_version = None; // The default auto preference.
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(45),
        zkf_prover::notarize(get),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(out.tls_version, "1.2");
    assert_eq!(connections.load(Ordering::SeqCst), 2, "GET retries TLS 1.2");

    let mut post = params(notary_url, fixture, vec![]);
    post.method = Some("POST".into());
    post.tls_version = Some("auto".into());
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(45),
            zkf_prover::notarize(post)
        )
        .await
        .unwrap()
        .is_err()
    );
    assert_eq!(
        connections.load(Ordering::SeqCst),
        3,
        "POST makes only one attempt"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn tls13_notarize_present_verify() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let fixture = spawn_fixture_version(true).await;
    let (notary_url, notary_key) = spawn_notary().await;
    let ca = b64::encode(CA_CERT_DER);

    let mut p = params(notary_url, fixture, vec![gte("id", 1000)]);
    p.tls_version = Some("1.3".into());
    p.binius = true;
    p.headers = vec![("Authorization".into(), "Bearer tls13-secret".into())];
    let out = tokio::time::timeout(std::time::Duration::from_secs(45), zkf_prover::notarize(p))
        .await
        .expect("TLS 1.3 session timeout")
        .expect("TLS 1.3 notarize");
    assert_eq!(out.tls_version, "1.3");
    assert_eq!(out.response.status, 200);
    let body: serde_json::Value = serde_json::from_str(&out.response.body).unwrap();
    assert_eq!(body["id"], serde_json::json!(1234567890));

    let opts = VerifyOptions {
        trusted_notary_keys: vec![notary_key],
        extra_root_certs: vec![ca],
        ..Default::default()
    };

    // Selective disclosure over TLS 1.3.
    let spec = RevealSpec {
        response: ResponseReveal {
            json_paths: vec!["information.name".into()],
            ..Default::default()
        },
        ..Default::default()
    };
    let presentation = zkf_prover::present(&out.attestation, &out.secrets, &spec).unwrap();
    let v = zkf_verifier::verify(&presentation, &opts).expect("verify TLS 1.3 presentation");
    assert_eq!(v.tls_version, "V1_3");
    assert_eq!(v.server_name, SERVER_DOMAIN);
    assert!(
        v.sent.starts_with("GET /formats/json HTTP/1.1"),
        "{}",
        v.sent
    );
    assert!(!v.sent.contains("tls13-secret"));
    assert!(v.recv.starts_with("HTTP/1.1 200 OK"), "{}", v.recv);
    assert!(v.recv.contains("\"name\":\"John Doe\""), "{}", v.recv);
    assert!(!v.recv.contains("1234567890"));

    // QuickSilver predicate over TLS 1.3.
    let spec = RevealSpec {
        prove: vec![gte("id", 1000)],
        ..Default::default()
    };
    let presentation = zkf_prover::present(&out.attestation, &out.secrets, &spec).unwrap();
    let v = zkf_verifier::verify(
        &presentation,
        &VerifyOptions {
            expected_predicates: vec![gte("id", 1000)],
            ..opts.clone()
        },
    )
    .expect("verify TLS 1.3 predicate");
    assert_eq!(v.predicates.len(), 1);

    // The opt-in backend can prove a new threshold after a TLS 1.3 fetch.
    let claim = gte("id", 1_000_000_000);
    let binius = zkf_prover::present(
        &out.attestation,
        &out.secrets,
        &RevealSpec {
            prove: vec![claim.clone()],
            backend: zkf_core::PredicateBackend::Binius,
            ..Default::default()
        },
    )
    .unwrap();
    let v = zkf_verifier::verify(
        &binius,
        &VerifyOptions {
            expected_predicates: vec![claim.clone()],
            ..opts.clone()
        },
    )
    .unwrap();
    assert_eq!(v.predicates, vec![claim]);
    assert!(!v.recv.contains("1234567890"));

    // A tampered revealed byte is rejected.
    let mut raw = b64::decode(
        &zkf_prover::present(
            &out.attestation,
            &out.secrets,
            &RevealSpec {
                response: ResponseReveal {
                    json_paths: vec!["id".into()],
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap(),
    )
    .unwrap();
    let pos = raw
        .windows(10)
        .position(|w| w == b"1234567890")
        .expect("revealed");
    raw[pos] ^= 1;
    assert!(zkf_verifier::verify(&b64::encode(&raw), &opts).is_err());

    // The certificate opening must agree with the signed protocol version.
    let secrets: tlsn::attestation::Secrets =
        bincode::deserialize(&b64::decode(&out.secrets).unwrap()).unwrap();
    let identity = secrets.identity_proof();
    assert!(
        identity
            .verify_tls_version(tlsn::connection::TlsVersion::V1_3)
            .is_ok()
    );
    assert!(
        identity
            .verify_tls_version(tlsn::connection::TlsVersion::V1_2)
            .is_err()
    );

    // Check the real CertificateVerify binding, then substitute a different
    // server key both in the binding and as the expected attested key. The
    // unchanged ServerHello must still reject it.
    let serialized = serde_json::to_value(&secrets).unwrap();
    let mut handshake: tlsn::connection::HandshakeData =
        serde_json::from_value(serialized["server_cert_opening"]["data"].clone()).unwrap();
    let attestation: tlsn::attestation::Attestation =
        bincode::deserialize(&b64::decode(&out.attestation).unwrap()).unwrap();
    let mut provider = tlsn::attestation::CryptoProvider::default();
    let mut roots = tlsn::webpki::RootCertStore::empty();
    roots
        .roots
        .push(tlsn::webpki::CertificateDer(CA_CERT_DER.to_vec()));
    provider.cert = tlsn::webpki::ServerCertVerifier::new(&roots).unwrap();
    let attestation_json = serde_json::to_value(&attestation).unwrap();
    let time = attestation_json["body"]["connection_info"]["data"]["time"]
        .as_u64()
        .unwrap();
    let key = handshake.binding.server_ephemeral_key().clone();
    handshake
        .verify(&provider.cert, time, &key, secrets.server_name())
        .unwrap();
    let tlsn::connection::CertBinding::V1_3(binding) = &mut handshake.binding else {
        panic!("expected TLS 1.3")
    };
    binding.server_ephemeral_key.key[10] ^= 1;
    let wrong_key = binding.server_ephemeral_key.clone();
    assert!(
        handshake
            .verify(&provider.cert, time, &wrong_key, secrets.server_name())
            .is_err()
    );
}
