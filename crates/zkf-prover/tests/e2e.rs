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

/// Reproducible W0 native baseline. Kept out of normal test runs because it
/// creates measured files and intentionally exercises the slower offline path.
#[cfg(feature = "legacy-binius")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "run explicitly to record the D1/D3 fixture baseline"]
async fn d1_d3_native_baseline() {
    let scenario = std::env::var("ZKF_D1_D3_SCENARIO").unwrap_or_else(|_| "binius".into());
    assert!(matches!(
        scenario.as_str(),
        "binius" | "quicksilver" | "reveal"
    ));
    let fixture = spawn_fixture_version(true).await;
    let (notary_url, notary_key) = spawn_proxy_notary(&fixture).await;
    let mut p = params(notary_url, String::new(), vec![]);
    p.connect_addr = None;
    p.mode = Some("proxy".into());
    p.tls_version = Some("1.3".into());
    p.protocol_v2 = Some(true); // Existing D4 wire flow; not D1 attestation v2.
    p.persistent_vole = Some(true);
    p.expected_notary_key = Some(notary_key.clone());
    p.binius = scenario == "binius";
    if !p.binius {
        p.predicates = vec![gte("id", 1000)];
    }
    let opts = VerifyOptions {
        trusted_notary_keys: vec![notary_key],
        extra_root_certs: vec![b64::encode(CA_CERT_DER)],
        expected_predicates: vec![gte("id", 1000)],
        ..Default::default()
    };
    let spec = RevealSpec {
        response: ResponseReveal {
            json_paths: vec!["information.name".into()],
            ..Default::default()
        },
        prove: vec![gte("id", 1000)],
        backend: if p.binius {
            zkf_core::PredicateBackend::Binius
        } else {
            zkf_core::PredicateBackend::Quicksilver
        },
        ..Default::default()
    };
    if scenario == "reveal" {
        p.reveal = Some(spec.clone());
    }
    let mut samples = Vec::new();
    for i in 0..3 {
        #[cfg(feature = "circuit-metrics")]
        tlsn::circuit_metrics::reset();
        let out = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            zkf_prover::notarize(p.clone()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(out.timings.vole_resumed, i != 0);
        let start = std::time::Instant::now();
        let presentation = zkf_prover::present(&out.attestation, &out.secrets, &spec).unwrap();
        let present_ms = start.elapsed().as_secs_f64() * 1000.0;
        let bytes = b64::decode(&presentation).unwrap();
        let offline_proof_bytes = zkf_predicates::decode(&bytes)
            .unwrap()
            .map_or(0, |e| e.proof.len());
        let start = std::time::Instant::now();
        let verified = zkf_verifier::verify(&presentation, &opts).unwrap();
        let verify_ms = start.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(verified.predicates.len(), spec.prove.len());
        for (actual, expected) in verified.predicates.iter().zip(&spec.prove) {
            assert_eq!(actual.json_path, expected.json_path);
            assert_eq!(
                actual.predicate.gte.as_ref().map(|v| v.value().unwrap()),
                expected.predicate.gte.as_ref().map(|v| v.value().unwrap())
            );
            assert_eq!(
                actual.predicate.gt.as_ref().map(|v| v.value().unwrap()),
                expected.predicate.gt.as_ref().map(|v| v.value().unwrap())
            );
        }
        #[cfg(feature = "circuit-metrics")]
        let allocations = serde_json::to_value(tlsn::circuit_metrics::snapshot()).unwrap();
        #[cfg(not(feature = "circuit-metrics"))]
        let allocations = serde_json::Value::Null;
        let sample = serde_json::json!({
            "session_index": i, "timings": out.timings,
            "presentation_prove_ms": present_ms, "presentation_verify_ms": verify_ms,
            "presentation_bytes": bytes.len(), "offline_proof_bytes": offline_proof_bytes,
            "attestation_bytes": b64::decode(&out.attestation).unwrap().len(),
            "circuit_allocations": allocations,
        });
        samples.push(sample);
    }
    let dir = std::env::var_os("ZKF_D1_D3_BASELINE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../docs/benchmarks/d1-d3-baseline")
        });
    std::fs::create_dir_all(&dir).unwrap();
    let report = serde_json::json!({
        "backend": if p.binius { "binius64" } else { "quicksilver" },
        "offline_security_bits": if p.binius { Some(96) } else { None },
        "scenario": scenario, "tls": "1.3", "mode": "proxy",
        "fixture": "/formats/json", "flow": "D4 existing protocol_v2",
        "latency_ms": 0, "architecture": std::env::consts::ARCH,
        "os": std::env::consts::OS, "samples": samples,
        "measurement_scope": "Presentation timings include parsing and transcript proof building, not just Binius.",
    });
    let path = dir.join(if scenario == "binius" {
        "native.json".into()
    } else {
        format!("native-{scenario}.json")
    });
    std::fs::write(&path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    eprintln!("D1/D3 baseline written to {}", path.display());
}

fn params(
    notary_url: String,
    fixture: String,
    predicates: Vec<zkf_core::PredicateSpec>,
) -> NotarizeParams {
    NotarizeParams {
        notary_url,
        persistent_vole: None,
        protocol_v2: None,
        expected_notary_key: None,
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
        reveal: None,
        tls_version: Some("1.2".into()),
        mode: None,
        relay_url: None,
        attestation_v2: false,
        signed_response_head: false,
        session_claims: vec![],
        session_claim_nonce: None,
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

#[cfg(feature = "legacy-binius")]
#[tokio::test(flavor = "multi_thread")]
async fn notarize_present_verify() {
    let fixture = spawn_fixture().await;
    let (notary_url, notary_key) = spawn_notary().await;
    let ca = b64::encode(CA_CERT_DER);

    let out = zkf_prover::notarize(NotarizeParams {
        notary_url,
        persistent_vole: None,
        protocol_v2: None,
        expected_notary_key: None,
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
        reveal: None,
        tls_version: Some("1.2".into()),
        mode: None,
        relay_url: None,
        attestation_v2: false,
        signed_response_head: false,
        session_claims: vec![],
        session_claim_nonce: None,
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
    assert_eq!(verified.mode, "mpc");
    // Shape proofs are attached by default, so disclosed values come with
    // authenticated paths (ZKF-07).
    let paths: Vec<&str> = verified.json.iter().map(|f| f.path.as_str()).collect();
    assert!(
        paths.contains(&"id") && paths.contains(&"meta.version"),
        "{paths:?}"
    );
    // MPC sessions pass a proxy-rejecting policy.
    zkf_verifier::verify(
        &presentation,
        &VerifyOptions {
            reject_proxy: true,
            ..opts.clone()
        },
    )
    .expect("MPC accepted with reject_proxy");
    // Authenticated ranges cover exactly what `recv` shows unredacted.
    assert!(!verified.recv_authed.is_empty());
    for [start, end] in &verified.recv_authed {
        assert!(!verified.recv.as_bytes()[*start..*end].is_empty());
    }

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

    // Byte-only disclosure must not leak parent keys or claim an authenticated path.
    let byte_only = RevealSpec {
        response: ResponseReveal {
            byte_only: true,
            json_paths: vec!["id".into()],
            ..Default::default()
        },
        ..Default::default()
    };
    let bytes = zkf_prover::present(&out.attestation, &out.secrets, &byte_only).unwrap();
    let view = zkf_verifier::verify(&bytes, &opts).unwrap();
    assert!(view.recv.contains("1234567890"));
    assert!(!view.recv.contains("information"));
    assert!(!view.json_paths_authenticated);
    assert!(
        zkf_verifier::verify(
            &bytes,
            &VerifyOptions {
                require_json_paths: true,
                ..opts.clone()
            }
        )
        .is_err()
    );

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

    // No trust policy fails closed; inspection must be explicit.
    let no_keys = VerifyOptions {
        trusted_notary_keys: vec![],
        ..opts.clone()
    };
    let err = zkf_verifier::verify(&presentation, &no_keys).unwrap_err();
    assert!(
        format!("{err:#}").contains("no trusted notary keys"),
        "{err:#}"
    );
    let inspected = zkf_verifier::verify(
        &presentation,
        &VerifyOptions {
            allow_untrusted_notary: true,
            ..no_keys
        },
    )
    .expect("explicit inspection");
    assert!(!inspected.notary_trusted);

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
async fn auto_never_retries_get_or_post() {
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
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(45),
            zkf_prover::notarize(get)
        )
        .await
        .unwrap()
        .is_err()
    );
    assert_eq!(connections.load(Ordering::SeqCst), 1, "GET must not retry");

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
        2,
        "POST makes only one attempt"
    );
}

#[cfg(feature = "legacy-binius")]
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

/// Notary that dials the fixture for `SERVER_DOMAIN` in proxy mode.
async fn spawn_proxy_notary(fixture: &str) -> (String, String) {
    let config = Arc::new(zkf_notary::NotaryConfig {
        signing_key: [7u8; 32],
        extra_roots: vec![CA_CERT_DER.to_vec()],
    });
    let key = config.public_key_hex().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let connector = Arc::new(zkf_notary::TcpConnector {
        resolve: vec![(SERVER_DOMAIN.to_string(), fixture.to_string())],
    });
    tokio::spawn(zkf_notary::serve(listener, config, connector));
    (url, key)
}

async fn proxy_round_trip(tls13: bool) {
    let fixture = spawn_fixture_version(tls13).await;
    let (notary_url, notary_key) = spawn_proxy_notary(&fixture).await;
    let mut p = params(notary_url, String::new(), vec![gte("id", 1000)]);
    p.connect_addr = None;
    p.mode = Some("proxy".into());
    p.tls_version = Some(if tls13 { "1.3" } else { "1.2" }.into());
    p.headers = vec![("Authorization".into(), "Bearer proxy-secret".into())];
    let out = tokio::time::timeout(std::time::Duration::from_secs(45), zkf_prover::notarize(p))
        .await
        .expect("proxy session timeout")
        .expect("proxy notarize");
    assert_eq!(out.tls_version, if tls13 { "1.3" } else { "1.2" });
    assert_eq!(out.response.status, 200);

    let opts = VerifyOptions {
        trusted_notary_keys: vec![notary_key],
        extra_root_certs: vec![b64::encode(CA_CERT_DER)],
        ..Default::default()
    };
    let spec = RevealSpec {
        response: ResponseReveal {
            json_paths: vec!["information.name".into()],
            ..Default::default()
        },
        ..Default::default()
    };
    let presentation = zkf_prover::present(&out.attestation, &out.secrets, &spec).unwrap();
    let v = zkf_verifier::verify(&presentation, &opts).expect("verify proxy presentation");
    assert_eq!(v.mode, "proxy");
    // The parent object is proven, not just a matching "name" key.
    assert_eq!(
        v.json,
        vec![zkf_core::JsonField {
            path: "information.name".into(),
            value: serde_json::json!("John Doe")
        }]
    );
    let err = zkf_verifier::verify(
        &presentation,
        &VerifyOptions {
            reject_proxy: true,
            ..opts.clone()
        },
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("proxy-mode sessions are not accepted"));
    assert_eq!(v.tls_version, if tls13 { "V1_3" } else { "V1_2" });
    assert_eq!(v.server_name, SERVER_DOMAIN);
    assert!(
        v.sent.starts_with("GET /formats/json HTTP/1.1"),
        "{}",
        v.sent
    );
    assert!(!v.sent.contains("proxy-secret"));
    assert!(v.recv.contains("\"name\":\"John Doe\""), "{}", v.recv);
    assert!(!v.recv.contains("1234567890"));

    // QuickSilver predicate attested during the proxy session.
    let presentation = zkf_prover::present(
        &out.attestation,
        &out.secrets,
        &RevealSpec {
            prove: vec![gte("id", 1000)],
            ..Default::default()
        },
    )
    .unwrap();
    let v = zkf_verifier::verify(
        &presentation,
        &VerifyOptions {
            expected_predicates: vec![gte("id", 1000)],
            ..opts
        },
    )
    .expect("verify proxy predicate");
    assert_eq!(v.predicates.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_tls13_notarize_present_verify() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    proxy_round_trip(true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_tls12_notarize_present_verify() {
    proxy_round_trip(false).await;
}

/// A server that reads the ClientHello and closes without an alert (as
/// servers without TLS 1.3 support may do) must fail the session cleanly
/// rather than overflow the stack or hang.
async fn spawn_hangup_server() -> String {
    use tokio::io::AsyncReadExt;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).await;
            });
        }
    });
    addr
}

async fn assert_handshake_hangup_fails(proxy: bool) {
    let server = spawn_hangup_server().await;
    let (notary_url, _) = if proxy {
        spawn_proxy_notary(&server).await
    } else {
        spawn_notary().await
    };
    let mut p = params(notary_url, server, vec![]);
    p.tls_version = Some("1.3".into());
    if proxy {
        p.connect_addr = None;
        p.mode = Some("proxy".into());
    }
    let err = tokio::time::timeout(std::time::Duration::from_secs(45), zkf_prover::notarize(p))
        .await
        .expect("session must fail, not hang")
        .expect_err("handshake cannot complete");
    assert!(
        format!("{err:#}").contains("server closed the connection during the TLS handshake"),
        "unexpected error: {err:#}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mpc_server_hangup_during_handshake_fails() {
    assert_handshake_hangup_fails(false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_server_hangup_during_handshake_fails() {
    assert_handshake_hangup_fails(true).await;
}

/// A session prepared ahead of the request notarizes like a fresh one, and
/// reports that connect and setup were done ahead.
async fn prepared_round_trip(proxy: bool) {
    let fixture = spawn_fixture_version(true).await;
    let (notary_url, notary_key) = if proxy {
        spawn_proxy_notary(&fixture).await
    } else {
        spawn_notary().await
    };
    let mut p = params(notary_url, fixture, vec![gte("id", 1000)]);
    p.tls_version = Some("auto".into());
    if proxy {
        p.connect_addr = None;
        p.mode = Some("proxy".into());
    }
    let prepared = zkf_prover::prepare(&p).await.expect("prepare");
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(45),
        zkf_prover::notarize_prepared(prepared, p.clone()),
    )
    .await
    .expect("prepared session timeout")
    .expect("notarize prepared");
    assert_eq!(out.response.status, 200);
    assert_eq!(out.tls_version, "1.3");
    assert!(out.timings.prewarmed);
    assert!(out.timings.setup_ms > 0.0);
    let waited = out.timings.tls_ms + out.timings.prove_ms + out.timings.attest_ms;
    assert!(
        out.timings.total_ms < waited + out.timings.setup_ms,
        "total excludes setup"
    );

    let opts = VerifyOptions {
        trusted_notary_keys: vec![notary_key],
        extra_root_certs: vec![b64::encode(CA_CERT_DER)],
        ..Default::default()
    };
    let presentation =
        zkf_prover::present(&out.attestation, &out.secrets, &RevealSpec::default()).unwrap();
    assert!(
        zkf_verifier::verify(&presentation, &opts)
            .unwrap()
            .notary_trusted
    );

    // A fresh session reports its own setup as part of the wait.
    let fresh = zkf_prover::notarize(p).await.expect("fresh notarize");
    assert!(!fresh.timings.prewarmed);
}

#[tokio::test(flavor = "multi_thread")]
async fn prepared_proxy_session() {
    prepared_round_trip(true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn prepared_mpc_session() {
    prepared_round_trip(false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn prepared_session_rejects_other_parameters() {
    let fixture = spawn_fixture_version(true).await;
    let (notary_url, _) = spawn_proxy_notary(&fixture).await;
    let mut p = params(notary_url, String::new(), vec![]);
    p.connect_addr = None;
    p.mode = Some("proxy".into());
    p.tls_version = Some("1.3".into());
    let prepared = zkf_prover::prepare(&p).await.expect("prepare");
    let mut other = p.clone();
    other.url = "https://other.example/formats/json".into();
    let err = zkf_prover::notarize_prepared(prepared, other)
        .await
        .expect_err("host differs from the prepared proxy session");
    assert!(format!("{err:#}").contains("does not match"), "{err:#}");
}

/// When the notary cannot reach the server it closes the connection. The
/// prover must report that promptly rather than wait on the closed socket.
#[tokio::test(flavor = "multi_thread")]
async fn proxy_unreachable_server_fails_fast() {
    // Nothing listens on port 1.
    let (notary_url, _) = spawn_proxy_notary("127.0.0.1:1").await;
    let mut p = params(notary_url, String::new(), vec![]);
    p.connect_addr = None;
    p.mode = Some("proxy".into());
    p.tls_version = Some("1.3".into());
    let err = tokio::time::timeout(std::time::Duration::from_secs(10), zkf_prover::notarize(p))
        .await
        .expect("session must fail, not hang")
        .expect_err("server is unreachable");
    assert!(
        (format!("{err:#}").contains("notary connection")
            || format!("{err:#}").contains("server closed the connection")),
        "unexpected error: {err:#}"
    );
}

/// Proxy mode has no preprocessing limit, so the prover enforces maxRecv
/// itself before spending minutes proving an oversized response.
#[tokio::test(flavor = "multi_thread")]
async fn proxy_response_over_max_recv_fails() {
    let fixture = spawn_fixture_version(true).await;
    let (notary_url, _) = spawn_proxy_notary(&fixture).await;
    let mut p = params(notary_url, String::new(), vec![]);
    p.connect_addr = None;
    p.mode = Some("proxy".into());
    p.tls_version = Some("1.3".into());
    p.max_recv = Some(64);
    let err = tokio::time::timeout(std::time::Duration::from_secs(45), zkf_prover::notarize(p))
        .await
        .expect("session must fail, not hang")
        .expect_err("response is larger than maxRecv");
    assert!(
        format!("{err:#}").contains("over the 64-byte limit for proxy mode"),
        "unexpected error: {err:#}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn notary_key_pin_is_checked_before_server_connection() {
    let fixture = spawn_fixture().await;
    let (url, key) = spawn_notary().await;
    let mut p = params(url, fixture, vec![]);
    p.expected_notary_key = Some("02".repeat(33));
    assert!(zkf_prover::prepare(&p).await.is_err());
    p.expected_notary_key = Some(key);
    assert!(zkf_prover::prepare(&p).await.is_ok());
}

/// Received-transcript ranges covered by the attestation's commitments.
fn committed_recv(attestation_b64: &str) -> tlsn::rangeset::set::RangeSet<usize> {
    use tlsn::{
        rangeset::set::RangeSet,
        transcript::{Direction, TranscriptCommitment},
    };
    let att: tlsn::attestation::Attestation =
        bincode::deserialize(&b64::decode(attestation_b64).unwrap()).unwrap();
    let mut all = RangeSet::default();
    for c in zkf_predicates::commitments(&att).unwrap() {
        if let TranscriptCommitment::Hash(h) = c
            && h.direction == Direction::Received
        {
            all.union_mut(&h.idx);
        }
    }
    all
}

fn recv_offset(secrets_b64: &str, needle: &str) -> std::ops::Range<usize> {
    let secrets: tlsn::attestation::Secrets =
        bincode::deserialize(&b64::decode(secrets_b64).unwrap()).unwrap();
    let recv = secrets.transcript().received();
    let at = recv
        .windows(needle.len())
        .position(|w| w == needle.as_bytes())
        .unwrap();
    at..at + needle.len()
}

async fn proxy_reveal_session(
    predicates: Vec<zkf_core::PredicateSpec>,
    reveal: RevealSpec,
    binius: bool,
) -> (zkf_core::NotarizeOutput, VerifyOptions) {
    let fixture = spawn_fixture_version(true).await;
    let (notary_url, notary_key) = spawn_proxy_notary(&fixture).await;
    let mut p = params(notary_url, String::new(), predicates);
    p.connect_addr = None;
    p.mode = Some("proxy".into());
    p.tls_version = Some("1.3".into());
    p.headers = vec![("Authorization".into(), "Bearer reveal-secret".into())];
    p.binius = binius;
    p.reveal = Some(reveal);
    let out = tokio::time::timeout(std::time::Duration::from_secs(45), zkf_prover::notarize(p))
        .await
        .expect("proxy session timeout")
        .expect("proxy notarize with reveal");
    let opts = VerifyOptions {
        trusted_notary_keys: vec![notary_key],
        extra_root_certs: vec![b64::encode(CA_CERT_DER)],
        ..Default::default()
    };
    (out, opts)
}

#[tokio::test(flavor = "multi_thread")]
async fn reveal_commits_only_disclosed_bytes() {
    use tlsn::rangeset::{ops::Set, set::RangeSet};
    let declared = RevealSpec {
        response: ResponseReveal {
            json_paths: vec!["information.name".into()],
            ..Default::default()
        },
        prove: vec![gte("id", 1000)],
        ..Default::default()
    };
    let (out, opts) = proxy_reveal_session(vec![gte("id", 1000)], declared.clone(), false).await;

    // Hidden values and secret headers are not committed at all.
    let committed = committed_recv(&out.attestation);
    for hidden in ["1234567890", "123 Elm Street"] {
        let idx = RangeSet::from(recv_offset(&out.secrets, hidden));
        assert!(
            idx.intersection(&committed).next().is_none(),
            "`{hidden}` must not be committed"
        );
    }

    // The declared disclosure verifies, with path-authenticated JSON and the predicate.
    let p = zkf_prover::present(&out.attestation, &out.secrets, &declared).unwrap();
    let v = zkf_verifier::verify(
        &p,
        &VerifyOptions {
            expected_predicates: vec![gte("id", 1000)],
            ..opts.clone()
        },
    )
    .expect("verify declared disclosure");
    assert_eq!(
        v.json,
        vec![zkf_core::JsonField {
            path: "information.name".into(),
            value: serde_json::json!("John Doe")
        }]
    );
    assert_eq!(v.predicates.len(), 1);
    assert_eq!(v.predicates[0].json_path, "id");
    assert_eq!(v.predicates[0].predicate.minimum().unwrap(), 1000);
    assert!(
        v.sent.starts_with("GET /formats/json HTTP/1.1"),
        "{}",
        v.sent
    );
    assert!(!v.sent.contains("reveal-secret"));
    assert!(!v.recv.contains("1234567890"));

    // Disclosing less, by whole units, still works...
    let less = RevealSpec {
        prove: vec![gte("id", 1000)],
        ..Default::default()
    };
    let p = zkf_prover::present(&out.attestation, &out.secrets, &less).unwrap();
    let v = zkf_verifier::verify(
        &p,
        &VerifyOptions {
            expected_predicates: vec![gte("id", 1000)],
            ..opts.clone()
        },
    )
    .expect("verify smaller disclosure");
    assert!(!v.recv.contains("John Doe"), "{}", v.recv);

    // ...but anything that was not declared fails closed.
    for more in [
        RevealSpec {
            response: ResponseReveal {
                body: true,
                ..Default::default()
            },
            ..Default::default()
        },
        RevealSpec {
            response: ResponseReveal {
                json_paths: vec!["information.address.street".into()],
                ..Default::default()
            },
            ..Default::default()
        },
    ] {
        let err = zkf_prover::present(&out.attestation, &out.secrets, &more).unwrap_err();
        assert!(
            format!("{err:#}").contains("not committed at fetch time"),
            "{err:#}"
        );
    }
}

#[cfg(feature = "legacy-binius")]
#[tokio::test(flavor = "multi_thread")]
async fn reveal_with_binius_keeps_later_predicates() {
    let declared = RevealSpec {
        response: ResponseReveal {
            json_paths: vec!["information.name".into()],
            ..Default::default()
        },
        ..Default::default()
    };
    let (out, opts) = proxy_reveal_session(vec![], declared, true).await;

    // A predicate chosen after the fetch, proven offline with Binius64.
    for minimum in [1000, 1_234_567_890] {
        let later = RevealSpec {
            response: ResponseReveal {
                json_paths: vec!["information.name".into()],
                ..Default::default()
            },
            prove: vec![gte("id", minimum)],
            backend: zkf_core::PredicateBackend::Binius,
            ..Default::default()
        };
        let p = zkf_prover::present(&out.attestation, &out.secrets, &later)
            .expect("Binius predicate after a reveal fetch");
        let v = zkf_verifier::verify(
            &p,
            &VerifyOptions {
                expected_predicates: vec![gte("id", minimum)],
                ..opts.clone()
            },
        )
        .expect("verify later Binius predicate");
        assert_eq!(v.predicates, vec![gte("id", minimum)]);
        assert!(v.recv.contains("John Doe"));
        assert!(!v.recv.contains("1234567890"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn persistent_vole_resumes_and_burns_cancelled_or_failed_sessions() {
    let fixture = spawn_fixture_version(true).await;
    let (notary_url, notary_key) = spawn_proxy_notary(&fixture).await;
    let mut p = params(notary_url, String::new(), vec![gte("id", 1000)]);
    p.connect_addr = None;
    p.mode = Some("proxy".into());
    p.tls_version = Some("1.3".into());
    p.expected_notary_key = Some(notary_key.clone());
    let opts = VerifyOptions {
        trusted_notary_keys: vec![notary_key],
        extra_root_certs: vec![b64::encode(CA_CERT_DER)],
        ..Default::default()
    };
    let spec = RevealSpec {
        response: ResponseReveal {
            json_paths: vec!["information.name".into()],
            ..Default::default()
        },
        ..Default::default()
    };
    for i in 0..4 {
        let out = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            zkf_prover::notarize(p.clone()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(out.timings.vole_resumed, i != 0);
        let presentation = zkf_prover::present(&out.attestation, &out.secrets, &spec).unwrap();
        zkf_verifier::verify(&presentation, &opts).unwrap();
        eprintln!(
            "pool run {i}: setup={}ms resumed={}",
            out.timings.setup_ms, out.timings.vole_resumed
        );
    }
    // Dropping a prepared warm session consumes its ticket without publishing
    // potentially partially consumed correlations back into the cache.
    drop(zkf_prover::prepare(&p).await.unwrap());
    let out = zkf_prover::notarize(p.clone()).await.unwrap();
    assert!(!out.timings.vole_resumed);
    let mut bad = p.clone();
    bad.predicates = vec![gte("id", 9_999_999_999)];
    assert!(zkf_prover::notarize(bad).await.is_err());
    let out = zkf_prover::notarize(p.clone()).await.unwrap();
    assert!(!out.timings.vole_resumed);
    p.persistent_vole = Some(false);
    let out = zkf_prover::notarize(p).await.unwrap();
    assert!(!out.timings.vole_resumed);
}

#[tokio::test(flavor = "multi_thread")]
async fn d4_budget_overflow_fails_without_interactive_proof_extension() {
    let fixture = spawn_fixture_version(true).await;
    let (notary_url, _) = spawn_proxy_notary(&fixture).await;
    let mut request = params(notary_url, fixture, vec![]);
    request.mode = Some("proxy".into());
    request.tls_version = Some("1.3".into());
    request.connect_addr = None;
    request.headers = vec![("X-Padding".into(), "x".repeat(32 * 1024))];
    // The same HTTP request remains valid through the unbounded legacy flow.
    let mut legacy = request.clone();
    legacy.protocol_v2 = Some(false);
    zkf_prover::notarize(legacy)
        .await
        .expect("large request works with legacy extension");
    tokio::time::timeout(
        std::time::Duration::from_secs(15),
        zkf_prover::notarize(request.clone()),
    )
    .await
    .expect("oversized proof must fail promptly")
    .expect_err("budget overflow must not attest");
    // A failed allocation burns its lease rather than restoring prefill state.
    request.headers.clear();
    let next = zkf_prover::notarize(request)
        .await
        .expect("fresh fallback after overflow");
    assert!(!next.timings.vole_resumed);
}

#[cfg(feature = "d1-experimental")]
mod attestation_v2 {
    use super::*;
    use zkf_core::{Decimal, MemberPredicate, PresentV2Request, VerifyV2Options};

    fn member(op: &str, value: u64) -> MemberPredicate {
        MemberPredicate {
            key: "id".into(),
            path: Vec::new(),
            unique: false,
            op: op.into(),
            value: Decimal::Number(value),
        }
    }

    fn request(predicate: MemberPredicate, nonce: &str) -> PresentV2Request {
        PresentV2Request {
            predicate,
            nonce: nonce.into(),
            parameters: None,
            allow_set_cookie: false,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn attestation_v2_notarize_present_verify() {
        let fixture = spawn_fixture_version(true).await;
        // Its own signing key gives this notary its own pool scope, so tests
        // running in parallel cannot take its warm lease.
        let config = Arc::new(zkf_notary::NotaryConfig {
            signing_key: [11u8; 32],
            extra_roots: vec![CA_CERT_DER.to_vec()],
        });
        let notary_key = config.public_key_hex().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let notary_url = format!("ws://{}", listener.local_addr().unwrap());
        let connector = Arc::new(zkf_notary::TcpConnector {
            resolve: vec![(SERVER_DOMAIN.to_string(), fixture.clone())],
        });
        tokio::spawn(zkf_notary::serve(listener, config, connector));
        let mut p = params(notary_url, String::new(), vec![]);
        p.connect_addr = None;
        p.mode = Some("proxy".into());
        p.tls_version = Some("1.3".into());
        p.expected_notary_key = Some(notary_key.clone());
        p.attestation_v2 = true;
        // Ciphertext-only uses 1M; the later known claim switches the same
        // parked pool to the bounded-response 2M class.
        p.max_recv = Some(8192);
        p.context = Some("challenge-1".into());
        p.headers = vec![("Authorization".into(), "Bearer v2-secret".into())];

        // Requests that cannot be served by a v2 session fail before any I/O.
        let mut mpc = p.clone();
        mpc.mode = None;
        assert!(zkf_prover::notarize(mpc).await.is_err());
        let mut with_predicates = p.clone();
        with_predicates.predicates = vec![gte("id", 1)];
        assert!(zkf_prover::notarize(with_predicates).await.is_err());

        // Cold (fresh OT) and then warm (resumed pool, batched flight). Fetch
        // both first: the in-process lease cache is shared with other tests.
        let mut sessions = Vec::new();
        for _ in 0..2 {
            sessions.push(
                tokio::time::timeout(
                    std::time::Duration::from_secs(60),
                    zkf_prover::notarize(p.clone()),
                )
                .await
                .expect("v2 session timeout")
                .expect("v2 notarize"),
            );
        }
        for (round, out) in (0u8..).zip(sessions) {
            assert_eq!(out.attestation_version, 2);
            assert_eq!(out.response.status, 200);
            assert_eq!(out.timings.vole_resumed, round == 1);
            assert_eq!(out.notary_key.key, notary_key);
            eprintln!("v2 round {round}: {:?}", out.timings);

            let nonce = hex::encode([round + 1; 32]);
            let started = std::time::Instant::now();
            let presentation =
                zkf_prover::present_v2(&out.attestation, &out.secrets, &request(member("ge", 1000), &nonce))
                    .expect("present v2");
            let proved = started.elapsed();
            let opts = VerifyV2Options {
                trusted_notary_keys: vec![notary_key.clone()],
                expected_server_name: SERVER_DOMAIN.into(),
                predicate: member("ge", 1000),
                nonce: nonce.clone(),
                max_age_secs: Some(600),
                expected_owner: None,
                expected_context: Some("challenge-1".into()),
            };
            let started = std::time::Instant::now();
            let v = zkf_verifier::verify_v2(&presentation, &opts).expect("verify v2");
            if round == 0 {
                if let Ok(path) = std::env::var("ZKF_V2_PROFILE_FIXTURE") {
                    // Explicit opt-in export of this local test session only.
                    std::fs::write(path, serde_json::to_vec(&serde_json::json!({
                        "attestation":out.attestation, "secrets":out.secrets,
                        "request":request(member("ge",1000), &nonce), "options":opts,
                    })).unwrap()).unwrap();
                }
            }
            eprintln!(
                "v2 presentation: {} bytes base64, prove {:?}, verify {:?}",
                presentation.len(),
                proved,
                started.elapsed()
            );
            assert!(zkf_verifier::is_v2(&presentation));
            assert_eq!(v.server_name, SERVER_DOMAIN);
            assert_eq!(v.mode, "proxy");
            assert_eq!(v.context.as_deref(), Some("challenge-1"));
            assert!(v.response_headers.starts_with("HTTP/1.1 200"), "{}", v.response_headers);
            assert!(!v.response_headers.contains("1234567890"));
            assert!(!presentation.contains("v2-secret"));

            // Bound to the verifier's nonce, claim, trust and policy.
            let other_nonce = VerifyV2Options {
                nonce: hex::encode([9; 32]),
                ..opts.clone()
            };
            assert!(zkf_verifier::verify_v2(&presentation, &other_nonce).is_err());
            let stronger = VerifyV2Options {
                predicate: member("ge", 2_000_000_000),
                ..opts.clone()
            };
            assert!(zkf_verifier::verify_v2(&presentation, &stronger).is_err());
            let untrusted = VerifyV2Options {
                trusted_notary_keys: vec![
                    zkf_notary::NotaryConfig {
                        signing_key: [8; 32],
                        extra_roots: vec![],
                    }
                    .public_key_hex()
                    .unwrap(),
                ],
                ..opts.clone()
            };
            assert!(zkf_verifier::verify_v2(&presentation, &untrusted).is_err());
            let other_server = VerifyV2Options {
                expected_server_name: "example.com".into(),
                ..opts.clone()
            };
            assert!(zkf_verifier::verify_v2(&presentation, &other_server).is_err());
            let other_context = VerifyV2Options {
                expected_context: Some("challenge-2".into()),
                ..opts.clone()
            };
            assert!(zkf_verifier::verify_v2(&presentation, &other_context).is_err());
            // A v2 presentation is not a v1 one.
            assert!(zkf_verifier::verify(&presentation, &VerifyOptions::default()).is_err());

            if round == 0 {
                use zkf_attestation::response::JsonPathSegment::{Member, Index};
                let nested = MemberPredicate {
                    key: "age".into(), path: vec![Member("information".into()), Member("family".into()),
                        Member("siblings".into()), Index(0), Member("age".into())],
                    unique: true, op: "eq".into(), value: zkf_core::Decimal::Number(24),
                };
                let proof = zkf_prover::present_v2(&out.attestation, &out.secrets, &request(nested.clone(), &nonce)).unwrap();
                let nested_opts = VerifyV2Options { predicate: nested.clone(), ..opts.clone() };
                zkf_verifier::verify_v2(&proof, &nested_opts).unwrap();
                let mut wrong = nested.clone(); wrong.path[3] = Index(1);
                assert!(zkf_verifier::verify_v2(&proof, &VerifyV2Options { predicate: wrong, ..opts.clone() }).is_err());
                let root = MemberPredicate { path: vec![], unique: false, ..nested };
                assert!(zkf_verifier::verify_v2(&proof, &VerifyV2Options { predicate: root, ..opts.clone() }).is_err());
            }

            // A false claim cannot be proven, and secrets do not transfer.
            assert!(
                zkf_prover::present_v2(
                    &out.attestation,
                    &out.secrets,
                    &request(member("gt", 1234567890), &nonce)
                )
                .is_err()
            );
        }
        let nonce=hex::encode([42;32]);
        let mut known=p.clone();known.session_claims=vec![member("ge",1000)];known.session_claim_nonce=Some(nonce.clone());
        let out=tokio::time::timeout(std::time::Duration::from_secs(60),zkf_prover::notarize(known)).await.unwrap().unwrap();
        let start=std::time::Instant::now();
        let fast=zkf_prover::present_v2(&out.attestation,&out.secrets,&request(member("ge",1000),&nonce)).unwrap();
        eprintln!("signed session claim presentation: {} bytes, {:?}",b64::decode(&fast).unwrap().len(),start.elapsed());
        let opts=VerifyV2Options {trusted_notary_keys:vec![notary_key],expected_server_name:SERVER_DOMAIN.into(),
            predicate:member("ge",1000),nonce:nonce.clone(),max_age_secs:Some(600),expected_owner:None,expected_context:Some("challenge-1".into())};
        zkf_verifier::verify_v2(&fast,&opts).unwrap();
        if let Ok(path)=std::env::var("ZKF_V2_PROFILE_FIXTURE") {
            let fresh_nonce=hex::encode([99;32]);
            let offline_opts=VerifyV2Options {nonce:fresh_nonce.clone(),..opts.clone()};
            std::fs::write(format!("{path}.signed-head"),serde_json::to_vec(&serde_json::json!({
                "attestation":out.attestation,"secrets":out.secrets,
                "request":request(member("ge",1000),&fresh_nonce),"options":offline_opts,
            })).unwrap()).unwrap();
        }

        assert!(zkf_verifier::verify_v2(&fast,&VerifyV2Options {nonce:hex::encode([43;32]),..opts.clone()}).is_err());
        let later=zkf_prover::present_v2(&out.attestation,&out.secrets,&request(member("gt",999),&nonce)).unwrap();
        zkf_verifier::verify_v2(&later,&VerifyV2Options {predicate:member("gt",999),..opts}).unwrap();
        let mut false_claim=p;false_claim.session_claims=vec![member("gt",1234567890)];false_claim.session_claim_nonce=Some(nonce);
        assert!(zkf_prover::notarize(false_claim).await.is_err());
    }
}

#[cfg(not(feature = "legacy-binius"))]
#[tokio::test]
async fn disabled_binius_fails_before_prepare_or_fetch_io() {
    let mut p = params("ws://127.0.0.1:1".into(), "127.0.0.1:1".into(), vec![]);
    p.binius = true;
    let fetch = zkf_prover::notarize(p.clone()).await.unwrap_err();
    assert!(fetch.to_string().contains("Binius is disabled"));
    let prepared = zkf_prover::prepare(&p).await;
    assert!(prepared.err().unwrap().to_string().contains("Binius is disabled"));
}
