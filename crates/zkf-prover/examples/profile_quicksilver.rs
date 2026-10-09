//! Deterministic full-session benchmark, with separate named prover/notary runtimes.
//! cargo run --release -p zkf-prover --example profile_quicksilver -- --out /tmp/qs.json
//! Use --mode mpc, --tls 1.2, --max-sent N, --max-recv N, --no-predicates, or
//! --reveal (commit only what the presentation discloses) for controlled
//! comparisons. Warmups are recorded but excluded from summaries.

use std::{path::PathBuf, sync::Arc, time::Instant};

use anyhow::{Context, Result, ensure};
use serde_json::json;
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncWriteCompatExt;
use zkf_core::{NotarizeParams, PredicateSpec, RevealSpec, VerifyOptions, b64};

struct Options {
    mode: String,
    tls: String,
    runs: usize,
    warmup: usize,
    max_sent: Option<usize>,
    max_recv: Option<usize>,
    predicates: bool,
    reveal: bool,
    delay_ms: u64,
    out: PathBuf,
    notary_url: Option<String>,
    fixture_addr: Option<String>,
    notary_key: Option<String>,
}

impl Options {
    fn parse() -> Result<Self> {
        let mut opts = Self {
            mode: "proxy".into(),
            tls: "1.3".into(),
            runs: 10,
            warmup: 2,
            max_sent: None,
            max_recv: None,
            predicates: true,
            reveal: false,
            delay_ms: 0,
            out: "qs-baseline.json".into(),
            notary_url: None,
            fixture_addr: None,
            notary_key: None,
        };
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            if arg == "--no-predicates" {
                opts.predicates = false;
                continue;
            }
            if arg == "--reveal" {
                opts.reveal = true;
                continue;
            }
            let value = args.next().context("option requires a value")?;
            match arg.as_str() {
                "--mode" => opts.mode = value,
                "--tls" => opts.tls = value,
                "--runs" => opts.runs = value.parse()?,
                "--warmup" => opts.warmup = value.parse()?,
                "--max-sent" => opts.max_sent = Some(value.parse()?),
                "--max-recv" => opts.max_recv = Some(value.parse()?),
                "--delay-ms" => opts.delay_ms = value.parse()?,
                "--out" => opts.out = value.into(),
                "--notary-url" => opts.notary_url = Some(value),
                "--fixture-addr" => opts.fixture_addr = Some(value),
                "--notary-key" => opts.notary_key = Some(value),
                _ => anyhow::bail!("unknown option: {arg}"),
            }
        }
        ensure!(
            matches!(opts.mode.as_str(), "proxy" | "mpc"),
            "invalid mode"
        );
        ensure!(
            matches!(opts.tls.as_str(), "1.2" | "1.3"),
            "invalid TLS version"
        );
        ensure!(opts.runs > 0, "runs must be positive");
        ensure!(
            [
                opts.notary_url.is_some(),
                opts.fixture_addr.is_some(),
                opts.notary_key.is_some()
            ]
            .iter()
            .all(|present| *present == opts.notary_url.is_some()),
            "external mode requires --notary-url, --fixture-addr and --notary-key"
        );
        Ok(opts)
    }
}

fn predicate(minimum: u64) -> PredicateSpec {
    PredicateSpec {
        json_path: "id".into(),
        predicate: zkf_core::NumericPredicate {
            gte: Some(zkf_core::Decimal::Number(minimum)),
            gt: None,
        },
    }
}

fn main() -> Result<()> {
    let opts = Options::parse()?;
    if let (Some(url), Some(fixture), Some(key)) =
        (&opts.notary_url, &opts.fixture_addr, &opts.notary_key)
    {
        return tokio::runtime::Builder::new_multi_thread()
            .thread_name("prover-worker")
            .enable_all()
            .build()?
            .block_on(run(&opts, fixture.clone(), url.clone(), key.clone()));
    }
    let tls13 = opts.tls == "1.3";
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let notary_thread = std::thread::Builder::new()
        .name("notary-main".into())
        .spawn(move || -> Result<()> {
            tokio::runtime::Builder::new_multi_thread()
                .thread_name("notary-worker")
                .enable_all()
                .build()?
                .block_on(async {
                    let fixture_listener = TcpListener::bind("127.0.0.1:0").await?;
                    let fixture = fixture_listener.local_addr()?.to_string();
                    tokio::spawn(async move {
                        loop {
                            let (socket, _) = fixture_listener.accept().await.unwrap();
                            tokio::spawn(async move {
                                if tls13 {
                                    tlsn_server_fixture::bind_tls13(socket.compat_write())
                                        .await
                                        .expect("TLS 1.3 fixture failed");
                                } else {
                                    tlsn_server_fixture::bind(socket.compat_write())
                                        .await
                                        .expect("TLS fixture failed");
                                }
                            });
                        }
                    });
                    // Test-only key and CA; this listener is loopback only.
                    let config = Arc::new(zkf_notary::NotaryConfig {
                        signing_key: [7; 32],
                        extra_roots: vec![CA_CERT_DER.to_vec()],
                    });
                    let key = config.public_key_hex()?;
                    let listener = TcpListener::bind("127.0.0.1:0").await?;
                    let url = format!("ws://{}", listener.local_addr()?);
                    let connector = Arc::new(zkf_notary::TcpConnector {
                        resolve: vec![(SERVER_DOMAIN.to_string(), fixture.clone())],
                    });
                    tokio::spawn(zkf_notary::serve(listener, config, connector));
                    ready_tx.send((fixture, url, key))?;
                    let _ = stop_rx.await;
                    Ok(())
                })
        })?;
    let (fixture, notary_url, notary_key) = ready_rx.recv()?;
    let result = tokio::runtime::Builder::new_multi_thread()
        .thread_name("prover-worker")
        .enable_all()
        .build()?
        .block_on(run(&opts, fixture, notary_url, notary_key));
    let _ = stop_tx.send(());
    notary_thread.join().expect("notary thread panicked")?;
    result
}

async fn run(
    opts: &Options,
    fixture: String,
    notary_url: String,
    notary_key: String,
) -> Result<()> {
    let ca = b64::encode(CA_CERT_DER);
    let predicates = if opts.predicates {
        vec![predicate(1000)]
    } else {
        vec![]
    };
    let verify_opts = VerifyOptions {
        trusted_notary_keys: vec![notary_key],
        extra_root_certs: vec![ca.clone()],
        expected_predicates: predicates.clone(),
        ..Default::default()
    };
    let spec = RevealSpec {
        prove: predicates.clone(),
        ..Default::default()
    };
    let mut results = json!({
        "workload": "local TLS fixture /formats/json, hidden id >= 1000",
        "mode": opts.mode, "tls": opts.tls, "backend": "quicksilver", "binius": false,
        "reveal": opts.reveal,
        "maxSent": opts.max_sent, "maxRecv": opts.max_recv,
        "predicates": opts.predicates, "warmup": opts.warmup, "requestedRuns": opts.runs,
        "processLayout": if opts.notary_url.is_some() { "separate processes" } else { "in process" },
        "logicalCpus": std::thread::available_parallelism()?.get(), "runs": []
    });
    let epoch = Instant::now();
    tokio::time::sleep(std::time::Duration::from_millis(opts.delay_ms)).await;
    for index in 0..opts.warmup + opts.runs {
        let started = Instant::now();
        let out = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            zkf_prover::notarize(NotarizeParams {
                notary_url: notary_url.clone(),
                expected_notary_key: None,
                url: format!("https://{SERVER_DOMAIN}/formats/json"),
                method: None,
                headers: vec![],
                body: None,
                connect_addr: (opts.mode == "mpc").then(|| fixture.clone()),
                extra_root_certs: vec![ca.clone()],
                max_sent: opts.max_sent,
                max_recv: opts.max_recv,
                owner: None,
                context: None,
                predicates: predicates.clone(),
                binius: false,
                reveal: opts.reveal.then(|| spec.clone()),
                tls_version: Some(opts.tls.clone()),
                mode: Some(opts.mode.clone()),
                relay_url: None,
            }),
        )
        .await
        .context("session timed out")??;
        ensure!(
            out.response.status == 200 && out.tls_version == opts.tls,
            "wrong response"
        );
        let present_start = Instant::now();
        let presentation = zkf_prover::present(&out.attestation, &out.secrets, &spec)?;
        let present_ms = present_start.elapsed().as_secs_f64() * 1000.0;
        let verify_start = Instant::now();
        let verified = zkf_verifier::verify(&presentation, &verify_opts)?;
        let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;
        ensure!(
            verified.notary_trusted && verified.server_name == SERVER_DOMAIN,
            "wrong identity"
        );
        ensure!(
            !verified.recv.contains("1234567890"),
            "predicate value disclosed"
        );
        if opts.predicates && index == 0 {
            let stronger = VerifyOptions {
                expected_predicates: vec![predicate(2_000_000_000)],
                ..verify_opts.clone()
            };
            ensure!(
                zkf_verifier::verify(&presentation, &stronger).is_err(),
                "stronger claim accepted"
            );
        }
        let row = json!({
            "index": index, "warmup": index < opts.warmup,
            "startMs": started.duration_since(epoch).as_secs_f64() * 1000.0,
            "timings": out.timings, "presentMs": present_ms, "verifyMs": verify_ms,
            "fullMs": started.elapsed().as_secs_f64() * 1000.0,
            "bodyBytes": out.response.body.len(),
            "presentationBytes": b64::decode(&presentation)?.len(), "verified": true
        });
        println!("{row}");
        results["runs"].as_array_mut().unwrap().push(row);
        std::fs::write(&opts.out, serde_json::to_vec_pretty(&results)?)?;
    }
    Ok(())
}
