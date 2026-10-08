//! `zkf-notary` server.
//!
//! Env:
//! - `ZKF_NOTARY_ADDR`   listen address (default `127.0.0.1:7047`)
//! - `ZKF_NOTARY_KEY`    hex secp256k1 signing key; if unset a key is loaded
//!   from / generated at `.zkf/notary.key` (development only)
//! - `ZKF_EXTRA_ROOTS`   comma-separated paths to extra DER root certs
//! - `ZKF_PROXY_RESOLVE` comma-separated `host=addr` dial overrides for proxy
//!   mode (testing / fixtures)

use std::{path::Path, sync::Arc};

use anyhow::{Context, Result};
use http_body_util::Full;
use hyper::{
    Request, Response,
    body::{Bytes, Incoming},
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::info;
use zkf_notary::{NotaryConfig, TcpConnector, serve};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tlsn=warn,mpz=warn".into()),
        )
        .init();

    let addr = std::env::var("ZKF_NOTARY_ADDR").unwrap_or_else(|_| "127.0.0.1:7047".into());
    let signing_key = load_key()?;
    let extra_roots = std::env::var("ZKF_EXTRA_ROOTS")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|paths| {
            paths
                .split(',')
                .map(|p| std::fs::read(p).with_context(|| format!("reading root cert {p}")))
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();

    let config = Arc::new(NotaryConfig {
        signing_key,
        extra_roots,
    });
    let listener = TcpListener::bind(&addr).await?;
    info!("notary listening on ws://{}", listener.local_addr()?);
    info!(
        "notary public key (secp256k1): {}",
        config.public_key_hex()?
    );
    // Machine-readable line for test harnesses.
    println!(
        "ZKF_NOTARY_READY {} {}",
        listener.local_addr()?,
        config.public_key_hex()?
    );

    let connector = Arc::new(TcpConnector {
        resolve: std::env::var("ZKF_PROXY_RESOLVE")
            .unwrap_or_default()
            .split(',')
            .filter_map(|entry| entry.split_once('='))
            .map(|(host, addr)| (host.to_string(), addr.to_string()))
            .collect(),
    });
    let server = async {
        if let Ok(addr) = std::env::var("ZKF_HEALTH_ADDR") {
            let health = TcpListener::bind(&addr).await?;
            tokio::try_join!(
                serve(listener, config.clone(), connector),
                serve_health(health, config)
            )?;
            Ok(())
        } else {
            serve(listener, config, connector).await
        }
    };
    // As PID 1 in a container, SIGTERM is ignored unless handled, so the
    // platform could never stop (and stop billing) an idle notary.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        res = server => res,
        _ = sigterm.recv() => {
            info!("SIGTERM received; shutting down");
            Ok(())
        }
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}

async fn serve_health(listener: TcpListener, config: Arc<NotaryConfig>) -> Result<()> {
    let metadata = Bytes::from(serde_json::to_vec(&serde_json::json!({
        "publicKey": config.public_key_hex()?,
        "tlsVersions": ["1.2", "1.3"],
        "cipher": "AES-128-GCM",
        "location": std::env::var("CLOUDFLARE_LOCATION").ok(),
        "region": std::env::var("CLOUDFLARE_REGION").ok(),
        "country": std::env::var("CLOUDFLARE_COUNTRY_A2").ok(),
    }))?);
    let slots = Arc::new(tokio::sync::Semaphore::new(16));
    loop {
        let (tcp, _) = listener.accept().await?;
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let metadata = metadata.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let service = service_fn(move |req: Request<Incoming>| {
                let metadata = metadata.clone();
                async move {
                    let response =
                        if req.method() == hyper::Method::GET && req.uri().path() == "/health" {
                            Response::builder()
                                .header("Content-Type", "application/json")
                                .header("Cache-Control", "no-store")
                                .body(Full::new(metadata))
                        } else {
                            Response::builder()
                                .status(404)
                                .body(Full::new(Bytes::from_static(b"Not found")))
                        };
                    response
                }
            });
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                hyper::server::conn::http1::Builder::new()
                    .max_buf_size(8192)
                    .serve_connection(TokioIo::new(tcp), service),
            )
            .await;
        });
    }
}

fn load_key() -> Result<[u8; 32]> {
    if let Ok(hex_key) = std::env::var("ZKF_NOTARY_KEY") {
        return parse_key(&hex_key);
    }
    anyhow::ensure!(
        std::env::var("ZKF_REQUIRE_KEY").as_deref() != Ok("1"),
        "ZKF_NOTARY_KEY is required for hosted deployment"
    );
    let path = Path::new(".zkf/notary.key");
    if path.exists() {
        return parse_key(&std::fs::read_to_string(path)?);
    }
    let key = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    std::fs::create_dir_all(".zkf")?;
    std::fs::write(path, hex::encode(key.to_bytes()))?;
    info!("generated development notary key at {}", path.display());
    Ok(key.to_bytes().into())
}

fn parse_key(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.trim()).context("notary key must be hex")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("notary key must be 32 bytes"))
}
