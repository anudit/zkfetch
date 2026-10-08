//! zkfetch notary.
//!
//! Accepts prover sessions over WebSocket, runs the TLSNotary MPC-TLS verifier
//! side, then signs an attestation over the prover's transcript commitments.
//! The notary never sees plaintext the prover does not explicitly reveal.

#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use futures::TryFutureExt;
use tlsn::{
    Session,
    attestation::{
        Attestation, AttestationConfig, CryptoProvider, InvalidExtension,
        request::Request as AttestationRequest, signing::Secp256k1Signer,
    },
    config::verifier::VerifierConfig,
    connection::{ConnectionInfo, TranscriptLength},
    transcript::ContentType,
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::{CertificateDer, RootCertStore},
};
use zkf_core::{EXT_CONTEXT, EXT_OWNER, transport};
use zkf_predicates::quicksilver::{AttestedPredicates, EXT_QS};

/// Opens the notary's own connection to the server in proxy mode, where the
/// notary relays the prover's TLS traffic.
pub trait ServerConnector {
    type Stream: futures::AsyncRead + futures::AsyncWrite + Send + Unpin;

    fn connect(&self, host: &str, port: u16) -> impl Future<Output = Result<Self::Stream>>;
}

/// TCP connector for the native notary.
#[cfg(not(target_arch = "wasm32"))]
pub struct TcpConnector {
    /// `host=addr` overrides for the dialed address (testing / fixtures).
    pub resolve: Vec<(String, String)>,
}

#[cfg(not(target_arch = "wasm32"))]
impl ServerConnector for TcpConnector {
    type Stream = tokio_util::compat::Compat<tokio::net::TcpStream>;

    async fn connect(&self, host: &str, port: u16) -> Result<Self::Stream> {
        use tokio_util::compat::TokioAsyncReadCompatExt;
        let addr = self
            .resolve
            .iter()
            .find(|(name, _)| name == host)
            .map(|(_, addr)| addr.clone())
            .unwrap_or_else(|| format!("{host}:{port}"));
        let tcp = tokio::net::TcpStream::connect(&addr)
            .await
            .with_context(|| format!("failed to connect to {addr}"))?;
        tcp.set_nodelay(true)?;
        Ok(tcp.compat())
    }
}

// DEBUG(mem): phase hook for memory profiling in the Worker.
pub static PHASE_HOOK: std::sync::OnceLock<fn(&str)> = std::sync::OnceLock::new();
fn phase(name: &str) {
    if let Some(hook) = PHASE_HOOK.get() {
        hook(name);
    }
}

/// Hard ceilings on what a prover may ask the notary to preprocess.
pub const MAX_SENT_LIMIT: usize = 1 << 14;
pub const MAX_RECV_LIMIT: usize = 1 << 18;

pub struct NotaryConfig {
    /// secp256k1 signing key.
    pub signing_key: [u8; 32],
    /// Extra trusted roots (DER) in addition to the Mozilla store.
    pub extra_roots: Vec<Vec<u8>>,
}

impl NotaryConfig {
    /// Compressed SEC1 public key, hex.
    pub fn public_key_hex(&self) -> Result<String> {
        let sk = k256::ecdsa::SigningKey::from_bytes(&self.signing_key.into())?;
        Ok(hex::encode(
            sk.verifying_key().to_encoded_point(true).as_bytes(),
        ))
    }

    fn root_store(&self) -> RootCertStore {
        let mut store = RootCertStore::mozilla();
        store
            .roots
            .extend(self.extra_roots.iter().cloned().map(CertificateDer));
        store
    }
}

/// Answers a plain HTTP request (no WebSocket upgrade) with `200 ok` and
/// returns `None`; returns the stream untouched for WebSocket upgrades.
#[cfg(not(target_arch = "wasm32"))]
async fn answer_probe(tcp: tokio::net::TcpStream) -> Option<tokio::net::TcpStream> {
    use tokio::io::AsyncWriteExt;
    let mut buf = [0u8; 4096];
    let head = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let n = tcp.peek(&mut buf).await.ok()?;
            let head = &buf[..n];
            if head.windows(4).any(|w| w == b"\r\n\r\n") || n == buf.len() {
                return Some(String::from_utf8_lossy(head).to_ascii_lowercase());
            }
            if n == 0 {
                return None;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .ok()
    .flatten()?;
    if head.contains("upgrade: websocket") {
        return Some(tcp);
    }
    let mut tcp = tcp;
    let _ = tcp
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await;
    None
}

/// Upper bound on one session (handshake through attestation). A prover that
/// disappears mid-protocol must not pin notary resources forever.
pub fn session_timeout() -> std::time::Duration {
    std::env::var("ZKF_SESSION_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map(std::time::Duration::from_secs)
        .unwrap_or(std::time::Duration::from_secs(120))
}

/// Serves prover sessions forever.
#[cfg(not(target_arch = "wasm32"))]
pub async fn serve(
    listener: tokio::net::TcpListener,
    config: Arc<NotaryConfig>,
    connector: Arc<TcpConnector>,
) -> Result<()> {
    use tracing::{info, warn};

    let timeout = session_timeout();
    let max_sessions: usize = std::env::var("ZKF_MAX_SESSIONS")
        .ok()
        .map(|value| value.parse())
        .transpose()
        .context("ZKF_MAX_SESSIONS must be an integer")?
        .unwrap_or(32);
    anyhow::ensure!(
        (1..=128).contains(&max_sessions),
        "ZKF_MAX_SESSIONS must be 1..=128"
    );
    let slots = Arc::new(tokio::sync::Semaphore::new(max_sessions));
    // A session stuck in a blocking call cannot be cancelled by the tokio
    // timeout and would hold its slot forever. Exit instead, so the platform
    // starts a fresh process; a plain thread keeps working if tokio is wedged.
    let started: Arc<std::sync::Mutex<std::collections::HashMap<u64, std::time::Instant>>> =
        Default::default();
    {
        let started = started.clone();
        let limit = timeout + std::time::Duration::from_secs(15);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                let stuck = started.lock().unwrap().values().any(|t| t.elapsed() > limit);
                if stuck {
                    eprintln!("notary watchdog: session exceeded {limit:?}; exiting");
                    std::process::exit(1);
                }
            }
        });
    }
    let mut next_id = 0u64;
    loop {
        let (tcp, peer) = listener.accept().await?;
        // Readiness probes (Cloudflare Containers sends `GET /ping`) must
        // succeed without consuming a session slot.
        let tcp = match answer_probe(tcp).await {
            Some(tcp) => tcp,
            None => continue,
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            warn!(%peer, "notary at session capacity");
            continue;
        };
        let config = config.clone();
        let connector = connector.clone();
        let started = started.clone();
        let id = next_id;
        next_id += 1;
        started.lock().unwrap().insert(id, std::time::Instant::now());
        tokio::spawn(async move {
            let _permit = permit;
            let res = tokio::time::timeout(timeout, async {
                let ws = transport::accept(tcp).await?;
                notarize(ws, &config, &*connector).await
            })
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("session timed out after {timeout:?}")));
            started.lock().unwrap().remove(&id);
            match res {
                Ok(()) => info!(%peer, "session notarized"),
                Err(err) => warn!(%peer, "session failed: {err:#}"),
            }
        });
    }
}

/// Runs one notarization session over an established byte stream.
///
/// The session driver is polled alongside the protocol rather than spawned,
/// so this runs on a single-threaded runtime (the Cloudflare Worker notary).
pub async fn notarize<S, C>(socket: S, config: &NotaryConfig, connector: &C) -> Result<()>
where
    S: futures::AsyncRead + futures::AsyncWrite + Unpin + 'static,
    C: ServerConnector,
{
    let session = Session::new(socket);
    let (driver, mut handle) = session.split();
    // On failure the protocol future returns early and drops the driver.
    let (mut socket, (transcript_commitments, verified_predicates, tls_transcript)) =
        futures::future::try_join(driver.err_into::<anyhow::Error>(), async move {
            let out = verify_session(&mut handle, config, connector).await;
            // Reclaim the socket for the attestation exchange.
            handle.close();
            out
        })
        .await?;

    let app_len = |records: &[tlsn::transcript::Record]| {
        records
            .iter()
            .filter(|r| matches!(r.typ, ContentType::ApplicationData))
            // TLS 1.3 records exclude their public suffix.
            .map(|r| r.content_len())
            .sum::<usize>()
    };
    let sent_len = app_len(tls_transcript.sent());
    let recv_len = app_len(tls_transcript.recv());

    let request_bytes = transport::read_frame(&mut socket).await?;
    let request: AttestationRequest =
        bincode::deserialize(&request_bytes).context("invalid attestation request")?;

    let signer = Box::new(Secp256k1Signer::new(&config.signing_key)?);
    let mut provider = CryptoProvider::default();
    provider.signer.set_signer(signer);

    let mut att_config = AttestationConfig::builder();
    att_config
        .supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()))
        .extension_validator(move |extensions| {
            let mut seen = std::collections::HashSet::new();
            for ext in extensions {
                if !seen.insert(ext.id.clone()) {
                    return Err(InvalidExtension::new("duplicate extension"));
                }
                if ext.id == EXT_QS {
                    // Only sign predicate claims that QuickSilver just verified.
                    let claims = AttestedPredicates::decode(&ext.value)
                        .map_err(|_| InvalidExtension::new("malformed predicate claims"))?;
                    if claims.predicates != verified_predicates {
                        return Err(InvalidExtension::new(
                            "predicate claims do not match the verified predicates",
                        ));
                    }
                    continue;
                }
                if ext.id != EXT_OWNER && ext.id != EXT_CONTEXT {
                    return Err(InvalidExtension::new("unsupported extension"));
                }
                if ext.value.len() > 256 {
                    return Err(InvalidExtension::new("extension value too long"));
                }
            }
            Ok(())
        });
    let att_config = att_config.build()?;

    anyhow::ensure!(
        tls_transcript.certificate_binding().tls_version() == tls_transcript.version(),
        "certificate binding does not match TLS version"
    );
    let server_ephemeral_key = tls_transcript
        .certificate_binding()
        .server_ephemeral_key()
        .clone();

    let mut builder = Attestation::builder(&att_config).accept_request(request)?;
    builder
        .connection_info(ConnectionInfo {
            time: tls_transcript.time(),
            version: tls_transcript.version(),
            transcript_length: TranscriptLength {
                sent: sent_len as u32,
                received: recv_len as u32,
            },
        })
        .server_ephemeral_key(server_ephemeral_key)
        .transcript_commitments(transcript_commitments);

    let attestation = builder.build(&provider)?;
    transport::write_frame(&mut socket, &bincode::serialize(&attestation)?).await?;
    futures::AsyncWriteExt::close(&mut socket).await.ok();

    Ok(())
}

/// Runs MPC-TLS and the commitment proofs, returning what the attestation
/// covers.
async fn verify_session<C: ServerConnector>(
    handle: &mut tlsn::SessionHandle,
    config: &NotaryConfig,
    connector: &C,
) -> Result<(
    Vec<tlsn::transcript::TranscriptCommitment>,
    Vec<tlsn::transcript::TranscriptPredicate>,
    tlsn::transcript::TlsTranscript,
)> {
    phase("start");
    let verifier_config = VerifierConfig::builder()
        .root_store(config.root_store())
        .build()?;
    phase("root store");

    let verifier = match handle.new_verifier(verifier_config)?.commit().await? {
        VerifierCommitStart::Mpc(verifier) => {
            let mpc = verifier.config();
            if mpc.max_sent_data() > MAX_SENT_LIMIT || mpc.max_recv_data() > MAX_RECV_LIMIT {
                verifier
                    .reject(Some("requested data limits too large"))
                    .await?;
                bail!("prover requested excessive limits");
            }
            verifier.accept().await?.run().await?
        }
        VerifierCommitStart::Proxy(verifier) => {
            // Dial the name the prover's TLS client validates, on 443 only, so
            // the prover cannot point the notary at another host or service.
            let host = verifier.config().server_name().as_str().to_string();
            let server = match connector.connect(&host, 443).await {
                Ok(server) => server,
                Err(err) => {
                    verifier.reject(Some("notary could not reach the server")).await?;
                    return Err(err);
                }
            };
            let accepted = verifier.accept().await?;
            phase("proxy accepted");
            accepted.run(server).await?
        }
    };

    phase("committed");
    let (
        VerifierOutput {
            transcript_commitments,
            predicates: verified_predicates,
            ..
        },
        verifier,
    ) = verifier.verify().await?.accept().await?;

    phase(&format!(
        "verified ({} commitments, {} bytes hashed)",
        transcript_commitments.len(),
        transcript_commitments
            .iter()
            .map(|c| match c {
                tlsn::transcript::TranscriptCommitment::Hash(h) => h.idx.len(),
                #[allow(unreachable_patterns)]
                _ => 0,
            })
            .sum::<usize>()
    ));
    let tls_transcript = verifier.tls_transcript().clone();
    verifier.close().await?;

    Ok((transcript_commitments, verified_predicates, tls_transcript))
}
