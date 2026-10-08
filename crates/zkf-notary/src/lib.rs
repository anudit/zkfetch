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
use zkf_core::{EXT_CONTEXT, EXT_MODE, EXT_OWNER, EXT_SERVER, transport};
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
        // Explicit overrides (tests, fixtures) are trusted configuration.
        if let Some((_, addr)) = self.resolve.iter().find(|(name, _)| name == host) {
            let tcp = tokio::net::TcpStream::connect(addr)
                .await
                .with_context(|| format!("failed to connect to {addr}"))?;
            tcp.set_nodelay(true)?;
            return Ok(tcp.compat());
        }
        // The prover picks the host, so only dial public addresses: never the
        // notary's own network, cloud metadata or other internal services.
        // Resolve once and connect to the checked address (no DNS rebinding).
        let candidates: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .with_context(|| format!("failed to resolve {host}"))?
            .collect();
        let allowed: Vec<_> = candidates
            .iter()
            .copied()
            .filter(|a| is_public(a.ip()))
            .collect();
        if allowed.is_empty() {
            bail!("{host} does not resolve to a public address");
        }
        let tcp = tokio::net::TcpStream::connect(allowed.as_slice())
            .await
            .with_context(|| format!("failed to connect to {host}:{port}"))?;
        tcp.set_nodelay(true)?;
        Ok(tcp.compat())
    }
}

/// Whether `ip` is a globally routable unicast address the notary may dial.
pub fn is_public(ip: std::net::IpAddr) -> bool {
    use std::net::{IpAddr, Ipv4Addr};
    fn v4(ip: Ipv4Addr) -> bool {
        let [a, b, c, _] = ip.octets();
        !(ip.is_unspecified()
            || ip.is_loopback()
            || ip.is_private()
            || ip.is_link_local()
            || ip.is_broadcast()
            || ip.is_multicast()
            || ip.is_documentation()
            || a == 0
            || (a == 100 && (64..128).contains(&b)) // shared / CGNAT
            || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
            || (a == 198 && (b == 18 || b == 19)) // benchmarking
            || a >= 240) // reserved
    }
    match ip {
        IpAddr::V4(ip) => v4(ip),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return v4(mapped);
            }
            let s = ip.segments();
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local
                || (s[0] & 0xffc0) == 0xfe80 // link local
                || (s[0] == 0x64 && s[1] == 0xff9b) // NAT64 can reach IPv4 internals
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || s[0..6] == [0, 0, 0, 0, 0, 0]) // IPv4-compatible
        }
    }
}

// DEBUG(mem): phase hook for memory profiling in the Worker.
pub static PHASE_HOOK: std::sync::OnceLock<fn(&str)> = std::sync::OnceLock::new();
fn phase(name: &str) {
    if let Some(hook) = PHASE_HOOK.get() {
        hook(name);
    }
}

/// How long a new connection may take to complete the WebSocket handshake
/// and to send its session configuration.
pub const OPENING_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);

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

/// Reads the HTTP request head without consuming it. Answers plain requests
/// (readiness probes) with `200 ok` and returns `None`; for WebSocket upgrades
/// returns the untouched stream and the lowercased head.
#[cfg(not(target_arch = "wasm32"))]
async fn answer_probe(tcp: tokio::net::TcpStream) -> Option<(tokio::net::TcpStream, String)> {
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
        return Some((tcp, head));
    }
    let mut tcp = tcp;
    let _ = tcp
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await;
    None
}

/// Refuses a WebSocket upgrade with an HTTP status, so the prover gets an
/// immediate error instead of a connection that never answers.
#[cfg(not(target_arch = "wasm32"))]
async fn refuse(mut tcp: tokio::net::TcpStream, status: &str) {
    use tokio::io::AsyncWriteExt;
    let reason = status.split_once(' ').map_or(status, |(_, r)| r);
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nRetry-After: 5\r\nConnection: close\r\n\r\n{reason}",
        reason.len()
    );
    let _ = tcp.write_all(response.as_bytes()).await;
    let _ = tcp.shutdown().await;
}

/// The client address: the socket peer, or with `ZKF_TRUST_FORWARDED=1` (only
/// behind a proxy that overwrites the header, such as Caddy) the last
/// `X-Forwarded-For` entry.
#[cfg(not(target_arch = "wasm32"))]
fn client_ip(head: &str, peer: std::net::IpAddr, trust_forwarded: bool) -> std::net::IpAddr {
    if !trust_forwarded {
        return peer;
    }
    head.lines()
        .find_map(|line| line.strip_prefix("x-forwarded-for:"))
        .and_then(|value| value.rsplit(',').next())
        .and_then(|ip| ip.trim().parse().ok())
        .unwrap_or(peer)
}

/// Removes a session from the watchdog's table when the session ends in any
/// way, including a panic, so one crashed session cannot later make the
/// watchdog restart the whole process.
#[cfg(not(target_arch = "wasm32"))]
struct Tracked {
    started: Arc<std::sync::Mutex<std::collections::HashMap<u64, std::time::Instant>>>,
    id: u64,
}

#[cfg(not(target_arch = "wasm32"))]
impl Drop for Tracked {
    fn drop(&mut self) {
        if let Ok(mut started) = self.started.lock() {
            started.remove(&self.id);
        }
    }
}

/// Counts one client's open sessions; decrements on drop.
#[cfg(not(target_arch = "wasm32"))]
struct ClientSlot {
    clients: Arc<std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, usize>>>,
    ip: std::net::IpAddr,
}

#[cfg(not(target_arch = "wasm32"))]
impl ClientSlot {
    fn acquire(
        clients: &Arc<std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, usize>>>,
        ip: std::net::IpAddr,
        max: usize,
    ) -> Option<Self> {
        let mut map = clients.lock().ok()?;
        let count = map.entry(ip).or_default();
        if *count >= max {
            return None;
        }
        *count += 1;
        Some(Self {
            clients: clients.clone(),
            ip,
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Drop for ClientSlot {
    fn drop(&mut self) {
        if let Ok(mut map) = self.clients.lock()
            && let Some(count) = map.get_mut(&self.ip)
        {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.ip);
            }
        }
    }
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
                let stuck = started
                    .lock()
                    .unwrap()
                    .values()
                    .any(|t| t.elapsed() > limit);
                if stuck {
                    eprintln!("notary watchdog: session exceeded {limit:?}; exiting");
                    std::process::exit(1);
                }
            }
        });
    }
    let env_usize = |name: &str, default: usize| -> Result<usize> {
        std::env::var(name)
            .ok()
            .map(|value| value.parse())
            .transpose()
            .with_context(|| format!("{name} must be an integer"))
            .map(|v| v.unwrap_or(default))
    };
    // One client may hold only part of the capacity (per address).
    let per_client = env_usize(
        "ZKF_MAX_SESSIONS_PER_CLIENT",
        max_sessions.div_ceil(4).max(1),
    )?;
    let trust_forwarded = std::env::var("ZKF_TRUST_FORWARDED").as_deref() == Ok("1");
    // Reading request heads happens off the accept loop, so a slow client
    // cannot stall others; this bounds how many may be read at once.
    let pending = Arc::new(tokio::sync::Semaphore::new(256));
    let clients: Arc<std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, usize>>> =
        Default::default();
    let mut next_id = 0u64;
    loop {
        let (tcp, peer) = listener.accept().await?;
        let Ok(pending_permit) = pending.clone().try_acquire_owned() else {
            warn!(%peer, "too many connections awaiting a request");
            continue;
        };
        let id = next_id;
        next_id += 1;
        let (slots, clients, started) = (slots.clone(), clients.clone(), started.clone());
        let (config, connector) = (config.clone(), connector.clone());
        tokio::spawn(async move {
            // Readiness probes (`GET /ping`) succeed without a session slot.
            let Some((tcp, head)) = answer_probe(tcp).await else {
                return;
            };
            drop(pending_permit);
            let client = client_ip(&head, peer.ip(), trust_forwarded);
            let Some(client_slot) = ClientSlot::acquire(&clients, client, per_client) else {
                warn!(%client, "client at its session limit");
                return refuse(tcp, "429 Too Many Requests").await;
            };
            let Ok(permit) = slots.try_acquire_owned() else {
                warn!(%client, "notary at session capacity");
                return refuse(tcp, "503 Service Unavailable").await;
            };
            started
                .lock()
                .unwrap()
                .insert(id, std::time::Instant::now());
            let _tracked = Tracked { started, id };
            let _slots = (permit, client_slot);
            let res = tokio::time::timeout(timeout, async {
                // A connection that does not finish its WebSocket handshake
                // promptly must not hold a slot until the session timeout.
                let ws = tokio::time::timeout(OPENING_DEADLINE, transport::accept(tcp))
                    .await
                    .map_err(|_| anyhow::anyhow!("WebSocket handshake not completed in time"))??;
                notarize(ws, &config, &*connector).await
            })
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("session timed out after {timeout:?}")));
            match res {
                Ok(()) => info!(%client, "session notarized"),
                Err(err) => warn!(%client, "session failed: {err:#}"),
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
    let (mut socket, (transcript_commitments, verified_predicates, tls_transcript, proxy_host)) =
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
    // Notary-owned facts about the session. The extension validator above
    // rejects these IDs from the prover, so only the notary can set them.
    builder.extension(tlsn::attestation::Extension {
        id: EXT_MODE.to_vec(),
        value: if proxy_host.is_some() {
            b"proxy".to_vec()
        } else {
            b"mpc".to_vec()
        },
    });
    if let Some(host) = proxy_host {
        builder.extension(tlsn::attestation::Extension {
            id: EXT_SERVER.to_vec(),
            value: host.into_bytes(),
        });
    }

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
    Option<String>,
)> {
    phase("start");
    let verifier_config = VerifierConfig::builder()
        .root_store(config.root_store())
        .build()?;
    phase("root store");

    let mut proxy_host = None;
    // The session configuration must arrive promptly; idle connections would
    // otherwise hold a slot for the whole session timeout (ZKF-09).
    let commit = handle.new_verifier(verifier_config)?.commit();
    #[cfg(not(target_arch = "wasm32"))]
    let commit = async {
        tokio::time::timeout(OPENING_DEADLINE, commit)
            .await
            .map_err(|_| anyhow::anyhow!("prover did not send its session configuration in time"))?
            .map_err(anyhow::Error::from)
    };
    let verifier = match commit.await? {
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
                    verifier
                        .reject(Some("notary could not reach the server"))
                        .await?;
                    return Err(err);
                }
            };
            let accepted = verifier.accept().await?;
            proxy_host = Some(host);
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

    Ok((
        transcript_commitments,
        verified_predicates,
        tls_transcript,
        proxy_host,
    ))
}

#[cfg(test)]
mod tests {
    use super::is_public;

    #[test]
    fn proxy_dials_only_public_addresses() {
        for blocked in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "240.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a00:1",
            "2001:db8::1",
            "::7f00:1",
        ] {
            assert!(
                !is_public(blocked.parse().unwrap()),
                "{blocked} must be blocked"
            );
        }
        for allowed in [
            "1.1.1.1",
            "93.184.215.14",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(
                is_public(allowed.parse().unwrap()),
                "{allowed} must be allowed"
            );
        }
    }
}
