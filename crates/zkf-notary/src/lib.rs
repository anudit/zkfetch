//! zkfetch notary.
//!
//! Accepts prover sessions over WebSocket, runs the TLSNotary MPC-TLS verifier
//! side, then signs an attestation over the prover's transcript commitments.
//! The notary never sees plaintext the prover does not explicitly reveal.

#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;

#[cfg(not(target_arch = "wasm32"))]
mod admission;
#[cfg(feature = "d1-experimental")]
mod d1;
pub mod metrics;
mod resources;

use anyhow::{Context, Result, bail};
use bincode::Options;
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
use zkf_core::{EXT_CONTEXT, EXT_HANDSHAKE, EXT_MODE, EXT_OWNER, EXT_SERVER, transport};
use zkf_predicates::quicksilver::{AttestedPredicates, EXT_QS};

static VOLE_POOLS: std::sync::LazyLock<
    zkf_core::setup_pool::PoolCache<tlsn::vole_pool::VerifierVolePool>,
> = std::sync::LazyLock::new(|| {
    zkf_core::setup_pool::PoolCache::new(16, std::time::Duration::from_secs(600))
});

fn pool_scope(config: &NotaryConfig, capability: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"zkfetch/pool-scope/v1\0");
    hash.update(config.signing_key);
    hash.update(capability.as_bytes());
    hash.finalize().into()
}

/// Opens the notary's own connection to the server in proxy mode, where the
/// notary relays the prover's TLS traffic.
pub trait ServerConnector {
    type Stream: futures::AsyncRead + futures::AsyncWrite + Send + Unpin;

    fn connect(&self, host: &str, port: u16) -> impl Future<Output = Result<Self::Stream>>;

    /// The address actually dialed, signed into v2 attestations.
    fn peer_ip(_stream: &Self::Stream) -> Option<std::net::IpAddr> {
        None
    }
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
        if let Ok(allowlist) = std::env::var("ZKF_DESTINATION_ALLOWLIST") {
            anyhow::ensure!(
                allowlist
                    .split(',')
                    .any(|name| name.trim().eq_ignore_ascii_case(host)),
                "destination is not allowlisted"
            );
        }

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

    fn peer_ip(stream: &Self::Stream) -> Option<std::net::IpAddr> {
        stream.get_ref().peer_addr().ok().map(|addr| addr.ip())
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
            // Fail closed outside currently allocated global unicast space.
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && s[1] < 0x0200) // special-use / Teredo / benchmarking / ORCHID
                && !(s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                && s[0] != 0x2002 // 6to4 embeds unvalidated IPv4
                && !(s[0] == 0x3fff && (s[1] & 0xf000) == 0) // documentation
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
                return Some(String::from_utf8_lossy(head).into_owned());
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
    if head.to_ascii_lowercase().contains("upgrade: websocket") {
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
    metrics::REJECTED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("x-forwarded-for"))
                .map(|(_, value)| value)
        })
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
            metrics::ACTIVE.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
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

    let admission = Arc::new(admission::Admission::from_env()?);
    anyhow::ensure!(
        !admission.is_empty() || listener.local_addr()?.ip().is_loopback(),
        "public notary requires ZKF_CAPABILITIES; anonymous admission is loopback-only"
    );
    let setup_slots = Arc::new(tokio::sync::Semaphore::new(16));
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
        let admission = admission.clone();
        let setup_slots = setup_slots.clone();
        tokio::spawn(async move {
            // Readiness probes (`GET /ping`) succeed without a session slot.
            let Some((tcp, head)) = answer_probe(tcp).await else {
                return;
            };
            let tenant_slot = if admission.is_empty() {
                None
            } else {
                match admission.admit(&head) {
                    Ok(slot) => Some(slot),
                    Err(status) => return refuse(tcp, status).await,
                }
            };
            let Ok(setup_permit) = setup_slots.try_acquire_owned() else {
                return refuse(tcp, "503 Service Unavailable").await;
            };
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
            metrics::ACCEPTED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            metrics::ACTIVE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let _tracked = Tracked { started, id };
            let _slots = (permit, client_slot, tenant_slot);
            let res = tokio::time::timeout(timeout, async {
                // A connection that does not finish its WebSocket handshake
                // promptly must not hold a slot until the session timeout.
                let ws = tokio::time::timeout(OPENING_DEADLINE, transport::accept(tcp))
                    .await
                    .map_err(|_| anyhow::anyhow!("WebSocket handshake not completed in time"))??;
                drop(setup_permit);
                drop(pending_permit);
                let target = head
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/");
                let url = url::Url::parse(&format!("https://notary.invalid{target}"))?;
                let capability = url
                    .query_pairs()
                    .find(|(k, _)| k == "capability")
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default();
                let scope = pool_scope(&config, &capability);
                let (name, value) = zkf_core::d1::QUERY;
                let attestation_v2 = url.query_pairs().any(|(k, v)| k == name && v == value);
                notarize_with(ws, &config, &*connector, scope, attestation_v2).await
            })
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("session timed out after {timeout:?}")));
            match res {
                Ok(()) => {
                    metrics::COMPLETED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    info!(%client, "session notarized");
                }
                Err(_) => {
                    metrics::FAILED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    warn!(%client, "session failed");
                }
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
    notarize_scoped(socket, config, connector, pool_scope(config, "")).await
}

/// Runs a session scoped to an already authenticated admission capability.
/// Hosts with external admission (e.g. Workers) must supply a distinct scope
/// per tenant. Reuse is in-memory only and fails closed to fresh OT.
pub async fn notarize_scoped<S, C>(
    socket: S,
    config: &NotaryConfig,
    connector: &C,
    scope: [u8; 32],
) -> Result<()>
where
    S: futures::AsyncRead + futures::AsyncWrite + Unpin + 'static,
    C: ServerConnector,
{
    notarize_with(socket, config, connector, scope, false).await
}

/// Like [`notarize_scoped`]; `attestation_v2` (selected by the prover in the
/// notary URL) signs a v2 attestation after the key-commitment proofs.
pub async fn notarize_with<S, C>(
    mut socket: S,
    config: &NotaryConfig,
    connector: &C,
    scope: [u8; 32],
    attestation_v2: bool,
) -> Result<()>
where
    S: futures::AsyncRead + futures::AsyncWrite + Unpin + 'static,
    C: ServerConnector,
{
    anyhow::ensure!(
        !attestation_v2 || cfg!(feature = "d1-experimental"),
        "this notary does not support v2 attestations"
    );
    let mut allocation = None;
    let allocation_slot = &mut allocation;
    let opening = zkf_core::notary_auth::respond_pool_with_async(
        &mut socket,
        &config.signing_key,
        scope,
        &VOLE_POOLS,
        |mut cached, setup| async move {
            if let Some(setup) = &setup {
                if let Some(open) = &setup.proxy {
                    tlsn::validate_proxy_open(&open.client_hello, &open.host)?;
                }
                anyhow::ensure!(
                    tlsn::vole_pool::valid_budget(setup.budget as usize),
                    "unsupported VOLE budget"
                );
            }
            // The opening deadline bounds queueing. Holding this guard through
            // verification also bounds simultaneous large-class allocations.
            *allocation_slot = Some(
                resources::acquire(
                    setup
                        .as_ref()
                        .map_or(tlsn::vole_pool::FLOW_BUDGET, |s| s.budget as usize),
                )
                .await?,
            );
            if let Some(setup) = &setup {
                if let Some(pool) = &mut cached {
                    pool.set_budget(setup.budget as usize)
                        .map_err(anyhow::Error::msg)?;
                    let reply = pool
                        .accept_prefill(&setup.ferret)
                        .map_err(anyhow::Error::msg)?;
                    return Ok((cached, reply));
                }
            }
            Ok((cached, vec![]))
        },
    );
    #[cfg(not(target_arch = "wasm32"))]
    let opening = tokio::time::timeout(OPENING_DEADLINE, opening)
        .await
        .map_err(|_| anyhow::anyhow!("notary authentication opening deadline exceeded"))??;
    #[cfg(target_arch = "wasm32")]
    let opening = opening.await?;
    // Plain legacy authentication bypasses the pool callback, but its record
    // layer allocation still consumes the conservative large-class allowance.
    let _allocation = match allocation {
        Some(permit) => permit,
        None => resources::acquire(tlsn::vole_pool::FLOW_BUDGET).await?,
    };
    let mut pool_lease = opening.map(|(opening, cached)| {
        let mut pool =
            cached.unwrap_or_else(|| tlsn::vole_pool::VerifierVolePool::new(opening.binding));
        pool.bind(opening.binding);
        // Setup is authenticated before forwarding or allocating the session.
        pool.set_budget(
            opening
                .setup
                .as_ref()
                .map_or(tlsn::vole_pool::FLOW_BUDGET, |setup| setup.budget as usize),
        )
        .expect("validated opening budget");
        pool.set_low_latency(opening.low_latency);
        pool.set_pipeline_tls(opening.proxy_open.is_some());
        pool.set_opened_host(if opening.resumed {
            opening.proxy_open.as_ref().map(|o| o.host.clone())
        } else {
            None
        });
        (opening, pool)
    });
    let low_latency = pool_lease.as_ref().is_some_and(|(o, _)| o.low_latency);
    let public_open = pool_lease
        .as_ref()
        .filter(|(o, _)| o.resumed)
        .and_then(|(o, _)| o.proxy_open.clone());
    let opened_server = if let Some(open) = public_open {
        tlsn::validate_proxy_open(&open.client_hello, &open.host)?;
        // Capability admission precedes this function. DNS/public-IP checks and
        // destination policy are enforced by the connector before any forwarding.
        let mut server = connector.connect(&open.host, 443).await?;
        futures::AsyncWriteExt::write_all(&mut server, &open.client_hello).await?;
        futures::AsyncWriteExt::flush(&mut server).await?;
        Some((server, open))
    } else {
        None
    };
    let session = if low_latency {
        Session::pipelined(socket)
    } else {
        Session::new(socket)
    };
    let (driver, mut handle) = session.split();
    if low_latency {
        let mut reply = handle.application_stream(b"zkfetch/flow2/attestation")?;
        let mut prefill_stream = handle.application_stream(b"zkfetch/flow3/prefill")?;
        let (opening, pool) = pool_lease.as_mut().expect("flow pool");
        let cold = !opening.resumed;
        let worker = pool.prefill_handle();
        let (tx, rx) = futures::channel::oneshot::channel();
        use futures::FutureExt;
        let ready = async move { rx.await.map_err(|_| "prefill cancelled".to_string())? }
            .boxed()
            .shared();
        pool.set_ready(ready.clone());
        let prefill = async move {
            let result = async {
                if cold {
                    let mut ctx = mpz_common::Context::new_single_threaded(prefill_stream);
                    worker
                        .cold_prefill(&mut ctx)
                        .await
                        .map_err(anyhow::Error::msg)?;
                } else {
                    let check = transport::read_frame(&mut prefill_stream).await?;
                    let reply = worker.finish_prefill(&check).map_err(anyhow::Error::msg)?;
                    transport::write_frame(&mut prefill_stream, &reply).await?;
                }
                Ok::<_, anyhow::Error>(())
            }
            .await;
            let _ = tx.send(result.as_ref().map(|_| ()).map_err(|e| e.to_string()));
            result
        };

        futures::future::try_join(driver.err_into::<anyhow::Error>(), async {
            let verification = async {
                if cold {
                    ready.await.map_err(anyhow::Error::msg)?;
                }
                let verified = verify_session(
                    &mut handle,
                    config,
                    connector,
                    pool_lease.as_mut().map(|(_, p)| p),
                    opened_server,
                    attestation_v2,
                )
                .await?;
                let bytes = transport::read_frame(&mut reply).await?;
                let attestation = sign_reply(config, &bytes, verified)?;
                // Publish the next lease before replying, so an immediate next session
                // cannot race attestation delivery and unexpectedly reset the pool.
                if let Some((opening, mut pool)) = pool_lease.take() {
                    if pool.park().is_ok() {
                        VOLE_POOLS.put(scope, opening.request, pool);
                    }
                }
                transport::write_frame(&mut reply, &attestation).await?;
                handle.close();
                Ok::<_, anyhow::Error>(())
            };
            futures::future::try_join(prefill, verification).await?;
            Ok::<_, anyhow::Error>(())
        })
        .await?;
        return Ok(());
    }
    let (mut socket, verified) =
        futures::future::try_join(driver.err_into::<anyhow::Error>(), async {
            let out = verify_session(
                &mut handle,
                config,
                connector,
                pool_lease.as_mut().map(|(_, p)| p),
                None,
                attestation_v2,
            )
            .await;
            handle.close();
            out
        })
        .await?;
    let request_bytes = transport::read_frame(&mut socket).await?;
    let attestation = sign_reply(config, &request_bytes, verified)?;
    transport::write_frame(&mut socket, &attestation).await?;
    if let Some((opening, mut pool)) = pool_lease {
        if pool.park().is_ok() {
            VOLE_POOLS.put(scope, opening.request, pool);
        }
    }
    futures::AsyncWriteExt::close(&mut socket).await.ok();
    Ok(())
}

/// What a verified session leaves to sign.
struct Verified {
    commitments: Vec<tlsn::transcript::TranscriptCommitment>,
    predicates: Vec<tlsn::transcript::TranscriptPredicate>,
    transcript: tlsn::transcript::TlsTranscript,
    host: Option<String>,
    #[cfg(feature = "d1-experimental")]
    d1: Option<d1::Evidence>,
}

/// Signs the attestation the session asked for; returns the reply frame.
fn sign_reply(config: &NotaryConfig, request_bytes: &[u8], verified: Verified) -> Result<Vec<u8>> {
    #[cfg(feature = "d1-experimental")]
    if let Some(evidence) = verified.d1 {
        let host = verified
            .host
            .as_deref()
            .expect("v2 sessions are proxy sessions");
        return d1::sign(config, request_bytes, &verified.transcript, host, evidence);
    }
    let attestation = sign_attestation(
        config,
        request_bytes,
        verified.commitments,
        verified.predicates,
        verified.transcript,
        verified.host,
    )?;
    Ok(bincode::serialize(&attestation)?)
}

fn sign_attestation(
    config: &NotaryConfig,
    request_bytes: &[u8],
    transcript_commitments: Vec<tlsn::transcript::TranscriptCommitment>,
    verified_predicates: Vec<tlsn::transcript::TranscriptPredicate>,
    tls_transcript: tlsn::transcript::TlsTranscript,
    proxy_host: Option<String>,
) -> Result<Attestation> {
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

    let request: AttestationRequest = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(zkf_core::MAX_FRAME_LEN as u64)
        .reject_trailing_bytes()
        .deserialize(request_bytes)
        .context("invalid attestation request")?;

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
    if let tlsn::connection::CertBinding::V1_3(binding) = tls_transcript.certificate_binding() {
        use sha2::Digest;
        builder.extension(tlsn::attestation::Extension {
            id: EXT_HANDSHAKE.to_vec(),
            value: sha2::Sha256::digest(&binding.handshake_messages).to_vec(),
        });
    }
    if let Some(host) = proxy_host {
        builder.extension(tlsn::attestation::Extension {
            id: EXT_SERVER.to_vec(),
            value: host.into_bytes(),
        });
    }

    Ok(builder.build(&provider)?)
}

/// Runs MPC-TLS and the commitment proofs, returning what the attestation
/// covers.
async fn verify_session<C: ServerConnector>(
    handle: &mut tlsn::SessionHandle,
    config: &NotaryConfig,
    connector: &C,
    pool: Option<&mut tlsn::vole_pool::VerifierVolePool>,
    opened_server: Option<(C::Stream, zkf_core::notary_auth::ProxyOpen)>,
    attestation_v2: bool,
) -> Result<Verified> {
    phase("start");
    let verifier_config = VerifierConfig::builder()
        .root_store(config.root_store())
        .build()?;
    phase("root store");

    let mut proxy_host = None;
    let mut dialed_ip = None;
    // The session configuration must arrive promptly; idle connections would
    // otherwise hold a slot for the whole session timeout (ZKF-09).
    let mut verifier = handle.new_verifier(verifier_config)?;
    if let Some(pool) = pool {
        verifier = verifier.with_vole_pool(pool);
    }
    let opened_config = opened_server
        .as_ref()
        .map(|(_, open)| {
            tlsn::config::tls_commit::proxy::ProxyTlsConfig::builder()
                .server_name(open.host.as_str().try_into()?)
                .tls_version(tlsn::connection::TlsVersion::V1_3)
                .build()
                .map_err(anyhow::Error::from)
        })
        .transpose()?;
    let commit = async move {
        match opened_config {
            Some(config) => verifier.commit_opened(config),
            None => verifier.commit().await,
        }
    };
    #[cfg(not(target_arch = "wasm32"))]
    let commit = async {
        tokio::time::timeout(OPENING_DEADLINE, commit)
            .await
            .map_err(|_| anyhow::anyhow!("prover did not send its session configuration in time"))?
            .map_err(anyhow::Error::from)
    };
    let verifier = match commit.await? {
        VerifierCommitStart::Mpc(verifier) => {
            anyhow::ensure!(opened_server.is_none(), "proxy opening cannot select MPC");
            if attestation_v2 {
                verifier
                    .reject(Some("v2 attestations require proxy mode"))
                    .await?;
                bail!("v2 attestation requested for an MPC session");
            }
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
            let (server, hello) = if let Some((server, open)) = opened_server {
                anyhow::ensure!(
                    host == open.host
                        && verifier.config().tls_version() == tlsn::connection::TlsVersion::V1_3,
                    "session configuration differs from signed opening"
                );
                (server, open.client_hello)
            } else {
                let server = match connector.connect(&host, 443).await {
                    Ok(server) => server,
                    Err(err) => {
                        verifier
                            .reject(Some("notary could not reach the server"))
                            .await?;
                        return Err(err);
                    }
                };
                (server, Vec::new())
            };
            dialed_ip = C::peer_ip(&server);
            let accepted = verifier.accept().await?;
            proxy_host = Some(host);
            phase("proxy accepted");
            accepted.run_opened(server, hello).await?
        }
    };

    phase("committed");
    let (
        VerifierOutput {
            transcript_commitments,
            predicates: verified_predicates,
            server_name: verified_server,
            ..
        },
        mut verifier,
    ) = verifier.verify().await?.accept().await?;

    let verified_server = verified_server
        .ok_or_else(|| anyhow::anyhow!("server identity must be verified during notarization"))?;
    if let Some(host) = &proxy_host {
        anyhow::ensure!(
            host.eq_ignore_ascii_case(&verified_server.to_string()),
            "verified identity differs from the proxy destination"
        );
    }

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
    #[cfg(feature = "d1-experimental")]
    let d1 = if attestation_v2 {
        anyhow::ensure!(
            transcript_commitments.is_empty() && verified_predicates.is_empty(),
            "v2 sessions carry no transcript commitments or session predicates"
        );
        Some(d1::verify(&mut verifier, handle, dialed_ip).await?)
    } else {
        None
    };
    #[cfg(not(feature = "d1-experimental"))]
    let _ = (&mut verifier, dialed_ip);
    let tls_transcript = verifier.tls_transcript().clone();
    verifier.close().await?;

    Ok(Verified {
        commitments: transcript_commitments,
        predicates: verified_predicates,
        transcript: tls_transcript,
        host: proxy_host,
        #[cfg(feature = "d1-experimental")]
        d1,
    })
}

#[cfg(test)]
mod tests {
    use super::is_public;

    #[test]
    fn per_client_slots_are_reclaimed() {
        let clients = Default::default();
        let ip = "127.0.0.1".parse().unwrap();
        let first = super::ClientSlot::acquire(&clients, ip, 1).unwrap();
        assert!(super::ClientSlot::acquire(&clients, ip, 1).is_none());
        drop(first);
        assert!(super::ClientSlot::acquire(&clients, ip, 1).is_some());
    }
    #[tokio::test]
    async fn refused_private_destination_receives_no_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let connector = super::TcpConnector { resolve: vec![] };
        use super::ServerConnector;
        assert!(
            connector
                .connect("127.0.0.1", listener.local_addr().unwrap().port())
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn slow_head_does_not_block_another_probe() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut slow = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        let task = tokio::spawn(super::answer_probe(socket));
        slow.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        let mut fast = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        let probe = tokio::spawn(super::answer_probe(socket));
        fast.write_all(b"GET /ping HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = [0u8; 128];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), fast.read(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response[..n].starts_with(b"HTTP/1.1 200 OK"));
        assert!(probe.await.unwrap().is_none());
        task.abort();
    }

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
            "2002:7f00:1::1",
            "2001:0:4136:e378::1",
            "2001:2::1",
            "2001:20::1",
            "3fff::1",
            "fec0::1",
            "100::1",
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
