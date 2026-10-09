//! zkfetch prover.
//!
//! [`notarize`] runs an HTTPS request as the TLS client half of an MPC-TLS
//! session with a notary and returns a signed attestation plus the secrets
//! needed to open it. [`present`] turns those into a selectively-disclosed
//! presentation according to a [`RevealSpec`].

mod commit;
mod present;
mod rt;

pub use present::present;

use web_time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use futures::future::RemoteHandle;
use http_body_util::Full;
use hyper::{Request, body::Bytes};
use tlsn::{
    Mpc, Proxy, Session, SessionHandle,
    attestation::{
        Attestation, CryptoProvider, Extension,
        request::{Request as AttestationRequest, RequestConfig},
    },
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{mpc::MpcTlsConfig, proxy::ProxyTlsConfig},
    },
    connection::{HandshakeData, ServerName, TlsVersion},
    prover::{Prover, ProverOutput, state::CommitAccepted},
    transcript::TranscriptCommitConfig,
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_formats::http::{BodyContent, HttpCommit, HttpTranscript};
use tracing::debug;
use zkf_core::{
    DEFAULT_MAX_RECV, DEFAULT_MAX_SENT, DEFAULT_PROXY_MAX_RECV, EXT_CONTEXT, EXT_OWNER,
    HttpResponseView, KeyView, NotarizeOutput, NotarizeParams, NotarizeTimings, b64, transport,
};

/// Headers zkfetch controls; user-supplied values are rejected.
const MANAGED_HEADERS: &[&str] = &["host", "connection", "accept-encoding", "content-length"];

pub(crate) fn root_store(extra_b64: &[String]) -> Result<RootCertStore> {
    let mut store = RootCertStore::mozilla();
    for cert in extra_b64 {
        store.roots.push(CertificateDer(b64::decode(cert)?));
    }
    Ok(store)
}

/// The prover's own TCP connection to the server (MPC mode).
#[cfg(not(target_arch = "wasm32"))]
async fn connect_server(
    dial: &str,
    relay_url: Option<&str>,
) -> Result<impl futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static> {
    use tokio_util::compat::TokioAsyncReadCompatExt;
    if relay_url.is_some() {
        bail!("relayUrl is only used by browser builds");
    }
    let tcp = tokio::net::TcpStream::connect(dial)
        .await
        .with_context(|| format!("failed to connect to {dial}"))?;
    tcp.set_nodelay(true)?;
    Ok(tcp.compat())
}

/// Browsers cannot open TCP sockets: MPC mode tunnels the TLS connection
/// through a WebSocket-to-TCP relay (`relayUrl?target=host:port`, binary
/// frames). Proxy mode needs no relay because the notary dials the server.
#[cfg(target_arch = "wasm32")]
async fn connect_server(
    dial: &str,
    relay_url: Option<&str>,
) -> Result<impl futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static> {
    let relay = relay_url.ok_or_else(|| {
        anyhow!("MPC mode in a browser needs zkConfig.relayUrl (a WebSocket-to-TCP relay); or use mode: \"proxy\"")
    })?;
    let mut url = url::Url::parse(relay).context("invalid relayUrl")?;
    url.query_pairs_mut().append_pair("target", dial);
    Ok(rt::AssertSend::new(
        zkf_core::transport::connect(url.as_str()).await?,
    ))
}

/// Performs a notarized HTTPS request.
///
/// `params.tls_version`: "1.3", "1.2" or "auto" (default). "auto" selects TLS
/// 1.3 first and retries over TLS 1.2 only for idempotent methods, so a
/// non-idempotent request is never sent twice.
pub async fn notarize(params: NotarizeParams) -> Result<NotarizeOutput> {
    notarize_auto(params, None).await
}

/// Like [`notarize`], but starts from a session set up ahead of time by
/// [`prepare`], so only the request-dependent phases remain. The prepared
/// session must match `params` (notary, mode, TLS version, MPC limits and, in
/// proxy mode, the host). An "auto" TLS 1.2 fallback uses a fresh session.
pub async fn notarize_prepared(
    prepared: Prepared,
    params: NotarizeParams,
) -> Result<NotarizeOutput> {
    notarize_auto(params, Some(prepared)).await
}

/// Request-independent setup for [`notarize_prepared`]: the notary connection
/// and the OT/MPC preprocessing, which dominate latency.
///
/// Use it once, before the notary's session timeout (120 s by default,
/// counted from the connection) leaves too little time for the request.
/// Dropping it closes the session.
pub struct Prepared {
    key: SessionKey,
    tls_version: TlsVersion,
    connect_ms: f64,
    setup_ms: f64,
    prewarmed: bool,
    handle: SessionHandle,
    driver_task: RemoteHandle<tlsn::Result<transport::ClientStream>>,
    prover: CommittedProver,
}

enum CommittedProver {
    Proxy(Prover<CommitAccepted<Proxy>>),
    Mpc(Prover<CommitAccepted<Mpc>>),
}

/// The parameters a prepared session is bound to.
#[derive(Debug, Clone, PartialEq)]
struct SessionKey {
    notary_url: String,
    expected_notary_key: Option<String>,
    proxy: bool,
    /// Proxy mode commits to the server name; MPC mode does not.
    proxy_host: Option<String>,
    max_sent: usize,
    max_recv: usize,
}

impl SessionKey {
    fn new(params: &NotarizeParams) -> Result<Self> {
        let proxy = match params.mode.as_deref().unwrap_or("mpc") {
            "mpc" => false,
            "proxy" => true,
            other => bail!("mode must be \"mpc\" or \"proxy\", got {other:?}"),
        };
        Ok(Self {
            notary_url: params.notary_url.clone(),
            expected_notary_key: params.expected_notary_key.clone(),
            proxy,
            proxy_host: if proxy {
                Some(Target::parse(&params.url)?.host)
            } else {
                None
            },
            max_sent: params.max_sent.unwrap_or(DEFAULT_MAX_SENT),
            max_recv: params.max_recv.unwrap_or(DEFAULT_MAX_RECV),
        })
    }
}

/// The parts of the request URL the protocol needs.
struct Target {
    host: String,
    port: u16,
    path_and_query: String,
}

impl Target {
    fn parse(url: &str) -> Result<Self> {
        let url = url::Url::parse(url).context("invalid url")?;
        if url.scheme() != "https" {
            bail!("only https:// URLs are supported");
        }
        Ok(Self {
            host: url
                .host_str()
                .ok_or_else(|| anyhow!("url has no host"))?
                .to_string(),
            port: url.port_or_known_default().unwrap_or(443),
            path_and_query: match url.query() {
                Some(q) => format!("{}?{q}", url.path()),
                None => url.path().to_string(),
            },
        })
    }
}

/// Connects to the notary and runs the preprocessing for `params`. The TLS
/// version is `params.tls_version`, with "auto" preparing TLS 1.3.
pub async fn prepare(params: &NotarizeParams) -> Result<Prepared> {
    let tls_version = match params.tls_version.as_deref().unwrap_or("auto") {
        "1.2" => TlsVersion::V1_2,
        "1.3" | "auto" => TlsVersion::V1_3,
        other => bail!("tlsVersion must be \"1.2\", \"1.3\" or \"auto\", got {other:?}"),
    };
    let mut prepared = prepare_with(params, tls_version).await?;
    prepared.prewarmed = true;
    Ok(prepared)
}

async fn prepare_with(params: &NotarizeParams, tls_version: TlsVersion) -> Result<Prepared> {
    let key = SessionKey::new(params)?;
    if key.proxy && params.connect_addr.is_some() {
        bail!("connectAddr is not supported in proxy mode: the notary dials the server");
    }

    // Session with the notary.
    let started = Instant::now();
    let endpoint = transport::validate_endpoint(&params.notary_url)?;
    if endpoint.scheme() == "wss" && params.expected_notary_key.is_none() {
        bail!("remote sessions require expectedNotaryKey before MPC setup");
    }
    let mut notary = transport::connect(&params.notary_url).await?;
    #[cfg(not(target_arch = "wasm32"))]
    tokio::time::timeout(
        std::time::Duration::from_secs(15),
        zkf_core::notary_auth::authenticate(&mut notary, params.expected_notary_key.as_deref()),
    )
    .await
    .context("notary authentication opening deadline exceeded")??;
    #[cfg(target_arch = "wasm32")]
    zkf_core::notary_auth::authenticate(&mut notary, params.expected_notary_key.as_deref()).await?;
    let connect_ms = started.elapsed().as_secs_f64() * 1e3;
    let (driver, mut handle) = Session::new(notary).split();
    let mut driver_task = rt::spawn(driver);

    let setup_started = Instant::now();
    let new_prover = handle.new_prover(ProverConfig::builder().build()?)?;
    let prover = watch_notary(&mut driver_task, async {
        Ok(match &key.proxy_host {
            Some(host) => CommittedProver::Proxy(
                new_prover
                    .commit(
                        ProxyTlsConfig::builder()
                            .server_name(host.as_str().try_into()?)
                            .tls_version(tls_version)
                            .build()?,
                    )
                    .await
                    .context("notary rejected the proxy session configuration")?,
            ),
            None => CommittedProver::Mpc(
                new_prover
                    .commit(
                        MpcTlsConfig::builder()
                            .max_sent_data(key.max_sent)
                            .max_recv_data(key.max_recv)
                            .tls_version(tls_version)
                            .build()?,
                    )
                    .await
                    .context("notary rejected the session configuration")?,
            ),
        })
    })
    .await?;
    Ok(Prepared {
        key,
        tls_version,
        connect_ms,
        setup_ms: setup_started.elapsed().as_secs_f64() * 1e3,
        prewarmed: false,
        handle,
        driver_task,
        prover,
    })
}

async fn notarize_auto(
    params: NotarizeParams,
    prepared: Option<Prepared>,
) -> Result<NotarizeOutput> {
    SessionKey::new(&params)?;
    let requested = params.tls_version.as_deref().unwrap_or("auto");
    let first = match (requested, prepared.as_ref().map(|p| p.tls_version)) {
        ("1.2", None | Some(TlsVersion::V1_2)) | ("auto", Some(TlsVersion::V1_2)) => {
            TlsVersion::V1_2
        }
        ("1.3" | "auto", None | Some(TlsVersion::V1_3)) => TlsVersion::V1_3,
        ("1.2" | "1.3", Some(_)) => {
            bail!("the prepared session uses a different TLS version than tlsVersion {requested:?}")
        }
        (other, _) => bail!("tlsVersion must be \"1.2\", \"1.3\" or \"auto\", got {other:?}"),
    };
    let result = match prepared {
        Some(prepared) => finish(prepared, params.clone()).await,
        None => match prepare_with(&params, first).await {
            Ok(prepared) => finish(prepared, params.clone()).await,
            Err(err) => Err(err),
        },
    };
    // Never retry an attempted session: failures may occur after HTTP transmission.
    // Callers may explicitly choose TLS 1.2 for compatibility before a new request.
    result
}

/// Runs the request-dependent phases on a prepared session.
/// Runs `work` while watching the notary connection. If the session driver
/// ends first (the notary failed to reach the server, hit a limit, or closed),
/// returns its error rather than waiting forever for a message that will not come.
async fn watch_notary<T>(
    driver: &mut RemoteHandle<tlsn::Result<transport::ClientStream>>,
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    futures::pin_mut!(work);
    match futures::future::select(work, driver).await {
        futures::future::Either::Left((result, _)) => result,
        futures::future::Either::Right((Err(err), _)) => {
            Err(anyhow!("the notary connection failed: {err}"))
        }
        futures::future::Either::Right((Ok(_), _)) => {
            Err(anyhow!("the notary closed the connection"))
        }
    }
}

async fn finish(prepared: Prepared, params: NotarizeParams) -> Result<NotarizeOutput> {
    let Prepared {
        key,
        tls_version,
        connect_ms,
        setup_ms,
        prewarmed,
        handle,
        mut driver_task,
        prover,
    } = prepared;
    if key != SessionKey::new(&params)? {
        bail!(
            "the prepared session does not match these parameters (notary, mode, host or MPC limits)"
        );
    }
    let Target {
        host,
        port,
        path_and_query: target,
    } = Target::parse(&params.url)?;
    let dial = params
        .connect_addr
        .clone()
        .unwrap_or_else(|| format!("{host}:{port}"));
    let method = params
        .method
        .clone()
        .unwrap_or_else(|| "GET".into())
        .to_uppercase();

    for (name, _) in &params.headers {
        if MANAGED_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
            bail!("header `{name}` is managed by zkfetch");
        }
    }

    let started = Instant::now();
    let mut lap = started;
    let mut split = || {
        let now = Instant::now();
        let ms = now.duration_since(lap).as_secs_f64() * 1e3;
        lap = now;
        ms
    };
    let mut timings = NotarizeTimings {
        notary_connect_ms: connect_ms,
        setup_ms,
        prewarmed,
        ..Default::default()
    };

    let tls_config = TlsClientConfig::builder()
        .server_name(ServerName::Dns(host.as_str().try_into()?))
        .root_store(root_store(&params.extra_root_certs)?)
        .build()?;
    let (tls_connection, prover_task) = match prover {
        CommittedProver::Proxy(prover) => {
            // The notary dials the server and relays this connection.
            let (tls_connection, prover) = prover.connect(tls_config)?;
            (tls_connection, rt::spawn(prover.into_future()))
        }
        CommittedProver::Mpc(prover) => {
            let server_socket = connect_server(&dial, params.relay_url.as_deref()).await?;
            let (tls_connection, prover) = prover.connect(tls_config, server_socket)?;
            (tls_connection, rt::spawn(prover.into_future()))
        }
    };

    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(rt::HyperIo(tls_connection)).await?;
    let _connection_task = rt::spawn(connection);

    let mut req = Request::builder()
        .method(method.as_str())
        .uri(&target)
        .header("Host", &host)
        .header("Accept-Encoding", "identity")
        .header("Connection", "close");
    for (name, value) in &params.headers {
        req = req.header(name, value);
    }
    let body = params.body.clone().unwrap_or_default();
    let request = req.body(Full::new(Bytes::from(body)))?;
    // Observe TLS failures while HTTP is waiting for bytes. Otherwise a failed
    // handshake can leave Hyper pending forever and prevent auto fallback.
    let (mut prover, ()) = watch_notary(&mut driver_task, async {
        futures::try_join!(
            async {
                let prover = prover_task.await.context("MPC-TLS client task failed")?;
                Ok::<_, anyhow::Error>(prover)
            },
            async {
                let response = sender.send_request(request).await?;
                debug!(status = %response.status(), "received response");
                // Drain the body; authoritative bytes come from the MPC transcript.
                http_body_util::BodyExt::collect(response.into_body()).await?;
                Ok::<(), anyhow::Error>(())
            },
        )
    })
    .await?;
    timings.tls_ms = split();
    // MPC mode enforces its limits in the protocol. Proxy mode does not, so a
    // large response would otherwise be proven for minutes until the notary
    // times out. Fail now with the size instead.
    if key.proxy {
        let limit = params.max_recv.unwrap_or(DEFAULT_PROXY_MAX_RECV);
        let received = prover.transcript().received().len();
        if received > limit {
            bail!(
                "the response is {received} bytes, over the {limit}-byte limit for proxy mode (raise maxRecv to allow it)"
            );
        }
    }

    // Parsed spans are !Send, so keep them out of scope across awaits.
    let (response_view, transcript_commit, qs_claims) = {
        zkf_core::parsing::check_http_json_nesting(prover.transcript().sent())?;
        zkf_core::parsing::check_http_json_nesting(prover.transcript().received())?;
        let transcript = HttpTranscript::parse(prover.transcript())
            .context("could not parse HTTP transcript")?;
        // QuickSilver predicates (default backend): shape proofs for every JSON
        // leaf plus the requested numeric predicates. Without predicates the
        // shape proofs are still attached when possible: they let a verifier
        // authenticate the JSON path of each disclosed value.
        let json_body = transcript
            .responses
            .first()
            .and_then(|r| r.body.as_ref())
            .and_then(|b| match &b.content {
                BodyContent::Json(doc) => Some(doc),
                _ => None,
            });
        let qs_claims = if params.predicates.is_empty() {
            json_body
                .filter(|_| !params.binius)
                .map(|doc| {
                    zkf_predicates::quicksilver::plan(
                        &doc.root,
                        prover.transcript().received(),
                        &[],
                    )
                })
                .transpose()
                .context("JSON shape authentication is unsupported for this response")?
        } else {
            let body = transcript
                .responses
                .first()
                .and_then(|r| r.body.as_ref())
                .ok_or_else(|| anyhow!("predicates require a response body"))?;
            let BodyContent::Json(doc) = &body.content else {
                bail!("predicates require a JSON response");
            };
            Some(zkf_predicates::quicksilver::plan(
                &doc.root,
                prover.transcript().received(),
                &params.predicates,
            )?)
        };
        let transcript_commit = match &params.reveal {
            // Only what the declared disclosure needs, one commitment per unit.
            Some(spec) => commit::disclosure(
                prover.transcript(),
                &transcript,
                spec,
                qs_claims.is_some(),
                params.binius,
            )?,
            None => {
                // Commit to the whole transcript at HTTP-part / JSON-node granularity.
                let mut commit = TranscriptCommitConfig::builder(prover.transcript());
                // DEBUG(mem): experiment with the coarsest possible commitments.
                if std::env::var("ZKF_DEBUG_COARSE_COMMIT").is_ok() {
                    let sent = prover.transcript().sent().len();
                    let recv = prover.transcript().received().len();
                    commit.commit_sent(&(0..sent))?;
                    commit.commit_recv(&(0..recv))?;
                } else {
                    commit::HttpCommitter {
                        binius: params.binius,
                    }
                    .commit_transcript(&mut commit, &transcript)?;
                }
                commit::disjoint(prover.transcript(), commit.build()?)?
            }
        };
        (response_view(&transcript)?, transcript_commit, qs_claims)
    };

    let mut request_config = RequestConfig::builder();
    request_config.transcript_commit(transcript_commit);
    if let Some(owner) = &params.owner {
        request_config.extension(Extension {
            id: EXT_OWNER.to_vec(),
            value: owner.as_bytes().to_vec(),
        });
    }
    if let Some(context) = &params.context {
        request_config.extension(Extension {
            id: EXT_CONTEXT.to_vec(),
            value: context.as_bytes().to_vec(),
        });
    }
    if let Some(claims) = &qs_claims {
        request_config.extension(Extension {
            id: zkf_predicates::quicksilver::EXT_QS.to_vec(),
            value: claims.encode()?,
        });
    }
    let request_config = request_config.build()?;

    let mut prove = ProveConfig::builder(prover.transcript());
    prove.server_identity();
    if let Some(config) = request_config.transcript_commit() {
        prove.transcript_commit(config.clone());
    }
    for predicate in qs_claims.iter().flat_map(|c| &c.predicates) {
        prove.predicate(predicate.clone())?;
    }
    let prove_config = prove.build()?;
    let (prover_transcript, tls_transcript, transcript_commitments, transcript_secrets) =
        watch_notary(&mut driver_task, async {
            let ProverOutput {
                transcript_commitments,
                transcript_secrets,
                ..
            } = prover.prove(&prove_config).await?;
            let prover_transcript = prover.transcript().clone();
            let tls_transcript = prover.tls_transcript().clone();
            prover.close().await?;
            Ok((
                prover_transcript,
                tls_transcript,
                transcript_commitments,
                transcript_secrets,
            ))
        })
        .await?;
    timings.prove_ms = split();

    let mut att_request = AttestationRequest::builder(&request_config);
    att_request
        .server_name(ServerName::Dns(host.as_str().try_into()?))
        .handshake_data(HandshakeData {
            certs: tls_transcript
                .server_cert_chain()
                .ok_or_else(|| anyhow!("missing server certificate chain"))?
                .to_vec(),
            sig: tls_transcript
                .server_signature()
                .ok_or_else(|| anyhow!("missing server signature"))?
                .clone(),
            binding: tls_transcript.certificate_binding().clone(),
        })
        .transcript(prover_transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);
    let (att_request, secrets) = att_request.build(&CryptoProvider::default())?;

    handle.close();
    let mut socket = driver_task.await?;
    transport::write_frame(&mut socket, &bincode::serialize(&att_request)?).await?;
    let bytes = transport::read_frame(&mut socket).await?;
    let attestation: Attestation = {
        use bincode::Options;
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(zkf_core::MAX_FRAME_LEN as u64)
            .reject_trailing_bytes()
            .deserialize(&bytes)
            .context("invalid attestation from notary")?
    };

    att_request
        .validate(&attestation, &CryptoProvider::default())
        .context("notary returned an attestation inconsistent with our request")?;
    timings.attest_ms = split();
    // What the caller waited for: setup counts only if it was not done ahead.
    timings.total_ms = started.elapsed().as_secs_f64() * 1e3
        + if prewarmed {
            0.0
        } else {
            connect_ms + setup_ms
        };

    let key = attestation.body.verifying_key();
    if let Some(expected) = &params.expected_notary_key {
        anyhow::ensure!(
            hex::decode(expected)? == key.data,
            "attestation key differs from the interactive notary pin"
        );
    }
    Ok(NotarizeOutput {
        attestation: b64::encode(bincode::serialize(&attestation)?),
        secrets: b64::encode(bincode::serialize(&secrets)?),
        response: response_view,
        tls_version: match tls_version {
            TlsVersion::V1_2 => "1.2",
            TlsVersion::V1_3 => "1.3",
        }
        .into(),
        notary_key: KeyView {
            alg: key.alg.to_string(),
            key: hex::encode(&key.data),
        },
        timings,
    })
}

fn response_view(transcript: &HttpTranscript) -> Result<HttpResponseView> {
    let response = transcript
        .responses
        .first()
        .ok_or_else(|| anyhow!("no HTTP response"))?;
    let status = response
        .status
        .code
        .as_str()
        .parse()
        .context("invalid status code")?;
    let headers = response
        .headers
        .iter()
        .map(|h| {
            (
                h.name.as_str().to_string(),
                String::from_utf8_lossy(&h.value.as_bytes())
                    .trim()
                    .to_string(),
            )
        })
        .collect();
    let body = response
        .body
        .as_ref()
        .map(|b| String::from_utf8_lossy(&b.content_data()).into_owned())
        .unwrap_or_default();
    Ok(HttpResponseView {
        status,
        headers,
        body,
    })
}
