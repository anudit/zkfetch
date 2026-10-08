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
use http_body_util::Full;
use hyper::{Request, body::Bytes};
use tlsn::{
    Session,
    attestation::{
        Attestation, CryptoProvider, Extension,
        request::{Request as AttestationRequest, RequestConfig},
    },
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::{mpc::MpcTlsConfig, proxy::ProxyTlsConfig},
    },
    connection::{HandshakeData, ServerName, TlsVersion},
    prover::ProverOutput,
    transcript::TranscriptCommitConfig,
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_formats::http::{BodyContent, HttpCommit, HttpTranscript};
use tracing::debug;
use zkf_core::{
    DEFAULT_MAX_RECV, DEFAULT_MAX_SENT, EXT_CONTEXT, EXT_OWNER, HttpResponseView, KeyView,
    NotarizeOutput, NotarizeParams, NotarizeTimings, b64, transport,
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
    Ok(rt::AssertSend(zkf_core::transport::connect(url.as_str()).await?))
}

/// Performs a notarized HTTPS request.
///
/// `params.tls_version`: "1.3", "1.2" or "auto" (default). "auto" tries TLS
/// 1.3 first and retries over TLS 1.2 only for idempotent methods, so a
/// non-idempotent request is never sent twice.
pub async fn notarize(params: NotarizeParams) -> Result<NotarizeOutput> {
    if !matches!(params.mode.as_deref().unwrap_or("mpc"), "mpc" | "proxy") {
        bail!("mode must be \"mpc\" or \"proxy\", got {:?}", params.mode);
    }
    let method = params
        .method
        .clone()
        .unwrap_or_else(|| "GET".into())
        .to_uppercase();
    match params.tls_version.as_deref().unwrap_or("auto") {
        "1.3" => notarize_with(params, TlsVersion::V1_3).await,
        "1.2" => notarize_with(params, TlsVersion::V1_2).await,
        "auto" => match notarize_with(params.clone(), TlsVersion::V1_3).await {
            Ok(out) => Ok(out),
            Err(err) if matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS") => {
                debug!("TLS 1.3 notarization failed ({err:#}); retrying with TLS 1.2");
                notarize_with(params, TlsVersion::V1_2)
                    .await
                    .with_context(|| format!("TLS 1.3 attempt failed first: {err:#}"))
            }
            Err(err) => Err(err.context(
                "TLS 1.3 notarization failed; set tlsVersion to \"1.2\" to use TLS 1.2 \
                 (not retried automatically for non-idempotent methods)",
            )),
        },
        other => bail!("tlsVersion must be \"1.2\", \"1.3\" or \"auto\", got {other:?}"),
    }
}

async fn notarize_with(params: NotarizeParams, tls_version: TlsVersion) -> Result<NotarizeOutput> {
    let url = url::Url::parse(&params.url).context("invalid url")?;
    if url.scheme() != "https" {
        bail!("only https:// URLs are supported");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("url has no host"))?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let target = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    };
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
    let mut timings = NotarizeTimings::default();

    let proxy = params.mode.as_deref() == Some("proxy");
    if proxy && params.connect_addr.is_some() {
        bail!("connectAddr is not supported in proxy mode: the notary dials the server");
    }

    // Session with the notary.
    let notary = transport::connect(&params.notary_url).await?;
    timings.notary_connect_ms = split();
    let (driver, mut handle) = Session::new(notary).split();
    let driver_task = rt::spawn(driver);

    let tls_config = TlsClientConfig::builder()
        .server_name(ServerName::Dns(host.as_str().try_into()?))
        .root_store(root_store(&params.extra_root_certs)?)
        .build()?;
    let new_prover = handle.new_prover(ProverConfig::builder().build()?)?;
    let (tls_connection, prover_task) = if proxy {
        let prover = new_prover
            .commit(
                ProxyTlsConfig::builder()
                    .server_name(host.as_str().try_into()?)
                    .tls_version(tls_version)
                    .build()?,
            )
            .await
            .context("notary rejected the proxy session configuration")?;
        timings.setup_ms = split();
        // The notary dials the server and relays this connection.
        let (tls_connection, prover) = prover.connect(tls_config)?;
        (tls_connection, rt::spawn(prover.into_future()))
    } else {
        let prover = new_prover
            .commit(
                MpcTlsConfig::builder()
                    .max_sent_data(params.max_sent.unwrap_or(DEFAULT_MAX_SENT))
                    .max_recv_data(params.max_recv.unwrap_or(DEFAULT_MAX_RECV))
                    .tls_version(tls_version)
                    .build()?,
            )
            .await
            .context("notary rejected the session configuration")?;
        timings.setup_ms = split();

        let server_socket = connect_server(&dial, params.relay_url.as_deref()).await?;
        let (tls_connection, prover) = prover.connect(tls_config, server_socket)?;
        (tls_connection, rt::spawn(prover.into_future()))
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
    let (mut prover, ()) = futures::try_join!(
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
    )?;
    timings.tls_ms = split();

    // Parsed spans are !Send, so keep them out of scope across awaits.
    let (response_view, transcript_commit, qs_claims) = {
        let transcript = HttpTranscript::parse(prover.transcript())
            .context("could not parse HTTP transcript")?;
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
        // QuickSilver predicates (default backend): shape proofs for every JSON
        // leaf plus the requested numeric predicates.
        let qs_claims = if params.predicates.is_empty() {
            None
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
        (response_view(&transcript)?, commit.build()?, qs_claims)
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
    if let Some(config) = request_config.transcript_commit() {
        prove.transcript_commit(config.clone());
    }
    for predicate in qs_claims.iter().flat_map(|c| &c.predicates) {
        prove.predicate(predicate.clone())?;
    }
    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&prove.build()?).await?;

    let prover_transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    prover.close().await?;
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
    let attestation: Attestation = bincode::deserialize(&transport::read_frame(&mut socket).await?)
        .context("invalid attestation from notary")?;

    att_request
        .validate(&attestation, &CryptoProvider::default())
        .context("notary returned an attestation inconsistent with our request")?;
    timings.attest_ms = split();
    timings.total_ms = started.elapsed().as_secs_f64() * 1e3;

    let key = attestation.body.verifying_key();
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
