//! Fresh, domain-separated proof of notary key possession before MPC setup.
use anyhow::{Result, ensure};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use k256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use rand::RngCore;

fn message(nonce: &[u8; 32]) -> Vec<u8> {
    let mut message = b"zkfetch/notary-auth/v1\0".to_vec();
    message.extend_from_slice(nonce);
    message
}

fn check(nonce: &[u8; 32], reply: &[u8; 97], expected: Option<&str>) -> Result<()> {
    let key = VerifyingKey::from_sec1_bytes(&reply[..33])?;
    if let Some(expected) = expected {
        let pinned = VerifyingKey::from_sec1_bytes(&hex::decode(expected)?)?;
        ensure!(
            key == pinned,
            "interactive notary key does not match the configured pin"
        );
    }
    key.verify(&message(nonce), &Signature::from_slice(&reply[33..])?)?;
    Ok(())
}

pub async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    expected: Option<&str>,
) -> Result<()> {
    let started = web_time::Instant::now();
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    stream.write_all(&nonce).await?;
    stream.flush().await?;
    let mut reply = [0u8; 97];
    stream.read_exact(&mut reply).await?;
    let result = check(&nonce, &reply, expected);
    tracing::info!(target: "zkfetch::setup", step = "notary_key_challenge", elapsed_ms = started.elapsed().as_secs_f64() * 1e3, sent_bytes = 32, received_bytes = 97, resumed = false, "setup sub-step");
    result
}

pub async fn respond<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    secret: &[u8; 32],
) -> Result<()> {
    let mut nonce = [0u8; 32];
    stream.read_exact(&mut nonce).await?;
    let key = SigningKey::from_slice(secret)?;
    let signature: Signature = key.sign(&message(&nonce));
    stream
        .write_all(key.verifying_key().to_encoded_point(true).as_bytes())
        .await?;
    stream.write_all(&signature.to_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_pin_freshness_and_signature_are_required() {
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let nonce = [4; 32];
        let mut reply = [0; 97];
        reply[..33].copy_from_slice(key.verifying_key().to_encoded_point(true).as_bytes());
        let signature: Signature = key.sign(&message(&nonce));
        reply[33..].copy_from_slice(&signature.to_bytes());
        let pin = hex::encode(&reply[..33]);
        assert!(check(&nonce, &reply, Some(&pin)).is_ok());
        assert!(check(&[5; 32], &reply, Some(&pin)).is_err());
        let other = SigningKey::from_slice(&[8; 32]).unwrap();
        let wrong = hex::encode(other.verifying_key().to_encoded_point(true).as_bytes());
        assert!(check(&nonce, &reply, Some(&wrong)).is_err());
        reply[40] ^= 1;
        assert!(check(&nonce, &reply, Some(&pin)).is_err());
    }
}

/// Opening marker: 192 random bits remain in the challenge.
pub const POOL_MAGIC: &[u8; 8] = b"ZKFPOOL1";
/// Negotiates the pipelined proof and in-session attestation flow.
pub const FLOW_MAGIC: &[u8; 8] = b"ZKFFLOW4";

/// Public TLS first flight. No application data or private proof inputs.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProxyOpen {
    pub host: String,
    pub client_hello: Vec<u8>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SetupOpen {
    pub proxy: Option<ProxyOpen>,
    pub budget: u32,
    pub ferret: Vec<u8>,
}

fn pool_message(nonce: &[u8; 32], request: &[u8; 72], response: &[u8; 41]) -> Vec<u8> {
    let mut out = b"zkfetch/notary-auth/pool/v1\0".to_vec();
    out.extend_from_slice(nonce);
    out.extend_from_slice(request);
    out.extend_from_slice(response);
    out
}
/// Signed result of pool negotiation. Its digest also binds the TLSN setup.
pub struct PoolOpening {
    pub request: crate::setup_pool::PoolRequest,
    pub resumed: bool,
    pub binding: [u8; 32],
    pub low_latency: bool,
    pub proxy_open: Option<ProxyOpen>,
    pub setup: Option<SetupOpen>,
    pub ferret_reply: Vec<u8>,
}
/// Authenticates the notary and negotiates a pool in the same exchange.
/// `None` means the authenticated peer speaks the legacy opening; reconnect
/// with fresh OT. No correlations have been used at this point.
pub async fn authenticate_pool<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    expected: Option<&str>,
    request: crate::setup_pool::PoolRequest,
) -> Result<Option<PoolOpening>> {
    authenticate_pool_inner(stream, expected, request, None, false).await
}

pub async fn authenticate_pool_open<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    expected: Option<&str>,
    request: crate::setup_pool::PoolRequest,
    proxy_open: Option<ProxyOpen>,
) -> Result<Option<PoolOpening>> {
    authenticate_pool_setup(
        stream,
        expected,
        request,
        SetupOpen {
            proxy: proxy_open,
            budget: 0,
            ferret: vec![],
        },
    )
    .await
}

pub async fn authenticate_pool_setup<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    expected: Option<&str>,
    request: crate::setup_pool::PoolRequest,
    setup: SetupOpen,
) -> Result<Option<PoolOpening>> {
    authenticate_pool_inner(stream, expected, request, Some(setup), true).await
}

async fn authenticate_pool_inner<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    expected: Option<&str>,
    request: crate::setup_pool::PoolRequest,
    setup: Option<SetupOpen>,
    low_latency: bool,
) -> Result<Option<PoolOpening>> {
    use sha2::{Digest, Sha256};
    let started = web_time::Instant::now();
    let mut nonce = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce[..8].copy_from_slice(if low_latency { FLOW_MAGIC } else { POOL_MAGIC });
    let request_bytes = request.encode();
    stream.write_all(&nonce).await?;
    stream.write_all(&request_bytes).await?;
    let public_bytes = bincode::serialize(&setup)?;
    if low_latency {
        crate::transport::write_frame(stream, &public_bytes).await?;
    }
    stream.flush().await?;
    let mut reply = [0; 97];
    stream.read_exact(&mut reply).await?;
    let key = VerifyingKey::from_sec1_bytes(&reply[..33])?;
    if let Some(pin) = expected {
        ensure!(
            key == VerifyingKey::from_sec1_bytes(&hex::decode(pin)?)?,
            "interactive notary key does not match the configured pin"
        );
    }
    // Only a valid legacy signature and matching key pin enables fallback.
    if check(&nonce, &reply, expected).is_ok() {
        return Ok(None);
    }
    let mut response = [0; 41];
    stream.read_exact(&mut response).await?;
    ensure!(response[40] <= 1, "invalid pool opening");
    let ferret_reply = if low_latency {
        crate::transport::read_frame(stream).await?
    } else {
        vec![]
    };
    let mut msg = pool_message(&nonce, &request_bytes, &response);
    if low_latency {
        msg.extend_from_slice(&(public_bytes.len() as u64).to_be_bytes());
        msg.extend_from_slice(&public_bytes);
        msg.extend_from_slice(&(ferret_reply.len() as u64).to_be_bytes());
        msg.extend_from_slice(&ferret_reply);
    }
    key.verify(&msg, &Signature::from_slice(&reply[33..])?)?;
    let generation = u64::from_be_bytes(response[32..40].try_into().unwrap());
    let ticket: [u8; 32] = response[..32].try_into().unwrap();
    let resumed = response[40] == 1;
    ensure!(
        !resumed || (generation == request.generation && ticket == request.ticket),
        "invalid resumed pool index"
    );
    ensure!(resumed || generation == 0, "invalid fresh pool index");
    tracing::info!(target: "zkfetch::setup", step = "notary_key_challenge", elapsed_ms = started.elapsed().as_secs_f64() * 1e3, sent_bytes = 104 + if low_latency { 4 + public_bytes.len() } else { 0 }, received_bytes = 138, resumed, "setup sub-step");
    Ok(Some(PoolOpening {
        request: crate::setup_pool::PoolRequest {
            device: request.device,
            ticket,
            generation,
        },
        resumed,
        binding: Sha256::digest(&msg).into(),
        low_latency,
        proxy_open: setup.as_ref().and_then(|s| s.proxy.clone()),
        setup,
        ferret_reply,
    }))
}
/// Reads either opening version. A pool is removed from the cache before the
/// response is signed, so a concurrent connection cannot obtain the same state.
pub async fn respond_pool<S: AsyncRead + AsyncWrite + Unpin, T>(
    stream: &mut S,
    secret: &[u8; 32],
    scope: [u8; 32],
    cache: &crate::setup_pool::PoolCache<T>,
) -> Result<Option<(PoolOpening, Option<T>)>> {
    respond_pool_with(stream, secret, scope, cache, |_, _| Ok(vec![])).await
}

pub async fn respond_pool_with<S: AsyncRead + AsyncWrite + Unpin, T, F>(
    stream: &mut S,
    secret: &[u8; 32],
    scope: [u8; 32],
    cache: &crate::setup_pool::PoolCache<T>,
    prefill: F,
) -> Result<Option<(PoolOpening, Option<T>)>>
where
    F: FnOnce(&mut Option<T>, &Option<SetupOpen>) -> Result<Vec<u8>>,
{
    respond_pool_with_async(
        stream,
        secret,
        scope,
        cache,
        |mut cached, setup| async move {
            let reply = prefill(&mut cached, &setup)?;
            Ok((cached, reply))
        },
    )
    .await
}

/// Removes a lease before awaiting admission, then preprocesses before signing
/// the opening. Cancellation burns the lease while waiting; no upstream I/O is
/// performed by this function.
pub async fn respond_pool_with_async<S: AsyncRead + AsyncWrite + Unpin, T, F, Fut>(
    stream: &mut S,
    secret: &[u8; 32],
    scope: [u8; 32],
    cache: &crate::setup_pool::PoolCache<T>,
    prefill: F,
) -> Result<Option<(PoolOpening, Option<T>)>>
where
    F: FnOnce(Option<T>, Option<SetupOpen>) -> Fut,
    Fut: std::future::Future<Output = Result<(Option<T>, Vec<u8>)>>,
{
    use sha2::{Digest, Sha256};
    let mut nonce = [0; 32];
    stream.read_exact(&mut nonce).await?;
    let key = SigningKey::from_slice(secret)?;
    let low_latency = &nonce[..8] == FLOW_MAGIC;
    if &nonce[..8] != POOL_MAGIC && !low_latency {
        let signature: Signature = key.sign(&message(&nonce));
        stream
            .write_all(key.verifying_key().to_encoded_point(true).as_bytes())
            .await?;
        stream.write_all(&signature.to_bytes()).await?;
        stream.flush().await?;
        return Ok(None);
    }
    let mut request_bytes = [0; 72];
    stream.read_exact(&mut request_bytes).await?;
    let request = crate::setup_pool::PoolRequest::decode(&request_bytes);
    let (setup, public_bytes) = if low_latency {
        use bincode::Options;
        // Bound the public opening before allocation; it only contains one
        // ClientHello and a DNS name, never a general transcript frame.
        let mut length = [0; 4];
        stream.read_exact(&mut length).await?;
        let length = u32::from_be_bytes(length) as usize;
        ensure!(length <= 20 * 1024, "public opening too large");
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await?;
        let open: Option<SetupOpen> = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(20 * 1024)
            .reject_trailing_bytes()
            .deserialize(&bytes)?;
        if let Some(setup) = &open {
            ensure!(
                setup.budget <= 3_500_000 && setup.ferret.len() <= 4096,
                "invalid setup budget"
            );
            if let Some(open) = &setup.proxy {
                ensure!(
                    open.host.len() <= 253 && open.client_hello.len() <= 16 * 1024,
                    "invalid public opening"
                );
            }
        }
        (open, bytes)
    } else {
        (None, Vec::new())
    };
    let cached = cache.take(scope, request);
    let (cached, ferret_reply) = prefill(cached, setup.clone()).await?;
    let resumed = cached.is_some();
    let mut next = request;
    if !resumed {
        rand::rngs::OsRng.fill_bytes(&mut next.ticket);
        next.generation = 0;
    }
    let mut response = [0; 41];
    response[..32].copy_from_slice(&next.ticket);
    response[32..40].copy_from_slice(&next.generation.to_be_bytes());
    response[40] = resumed as u8;
    let mut msg = pool_message(&nonce, &request_bytes, &response);
    if low_latency {
        msg.extend_from_slice(&(public_bytes.len() as u64).to_be_bytes());
        msg.extend_from_slice(&public_bytes);
        msg.extend_from_slice(&(ferret_reply.len() as u64).to_be_bytes());
        msg.extend_from_slice(&ferret_reply);
    }
    let signature: Signature = key.sign(&msg);
    stream
        .write_all(key.verifying_key().to_encoded_point(true).as_bytes())
        .await?;
    stream.write_all(&signature.to_bytes()).await?;
    stream.write_all(&response).await?;
    if low_latency {
        crate::transport::write_frame(stream, &ferret_reply).await?;
    }
    stream.flush().await?;
    Ok(Some((
        PoolOpening {
            request: next,
            resumed,
            binding: Sha256::digest(&msg).into(),
            low_latency,
            proxy_open: setup.as_ref().and_then(|s| s.proxy.clone()),
            setup,
            ferret_reply,
        },
        cached,
    )))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod pool_tests {
    use super::*;
    use crate::setup_pool::{PoolCache, PoolRequest};
    use tokio_util::compat::TokioAsyncReadCompatExt;
    async fn opening(
        cache: &PoolCache<u8>,
        request: PoolRequest,
        pin: Option<&str>,
    ) -> Result<Option<PoolOpening>> {
        let (a, b) = tokio::io::duplex(4096);
        let (mut a, mut b) = (a.compat(), b.compat());
        let (client, server) = futures::join!(
            authenticate_pool(&mut a, pin, request),
            respond_pool(&mut b, &[7; 32], [9; 32], cache)
        );
        server?;
        client
    }
    #[tokio::test]
    async fn flow3_opening_authenticates_public_hello_and_protocol() {
        let cache = PoolCache::<u8>::new(2, std::time::Duration::from_secs(60));
        let (a, b) = tokio::io::duplex(4096);
        let (mut a, mut b) = (a.compat(), b.compat());
        let hello = ProxyOpen {
            host: "example.com".into(),
            client_hello: vec![1, 2, 3],
        };
        let (client, server) = futures::join!(
            authenticate_pool_open(&mut a, None, PoolRequest::default(), Some(hello)),
            respond_pool(&mut b, &[7; 32], [9; 32], &cache)
        );
        let client = client.unwrap().unwrap();
        let server = server.unwrap().unwrap().0;
        assert!(client.low_latency && server.low_latency);
        assert_eq!(client.binding, server.binding);
        assert_eq!(server.proxy_open.unwrap().host, "example.com");
        assert_eq!(client.proxy_open.unwrap().client_hello, [1, 2, 3]);
    }
    #[tokio::test]
    async fn flow3_authenticates_both_prefill_flights_and_budget() {
        let cache = PoolCache::<u8>::new(2, std::time::Duration::from_secs(60));
        let (a, b) = tokio::io::duplex(4096);
        let (mut a, mut b) = (a.compat(), b.compat());
        let setup = SetupOpen {
            proxy: None,
            budget: 3_500_000,
            ferret: vec![1, 2, 3],
        };
        let (client, server) = futures::join!(
            authenticate_pool_setup(&mut a, None, PoolRequest::default(), setup),
            respond_pool_with(&mut b, &[7; 32], [9; 32], &cache, |_, setup| {
                let setup = setup.as_ref().unwrap();
                assert_eq!(setup.budget, 3_500_000);
                assert_eq!(setup.ferret, [1, 2, 3]);
                Ok(vec![4, 5, 6])
            })
        );
        let client = client.unwrap().unwrap();
        let server = server.unwrap().unwrap().0;
        assert_eq!(client.ferret_reply, [4, 5, 6]);
        assert_eq!(client.binding, server.binding);
    }

    #[tokio::test]
    async fn cancellation_while_waiting_for_admission_burns_checked_out_state() {
        use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
        struct Tracked(Arc<AtomicBool>);
        impl Drop for Tracked {
            fn drop(&mut self) { self.0.store(true, Ordering::SeqCst); }
        }
        let cache = PoolCache::new(1, std::time::Duration::from_secs(60));
        let dropped = Arc::new(AtomicBool::new(false));
        let entered = Arc::new(AtomicBool::new(false));
        let old = PoolRequest::default();
        cache.put([9; 32], old, Tracked(dropped.clone()));
        let request = PoolRequest { generation: 1, ..old };
        let (a, b) = tokio::io::duplex(4096);
        let (mut a, mut b) = (a.compat(), b.compat());
        let setup = SetupOpen { proxy: None, budget: 1_000_000, ferret: vec![] };
        let entered_callback = entered.clone();
        let mut waiting = Box::pin(async {
            futures::join!(
                authenticate_pool_setup(&mut a, None, request, setup),
                respond_pool_with_async(&mut b, &[7; 32], [9; 32], &cache,
                    |cached, _| async move {
                        assert!(cached.is_some());
                        entered_callback.store(true, Ordering::SeqCst);
                        std::future::pending::<()>().await;
                        Ok((cached, vec![]))
                    })
            )
        });
        assert!(futures::poll!(&mut waiting).is_pending());
        assert!(entered.load(Ordering::SeqCst));
        assert!(!dropped.load(Ordering::SeqCst));
        assert!(cache.take([9; 32], request).is_none());
        drop(waiting);
        assert!(dropped.load(Ordering::SeqCst));
        assert!(cache.take([9; 32], request).is_none());
    }

    #[test]
    fn flow3_signature_binds_host_hello_and_marker() {
        let mut nonce = [3; 32];
        nonce[..8].copy_from_slice(FLOW_MAGIC);
        let request = PoolRequest::default().encode();
        let response = [0; 41];
        let hello = ProxyOpen {
            host: "example.com".into(),
            client_hello: vec![1, 2, 3],
        };
        let opening = bincode::serialize(&Some(SetupOpen {
            proxy: Some(hello),
            budget: 3_500_000,
            ferret: vec![9, 8, 7],
        }))
        .unwrap();
        let mut msg = pool_message(&nonce, &request, &response);
        msg.extend_from_slice(&(opening.len() as u64).to_be_bytes());
        msg.extend_from_slice(&opening);
        msg.extend_from_slice(&3u64.to_be_bytes());
        msg.extend_from_slice(&[4, 5, 6]);
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let sig: Signature = key.sign(&msg);
        for index in [
            msg.len() - 1,
            msg.len() - opening.len() + 9,
            b"zkfetch/notary-auth/pool/v1\0".len(),
        ] {
            let mut changed = msg.clone();
            changed[index] ^= 1;
            assert!(key.verifying_key().verify(&changed, &sig).is_err());
        }
    }
    #[tokio::test]
    async fn signed_opening_resumes_once_and_resets_stale_tickets() {
        let cache = PoolCache::new(2, std::time::Duration::from_secs(60));
        let r = PoolRequest {
            device: [1; 32],
            ..Default::default()
        };
        let first = opening(&cache, r, None).await.unwrap().unwrap();
        assert!(!first.resumed);
        cache.put([9; 32], first.request, 42);
        let next = PoolRequest {
            generation: 1,
            ..first.request
        };
        let warm = opening(&cache, next, None).await.unwrap().unwrap();
        assert!(warm.resumed);
        assert_ne!(first.binding, warm.binding);
        let replay = opening(&cache, next, None).await.unwrap().unwrap();
        assert!(!replay.resumed);
        assert_ne!(warm.request.ticket, replay.request.ticket);
    }
    #[tokio::test]
    async fn legacy_fallback_requires_a_valid_pinned_signature() {
        let (a, b) = tokio::io::duplex(4096);
        let (mut a, mut b) = (a.compat(), b.compat());
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let pin = hex::encode(key.verifying_key().to_encoded_point(true).as_bytes());
        let (client, server) = futures::join!(
            authenticate_pool(&mut a, Some(&pin), PoolRequest::default()),
            respond(&mut b, &[7; 32])
        );
        server.unwrap();
        assert!(client.unwrap().is_none());
        let other = SigningKey::from_slice(&[8; 32]).unwrap();
        let wrong = hex::encode(other.verifying_key().to_encoded_point(true).as_bytes());
        assert!(
            opening(
                &PoolCache::new(1, std::time::Duration::from_secs(60)),
                PoolRequest::default(),
                Some(&wrong)
            )
            .await
            .is_err()
        );
    }
    #[test]
    fn signature_binds_device_ticket_generation_and_freshness() {
        let nonce = [1; 32];
        let request = PoolRequest {
            device: [2; 32],
            ticket: [3; 32],
            generation: 42,
        }
        .encode();
        let mut response = [0; 41];
        response[..32].copy_from_slice(&[3; 32]);
        response[32..40].copy_from_slice(&42u64.to_be_bytes());
        response[40] = 1;
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let sig: Signature = key.sign(&pool_message(&nonce, &request, &response));
        for index in [0, 32, 71] {
            let mut changed = request;
            changed[index] ^= 1;
            assert!(
                key.verifying_key()
                    .verify(&pool_message(&nonce, &changed, &response), &sig)
                    .is_err()
            );
        }
        for index in [0, 39, 40] {
            let mut changed = response;
            changed[index] ^= 1;
            assert!(
                key.verifying_key()
                    .verify(&pool_message(&nonce, &request, &changed), &sig)
                    .is_err()
            );
        }
        assert!(
            key.verifying_key()
                .verify(&pool_message(&[5; 32], &request, &response), &sig)
                .is_err()
        );
    }
}
