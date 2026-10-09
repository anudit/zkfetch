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
}
/// Authenticates the notary and negotiates a pool in the same exchange.
/// `None` means the authenticated peer speaks the legacy opening; reconnect
/// with fresh OT. No correlations have been used at this point.
pub async fn authenticate_pool<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    expected: Option<&str>,
    request: crate::setup_pool::PoolRequest,
) -> Result<Option<PoolOpening>> {
    use sha2::{Digest, Sha256};
    let started = web_time::Instant::now();
    let mut nonce = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce[..8].copy_from_slice(POOL_MAGIC);
    let request_bytes = request.encode();
    stream.write_all(&nonce).await?;
    stream.write_all(&request_bytes).await?;
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
    let msg = pool_message(&nonce, &request_bytes, &response);
    key.verify(&msg, &Signature::from_slice(&reply[33..])?)?;
    let generation = u64::from_be_bytes(response[32..40].try_into().unwrap());
    let ticket: [u8; 32] = response[..32].try_into().unwrap();
    let resumed = response[40] == 1;
    ensure!(
        !resumed || (generation == request.generation && ticket == request.ticket),
        "invalid resumed pool index"
    );
    ensure!(resumed || generation == 0, "invalid fresh pool index");
    tracing::info!(target: "zkfetch::setup", step = "notary_key_challenge", elapsed_ms = started.elapsed().as_secs_f64() * 1e3, sent_bytes = 104, received_bytes = 138, resumed, "setup sub-step");
    Ok(Some(PoolOpening {
        request: crate::setup_pool::PoolRequest {
            device: request.device,
            ticket,
            generation,
        },
        resumed,
        binding: Sha256::digest(&msg).into(),
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
    use sha2::{Digest, Sha256};
    let mut nonce = [0; 32];
    stream.read_exact(&mut nonce).await?;
    let key = SigningKey::from_slice(secret)?;
    if &nonce[..8] != POOL_MAGIC {
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
    let cached = cache.take(scope, request);
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
    let msg = pool_message(&nonce, &request_bytes, &response);
    let signature: Signature = key.sign(&msg);
    stream
        .write_all(key.verifying_key().to_encoded_point(true).as_bytes())
        .await?;
    stream.write_all(&signature.to_bytes()).await?;
    stream.write_all(&response).await?;
    stream.flush().await?;
    Ok(Some((
        PoolOpening {
            request: next,
            resumed,
            binding: Sha256::digest(&msg).into(),
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
