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
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    stream.write_all(&nonce).await?;
    stream.flush().await?;
    let mut reply = [0u8; 97];
    stream.read_exact(&mut reply).await?;
    check(&nonce, &reply, expected)
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
