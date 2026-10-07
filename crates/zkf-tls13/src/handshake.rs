//! Authenticate a minimal TLS_AES_128_GCM_SHA256 / P-256 handshake independently.
//! Callers must supply the actual joint client share and server share used by MPC.
use aes_gcm::{
    Aes128Gcm, KeyInit,
    aead::{Aead, Payload},
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use hmac::{Hmac, Mac};
use ring::digest::{SHA256, digest};
use sha2::Sha256;
use tls_core::{
    key::Certificate,
    msgs::{
        codec::{Codec, Reader},
        enums::{CipherSuite, Compression, NamedGroup, ProtocolVersion},
        handshake::{
            ConvertServerNameList, HandshakeMessagePayload, HandshakePayload, HasServerExtensions,
        },
    },
    verify::{ServerCertVerifier, construct_tls13_server_verify_message},
};

use crate::{
    HandshakeKeys,
    record::{self, ContentType, Sequence},
};

const MAX_HANDSHAKE_BYTES: usize = 128 * 1024;

fn message(bytes: &[u8]) -> Result<(HandshakeMessagePayload, usize)> {
    let mut reader = Reader::init(bytes);
    let msg = HandshakeMessagePayload::read_version(&mut reader, ProtocolVersion::TLSv1_3)
        .ok_or_else(|| anyhow!("malformed TLS 1.3 handshake message"))?;
    Ok((msg, reader.used()))
}

/// Values needed to bind the certificate to the MPC key exchange.
pub struct HelloBinding<'a> {
    pub client_hello: &'a [u8],
    pub server_hello: &'a [u8],
    pub joint_client_share: &'a [u8],
    pub server_share: &'a [u8],
    pub server_name: &'a str,
}

impl HelloBinding<'_> {
    /// Hash of the actual ClientHello || ServerHello supplied to the joint KDF.
    pub fn verify(&self) -> Result<[u8; 32]> {
        let (client, len) = message(self.client_hello)?;
        ensure!(len == self.client_hello.len(), "trailing ClientHello bytes");
        let HandshakePayload::ClientHello(client) = client.payload else {
            bail!("expected ClientHello");
        };
        let (server, len) = message(self.server_hello)?;
        ensure!(len == self.server_hello.len(), "trailing ServerHello bytes");
        let HandshakePayload::ServerHello(server) = server.payload else {
            bail!("HelloRetryRequest is unsupported");
        };
        ensure!(
            !client.has_duplicate_extension() && !server.has_duplicate_extension(),
            "duplicate hello extension"
        );
        ensure!(
            client.client_version == ProtocolVersion::TLSv1_2
                && server.legacy_version == ProtocolVersion::TLSv1_2,
            "invalid hello legacy version"
        );
        ensure!(
            client.get_versions_extension() == Some(&vec![ProtocolVersion::TLSv1_3]),
            "client must offer only TLS 1.3"
        );
        ensure!(
            server.get_supported_versions() == Some(ProtocolVersion::TLSv1_3),
            "TLS version mismatch"
        );
        ensure!(
            client.cipher_suites == [CipherSuite::TLS13_AES_128_GCM_SHA256]
                && server.cipher_suite == CipherSuite::TLS13_AES_128_GCM_SHA256,
            "unsupported cipher suite"
        );
        ensure!(
            client.compression_methods == [Compression::Null]
                && server.compression_method == Compression::Null,
            "unsupported compression"
        );
        ensure!(
            client.session_id.get_encoding() == server.session_id.get_encoding(),
            "session id mismatch"
        );
        ensure!(
            client.get_psk().is_none()
                && server.get_psk_index().is_none()
                && !client.early_data_extension_offered(),
            "PSK/early data are unsupported"
        );
        let names = client
            .get_sni_extension()
            .ok_or_else(|| anyhow!("missing SNI"))?;
        ensure!(!names.has_duplicate_names_for_type(), "duplicate SNI");
        ensure!(
            names
                .get_single_hostname()
                .is_some_and(|n| n.as_ref().eq_ignore_ascii_case(self.server_name)),
            "SNI mismatch"
        );
        let shares = client
            .get_keyshare_extension()
            .ok_or_else(|| anyhow!("missing client share"))?;
        ensure!(
            shares.len() == 1
                && shares[0].group == NamedGroup::secp256r1
                && shares[0].payload.0 == self.joint_client_share,
            "ClientHello does not contain joint MPC share"
        );
        let share = server
            .get_key_share()
            .ok_or_else(|| anyhow!("missing server share"))?;
        ensure!(
            share.group == NamedGroup::secp256r1 && share.payload.0 == self.server_share,
            "server share differs from MPC input"
        );
        p256::PublicKey::from_sec1_bytes(self.joint_client_share)
            .context("invalid joint P-256 share")?;
        p256::PublicKey::from_sec1_bytes(self.server_share)
            .context("invalid server P-256 share")?;
        let mut bytes = self.client_hello.to_vec();
        bytes.extend_from_slice(self.server_hello);
        Ok(digest(&SHA256, &bytes).as_ref().try_into()?)
    }
}

pub struct VerifiedHandshake {
    /// SHA256(ClientHello || ServerHello), bound into the MPC key schedule.
    pub hello_hash: [u8; 32],
    /// SHA256(transcript through server Finished), bound into the application KDF.
    pub application_hash: [u8; 32],
    pub cert_chain: Vec<Certificate>,
    /// The exact transcript before CertificateVerify, for later identity proofs.
    pub certificate_verify_transcript: Vec<u8>,
    pub certificate_verify: Vec<u8>,
    pub client_finished: Vec<u8>,
}

/// Decrypt handshake records with public handshake keys. Never use this for application records.
pub fn decrypt_server_records(keys: &HandshakeKeys, records: &[Vec<u8>]) -> Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(&keys.server_write_key)?;
    let mut sequence = Sequence::default();
    let mut plaintext = Vec::new();
    for wire in records {
        ensure!(wire.len() >= 5, "truncated handshake record header");
        let len = u16::from_be_bytes([wire[3], wire[4]]) as usize;
        ensure!(
            wire.len() == 5 + len && wire[..5] == record::aad(len)?,
            "invalid handshake record header"
        );
        let nonce = record::nonce(keys.server_iv, sequence.take()?);
        let inner = cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &wire[5..],
                    aad: &wire[..5],
                },
            )
            .map_err(|_| anyhow!("server handshake AEAD tag invalid"))?;
        let (typ, content) = record::decode_inner(&inner)?;
        ensure!(
            typ == ContentType::Handshake,
            "unexpected content during server handshake"
        );
        ensure!(
            plaintext.len() + content.len() <= MAX_HANDSHAKE_BYTES,
            "server handshake too large"
        );
        plaintext.extend_from_slice(content);
    }
    Ok(plaintext)
}

/// Independently check certificate chain, CertificateVerify and server Finished.
pub fn verify_server(
    hello: &HelloBinding<'_>,
    keys: &HandshakeKeys,
    records: &[Vec<u8>],
    verifier: &dyn ServerCertVerifier,
    time: std::time::SystemTime,
) -> Result<VerifiedHandshake> {
    let hello_hash = hello.verify()?;
    let server_handshake = decrypt_server_records(keys, records)?;
    let mut transcript = hello.client_hello.to_vec();
    transcript.extend_from_slice(hello.server_hello);
    let mut rest = server_handshake.as_slice();
    let mut cert_chain = Vec::new();
    let mut certificate_verify_transcript = Vec::new();
    let mut certificate_verify = Vec::new();
    for step in 0..4 {
        let (msg, used) = message(rest)?;
        let wire = &rest[..used];
        match (step, msg.payload) {
            (0, HandshakePayload::EncryptedExtensions(ext)) => {
                ensure!(
                    !ext.has_duplicate_extension(),
                    "duplicate EncryptedExtensions"
                );
            }
            (1, HandshakePayload::CertificateTLS13(cert)) => {
                ensure!(
                    cert.context.0.is_empty() && !cert.any_entry_has_duplicate_extension(),
                    "invalid certificate message"
                );
                cert_chain = cert.entries.into_iter().map(|e| e.cert).collect();
                let (leaf, intermediates) = cert_chain
                    .split_first()
                    .ok_or_else(|| anyhow!("empty certificate chain"))?;
                verifier.verify_server_cert(
                    leaf,
                    intermediates,
                    &hello.server_name.try_into()?,
                    &mut std::iter::empty(),
                    &[],
                    time,
                )?;
            }
            (2, HandshakePayload::CertificateVerify(sig)) => {
                let hash = digest(&SHA256, &transcript);
                verifier.verify_tls13_signature(
                    &construct_tls13_server_verify_message(&hash),
                    &cert_chain[0],
                    &sig,
                )?;
                certificate_verify_transcript = transcript.clone();
                certificate_verify = wire.to_vec();
            }
            (3, HandshakePayload::Finished(finished)) => {
                let hash = digest(&SHA256, &transcript);
                let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&keys.server_finished_key)?;
                mac.update(hash.as_ref());
                mac.verify_slice(&finished.0)
                    .map_err(|_| anyhow!("server Finished invalid"))?;
            }
            _ => bail!("unexpected server handshake message at step {step}"),
        }
        transcript.extend_from_slice(wire);
        rest = &rest[used..];
    }
    ensure!(
        rest.is_empty(),
        "extra server handshake messages after Finished"
    );
    let application_hash: [u8; 32] = digest(&SHA256, &transcript).as_ref().try_into()?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&keys.client_finished_key)?;
    mac.update(&application_hash);
    let mut client_finished = vec![20, 0, 0, 32];
    client_finished.extend_from_slice(&mac.finalize().into_bytes());
    Ok(VerifiedHandshake {
        hello_hash,
        application_hash,
        cert_chain,
        certificate_verify_transcript,
        certificate_verify,
        client_finished,
    })
}
