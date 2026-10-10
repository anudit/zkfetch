//! TLS 1.3 proxy mode (zkfetch patch P4).
//!
//! The verifier relays the prover's TLS 1.3 connection and records every byte.
//! The prover runs a normal TLS_AES_128_GCM_SHA256 / P-256 client and, after
//! the connection closes, proves the TLS 1.3 key schedule in zero knowledge:
//!
//! 1. The ECDHE shared secret is a private prover input to the key schedule.
//! 2. `H(ClientHello || ServerHello)` is computed by each side from the
//!    observed plaintext hellos. The handshake traffic secrets are decoded to
//!    both parties (as in TLS 1.3 MPC-TLS): application secrets derive from the
//!    handshake secret, not from these.
//! 3. Each side decrypts the encrypted handshake it observed with the public
//!    handshake keys. The server records' AEAD tags only verify under the
//!    server's real handshake key, which binds the private shared secret to the
//!    server's key exchange. The server Finished MAC is checked, which binds
//!    the transcript. Each side computes `H(ClientHello ..= server Finished)`.
//! 4. Application keys stay inside the VM; their IVs are decoded (not secret).
//!    Application records use the TLS 1.2-style nonce `iv[0..4] ||
//!    (iv[4..12] XOR seq)`, so tag and suffix proofs apply unchanged.
//! 5. The prover discloses each application-epoch record's suffix (inner
//!    content type and padding, or the whole non-application record); the
//!    suffixes are proven against the ciphertext during proving.
//!
//! The certificate chain and CertificateVerify signature are bound offline by
//! `CertBindingV1_3`, as for TLS 1.3 MPC-TLS. Only fresh full handshakes are
//! supported: no PSK, 0-RTT, HelloRetryRequest or key updates.

use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, NewAead, Payload, generic_array::GenericArray},
};
use cipher::{Cipher, aes::Aes128};
use hmac::{Hmac, Mac};
use mpc_tls::SessionKeys;
use mpz_common::Context;
use mpz_memory_core::{
    Array, DecodeFutureTyped, MemoryExt, Vector, ViewExt,
    binary::{Binary, U8},
};
use mpz_vm_core::{Execute, Vm};
use serio::{SinkExt, stream::IoStreamExt};
use sha2::{Digest, Sha256};
use tls_core::msgs::{
    codec::Reader,
    enums::{CipherSuite, Compression, ContentType as TlsContentType, NamedGroup, ProtocolVersion},
    handshake::{HandshakeMessagePayload, HandshakePayload, HasServerExtensions},
    message::OpaqueMessage,
};
use tls13_schedule::{HandshakeKeys, Mode, OrigoClaim, OrigoSchedule, Role, Tls13KeySched};
use tlsn_core::{
    connection::{
        CertBinding, CertBindingV1_3, KeyType, ServerEphemKey, ServerSignature, SignatureAlgorithm,
        TlsVersion,
    },
    transcript::{ContentType, Record, TlsTranscript},
    webpki::CertificateDer,
};

use crate::{Error as TlsnError, TlsOutput, proxy::alloc_ghash_key};
use mpz_core::bitvec::BitVec;

const TAG_LEN: usize = 16;
const MAX_CONTENT: usize = 16384;
const MAX_HANDSHAKE_BYTES: usize = 128 * 1024;

fn err(msg: impl Into<String>) -> TlsnError {
    TlsnError::internal().with_msg(msg.into())
}

fn peer(msg: impl Into<String>) -> TlsnError {
    TlsnError::user().with_msg(msg.into())
}

fn vm_err(e: impl std::error::Error + Send + Sync + 'static) -> TlsnError {
    TlsnError::internal().with_source(e)
}

type IvFuture = DecodeFutureTyped<BitVec, [u8; 12]>;

/// VM state shared by the TLS 1.3 proxy prover and verifier.
struct Schedule {
    ks: Option<Tls13KeySched>,
    origo: Option<OrigoSchedule>,
    origo_claim: Option<OrigoClaim>,
    pms: Option<Array<U8, 32>>,
    keys: SessionKeys,
    civ: IvFuture,
    siv: IvFuture,
}

fn iv_prefix(iv: Array<U8, 12>) -> Array<U8, 4> {
    Vector::<U8>::from(iv)
        .get(0..4)
        .expect("12 > 4")
        .try_into()
        .expect("length is 4")
}

impl Schedule {
    fn alloc(
        vm: &mut dyn Vm<Binary>,
        prover: bool,
        origo_enabled: bool,
    ) -> Result<Self, TlsnError> {
        let (ks, pms, origo, app) = if origo_enabled {
            let origo = OrigoSchedule::alloc(vm, prover).map_err(vm_err)?;
            let app = origo.keys;
            (None, None, Some(origo), app)
        } else {
            let pms: Array<U8, 32> = vm.alloc().map_err(vm_err)?;
            if prover {
                vm.mark_private(pms).map_err(vm_err)?;
            } else {
                vm.mark_blind(pms).map_err(vm_err)?;
            }
            let role = if prover { Role::Leader } else { Role::Follower };
            let mut ks = Tls13KeySched::new(Mode::Normal, role);
            ks.alloc(vm, pms).map_err(vm_err)?;
            let app = ks.application_key_refs().map_err(vm_err)?;
            (Some(ks), Some(pms), None, app)
        };

        let mut encrypt = Aes128::default();
        encrypt.set_key(app.client_write_key);
        encrypt.set_iv(iv_prefix(app.client_iv));
        let mut decrypt = Aes128::default();
        decrypt.set_key(app.server_write_key);
        decrypt.set_iv(iv_prefix(app.server_iv));
        let server_write_mac_key = alloc_ghash_key(vm, &mut decrypt)?;

        let civ = vm.decode(app.client_iv).map_err(vm_err)?;
        let siv = vm.decode(app.server_iv).map_err(vm_err)?;

        Ok(Self {
            ks,
            origo,
            origo_claim: None,
            pms,
            keys: SessionKeys {
                client_write_key: app.client_write_key,
                client_write_iv: iv_prefix(app.client_iv),
                server_write_key: app.server_write_key,
                server_write_iv: iv_prefix(app.server_iv),
                server_write_mac_key,
            },
            civ,
            siv,
        })
    }

    /// Assigns the whole key schedule from the observed hello hash and the
    /// prover's claimed handshake hash, then runs it in one VM execution.
    /// Returns the revealed handshake keys and the application IVs.
    async fn run<V: Vm<Binary> + Execute + Send>(
        &mut self,
        vm: &mut V,
        ctx: &mut Context,
        hello_hash: [u8; 32],
        handshake_hash: [u8; 32],
        shared_secret: Option<[u8; 32]>,
    ) -> Result<(HandshakeKeys, [u8; 12], [u8; 12]), TlsnError> {
        self.assign(vm, hello_hash, handshake_hash, shared_secret)?;
        vm.execute_all(ctx).await.map_err(vm_err)?;
        self.finish()
    }

    fn assign<V: Vm<Binary>>(
        &mut self,
        vm: &mut V,
        hello_hash: [u8; 32],
        handshake_hash: [u8; 32],
        shared_secret: Option<[u8; 32]>,
    ) -> Result<(), TlsnError> {
        if let Some(mut secret) = shared_secret {
            use zeroize::Zeroize;
            let result = vm
                .assign(self.pms.expect("normal schedule"), secret)
                .map_err(vm_err);
            secret.zeroize();
            result?;
        }
        vm.commit(self.pms.expect("normal schedule"))
            .map_err(vm_err)?;
        self.ks
            .as_mut()
            .expect("normal schedule")
            .assign_all(vm, hello_hash, handshake_hash)
            .map_err(vm_err)?;
        Ok(())
    }

    fn assign_origo<V: Vm<Binary>>(
        &mut self,
        vm: &mut V,
        claim: OrigoClaim,
        handshake_hash: [u8; 32],
        mut witness: Option<[u8; 32]>,
    ) -> Result<(), TlsnError> {
        use zeroize::Zeroize;
        let result = self
            .origo
            .as_mut()
            .expect("ORIGO schedule")
            .assign(vm, &claim, handshake_hash, witness)
            .map_err(vm_err);
        witness.zeroize();
        result?;
        self.origo_claim = Some(claim);
        Ok(())
    }

    fn finish(&mut self) -> Result<(HandshakeKeys, [u8; 12], [u8; 12]), TlsnError> {
        let hs_keys = if let Some(origo) = &mut self.origo {
            let claim = self.origo_claim.as_ref().expect("ORIGO assigned");
            origo.verify(claim).map_err(vm_err)?;
            let (client, server) = claim.handshake_secrets();
            native_handshake_keys(&client, &server)
        } else {
            self.ks
                .as_mut()
                .expect("normal schedule")
                .finish_all()
                .map_err(vm_err)?
                .0
        };

        let civ = self
            .civ
            .try_recv()
            .map_err(vm_err)?
            .ok_or_else(|| err("client application IV not decoded"))?;
        let siv = self
            .siv
            .try_recv()
            .map_err(vm_err)?
            .ok_or_else(|| err("server application IV not decoded"))?;
        Ok((hs_keys, civ, siv))
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct PublicKeys {
    client_write_key: [u8; 16],
    server_write_key: [u8; 16],
    client_iv: [u8; 12],
    server_iv: [u8; 12],
    client_finished_key: [u8; 32],
    server_finished_key: [u8; 32],
    civ: [u8; 12],
    siv: [u8; 12],
    origo: OrigoClaim,
}
impl PublicKeys {
    fn new(keys: HandshakeKeys, civ: [u8; 12], siv: [u8; 12], origo: OrigoClaim) -> Self {
        let HandshakeKeys {
            client_write_key,
            server_write_key,
            client_iv,
            server_iv,
            client_finished_key,
            server_finished_key,
        } = keys;
        Self {
            client_write_key,
            server_write_key,
            client_iv,
            server_iv,
            client_finished_key,
            server_finished_key,
            civ,
            siv,
            origo,
        }
    }
    fn handshake(&self) -> HandshakeKeys {
        HandshakeKeys {
            client_write_key: self.client_write_key,
            server_write_key: self.server_write_key,
            client_iv: self.client_iv,
            server_iv: self.server_iv,
            client_finished_key: self.client_finished_key,
            server_finished_key: self.server_finished_key,
        }
    }
}
/// Deferred equality check between disclosed handshake keys/IVs and the VM's
/// key-schedule outputs. No attestation may be issued before this succeeds.
pub(crate) struct ScheduleProof {
    schedule: Schedule,
    claimed: PublicKeys,
}
impl ScheduleProof {
    pub(crate) fn verify(mut self) -> Result<(), TlsnError> {
        let (keys, civ, siv) = self.schedule.finish()?;
        if keys != self.claimed.handshake() || civ != self.claimed.civ || siv != self.claimed.siv {
            return Err(peer("disclosed TLS keys differ from proven key schedule"));
        }
        Ok(())
    }
}

/// Raw TLS records in both directions, as relayed.
pub(crate) struct Traffic {
    sent: Vec<OpaqueMessage>,
    recv: Vec<OpaqueMessage>,
}

struct Hello {
    client_hello: Vec<u8>,
    server_hello: Vec<u8>,
    server_share: Vec<u8>,
    hash: [u8; 32],
    /// Index of the first record after the plaintext hellos.
    sent_next: usize,
    recv_next: usize,
}

struct Handshake {
    application_hash: [u8; 32],
    /// ClientHello ..= Certificate, signed by CertificateVerify.
    handshake_messages: Vec<u8>,
    cert_chain: Vec<CertificateDer>,
    signature: ServerSignature,
    server_share: Vec<u8>,
    /// Index of the first application-epoch record.
    sent_app: usize,
    recv_app: usize,
}

fn parse_records(bytes: &[u8]) -> Result<Vec<OpaqueMessage>, TlsnError> {
    let mut reader = Reader::init(bytes);
    let mut records = Vec::new();
    while reader.any_left() {
        records.push(
            OpaqueMessage::read(&mut reader)
                .map_err(|e| peer(format!("malformed TLS record: {e:?}")))?,
        );
    }
    Ok(records)
}

fn handshake_message(bytes: &[u8]) -> Result<(HandshakeMessagePayload, usize), TlsnError> {
    let mut reader = Reader::init(bytes);
    let msg = HandshakeMessagePayload::read_version(&mut reader, ProtocolVersion::TLSv1_3)
        .ok_or_else(|| peer("malformed TLS 1.3 handshake message"))?;
    Ok((msg, reader.used()))
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn nonce(iv: [u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = iv;
    for (n, s) in nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
        *n ^= s;
    }
    nonce
}

fn aad(len: usize) -> [u8; 5] {
    [0x17, 0x03, 0x03, (len >> 8) as u8, len as u8]
}

/// Opens one TLS 1.3 record and returns the inner plaintext (content type
/// byte and padding included).
fn open(
    key: [u8; 16],
    iv: [u8; 12],
    seq: u64,
    record: &OpaqueMessage,
) -> Result<Vec<u8>, TlsnError> {
    let payload = &record.payload.0;
    if record.typ != TlsContentType::ApplicationData
        || !(TAG_LEN + 1..=MAX_CONTENT + 256).contains(&payload.len())
    {
        return Err(peer("malformed TLS 1.3 protected record"));
    }
    Aes128Gcm::new(GenericArray::from_slice(&key))
        .decrypt(
            GenericArray::from_slice(&nonce(iv, seq)),
            Payload {
                msg: payload,
                aad: &aad(payload.len()),
            },
        )
        .map_err(|_| peer("TLS 1.3 record authentication failed"))
}

/// Splits a TLS 1.3 inner plaintext into its content type, content and
/// public suffix (type byte plus padding, or the whole non-application
/// plaintext).
fn split_inner(inner: &[u8]) -> Result<(TlsContentType, usize, Vec<u8>), TlsnError> {
    let end = inner
        .iter()
        .rposition(|b| *b != 0)
        .ok_or_else(|| peer("TLS 1.3 record has no content type"))?;
    if end > MAX_CONTENT {
        return Err(peer("TLS 1.3 record content exceeds limit"));
    }
    let typ = TlsContentType::from(inner[end]);
    match typ {
        TlsContentType::ApplicationData => Ok((typ, end, inner[end..].to_vec())),
        TlsContentType::Alert | TlsContentType::Handshake => Ok((typ, end, inner.to_vec())),
        typ => Err(peer(format!(
            "unexpected TLS 1.3 inner content type {typ:?}"
        ))),
    }
}

/// HKDF-Expand-Label (RFC 8446 7.1) for outputs of at most 32 bytes.
pub(crate) fn hkdf_expand_label(secret: &[u8], label: &[u8], len: usize) -> Vec<u8> {
    let mut info = (len as u16).to_be_bytes().to_vec();
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    info.push(1);
    hmac(secret, &info)[..len].to_vec()
}

/// Handshake keys derived natively from the traffic secrets (prover only).
fn native_handshake_keys(client: &[u8; 32], server: &[u8; 32]) -> HandshakeKeys {
    let k = |s: &[u8; 32], l: &[u8], n| hkdf_expand_label(s, l, n);
    HandshakeKeys {
        client_write_key: k(client, b"key", 16).try_into().expect("16 bytes"),
        client_iv: k(client, b"iv", 12).try_into().expect("12 bytes"),
        server_write_key: k(server, b"key", 16).try_into().expect("16 bytes"),
        server_iv: k(server, b"iv", 12).try_into().expect("12 bytes"),
        client_finished_key: k(client, b"finished", 32).try_into().expect("32 bytes"),
        server_finished_key: k(server, b"finished", 32).try_into().expect("32 bytes"),
    }
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn signature_alg(
    scheme: tls_core::msgs::enums::SignatureScheme,
) -> Result<SignatureAlgorithm, TlsnError> {
    use tls_core::msgs::enums::SignatureScheme as S;
    Ok(match scheme {
        S::ECDSA_NISTP256_SHA256 => SignatureAlgorithm::ECDSA_NISTP256_SHA256,
        S::ECDSA_NISTP384_SHA384 => SignatureAlgorithm::ECDSA_NISTP384_SHA384,
        S::ED25519 => SignatureAlgorithm::ED25519,
        S::RSA_PSS_SHA256 => SignatureAlgorithm::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        S::RSA_PSS_SHA384 => SignatureAlgorithm::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        S::RSA_PSS_SHA512 => SignatureAlgorithm::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        scheme => {
            return Err(peer(format!(
                "unsupported TLS 1.3 signature scheme {scheme:?}"
            )));
        }
    })
}

/// Skips TLS 1.3 middlebox-compatibility ChangeCipherSpec records.
fn skip_ccs(records: &[OpaqueMessage], mut idx: usize) -> usize {
    while records
        .get(idx)
        .is_some_and(|r| r.typ == TlsContentType::ChangeCipherSpec && r.payload.0 == [1])
    {
        idx += 1;
    }
    idx
}

impl Traffic {
    pub(crate) fn parse(sent: &[u8], recv: &[u8]) -> Result<Self, TlsnError> {
        Ok(Self {
            sent: parse_records(sent)?,
            recv: parse_records(recv)?,
        })
    }

    /// Reads a plaintext handshake message, possibly fragmented over several
    /// records.
    fn plaintext_message(
        records: &[OpaqueMessage],
        mut idx: usize,
    ) -> Result<(Vec<u8>, usize), TlsnError> {
        let mut buf = Vec::new();
        loop {
            let record = records
                .get(idx)
                .ok_or_else(|| peer("truncated plaintext handshake"))?;
            if record.typ != TlsContentType::Handshake {
                return Err(peer("expected a plaintext handshake record"));
            }
            buf.extend_from_slice(&record.payload.0);
            idx += 1;
            if buf.len() >= 4 {
                let len = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
                if buf.len() == 4 + len {
                    return Ok((buf, idx));
                }
                if buf.len() > 4 + len {
                    return Err(peer("plaintext handshake record carries extra messages"));
                }
            }
        }
    }

    fn validate_sni(&self, expected: &str) -> Result<(), TlsnError> {
        use tls_core::msgs::handshake::ConvertServerNameList;
        let (hello, _) = Self::plaintext_message(&self.sent, 0)?;
        let (message, used) = handshake_message(&hello)?;
        let HandshakePayload::ClientHello(client) = message.payload else {
            return Err(peer("first sent message is not ClientHello"));
        };
        if used != hello.len() || client.has_duplicate_extension() {
            return Err(peer("invalid ClientHello"));
        }
        let names = client
            .get_sni_extension()
            .ok_or_else(|| peer("ClientHello has no SNI"))?;
        if names.has_duplicate_names_for_type() || names.len() != 1 {
            return Err(peer("ClientHello must have one SNI name"));
        }
        let name = names
            .get_single_hostname()
            .ok_or_else(|| peer("invalid SNI hostname"))?;
        if !name.as_ref().eq_ignore_ascii_case(expected) {
            return Err(peer("ClientHello SNI does not match the dialed server"));
        }
        Ok(())
    }

    fn hello(&self) -> Result<Hello, TlsnError> {
        let (client_hello, sent_next) = Self::plaintext_message(&self.sent, 0)?;
        let (server_hello, recv_next) = Self::plaintext_message(&self.recv, 0)?;

        let (client, _) = handshake_message(&client_hello)?;
        let HandshakePayload::ClientHello(client) = client.payload else {
            return Err(peer("first sent message is not a ClientHello"));
        };
        let (server, _) = handshake_message(&server_hello)?;
        let HandshakePayload::ServerHello(server) = server.payload else {
            return Err(peer("HelloRetryRequest is not supported in proxy mode"));
        };

        if client.has_duplicate_extension() || server.has_duplicate_extension() {
            return Err(peer("duplicate hello extension"));
        }
        if server.get_supported_versions() != Some(ProtocolVersion::TLSv1_3)
            || server.legacy_version != ProtocolVersion::TLSv1_2
        {
            return Err(peer("server did not negotiate TLS 1.3"));
        }
        if server.cipher_suite != CipherSuite::TLS13_AES_128_GCM_SHA256
            || server.compression_method != Compression::Null
        {
            return Err(peer("unsupported TLS 1.3 cipher suite"));
        }
        if client.get_psk().is_some()
            || server.get_psk_index().is_some()
            || client.early_data_extension_offered()
        {
            return Err(peer("PSK and early data are not supported in proxy mode"));
        }
        let shares = client
            .get_keyshare_extension()
            .ok_or_else(|| peer("ClientHello has no key share"))?;
        if shares.len() != 1 || shares[0].group != NamedGroup::secp256r1 {
            return Err(peer("ClientHello must offer exactly one P-256 key share"));
        }
        let share = server
            .get_key_share()
            .ok_or_else(|| peer("ServerHello has no key share"))?;
        if share.group != NamedGroup::secp256r1 || share.payload.0.len() != 65 {
            return Err(peer("server key share is not P-256"));
        }

        let hash = sha256(&[&client_hello, &server_hello]);
        Ok(Hello {
            server_share: share.payload.0.clone(),
            client_hello,
            server_hello,
            hash,
            sent_next,
            recv_next,
        })
    }

    /// Decrypts the handshake messages of one direction, possibly spread
    /// over several records, and returns them with the index of the first
    /// record after the last one.
    fn decrypt_handshake(
        records: &[OpaqueMessage],
        start: usize,
        key: [u8; 16],
        iv: [u8; 12],
        mut done: impl FnMut(&HandshakeMessagePayload) -> bool,
    ) -> Result<(Vec<(HandshakeMessagePayload, Vec<u8>)>, usize), TlsnError> {
        let mut idx = skip_ccs(records, start);
        let mut seq = 0u64;
        let mut buf = Vec::new();
        let mut total = 0;
        let mut messages = Vec::new();
        loop {
            while let Ok((msg, used)) = handshake_message(&buf) {
                let wire: Vec<u8> = buf.drain(..used).collect();
                let last = done(&msg);
                messages.push((msg, wire));
                if last {
                    if !buf.is_empty() {
                        return Err(peer("extra handshake data after Finished"));
                    }
                    return Ok((messages, idx));
                }
            }
            let record = records
                .get(idx)
                .ok_or_else(|| peer("truncated TLS 1.3 handshake"))?;
            let inner = open(key, iv, seq, record)?;
            seq += 1;
            idx += 1;
            let (typ, end, _) = split_inner(&inner)?;
            if typ != TlsContentType::Handshake {
                return Err(peer("unexpected record during the TLS 1.3 handshake"));
            }
            total += end;
            if total > MAX_HANDSHAKE_BYTES {
                return Err(peer("TLS 1.3 handshake too large"));
            }
            buf.extend_from_slice(&inner[..end]);
        }
    }

    /// Decrypts and checks the handshake epoch in both directions.
    fn handshake(&self, hello: &Hello, keys: &HandshakeKeys) -> Result<Handshake, TlsnError> {
        let is_finished =
            |m: &HandshakeMessagePayload| matches!(m.payload, HandshakePayload::Finished(_));

        // Server flight: EncryptedExtensions, [CertificateRequest],
        // Certificate, CertificateVerify, Finished.
        let (server_msgs, recv_app) = Self::decrypt_handshake(
            &self.recv,
            hello.recv_next,
            keys.server_write_key,
            keys.server_iv,
            is_finished,
        )?;
        let mut transcript = [hello.client_hello.as_slice(), &hello.server_hello].concat();
        let mut handshake_messages = Vec::new();
        let mut cert_chain = Vec::new();
        let mut signature = None;
        let mut step = 0;
        for (msg, wire) in server_msgs {
            let typ = msg.typ;
            step = match (step, msg.payload) {
                (0, HandshakePayload::EncryptedExtensions(ext)) => {
                    if ext.has_duplicate_extension() {
                        return Err(peer("duplicate EncryptedExtensions"));
                    }
                    1
                }
                (1, HandshakePayload::CertificateRequestTLS13(_)) => 2,
                (1 | 2, HandshakePayload::CertificateTLS13(cert)) => {
                    if !cert.context.0.is_empty() {
                        return Err(peer("unexpected certificate request context"));
                    }
                    cert_chain = cert
                        .entries
                        .into_iter()
                        .map(|e| CertificateDer(e.cert.0))
                        .collect();
                    if cert_chain.is_empty() {
                        return Err(peer("empty certificate chain"));
                    }
                    handshake_messages = [transcript.as_slice(), &wire].concat();
                    3
                }
                (3, HandshakePayload::CertificateVerify(sig)) => {
                    signature = Some(ServerSignature {
                        alg: signature_alg(sig.scheme)?,
                        sig: sig.sig.0,
                    });
                    4
                }
                (4, HandshakePayload::Finished(finished)) => {
                    let expected = hmac(&keys.server_finished_key, &sha256(&[&transcript]));
                    if finished.0 != expected {
                        return Err(peer("server Finished is invalid"));
                    }
                    5
                }
                _ => {
                    return Err(peer(format!(
                        "unexpected server handshake message {typ:?} at step {step}"
                    )));
                }
            };
            transcript.extend_from_slice(&wire);
        }
        if step != 5 {
            return Err(peer("incomplete server handshake"));
        }
        let application_hash = sha256(&[&transcript]);

        // Client flight: [Certificate, [CertificateVerify]], Finished.
        let (client_msgs, sent_app) = Self::decrypt_handshake(
            &self.sent,
            hello.sent_next,
            keys.client_write_key,
            keys.client_iv,
            is_finished,
        )?;
        for (msg, wire) in client_msgs {
            match msg.payload {
                HandshakePayload::CertificateTLS13(_) | HandshakePayload::CertificateVerify(_) => {}
                HandshakePayload::Finished(finished) => {
                    let expected = hmac(&keys.client_finished_key, &sha256(&[&transcript]));
                    if finished.0 != expected {
                        return Err(peer("client Finished is invalid"));
                    }
                }
                _ => return Err(peer("unexpected client handshake message")),
            }
            transcript.extend_from_slice(&wire);
        }

        Ok(Handshake {
            application_hash,
            handshake_messages,
            cert_chain,
            signature: signature.ok_or_else(|| peer("missing CertificateVerify"))?,
            server_share: hello.server_share.clone(),
            sent_app,
            recv_app,
        })
    }

    /// Application-epoch records with TLS 1.2-style explicit nonces.
    fn app_records(
        records: &[OpaqueMessage],
        start: usize,
        iv: [u8; 12],
    ) -> Result<Vec<Record>, TlsnError> {
        records[start.min(records.len())..]
            .iter()
            .enumerate()
            .map(|(seq, record)| {
                let payload = &record.payload.0;
                if record.typ != TlsContentType::ApplicationData
                    || !(TAG_LEN + 1..=MAX_CONTENT + 256).contains(&payload.len())
                {
                    return Err(peer("malformed TLS 1.3 application record"));
                }
                let seq = seq as u64;
                Ok(Record {
                    seq,
                    typ: ContentType::ApplicationData,
                    plaintext: None,
                    explicit_nonce: nonce(iv, seq)[4..].to_vec(),
                    ciphertext: payload[..payload.len() - TAG_LEN].to_vec(),
                    tag: Some(payload[payload.len() - TAG_LEN..].to_vec()),
                    suffix: Vec::new(),
                })
            })
            .collect()
    }
}

/// The prover's own key share, from the ClientHello it sent.
pub(crate) fn client_key_share(tls_sent: &[u8]) -> Result<Vec<u8>, TlsnError> {
    let traffic = Traffic::parse(tls_sent, &[])?;
    let (client_hello, _) = Traffic::plaintext_message(&traffic.sent, 0)?;
    let (client, _) = handshake_message(&client_hello)?;
    let HandshakePayload::ClientHello(client) = client.payload else {
        return Err(peer("first sent message is not a ClientHello"));
    };
    let shares = client
        .get_keyshare_extension()
        .ok_or_else(|| peer("ClientHello has no key share"))?;
    match shares.as_slice() {
        [share] => Ok(share.payload.0.clone()),
        _ => Err(peer("ClientHello must offer exactly one key share")),
    }
}

/// Validates a disclosed suffix against its record and applies it.
fn apply_suffixes(records: &mut [Record], suffixes: Vec<Vec<u8>>) -> Result<(), TlsnError> {
    if records.len() != suffixes.len() {
        return Err(peer("TLS 1.3 record suffix count mismatch"));
    }
    for (record, suffix) in records.iter_mut().zip(suffixes) {
        let len = record.ciphertext.len();
        if suffix.is_empty() || suffix.len() > len {
            return Err(peer("invalid TLS 1.3 record suffix length"));
        }
        let end = suffix
            .iter()
            .rposition(|b| *b != 0)
            .ok_or_else(|| peer("TLS 1.3 record suffix has no content type"))?;
        let typ = TlsContentType::from(suffix[end]);
        match typ {
            TlsContentType::ApplicationData if end == 0 && len - suffix.len() <= MAX_CONTENT => {
                if let Some(plaintext) = record.plaintext.as_mut() {
                    let content_len = len - suffix.len();
                    if plaintext.len() != len || plaintext[content_len..] != suffix {
                        return Err(peer("TLS 1.3 record suffix does not match plaintext"));
                    }
                    plaintext.truncate(content_len);
                }
            }
            TlsContentType::Alert | TlsContentType::Handshake
                if suffix.len() == len && end <= MAX_CONTENT =>
            {
                if record.plaintext.as_ref().is_some_and(|p| *p != suffix) {
                    return Err(peer("TLS 1.3 record suffix does not match plaintext"));
                }
                record.plaintext = Some(suffix[..end].to_vec());
            }
            _ => return Err(peer("malformed TLS 1.3 record suffix")),
        }
        record.typ = typ.into();
        record.suffix = suffix;
    }
    Ok(())
}

/// Sent by the prover before the key schedule runs, so the schedule needs a
/// single VM execution. The verifier checks the hash against the handshake
/// it decrypts and the suffixes in the proving phase.
#[derive(serde::Serialize, serde::Deserialize)]
struct Claim {
    handshake_hash: [u8; 32],
    sent: Vec<Vec<u8>>,
    recv: Vec<Vec<u8>>,
}

fn build_transcript(
    time: u64,
    handshake: Handshake,
    sent: Vec<Record>,
    recv: Vec<Record>,
) -> Result<TlsTranscript, TlsnError> {
    TlsTranscript::builder()
        .time(time)
        .version(TlsVersion::V1_3)
        .server_signature(handshake.signature)
        .server_cert_chain(handshake.cert_chain)
        .certificate_binding(CertBinding::V1_3(CertBindingV1_3 {
            handshake_messages: handshake.handshake_messages,
            server_ephemeral_key: ServerEphemKey {
                typ: KeyType::SECP256R1,
                key: handshake.server_share,
            },
        }))
        .records_sent(sent)
        .records_recv(recv)
        .build()
        .map_err(|e| err("could not build TLS 1.3 transcript").with_source(e))
}

/// TLS 1.3 proxy prover.
pub(crate) struct ProxyProver13<V> {
    ctx: Context,
    vm: V,
    schedule: Option<Schedule>,
    deferred: bool,
    ready: Option<crate::vole_pool::PrefillReady>,
    begin_proof: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

/// Secrets the prover's TLS client exposes for TLS 1.3 proxy mode.
pub(crate) struct Tls13ClientSecrets {
    /// ECDHE shared secret (P-256 x-coordinate).
    pub(crate) shared_secret: [u8; 32],
    /// Handshake traffic secrets, client then server.
    pub(crate) client_hs: [u8; 32],
    pub(crate) server_hs: [u8; 32],
    /// Application traffic key and IV, client then server.
    pub(crate) client_app: ([u8; 16], [u8; 12]),
    pub(crate) server_app: ([u8; 16], [u8; 12]),
}

impl Drop for Tls13ClientSecrets {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.shared_secret.zeroize();
        self.client_hs.zeroize();
        self.server_hs.zeroize();
        self.client_app.0.zeroize();
        self.client_app.1.zeroize();
        self.server_app.0.zeroize();
        self.server_app.1.zeroize();
    }
}

impl<V: Vm<Binary> + Execute + Send + crate::deps::StatementBinding> ProxyProver13<V> {
    pub(crate) fn new(
        vm: V,
        ctx: Context,
        deferred: bool,
        ready: Option<crate::vole_pool::PrefillReady>,
        begin_proof: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
    ) -> Self {
        Self {
            ctx,
            vm,
            schedule: None,
            deferred,
            ready,
            begin_proof,
        }
    }

    pub(crate) fn alloc(&mut self) -> Result<(), TlsnError> {
        self.schedule = Some(Schedule::alloc(&mut self.vm, true, self.deferred)?);
        Ok(())
    }

    pub(crate) async fn preprocess(&mut self) -> Result<(), TlsnError> {
        self.vm
            .flush(&mut self.ctx)
            .await
            .map_err(|e| err("preprocessing proxy-tls failed").with_source(e))
    }

    pub(crate) async fn finalize(
        mut self,
        secrets: Tls13ClientSecrets,
        time: u64,
        tls_sent: &[u8],
        tls_recv: &[u8],
    ) -> Result<(Context, V, TlsOutput), TlsnError> {
        if let Some(ready) = self.ready.take() {
            ready.await.map_err(err)?;
        }
        if let Some(begin) = self.begin_proof.take() {
            begin();
        }
        if self.deferred {
            self.vm.bind_statement(tls_sent);
            self.vm.bind_statement(tls_recv);
        }
        let traffic = Traffic::parse(tls_sent, tls_recv)?;
        let hello = traffic.hello()?;
        let native_keys = native_handshake_keys(&secrets.client_hs, &secrets.server_hs);
        let handshake = traffic.handshake(&hello, &native_keys)?;
        let (civ, siv) = (secrets.client_app.1, secrets.server_app.1);

        let records = |raw: &[OpaqueMessage], start: usize, (key, iv): ([u8; 16], [u8; 12])| {
            let mut records = Traffic::app_records(raw, start, iv)?;
            let mut suffixes = Vec::with_capacity(records.len());
            for (record, raw) in records.iter_mut().zip(raw.get(start..).unwrap_or(&[])) {
                let inner = open(key, iv, record.seq, raw)?;
                suffixes.push(split_inner(&inner)?.2);
                record.plaintext = Some(inner);
            }
            Ok::<_, TlsnError>((records, suffixes))
        };
        let (mut sent, sent_suffixes) =
            records(&traffic.sent, handshake.sent_app, secrets.client_app)?;
        let (mut recv, recv_suffixes) =
            records(&traffic.recv, handshake.recv_app, secrets.server_app)?;

        let claim = Claim {
            handshake_hash: handshake.application_hash,
            sent: sent_suffixes.clone(),
            recv: recv_suffixes.clone(),
        };
        if self.deferred {
            self.vm
                .bind_statement(&bincode::serialize(&claim).map_err(vm_err)?);
        }
        self.ctx
            .io_mut()
            .send(claim)
            .await
            .map_err(|e| err("failed to send TLS 1.3 claim").with_source(e))?;

        let mut schedule = self.schedule.take().expect("schedule allocated");
        let keys = schedule.keys.clone();
        let deferred_schedule = if self.deferred {
            let (origo, mut witness) = OrigoClaim::preprocess(
                &secrets.shared_secret,
                hello.hash,
                handshake.application_hash,
            );
            let claimed = PublicKeys::new(native_keys, civ, siv, origo);
            self.vm
                .bind_statement(&bincode::serialize(&claimed).map_err(vm_err)?);
            self.ctx
                .io_mut()
                .send(claimed.clone())
                .await
                .map_err(|e| err("failed to send public TLS keys").with_source(e))?;
            let result = schedule.assign_origo(
                &mut self.vm,
                claimed.origo.clone(),
                handshake.application_hash,
                Some(witness),
            );
            {
                use zeroize::Zeroize;
                witness.zeroize();
            }
            result?;
            Some(ScheduleProof { schedule, claimed })
        } else {
            let (hs_keys, proven_civ, proven_siv) = schedule
                .run(
                    &mut self.vm,
                    &mut self.ctx,
                    hello.hash,
                    handshake.application_hash,
                    Some(secrets.shared_secret),
                )
                .await?;
            if hs_keys != native_keys || proven_civ != civ || proven_siv != siv {
                return Err(err("proven TLS 1.3 keys differ from the TLS client's"));
            }

            None
        };

        #[cfg(feature = "d1-experimental")]
        let epoch_ciphertext = crate::ApplicationEpochCiphertext {
            sent: traffic.sent[handshake.sent_app..].iter().cloned().map(OpaqueMessage::encode).collect(),
            received: traffic.recv[handshake.recv_app..].iter().cloned().map(OpaqueMessage::encode).collect(),
            iv_client: civ, iv_server: siv, hello_hash: hello.hash,
            application_hash: handshake.application_hash,
        };
        apply_suffixes(&mut sent, sent_suffixes)?;
        apply_suffixes(&mut recv, recv_suffixes)?;
        let tls_transcript = build_transcript(time, handshake, sent, recv)?;
        tracing::info!("Proxy TLS 1.3 done");
        Ok((
            self.ctx,
            self.vm,
            TlsOutput {
                #[cfg(feature = "d1-experimental")]
                epoch_ciphertext: Some(epoch_ciphertext),
                #[cfg(feature = "d1-experimental")]
                native_keys: Some(crate::ApplicationKeySecrets::new(secrets.client_app.0, secrets.server_app.0)),
                keys,
                tls_transcript,
                deferred_schedule,
            },
        ))
    }
}

/// TLS 1.3 proxy verifier.
pub(crate) struct ProxyVerifier13<V> {
    ctx: Context,
    vm: V,
    schedule: Option<Schedule>,
    deferred: bool,
    ready: Option<crate::vole_pool::PrefillReady>,
}

impl<V: Vm<Binary> + Execute + Send + crate::deps::StatementBinding> ProxyVerifier13<V> {
    pub(crate) fn new(
        vm: V,
        ctx: Context,
        deferred: bool,
        ready: Option<crate::vole_pool::PrefillReady>,
    ) -> Self {
        Self {
            ctx,
            vm,
            schedule: None,
            deferred,
            ready,
        }
    }

    pub(crate) fn alloc(&mut self) -> Result<(), TlsnError> {
        self.schedule = Some(Schedule::alloc(&mut self.vm, false, self.deferred)?);
        Ok(())
    }

    pub(crate) async fn preprocess(&mut self) -> Result<(), TlsnError> {
        self.vm
            .flush(&mut self.ctx)
            .await
            .map_err(|e| err("preprocessing proxy-tls failed").with_source(e))
    }

    pub(crate) async fn finalize(
        mut self,
        tls_sent: &[u8],
        tls_recv: &[u8],
        time: u64,
    ) -> Result<(Context, V, TlsOutput), TlsnError> {
        if let Some(ready) = self.ready.take() {
            ready.await.map_err(err)?;
        }
        if self.deferred {
            self.vm.bind_statement(tls_sent);
            self.vm.bind_statement(tls_recv);
        }
        let traffic = Traffic::parse(tls_sent, tls_recv)?;
        let hello = traffic.hello()?;
        let claim: Claim = self
            .ctx
            .io_mut()
            .expect_next()
            .await
            .map_err(|e| err("failed to receive TLS 1.3 claim").with_source(e))?;

        if self.deferred {
            self.vm
                .bind_statement(&bincode::serialize(&claim).map_err(vm_err)?);
        }
        let mut schedule = self.schedule.take().expect("schedule allocated");
        let keys = schedule.keys.clone();
        let (hs_keys, civ, siv, deferred_schedule) = if self.deferred {
            let claimed: PublicKeys = self
                .ctx
                .io_mut()
                .expect_next()
                .await
                .map_err(|e| err("missing public TLS keys").with_source(e))?;
            self.vm
                .bind_statement(&bincode::serialize(&claimed).map_err(vm_err)?);
            schedule.assign_origo(
                &mut self.vm,
                claimed.origo.clone(),
                claim.handshake_hash,
                None,
            )?;
            let public = (claimed.handshake(), claimed.civ, claimed.siv);
            (
                public.0,
                public.1,
                public.2,
                Some(ScheduleProof { schedule, claimed }),
            )
        } else {
            let (hs_keys, civ, siv) = schedule
                .run(
                    &mut self.vm,
                    &mut self.ctx,
                    hello.hash,
                    claim.handshake_hash,
                    None,
                )
                .await?;

            (hs_keys, civ, siv, None)
        };

        // The application keys were derived from the claimed hash; it must be
        // the hash of the handshake the verifier relayed and now decrypts.
        let handshake = traffic.handshake(&hello, &hs_keys)?;
        if handshake.application_hash != claim.handshake_hash {
            return Err(peer(
                "claimed TLS 1.3 handshake hash does not match the relayed handshake",
            ));
        }

        let mut sent = Traffic::app_records(&traffic.sent, handshake.sent_app, civ)?;
        let mut recv = Traffic::app_records(&traffic.recv, handshake.recv_app, siv)?;
        #[cfg(feature = "d1-experimental")]
        let epoch_ciphertext = crate::ApplicationEpochCiphertext {
            sent: traffic.sent[handshake.sent_app..].iter().cloned().map(OpaqueMessage::encode).collect(),
            received: traffic.recv[handshake.recv_app..].iter().cloned().map(OpaqueMessage::encode).collect(),
            iv_client: civ, iv_server: siv, hello_hash: hello.hash,
            application_hash: handshake.application_hash,
        };
        apply_suffixes(&mut sent, claim.sent)?;
        apply_suffixes(&mut recv, claim.recv)?;

        let tls_transcript = build_transcript(time, handshake, sent, recv)?;
        tracing::info!("Proxy-TLS 1.3 done");
        Ok((
            self.ctx,
            self.vm,
            TlsOutput {
                #[cfg(feature = "d1-experimental")]
                epoch_ciphertext: Some(epoch_ciphertext),
                #[cfg(feature = "d1-experimental")]
                native_keys: None,
                keys,
                tls_transcript,
                deferred_schedule,
            },
        ))
    }
}

pub(crate) fn validate_sni(sent: &[u8], expected: &str) -> Result<(), TlsnError> {
    Traffic {
        sent: parse_records(sent)?,
        recv: Vec::new(),
    }
    .validate_sni(expected)
}

/// Validates the entire public TLS 1.3 ClientHello before it leaves the notary.
pub(crate) fn validate_open(sent: &[u8], expected: &str) -> Result<(), TlsnError> {
    if sent.len() > 16 * 1024 {
        return Err(peer("ClientHello too large"));
    }
    let records = parse_records(sent)?;
    let (wire, used_records) = Traffic::plaintext_message(&records, 0)?;
    if used_records != records.len() {
        return Err(peer("extra records in public opening"));
    }
    let (message, used) = handshake_message(&wire)?;
    let HandshakePayload::ClientHello(client) = message.payload else {
        return Err(peer("expected ClientHello"));
    };
    if used != wire.len()
        || client.has_duplicate_extension()
        || client.get_psk().is_some()
        || client.early_data_extension_offered()
    {
        return Err(peer("unsupported ClientHello policy"));
    }
    let versions = client
        .extensions
        .iter()
        .find_map(|ext| match ext {
            tls_core::msgs::handshake::ClientExtension::SupportedVersions(v) => Some(v),
            _ => None,
        })
        .ok_or_else(|| peer("missing TLS versions"))?;
    if !versions.contains(&ProtocolVersion::TLSv1_3) {
        return Err(peer("opening requires TLS 1.3"));
    }
    if client
        .extensions
        .iter()
        .any(|ext| ext.get_type().get_u16() == 0xfe0d)
    {
        return Err(peer("ECH is not supported"));
    }
    let shares = client
        .get_keyshare_extension()
        .ok_or_else(|| peer("missing key share"))?;
    if shares.len() != 1
        || shares[0].group != NamedGroup::secp256r1
        || shares[0].payload.0.len() != 65
    {
        return Err(peer("opening requires one P-256 share"));
    }
    Traffic {
        sent: records,
        recv: Vec::new(),
    }
    .validate_sni(expected)
}
