//! TLS 1.3 MPC-TLS leader and follower (zkfetch patch).
//!
//! Protocol (prover = leader P, verifier = follower V):
//!
//! 1. Preprocessing as in TLS 1.2: P-256 key-exchange shares, record layer
//!    and the TLS 1.3 key schedule are allocated before the connection.
//! 2. ClientHello carries the joint key share. On ServerHello, P sends V the
//!    server key share and `H(ClientHello || ServerHello)`; both run the key
//!    exchange and the handshake stage of the key schedule. The handshake
//!    traffic secrets are decoded to both parties (GtP §4.3): application
//!    secrets derive from the handshake secret, not from these.
//! 3. The encrypted server flight and the client Finished are processed
//!    locally by P with the handshake keys. P sends V `H(ClientHello ..=
//!    server Finished)`; both derive the application keys, which stay inside
//!    the VM. The application IVs are decoded (they are not secret).
//! 4. Application records go through the MPC record layer. Each TLS 1.3
//!    nonce `iv XOR seq` is expressed as `iv[0..4] || explicit_nonce` so the
//!    TLS 1.2 AES-GCM machinery and transcript proofs apply unchanged.
//! 5. After the connection closes, P discloses each application-epoch
//!    record's suffix (inner content type and padding, or the whole plaintext
//!    for non-application records). The suffixes are proven against the
//!    ciphertext in zero knowledge during the proving phase.
//!
//! Soundness of the server's data does not depend on V checking the server
//! flight: application data authenticates only under keys derived from the
//! joint ECDH with the server's ephemeral key, which only the server knows the
//! private half of. The certificate is bound to that key offline through the
//! TLS 1.3 CertificateVerify (see `tlsn_core::connection::CertBindingV1_3`).

use std::collections::VecDeque;

use aes_gcm::{
    Aes128Gcm,
    aead::{AeadInPlace, NewAead, generic_array::GenericArray},
};
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use key_exchange::{self as ke, KeyExchange, MpcKeyExchange};
use mpz_common::{Context, Flush};
use mpz_core::{Block, bitvec::BitVec};
use mpz_memory_core::{Array, DecodeFutureTyped, MemoryExt, Vector, binary::U8};
use mpz_ole::{Receiver as OLEReceiver, Sender as OLESender};
use mpz_ot::{
    rcot::{RCOTReceiver, RCOTSender},
    rot::{
        any::{AnyReceiver, AnySender},
        randomize::{RandomizeRCOTReceiver, RandomizeRCOTSender},
    },
};
use mpz_share_conversion::{ShareConversionReceiver, ShareConversionSender};
use serio::{SinkExt, stream::IoStreamExt};
use sha2::Sha256;
use tls_client::{
    Backend, BackendError, BackendNotifier, BackendNotify, DecryptMode as ClientDecryptMode,
    EncryptMode as ClientEncryptMode,
};
use tls_core::{
    cert::ServerCertDetails,
    ke::ServerKxDetails,
    key::{Certificate, PublicKey},
    msgs::{
        base::Payload,
        enums::{CipherSuite, ContentType, NamedGroup, ProtocolVersion, SignatureScheme},
        handshake::{DigitallySignedStruct, Random},
        message::{OpaqueMessage, PlainMessage},
    },
    suites::SupportedCipherSuite,
};
use tls13_schedule::{Mode, Role as KsRole, Tls13KeySched};
use tlsn_core::{
    connection::{CertBinding, CertBindingV1_3, ServerSignature, SignatureAlgorithm, TlsVersion},
    transcript::{Record, TlsTranscript},
    webpki::CertificateDer,
};
use tracing::{debug, instrument};

use crate::{
    Config, MpcTlsError, Role, SessionKeys, Vm,
    msg::{Decrypt, Encrypt, Message, StartHandshake},
    record_layer::{DecryptMode, EncryptMode, RecordLayer, aead::MpcAesGcm},
    utils::check_close_notify,
};

/// Maximum handshake time difference in seconds.
const MAX_TIME_DIFF: u64 = 5;
const TAG_LEN: usize = 16;

type ApplicationIvFutures = (
    DecodeFutureTyped<BitVec, [u8; 12]>,
    DecodeFutureTyped<BitVec, [u8; 12]>,
);

fn ks_mode(config: &Config) -> Mode {
    match config.prf {
        hmac_sha256::NetworkMode::Normal => Mode::Normal,
        hmac_sha256::NetworkMode::Reduced => Mode::Reduced,
    }
}

/// First 4 bytes of a 12-byte IV reference: the TLS 1.2-style fixed IV.
fn iv_prefix(iv: Array<U8, 12>) -> Array<U8, 4> {
    Vector::<U8>::from(iv)
        .get(0..4)
        .expect("12 > 4")
        .try_into()
        .expect("length is 4")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn signature_alg(scheme: SignatureScheme) -> Result<SignatureAlgorithm, MpcTlsError> {
    Ok(match scheme {
        SignatureScheme::ECDSA_NISTP256_SHA256 => SignatureAlgorithm::ECDSA_NISTP256_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384 => SignatureAlgorithm::ECDSA_NISTP384_SHA384,
        SignatureScheme::ED25519 => SignatureAlgorithm::ED25519,
        SignatureScheme::RSA_PSS_SHA256 => SignatureAlgorithm::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        SignatureScheme::RSA_PSS_SHA384 => SignatureAlgorithm::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        SignatureScheme::RSA_PSS_SHA512 => SignatureAlgorithm::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        scheme => {
            return Err(MpcTlsError::hs(format!(
                "unsupported TLS 1.3 signature scheme: {scheme:?}"
            )));
        }
    })
}

/// Splits a TLS 1.3 inner plaintext into its inner content type, content
/// length and public suffix.
pub(crate) fn split_inner(plaintext: &[u8]) -> Result<(ContentType, usize, Vec<u8>), MpcTlsError> {
    let end = plaintext
        .iter()
        .rposition(|b| *b != 0)
        .ok_or_else(|| MpcTlsError::peer("TLS 1.3 record has no content type"))?;
    let typ = ContentType::from(plaintext[end]);
    if end > 16384 {
        return Err(MpcTlsError::peer("TLS 1.3 record content exceeds limit"));
    }
    match typ {
        ContentType::ApplicationData => Ok((typ, end, plaintext[end..].to_vec())),
        ContentType::Alert | ContentType::Handshake => Ok((typ, end, plaintext.to_vec())),
        typ => Err(MpcTlsError::peer(format!(
            "unexpected TLS 1.3 inner content type: {typ:?}"
        ))),
    }
}

/// Validates a disclosed suffix against its record and returns the inner
/// content type and, for non-application records, the disclosed content.
pub(crate) fn parse_suffix(
    suffix: &[u8],
    ciphertext_len: usize,
) -> Result<(ContentType, Option<Vec<u8>>), MpcTlsError> {
    if suffix.is_empty() || suffix.len() > ciphertext_len || ciphertext_len > 16384 + 256 - TAG_LEN
    {
        return Err(MpcTlsError::peer("invalid TLS 1.3 record suffix length"));
    }
    let end = suffix
        .iter()
        .rposition(|b| *b != 0)
        .ok_or_else(|| MpcTlsError::peer("TLS 1.3 record suffix has no content type"))?;
    let typ = ContentType::from(suffix[end]);
    match typ {
        ContentType::ApplicationData if end == 0 && ciphertext_len - suffix.len() <= 16384 => {
            Ok((typ, None))
        }
        ContentType::Alert | ContentType::Handshake
            if suffix.len() == ciphertext_len && end <= 16384 =>
        {
            Ok((typ, Some(suffix[..end].to_vec())))
        }
        _ => Err(MpcTlsError::peer("malformed TLS 1.3 record suffix")),
    }
}

/// Applies disclosed suffixes to committed records.
fn apply_suffixes(records: &mut [Record], suffixes: Vec<Vec<u8>>) -> Result<(), MpcTlsError> {
    if records.len() != suffixes.len() {
        return Err(MpcTlsError::peer("TLS 1.3 record suffix count mismatch"));
    }
    for (record, suffix) in records.iter_mut().zip(suffixes) {
        let (typ, content) = parse_suffix(&suffix, record.ciphertext.len())?;
        record.typ = typ.into();
        if let Some(content) = content {
            record.plaintext = Some(content);
        } else if let Some(plaintext) = record.plaintext.as_mut() {
            // Only the content belongs to the application data transcript.
            let content_len = record.ciphertext.len() - suffix.len();
            if plaintext.len() != record.ciphertext.len() || plaintext[content_len..] != suffix {
                return Err(MpcTlsError::peer(
                    "TLS 1.3 record suffix does not match plaintext",
                ));
            }
            plaintext.truncate(content_len);
        }
        record.suffix = suffix;
    }
    Ok(())
}

/// Local AES-128-GCM record protection for the handshake epoch, whose keys are
/// known to both parties.
struct LocalAead {
    cipher: Aes128Gcm,
    iv: [u8; 12],
    seq: u64,
}

impl LocalAead {
    fn new(key: [u8; 16], iv: [u8; 12]) -> Self {
        Self {
            cipher: Aes128Gcm::new(GenericArray::from_slice(&key)),
            iv,
            seq: 0,
        }
    }

    fn nonce(&mut self) -> Result<[u8; 12], MpcTlsError> {
        let mut nonce = self.iv;
        for (n, s) in nonce[4..].iter_mut().zip(self.seq.to_be_bytes()) {
            *n ^= s;
        }
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| MpcTlsError::record_layer("TLS 1.3 sequence exhausted"))?;
        Ok(nonce)
    }

    fn seal(&mut self, typ: ContentType, content: &[u8]) -> Result<OpaqueMessage, MpcTlsError> {
        if content.len() > 16384 {
            return Err(MpcTlsError::peer("TLS 1.3 record content exceeds limit"));
        }
        let mut buf = content.to_vec();
        buf.push(typ.get_u8());
        let aad = crate::record_layer::tls13_aad(buf.len());
        let nonce = self.nonce()?;
        let tag = self
            .cipher
            .encrypt_in_place_detached(GenericArray::from_slice(&nonce), &aad, &mut buf)
            .map_err(|_| MpcTlsError::hs("handshake record encryption failed"))?;
        buf.extend_from_slice(&tag);
        Ok(OpaqueMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(buf),
        })
    }

    fn open(&mut self, msg: OpaqueMessage) -> Result<PlainMessage, MpcTlsError> {
        if msg.typ != ContentType::ApplicationData || msg.version != ProtocolVersion::TLSv1_2 {
            return Err(MpcTlsError::peer(
                "unexpected record type in TLS 1.3 handshake",
            ));
        }
        let mut buf = msg.payload.0;
        if !(TAG_LEN + 1..=16384 + 256).contains(&buf.len()) {
            return Err(MpcTlsError::peer("invalid TLS 1.3 record length"));
        }
        let tag = buf.split_off(buf.len() - TAG_LEN);
        let aad = crate::record_layer::tls13_aad(buf.len());
        let nonce = self.nonce()?;
        self.cipher
            .decrypt_in_place_detached(
                GenericArray::from_slice(&nonce),
                &aad,
                &mut buf,
                GenericArray::from_slice(&tag),
            )
            .map_err(|_| MpcTlsError::peer("handshake record failed to authenticate"))?;
        let (typ, content_len, _) = split_inner(&buf)?;
        buf.truncate(content_len);
        Ok(PlainMessage {
            typ,
            version: ProtocolVersion::TLSv1_3,
            payload: Payload::new(buf),
        })
    }
}

/// The handshake epoch keys and buffers on the leader.
#[derive(Default)]
struct HandshakeEpoch {
    enc: Option<LocalAead>,
    dec: Option<LocalAead>,
    client_finished_key: Option<[u8; 32]>,
    server_finished_key: Option<[u8; 32]>,
    outgoing: VecDeque<OpaqueMessage>,
    incoming: VecDeque<PlainMessage>,
}

/// TLS 1.3 MPC-TLS leader.
pub(crate) struct Tls13Leader {
    config: Config,
    ctx: Option<Context>,
    vm: Option<Vm>,
    ke: Option<Box<dyn KeyExchange + Send + Sync + 'static>>,
    ks: Tls13KeySched,
    record_layer: Option<RecordLayer>,
    notifier: BackendNotifier,
    is_decrypting: bool,

    client_random: Random,
    time: Option<u64>,
    server_key: Option<PublicKey>,
    iv_futs: Option<ApplicationIvFutures>,
    hs: HandshakeEpoch,
    encrypt_app: bool,
    decrypt_app: bool,
    traffic: bool,
    app_stage_done: bool,
    binding: Option<(Vec<Certificate>, Vec<u8>, DigitallySignedStruct)>,
    closed: Option<TlsTranscript>,
}

impl std::fmt::Debug for Tls13Leader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tls13Leader").finish_non_exhaustive()
    }
}

impl Tls13Leader {
    pub(crate) fn new<CS, CR>(
        config: Config,
        ctx: Context,
        vm: Vm,
        cot_send: (CS, CS, CS),
        cot_recv: CR,
    ) -> Self
    where
        CS: RCOTSender<Block> + Flush + Send + Sync + 'static,
        CR: RCOTReceiver<bool, Block> + Flush + Send + Sync + 'static,
    {
        let mut rng = rand::rng();
        let ke = Box::new(MpcKeyExchange::new(
            ke::Role::Leader,
            ShareConversionSender::new(OLESender::new(
                Block::random(&mut rng),
                AnySender::new(RandomizeRCOTSender::new(cot_send.0)),
            )),
            ShareConversionReceiver::new(OLEReceiver::new(AnyReceiver::new(
                RandomizeRCOTReceiver::new(cot_recv),
            ))),
        )) as Box<dyn KeyExchange + Send + Sync>;
        let encrypter = MpcAesGcm::new(
            ShareConversionSender::new(OLESender::new(
                Block::random(&mut rng),
                AnySender::new(RandomizeRCOTSender::new(cot_send.1)),
            )),
            Role::Leader,
        );
        let decrypter = MpcAesGcm::new(
            ShareConversionSender::new(OLESender::new(
                Block::random(&mut rng),
                AnySender::new(RandomizeRCOTSender::new(cot_send.2)),
            )),
            Role::Leader,
        );
        let mut record_layer = RecordLayer::new(Role::Leader, encrypter, decrypter);
        record_layer.enable_tls13();
        let is_decrypting = !config.defer_decryption;
        let ks = Tls13KeySched::new(ks_mode(&config), KsRole::Leader);

        Self {
            config,
            ctx: Some(ctx),
            vm: Some(vm),
            ke: Some(ke),
            ks,
            record_layer: Some(record_layer),
            notifier: BackendNotifier::new(),
            is_decrypting,
            client_random: Random::new().expect("rng is available"),
            time: None,
            server_key: None,
            iv_futs: None,
            hs: HandshakeEpoch::default(),
            encrypt_app: false,
            decrypt_app: false,
            traffic: false,
            app_stage_done: false,
            binding: None,
            closed: None,
        }
    }

    fn ctx(&mut self) -> Result<&mut Context, MpcTlsError> {
        self.ctx
            .as_mut()
            .ok_or_else(|| MpcTlsError::state("connection is finished"))
    }

    pub(crate) fn alloc(&mut self) -> Result<SessionKeys, MpcTlsError> {
        let mut vm = self
            .vm
            .as_ref()
            .expect("VM available")
            .clone()
            .try_lock_owned()
            .map_err(|_| MpcTlsError::other("VM lock is held"))?;
        let pms = self
            .ke
            .as_mut()
            .expect("key exchange available")
            .alloc(&mut (*vm))?;
        alloc_common(
            &mut (*vm),
            &self.config,
            pms,
            &mut self.ks,
            self.record_layer.as_mut().expect("record layer available"),
            &mut self.iv_futs,
        )
    }

    pub(crate) async fn preprocess(&mut self) -> Result<(), MpcTlsError> {
        let vm = self.vm.as_ref().expect("VM available").clone();
        let ctx = self
            .ctx
            .as_mut()
            .ok_or_else(|| MpcTlsError::state("connection is finished"))?;
        let ke = self
            .ke
            .take()
            .ok_or_else(|| MpcTlsError::state("preprocessing already started"))?;
        let record_layer = self
            .record_layer
            .take()
            .ok_or_else(|| MpcTlsError::state("preprocessing already started"))?;
        let (ke, record_layer) = preprocess_common(ctx, vm, ke, record_layer).await?;
        self.ke = Some(ke);
        self.record_layer = Some(record_layer);
        Ok(())
    }

    pub(crate) fn is_decrypting(&self) -> bool {
        self.is_decrypting
    }

    /// Runs the handshake stage of the key schedule and installs the local
    /// handshake-epoch ciphers.
    async fn handshake_stage(&mut self, hello_hash: [u8; 32]) -> Result<(), MpcTlsError> {
        let key = self
            .server_key
            .clone()
            .ok_or_else(|| MpcTlsError::hs("server key share not set"))?;
        let vm = self.vm.as_ref().expect("VM available").clone();
        let ctx = self
            .ctx
            .as_mut()
            .ok_or_else(|| MpcTlsError::state("connection is finished"))?;
        ctx.io_mut()
            .send(Message::Tls13ServerHello(Tls13ServerHello {
                server_key: key.clone(),
                hello_hash,
            }))
            .await?;
        run_handshake_stage(
            ctx,
            vm,
            self.ke.as_mut().expect("key exchange available"),
            &mut self.ks,
            &key,
            hello_hash,
        )
        .await?;

        let keys = self.ks.handshake_keys().map_err(MpcTlsError::hs)?;
        self.hs.enc = Some(LocalAead::new(keys.client_write_key, keys.client_iv));
        self.hs.dec = Some(LocalAead::new(keys.server_write_key, keys.server_iv));
        self.hs.client_finished_key = Some(keys.client_finished_key);
        self.hs.server_finished_key = Some(keys.server_finished_key);
        Ok(())
    }

    #[instrument(name = "close_connection", level = "debug", skip_all, err)]
    async fn close_connection(&mut self) -> Result<(), MpcTlsError> {
        if self.closed.is_some() {
            return Ok(());
        }
        let vm = self.vm.as_ref().expect("VM available").clone();
        let ctx = self
            .ctx
            .as_mut()
            .ok_or_else(|| MpcTlsError::state("connection is finished"))?;
        ctx.io_mut().send(Message::CloseConnection).await?;
        let (mut sent, mut recv) = self
            .record_layer
            .as_mut()
            .expect("record layer available")
            .commit(ctx, vm)
            .await?;

        // Disclose each record's suffix (inner type + padding, or the whole
        // non-application record) and strip it from the plaintext.
        let suffixes = |records: &[Record]| -> Result<Vec<Vec<u8>>, MpcTlsError> {
            records
                .iter()
                .map(|r| {
                    let plaintext = r
                        .plaintext
                        .as_ref()
                        .ok_or_else(|| MpcTlsError::other("leader must know all plaintext"))?;
                    Ok(split_inner(plaintext)?.2)
                })
                .collect()
        };
        let sent_suffixes = suffixes(&sent)?;
        let recv_suffixes = suffixes(&recv)?;
        ctx.io_mut()
            .send(Message::Tls13Suffixes(Tls13Suffixes {
                sent: sent_suffixes.clone(),
                recv: recv_suffixes.clone(),
            }))
            .await?;
        apply_suffixes(&mut sent, sent_suffixes)?;
        apply_suffixes(&mut recv, recv_suffixes)?;

        if !self
            .record_layer
            .as_ref()
            .expect("record layer available")
            .is_empty()
        {
            self.notifier.set();
        }

        let (certs, handshake_messages, sig) = self
            .binding
            .clone()
            .ok_or_else(|| MpcTlsError::hs("server certificate was not received"))?;
        let server_key = self
            .server_key
            .clone()
            .ok_or_else(|| MpcTlsError::hs("server key share not set"))?;
        let time = self
            .time
            .ok_or_else(|| MpcTlsError::hs("time is not set"))?;

        let transcript = TlsTranscript::builder()
            .time(time)
            .version(TlsVersion::V1_3)
            .server_signature(ServerSignature {
                alg: signature_alg(sig.scheme)?,
                sig: sig.sig.0.clone(),
            })
            .server_cert_chain(certs.iter().map(|c| CertificateDer(c.0.clone())).collect())
            .certificate_binding(CertBinding::V1_3(CertBindingV1_3 {
                handshake_messages,
                server_ephemeral_key: server_key
                    .try_into()
                    .map_err(|_| MpcTlsError::hs("unsupported server key"))?,
            }))
            .records_sent(sent)
            .records_recv(recv)
            .build()
            .map_err(MpcTlsError::other)?;

        check_close_notify(transcript.sent())?;
        check_close_notify(transcript.recv())?;

        self.closed = Some(transcript);
        Ok(())
    }
}

/// Allocation shared by leader and follower.
fn alloc_common(
    vm: &mut dyn mpz_vm_core::Vm<mpz_memory_core::binary::Binary>,
    config: &Config,
    pms: ke::Pms,
    ks: &mut Tls13KeySched,
    record_layer: &mut RecordLayer,
    iv_futs: &mut Option<ApplicationIvFutures>,
) -> Result<SessionKeys, MpcTlsError> {
    ks.alloc(vm, pms).map_err(MpcTlsError::alloc)?;
    let keys = ks.application_key_refs().map_err(MpcTlsError::alloc)?;
    let (client_iv, server_iv) = (iv_prefix(keys.client_iv), iv_prefix(keys.server_iv));
    record_layer.set_keys(
        keys.client_write_key,
        client_iv,
        keys.server_write_key,
        server_iv,
    )?;
    // Application IVs are not secret; both parties learn them to form nonces.
    *iv_futs = Some((
        vm.decode(keys.client_iv).map_err(MpcTlsError::alloc)?,
        vm.decode(keys.server_iv).map_err(MpcTlsError::alloc)?,
    ));
    let server_write_mac_key = record_layer.alloc(
        vm,
        config.max_sent_records,
        config.max_recv_records_online,
        config.max_sent,
        config.max_recv_online,
        config.max_recv,
    )?;
    Ok(SessionKeys {
        client_write_key: keys.client_write_key,
        client_write_iv: client_iv,
        server_write_key: keys.server_write_key,
        server_write_iv: server_iv,
        server_write_mac_key,
    })
}

async fn preprocess_common(
    ctx: &mut Context,
    vm: Vm,
    mut ke: Box<dyn KeyExchange + Send + Sync + 'static>,
    mut record_layer: RecordLayer,
) -> Result<(Box<dyn KeyExchange + Send + Sync + 'static>, RecordLayer), MpcTlsError> {
    let mut vm = vm
        .try_lock_owned()
        .map_err(|_| MpcTlsError::other("VM lock is held"))?;
    // Match the TLS 1.2 context tree on both peers. OT setup for the key
    // exchange depends on the shared VM progressing at the same time.
    let (ke, record_layer, _) = ctx
        .try_join3(
            move |ctx| {
                Box::pin(async move {
                    ke.setup(ctx).await.map_err(MpcTlsError::preprocess)?;
                    Ok::<_, MpcTlsError>(ke)
                })
            },
            move |ctx| {
                Box::pin(async move {
                    record_layer
                        .preprocess(ctx)
                        .await
                        .map_err(MpcTlsError::preprocess)?;
                    Ok::<_, MpcTlsError>(record_layer)
                })
            },
            move |ctx| {
                Box::pin(async move {
                    vm.preprocess(ctx).await.map_err(MpcTlsError::preprocess)?;
                    vm.flush(ctx).await.map_err(MpcTlsError::preprocess)?;
                    Ok::<_, MpcTlsError>(())
                })
            },
        )
        .await
        .map_err(MpcTlsError::preprocess)??;
    Ok((ke, record_layer))
}

async fn run_handshake_stage(
    ctx: &mut Context,
    vm: Vm,
    ke: &mut Box<dyn KeyExchange + Send + Sync + 'static>,
    ks: &mut Tls13KeySched,
    server_key: &PublicKey,
    hello_hash: [u8; 32],
) -> Result<(), MpcTlsError> {
    if server_key.group != NamedGroup::secp256r1 {
        return Err(MpcTlsError::hs("unsupported server key group"));
    }
    ke.set_server_key(
        p256::PublicKey::from_sec1_bytes(&server_key.key)
            .map_err(|_| MpcTlsError::hs("failed to parse server key"))?,
    )?;
    ke.compute_shares(ctx).await?;
    let mut vm = vm
        .try_lock()
        .map_err(|_| MpcTlsError::other("VM lock is held"))?;
    ke.assign(&mut (*vm))?;
    ks.set_hello_hash(hello_hash).map_err(MpcTlsError::hs)?;
    while ks.wants_flush() {
        ks.flush(&mut *vm).map_err(MpcTlsError::hs)?;
        vm.execute_all(ctx).await.map_err(MpcTlsError::hs)?;
    }
    ke.finalize().await?;
    Ok(())
}

async fn run_application_stage(
    ctx: &mut Context,
    vm: Vm,
    ks: &mut Tls13KeySched,
    record_layer: &mut RecordLayer,
    iv_futs: &mut Option<ApplicationIvFutures>,
    handshake_hash: [u8; 32],
) -> Result<(), MpcTlsError> {
    {
        let mut vm = vm
            .try_lock()
            .map_err(|_| MpcTlsError::other("VM lock is held"))?;
        ks.continue_to_app_keys().map_err(MpcTlsError::hs)?;
        // The master secret may need flushing before the handshake hash is set.
        while ks.wants_flush() {
            ks.flush(&mut *vm).map_err(MpcTlsError::hs)?;
            vm.execute_all(ctx).await.map_err(MpcTlsError::hs)?;
        }
        ks.set_handshake_hash(handshake_hash)
            .map_err(MpcTlsError::hs)?;
        while ks.wants_flush() {
            ks.flush(&mut *vm).map_err(MpcTlsError::hs)?;
            vm.execute_all(ctx).await.map_err(MpcTlsError::hs)?;
        }
    }
    let (mut civ, mut siv) = iv_futs
        .take()
        .ok_or_else(|| MpcTlsError::state("application IVs not allocated"))?;
    let civ = civ
        .try_recv()
        .map_err(MpcTlsError::hs)?
        .ok_or_else(|| MpcTlsError::hs("client application IV not decoded"))?;
    let siv = siv
        .try_recv()
        .map_err(MpcTlsError::hs)?
        .ok_or_else(|| MpcTlsError::hs("server application IV not decoded"))?;
    record_layer.set_tls13_ivs(civ, siv)?;
    // GHASH keys are derived from the (now computed) application keys.
    record_layer.setup(ctx).await?;
    Ok(())
}

#[async_trait]
impl Backend for Tls13Leader {
    async fn set_protocol_version(&mut self, version: ProtocolVersion) -> Result<(), BackendError> {
        if version != ProtocolVersion::TLSv1_3 {
            return Err(BackendError::UnsupportedProtocolVersion(version));
        }
        Ok(())
    }

    async fn set_cipher_suite(&mut self, suite: SupportedCipherSuite) -> Result<(), BackendError> {
        if suite.suite() != CipherSuite::TLS13_AES_128_GCM_SHA256 {
            return Err(BackendError::UnsupportedCiphersuite(suite.suite()));
        }
        Ok(())
    }

    async fn set_encrypt(&mut self, mode: ClientEncryptMode) -> Result<(), BackendError> {
        match mode {
            ClientEncryptMode::Handshake => {
                if self.hs.enc.is_none() {
                    return Err(MpcTlsError::state("handshake keys not derived").into());
                }
            }
            ClientEncryptMode::Application => self.encrypt_app = true,
            ClientEncryptMode::EarlyData => {
                return Err(BackendError::InvalidConfig(
                    "early data is not supported".into(),
                ));
            }
        }
        Ok(())
    }

    async fn set_decrypt(&mut self, mode: ClientDecryptMode) -> Result<(), BackendError> {
        match mode {
            ClientDecryptMode::Handshake => {
                if self.hs.dec.is_none() {
                    return Err(MpcTlsError::state("handshake keys not derived").into());
                }
            }
            ClientDecryptMode::Application => self.decrypt_app = true,
        }
        Ok(())
    }

    async fn get_client_random(&mut self) -> Result<Random, BackendError> {
        Ok(self.client_random)
    }

    async fn get_client_key_share(&mut self) -> Result<PublicKey, BackendError> {
        let pk = self
            .ke
            .as_mut()
            .expect("key exchange available")
            .client_key()
            .map_err(|err| BackendError::InvalidState(err.to_string()))?;
        Ok(PublicKey::new(
            NamedGroup::secp256r1,
            &p256::EncodedPoint::from(pk).to_bytes(),
        ))
    }

    async fn set_server_random(&mut self, _random: Random) -> Result<(), BackendError> {
        let now = web_time::UNIX_EPOCH
            .elapsed()
            .expect("system time is available")
            .as_secs();
        self.time = Some(now);
        self.ctx()?
            .io_mut()
            .send(Message::StartHandshake(StartHandshake { time: now }))
            .await
            .map_err(MpcTlsError::from)?;
        Ok(())
    }

    async fn set_server_key_share(&mut self, key: PublicKey) -> Result<(), BackendError> {
        if key.group != NamedGroup::secp256r1 {
            return Err(BackendError::InvalidServerKey);
        }
        self.server_key = Some(key);
        Ok(())
    }

    async fn set_server_cert_details(&mut self, _: ServerCertDetails) -> Result<(), BackendError> {
        Ok(())
    }

    async fn set_server_kx_details(&mut self, _: ServerKxDetails) -> Result<(), BackendError> {
        Ok(())
    }

    async fn set_hs_hash_client_key_exchange(&mut self, _: Vec<u8>) -> Result<(), BackendError> {
        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn set_hs_hash_server_hello(&mut self, hash: Vec<u8>) -> Result<(), BackendError> {
        let hash: [u8; 32] = hash
            .try_into()
            .map_err(|_| MpcTlsError::hs("hello hash is not 32 bytes"))?;
        self.handshake_stage(hash).await?;
        Ok(())
    }

    async fn set_server_handshake_tls13(
        &mut self,
        certs: Vec<Certificate>,
        handshake_messages: Vec<u8>,
        sig: DigitallySignedStruct,
    ) -> Result<(), BackendError> {
        self.binding = Some((certs, handshake_messages, sig));
        Ok(())
    }

    async fn get_server_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, BackendError> {
        let key = self
            .hs
            .server_finished_key
            .ok_or_else(|| MpcTlsError::state("handshake keys not derived"))?;
        Ok(hmac_sha256(&key, &hash))
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn set_hs_hash_server_finished(&mut self, hash: Vec<u8>) -> Result<(), BackendError> {
        let handshake_hash: [u8; 32] = hash
            .try_into()
            .map_err(|_| MpcTlsError::hs("handshake hash is not 32 bytes"))?;
        if self.app_stage_done {
            return Err(MpcTlsError::hs("application keys already derived").into());
        }
        let vm = self.vm.as_ref().expect("VM available").clone();
        let ctx = self
            .ctx
            .as_mut()
            .ok_or_else(|| MpcTlsError::state("connection is finished"))?;
        ctx.io_mut()
            .send(Message::Tls13HandshakeHash(handshake_hash))
            .await
            .map_err(MpcTlsError::from)?;
        run_application_stage(
            ctx,
            vm,
            &mut self.ks,
            self.record_layer.as_mut().expect("record layer available"),
            &mut self.iv_futs,
            handshake_hash,
        )
        .await?;
        self.app_stage_done = true;
        Ok(())
    }

    async fn get_client_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, BackendError> {
        if !self.app_stage_done {
            return Err(MpcTlsError::hs("server Finished was not processed").into());
        }
        let key = self
            .hs
            .client_finished_key
            .ok_or_else(|| MpcTlsError::state("handshake keys not derived"))?;
        Ok(hmac_sha256(&key, &hash))
    }

    async fn prepare_encryption(&mut self) -> Result<(), BackendError> {
        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn push_incoming(&mut self, msg: OpaqueMessage) -> Result<(), BackendError> {
        if !self.decrypt_app {
            let plain = self
                .hs
                .dec
                .as_mut()
                .ok_or_else(|| MpcTlsError::state("handshake keys not derived"))?
                .open(msg)?;
            self.hs.incoming.push_back(plain);
            return Ok(());
        }

        let OpaqueMessage {
            typ,
            version,
            payload,
        } = msg;
        if typ != ContentType::ApplicationData || version != ProtocolVersion::TLSv1_2 {
            return Err(MpcTlsError::peer("unexpected outer record type in TLS 1.3").into());
        }
        let mut ciphertext = payload.0;
        if !(TAG_LEN + 1..=16384 + 256).contains(&ciphertext.len()) {
            return Err(MpcTlsError::peer("invalid TLS 1.3 record length").into());
        }
        let tag = ciphertext.split_off(ciphertext.len() - TAG_LEN);
        // The record layer derives the TLS 1.3 nonce itself.
        self.record_layer
            .as_mut()
            .expect("record layer available")
            .push_decrypt(
                typ,
                version,
                Vec::new(),
                ciphertext.clone(),
                tag.clone(),
                DecryptMode::Private,
            )?;
        self.ctx()?
            .io_mut()
            .send(Message::Decrypt(Decrypt {
                typ,
                version,
                explicit_nonce: Vec::new(),
                ciphertext,
                tag,
                mode: DecryptMode::Private,
            }))
            .await
            .map_err(MpcTlsError::from)?;
        Ok(())
    }

    async fn next_incoming(&mut self) -> Result<Option<PlainMessage>, BackendError> {
        if let Some(msg) = self.hs.incoming.pop_front() {
            return Ok(Some(msg));
        }
        let Some(record) = self
            .record_layer
            .as_mut()
            .expect("record layer available")
            .next_decrypted()
        else {
            return Ok(None);
        };
        let plaintext = record
            .plaintext
            .ok_or_else(|| MpcTlsError::other("leader should always know plaintext"))?;
        let (typ, content_len, _) = split_inner(&plaintext)?;
        debug!(?typ, content_len, "processing incoming TLS 1.3 record");
        let mut content = plaintext;
        content.truncate(content_len);
        Ok(Some(PlainMessage {
            typ,
            version: ProtocolVersion::TLSv1_3,
            payload: Payload::new(content),
        }))
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn push_outgoing(&mut self, msg: PlainMessage) -> Result<(), BackendError> {
        if !self.encrypt_app {
            let opaque = self
                .hs
                .enc
                .as_mut()
                .ok_or_else(|| MpcTlsError::state("handshake keys not derived"))?
                .seal(msg.typ, &msg.payload.0)?;
            self.hs.outgoing.push_back(opaque);
            return Ok(());
        }

        let mode = match msg.typ {
            ContentType::ApplicationData => EncryptMode::Private,
            _ => EncryptMode::Public,
        };
        let mut inner = msg.payload.0;
        inner.push(msg.typ.get_u8());
        let typ = ContentType::ApplicationData;
        let version = ProtocolVersion::TLSv1_2;
        self.record_layer
            .as_mut()
            .expect("record layer available")
            .push_encrypt(typ, version, inner.len(), Some(inner.clone()), mode)?;
        self.ctx()?
            .io_mut()
            .send(Message::Encrypt(Encrypt {
                typ,
                version,
                len: inner.len(),
                plaintext: match mode {
                    EncryptMode::Private => None,
                    EncryptMode::Public => Some(inner),
                },
                mode,
            }))
            .await
            .map_err(MpcTlsError::from)?;
        Ok(())
    }

    async fn next_outgoing(&mut self) -> Result<Option<OpaqueMessage>, BackendError> {
        if let Some(msg) = self.hs.outgoing.pop_front() {
            return Ok(Some(msg));
        }
        Ok(self
            .record_layer
            .as_mut()
            .expect("record layer available")
            .next_encrypted()
            .map(|record| {
                let mut payload = record.ciphertext;
                payload.extend_from_slice(&record.tag.expect("leader should always know tag"));
                OpaqueMessage {
                    typ: ContentType::ApplicationData,
                    version: ProtocolVersion::TLSv1_2,
                    payload: Payload::new(payload),
                }
            }))
    }

    async fn start_traffic(&mut self) -> Result<(), BackendError> {
        self.traffic = true;
        self.record_layer
            .as_mut()
            .expect("record layer available")
            .start_traffic();
        self.ctx()?
            .io_mut()
            .send(Message::StartTraffic)
            .await
            .map_err(MpcTlsError::from)?;
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), BackendError> {
        if !self.traffic
            || !self
                .record_layer
                .as_mut()
                .expect("record layer available")
                .wants_flush()
        {
            return Ok(());
        }
        let is_decrypting = self.is_decrypting;
        let vm = self.vm.as_ref().expect("VM available").clone();
        let ctx = self
            .ctx
            .as_mut()
            .ok_or_else(|| MpcTlsError::state("connection is finished"))?;
        ctx.io_mut()
            .send(Message::Flush { is_decrypting })
            .await
            .map_err(MpcTlsError::from)?;
        self.record_layer
            .as_mut()
            .expect("record layer available")
            .flush(ctx, vm, is_decrypting)
            .await
            .map_err(BackendError::from)
    }

    async fn get_notify(&mut self) -> Result<BackendNotify, BackendError> {
        Ok(self.notifier.get())
    }

    fn is_empty(&self) -> Result<bool, BackendError> {
        let empty = self.hs.incoming.is_empty()
            && self.hs.outgoing.is_empty()
            && (!self.traffic
                || self
                    .record_layer
                    .as_ref()
                    .expect("record layer available")
                    .is_empty());
        Ok(empty)
    }

    async fn server_closed(&mut self) -> Result<(), BackendError> {
        self.close_connection().await.map_err(BackendError::from)
    }

    fn enable_decryption(&mut self, enable: bool) -> Result<(), BackendError> {
        self.is_decrypting = enable;
        if enable {
            self.notifier.set();
        } else {
            self.notifier.clear();
        }
        Ok(())
    }

    fn finish(&mut self) -> Option<(Context, TlsTranscript)> {
        let transcript = self.closed.take()?;
        match self.ctx.take() {
            Some(ctx) => {
                // Release shared OT registrations and the backend VM reference
                // before DEAP finalization, as the TLS 1.2 state transition does.
                self.ke.take();
                self.record_layer.take();
                self.vm.take();
                Some((ctx, transcript))
            }
            None => {
                self.closed = Some(transcript);
                None
            }
        }
    }
}

/// TLS 1.3 MPC-TLS follower.
pub(crate) struct Tls13Follower {
    config: Config,
    ctx: Context,
    vm: Vm,
    ke: Option<Box<dyn KeyExchange + Send + Sync + 'static>>,
    ks: Tls13KeySched,
    record_layer: Option<RecordLayer>,
    iv_futs: Option<ApplicationIvFutures>,
}

impl std::fmt::Debug for Tls13Follower {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tls13Follower").finish_non_exhaustive()
    }
}

impl Tls13Follower {
    pub(crate) fn new<CS, CR>(
        config: Config,
        ctx: Context,
        vm: Vm,
        cot_send: CS,
        cot_recv: (CR, CR, CR),
    ) -> Self
    where
        CS: RCOTSender<Block> + Flush + Send + Sync + 'static,
        CR: RCOTReceiver<bool, Block> + Flush + Send + Sync + 'static,
    {
        let mut rng = rand::rng();
        let ke = Box::new(MpcKeyExchange::new(
            ke::Role::Follower,
            ShareConversionReceiver::new(OLEReceiver::new(AnyReceiver::new(
                RandomizeRCOTReceiver::new(cot_recv.0),
            ))),
            ShareConversionSender::new(OLESender::new(
                Block::random(&mut rng),
                AnySender::new(RandomizeRCOTSender::new(cot_send)),
            )),
        )) as Box<dyn KeyExchange + Send + Sync>;
        let encrypter = MpcAesGcm::new(
            ShareConversionReceiver::new(OLEReceiver::new(AnyReceiver::new(
                RandomizeRCOTReceiver::new(cot_recv.1),
            ))),
            Role::Follower,
        );
        let decrypter = MpcAesGcm::new(
            ShareConversionReceiver::new(OLEReceiver::new(AnyReceiver::new(
                RandomizeRCOTReceiver::new(cot_recv.2),
            ))),
            Role::Follower,
        );
        let mut record_layer = RecordLayer::new(Role::Follower, encrypter, decrypter);
        record_layer.enable_tls13();
        let ks = Tls13KeySched::new(ks_mode(&config), KsRole::Follower);
        Self {
            config,
            ctx,
            vm,
            ke: Some(ke),
            ks,
            record_layer: Some(record_layer),
            iv_futs: None,
        }
    }

    pub(crate) fn alloc(&mut self) -> Result<SessionKeys, MpcTlsError> {
        let mut vm = self
            .vm
            .clone()
            .try_lock_owned()
            .map_err(|_| MpcTlsError::other("VM lock is held"))?;
        let pms = self
            .ke
            .as_mut()
            .expect("key exchange available")
            .alloc(&mut (*vm))?;
        alloc_common(
            &mut (*vm),
            &self.config,
            pms,
            &mut self.ks,
            self.record_layer.as_mut().expect("record layer available"),
            &mut self.iv_futs,
        )
    }

    pub(crate) async fn preprocess(&mut self) -> Result<(), MpcTlsError> {
        let ke = self
            .ke
            .take()
            .ok_or_else(|| MpcTlsError::state("preprocessing already started"))?;
        let record_layer = self
            .record_layer
            .take()
            .ok_or_else(|| MpcTlsError::state("preprocessing already started"))?;
        let (ke, record_layer) =
            preprocess_common(&mut self.ctx, self.vm.clone(), ke, record_layer).await?;
        self.ke = Some(ke);
        self.record_layer = Some(record_layer);
        Ok(())
    }

    #[instrument(skip_all, err)]
    pub(crate) async fn run(mut self) -> Result<(Context, TlsTranscript), MpcTlsError> {
        let mut time = None;
        let mut server_key = None;
        let mut app_keys = false;
        loop {
            let msg: Message = self.ctx.io_mut().expect_next().await?;
            match msg {
                Message::StartHandshake(StartHandshake { time: prover_time }) => {
                    if time.is_some() {
                        return Err(MpcTlsError::hs("time already set"));
                    }
                    let now = web_time::UNIX_EPOCH
                        .elapsed()
                        .expect("system time is available")
                        .as_secs();
                    if prover_time.abs_diff(now) > MAX_TIME_DIFF {
                        return Err(MpcTlsError::hs("handshake time difference exceeds limit"));
                    }
                    time = Some(prover_time);
                }
                Message::Tls13ServerHello(Tls13ServerHello {
                    server_key: key,
                    hello_hash,
                }) => {
                    if server_key.is_some() {
                        return Err(MpcTlsError::hs("server key already set"));
                    }
                    run_handshake_stage(
                        &mut self.ctx,
                        self.vm.clone(),
                        self.ke.as_mut().expect("key exchange available"),
                        &mut self.ks,
                        &key,
                        hello_hash,
                    )
                    .await?;
                    server_key = Some(key);
                }
                Message::Tls13HandshakeHash(hash) => {
                    if server_key.is_none() || app_keys {
                        return Err(MpcTlsError::hs("unexpected handshake hash"));
                    }
                    run_application_stage(
                        &mut self.ctx,
                        self.vm.clone(),
                        &mut self.ks,
                        self.record_layer.as_mut().expect("record layer available"),
                        &mut self.iv_futs,
                        hash,
                    )
                    .await?;
                    app_keys = true;
                }
                Message::Encrypt(encrypt) => {
                    if !app_keys {
                        return Err(MpcTlsError::hs("encrypt before application keys"));
                    }
                    self.record_layer
                        .as_mut()
                        .expect("record layer available")
                        .push_encrypt(
                            encrypt.typ,
                            encrypt.version,
                            encrypt.len,
                            encrypt.plaintext,
                            encrypt.mode,
                        )
                        .map_err(MpcTlsError::record_layer)?;
                }
                Message::Decrypt(decrypt) => {
                    if !app_keys {
                        return Err(MpcTlsError::hs("decrypt before application keys"));
                    }
                    self.record_layer
                        .as_mut()
                        .expect("record layer available")
                        .push_decrypt(
                            decrypt.typ,
                            decrypt.version,
                            decrypt.explicit_nonce,
                            decrypt.ciphertext,
                            decrypt.tag,
                            decrypt.mode,
                        )
                        .map_err(MpcTlsError::record_layer)?;
                }
                Message::StartTraffic => self
                    .record_layer
                    .as_mut()
                    .expect("record layer available")
                    .start_traffic(),
                Message::Flush { is_decrypting } => {
                    self.record_layer
                        .as_mut()
                        .expect("record layer available")
                        .flush(&mut self.ctx, self.vm.clone(), is_decrypting)
                        .await?;
                    debug!("flushed record layer");
                }
                Message::CloseConnection => break,
                _ => return Err(MpcTlsError::peer("unexpected message in TLS 1.3 session")),
            }
        }

        let (mut sent, mut recv) = self
            .record_layer
            .as_mut()
            .expect("record layer available")
            .commit(&mut self.ctx, self.vm.clone())
            .await?;
        let Message::Tls13Suffixes(suffixes) = self.ctx.io_mut().expect_next().await? else {
            return Err(MpcTlsError::peer("expected TLS 1.3 record suffixes"));
        };
        apply_suffixes(&mut sent, suffixes.sent)?;
        apply_suffixes(&mut recv, suffixes.recv)?;

        let time = time.ok_or(MpcTlsError::hs("time was not set"))?;
        let server_key = server_key.ok_or(MpcTlsError::hs("server key not set"))?;
        if !app_keys {
            return Err(MpcTlsError::hs("handshake did not complete"));
        }

        // The follower attests the server ephemeral key it used; the prover
        // supplies the handshake messages when proving the server identity.
        let transcript = TlsTranscript::builder()
            .time(time)
            .version(TlsVersion::V1_3)
            .certificate_binding(CertBinding::V1_3(CertBindingV1_3 {
                handshake_messages: Vec::new(),
                server_ephemeral_key: server_key
                    .try_into()
                    .map_err(|_| MpcTlsError::hs("unsupported server key"))?,
            }))
            .records_sent(sent)
            .records_recv(recv)
            .build()
            .map_err(MpcTlsError::other)?;

        // Suffixes are only claims until the proving phase checks them against
        // the ciphertext in zero knowledge.
        check_close_notify(transcript.sent())?;
        check_close_notify(transcript.recv())?;

        Ok((self.ctx, transcript))
    }
}

/// Server key share and hello hash (TLS 1.3).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct Tls13ServerHello {
    pub(crate) server_key: PublicKey,
    pub(crate) hello_hash: [u8; 32],
}

/// Disclosed record suffixes (TLS 1.3).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct Tls13Suffixes {
    pub(crate) sent: Vec<Vec<u8>>,
    pub(crate) recv: Vec<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_nonce_exhaustion_is_rejected() {
        let mut cipher = LocalAead::new([1; 16], [2; 12]);
        cipher.seq = u64::MAX;
        assert!(cipher.seal(ContentType::Handshake, b"finished").is_err());
    }

    #[test]
    fn suffix_roundtrip() {
        let mut app = b"hello".to_vec();
        app.push(23);
        app.extend([0, 0, 0]);
        let (typ, len, suffix) = split_inner(&app).unwrap();
        assert_eq!(typ, ContentType::ApplicationData);
        assert_eq!(len, 5);
        assert_eq!(suffix, vec![23, 0, 0, 0]);
        assert_eq!(parse_suffix(&suffix, app.len()).unwrap(), (typ, None));

        let alert = vec![1, 0, 21];
        let (typ, _, suffix) = split_inner(&alert).unwrap();
        assert_eq!(typ, ContentType::Alert);
        assert_eq!(
            parse_suffix(&suffix, alert.len()).unwrap(),
            (typ, Some(vec![1, 0]))
        );

        // An application record cannot claim to be shorter or longer.
        assert!(parse_suffix(&[23, 0], 1).is_err());
        assert!(parse_suffix(&[5, 23], 10).is_err());
        // A non-application record must be fully disclosed.
        assert!(parse_suffix(&[1, 0, 21], 10).is_err());
        assert!(parse_suffix(&[0, 0], 2).is_err());
        assert!(split_inner(&[0, 0]).is_err());
        let mut oversized = vec![42; 16385];
        oversized.push(23);
        assert!(split_inner(&oversized).is_err());
        assert!(parse_suffix(&[23], 16386).is_err());
    }
}
