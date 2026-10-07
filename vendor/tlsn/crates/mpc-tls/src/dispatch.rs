//! Version dispatch for the MPC-TLS leader and follower (zkfetch patch).
//!
//! The protocol version is fixed by the configuration before preprocessing,
//! since the key-derivation circuits differ between TLS 1.2 and TLS 1.3.

use async_trait::async_trait;
use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_ot::rcot::{RCOTReceiver, RCOTSender};
use tls_client::{
    Backend, BackendError, BackendNotify, DecryptMode as ClientDecryptMode,
    EncryptMode as ClientEncryptMode,
};
use tls_core::{
    cert::ServerCertDetails,
    ke::ServerKxDetails,
    key::{Certificate, PublicKey},
    msgs::{
        enums::ProtocolVersion,
        handshake::{DigitallySignedStruct, Random},
        message::{OpaqueMessage, PlainMessage},
    },
    suites::SupportedCipherSuite,
};
use tlsn_core::{connection::TlsVersion, transcript::TlsTranscript};

use crate::{
    Config, MpcTlsError, SessionKeys, Vm,
    follower::Tls12Follower,
    leader::Tls12Leader,
    tls13::{Tls13Follower, Tls13Leader},
};

/// MPC-TLS leader.
#[derive(Debug)]
pub struct MpcTlsLeader(Leader);

#[derive(Debug)]
enum Leader {
    Tls12(Box<Tls12Leader>),
    Tls13(Box<Tls13Leader>),
}

impl MpcTlsLeader {
    /// Creates a new leader instance for the configured TLS version.
    pub fn new<CS, CR>(
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
        Self(match config.tls_version {
            TlsVersion::V1_2 => Leader::Tls12(Box::new(Tls12Leader::new(
                config, ctx, vm, cot_send, cot_recv,
            ))),
            TlsVersion::V1_3 => Leader::Tls13(Box::new(Tls13Leader::new(
                config, ctx, vm, cot_send, cot_recv,
            ))),
        })
    }

    /// Allocates resources for the connection.
    pub fn alloc(&mut self) -> Result<SessionKeys, MpcTlsError> {
        match &mut self.0 {
            Leader::Tls12(l) => l.alloc(),
            Leader::Tls13(l) => l.alloc(),
        }
    }

    /// Preprocesses the connection.
    pub async fn preprocess(&mut self) -> Result<(), MpcTlsError> {
        match &mut self.0 {
            Leader::Tls12(l) => l.preprocess().await,
            Leader::Tls13(l) => l.preprocess().await,
        }
    }

    /// Returns the TLS protocol version this leader negotiates.
    pub fn tls_version(&self) -> TlsVersion {
        match &self.0 {
            Leader::Tls12(_) => TlsVersion::V1_2,
            Leader::Tls13(_) => TlsVersion::V1_3,
        }
    }

    /// Returns if incoming messages are decrypted.
    pub fn is_decrypting(&self) -> bool {
        match &self.0 {
            Leader::Tls12(l) => l.is_decrypting(),
            Leader::Tls13(l) => l.is_decrypting(),
        }
    }
}

macro_rules! forward {
    ($self:ident, $l:ident => $e:expr) => {
        match &mut $self.0 {
            Leader::Tls12($l) => $e,
            Leader::Tls13($l) => $e,
        }
    };
}

#[async_trait]
impl Backend for MpcTlsLeader {
    async fn set_protocol_version(&mut self, version: ProtocolVersion) -> Result<(), BackendError> {
        forward!(self, l => l.set_protocol_version(version).await)
    }
    async fn set_cipher_suite(&mut self, suite: SupportedCipherSuite) -> Result<(), BackendError> {
        forward!(self, l => l.set_cipher_suite(suite).await)
    }
    async fn get_suite(&mut self) -> Result<SupportedCipherSuite, BackendError> {
        forward!(self, l => l.get_suite().await)
    }
    async fn set_encrypt(&mut self, mode: ClientEncryptMode) -> Result<(), BackendError> {
        forward!(self, l => l.set_encrypt(mode).await)
    }
    async fn set_decrypt(&mut self, mode: ClientDecryptMode) -> Result<(), BackendError> {
        forward!(self, l => l.set_decrypt(mode).await)
    }
    async fn get_client_random(&mut self) -> Result<Random, BackendError> {
        forward!(self, l => l.get_client_random().await)
    }
    async fn get_client_key_share(&mut self) -> Result<PublicKey, BackendError> {
        forward!(self, l => l.get_client_key_share().await)
    }
    async fn set_server_random(&mut self, random: Random) -> Result<(), BackendError> {
        forward!(self, l => l.set_server_random(random).await)
    }
    async fn set_server_key_share(&mut self, key: PublicKey) -> Result<(), BackendError> {
        forward!(self, l => l.set_server_key_share(key).await)
    }
    async fn set_server_cert_details(
        &mut self,
        cert_details: ServerCertDetails,
    ) -> Result<(), BackendError> {
        forward!(self, l => l.set_server_cert_details(cert_details).await)
    }
    async fn set_server_kx_details(
        &mut self,
        kx_details: ServerKxDetails,
    ) -> Result<(), BackendError> {
        forward!(self, l => l.set_server_kx_details(kx_details).await)
    }
    async fn set_hs_hash_client_key_exchange(&mut self, hash: Vec<u8>) -> Result<(), BackendError> {
        forward!(self, l => l.set_hs_hash_client_key_exchange(hash).await)
    }
    async fn set_hs_hash_server_hello(&mut self, hash: Vec<u8>) -> Result<(), BackendError> {
        forward!(self, l => l.set_hs_hash_server_hello(hash).await)
    }
    async fn set_server_handshake_tls13(
        &mut self,
        certs: Vec<Certificate>,
        handshake_messages: Vec<u8>,
        sig: DigitallySignedStruct,
    ) -> Result<(), BackendError> {
        forward!(self, l => l.set_server_handshake_tls13(certs, handshake_messages, sig).await)
    }
    async fn set_hs_hash_server_finished(&mut self, hash: Vec<u8>) -> Result<(), BackendError> {
        forward!(self, l => l.set_hs_hash_server_finished(hash).await)
    }
    async fn get_server_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, BackendError> {
        forward!(self, l => l.get_server_finished_vd(hash).await)
    }
    async fn get_client_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, BackendError> {
        forward!(self, l => l.get_client_finished_vd(hash).await)
    }
    async fn prepare_encryption(&mut self) -> Result<(), BackendError> {
        forward!(self, l => l.prepare_encryption().await)
    }
    async fn push_incoming(&mut self, msg: OpaqueMessage) -> Result<(), BackendError> {
        forward!(self, l => l.push_incoming(msg).await)
    }
    async fn next_incoming(&mut self) -> Result<Option<PlainMessage>, BackendError> {
        forward!(self, l => l.next_incoming().await)
    }
    async fn push_outgoing(&mut self, msg: PlainMessage) -> Result<(), BackendError> {
        forward!(self, l => l.push_outgoing(msg).await)
    }
    async fn next_outgoing(&mut self) -> Result<Option<OpaqueMessage>, BackendError> {
        forward!(self, l => l.next_outgoing().await)
    }
    async fn start_traffic(&mut self) -> Result<(), BackendError> {
        forward!(self, l => l.start_traffic().await)
    }
    async fn flush(&mut self) -> Result<(), BackendError> {
        forward!(self, l => l.flush().await)
    }
    async fn get_notify(&mut self) -> Result<BackendNotify, BackendError> {
        forward!(self, l => l.get_notify().await)
    }
    fn is_empty(&self) -> Result<bool, BackendError> {
        match &self.0 {
            Leader::Tls12(l) => l.is_empty(),
            Leader::Tls13(l) => l.is_empty(),
        }
    }
    async fn server_closed(&mut self) -> Result<(), BackendError> {
        forward!(self, l => l.server_closed().await)
    }
    fn enable_decryption(&mut self, enable: bool) -> Result<(), BackendError> {
        forward!(self, l => l.enable_decryption(enable))
    }
    fn finish(&mut self) -> Option<(Context, TlsTranscript)> {
        forward!(self, l => l.finish())
    }
}

/// MPC-TLS follower.
#[derive(Debug)]
pub struct MpcTlsFollower(Follower);

#[derive(Debug)]
enum Follower {
    Tls12(Box<Tls12Follower>),
    Tls13(Box<Tls13Follower>),
}

impl MpcTlsFollower {
    /// Creates a new follower for the configured TLS version.
    pub fn new<CS, CR>(
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
        Self(match config.tls_version {
            TlsVersion::V1_2 => Follower::Tls12(Box::new(Tls12Follower::new(
                config, ctx, vm, cot_send, cot_recv,
            ))),
            TlsVersion::V1_3 => Follower::Tls13(Box::new(Tls13Follower::new(
                config, ctx, vm, cot_send, cot_recv,
            ))),
        })
    }

    /// Allocates resources for the connection.
    pub fn alloc(&mut self) -> Result<SessionKeys, MpcTlsError> {
        match &mut self.0 {
            Follower::Tls12(f) => f.alloc(),
            Follower::Tls13(f) => f.alloc(),
        }
    }

    /// Preprocesses the connection.
    pub async fn preprocess(&mut self) -> Result<(), MpcTlsError> {
        match &mut self.0 {
            Follower::Tls12(f) => f.preprocess().await,
            Follower::Tls13(f) => f.preprocess().await,
        }
    }

    /// Runs the follower.
    pub async fn run(self) -> Result<(Context, TlsTranscript), MpcTlsError> {
        match self.0 {
            Follower::Tls12(f) => f.run().await,
            Follower::Tls13(f) => f.run().await,
        }
    }
}
