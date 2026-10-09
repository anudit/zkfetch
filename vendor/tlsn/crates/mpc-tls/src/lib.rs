//! TLSNotary MPC-TLS protocol implementation.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod config;
mod decode;
mod dispatch;
mod error;
pub(crate) mod follower;
pub(crate) mod leader;
mod msg;
mod record_layer;
mod tls13;
pub(crate) mod utils;

pub use config::{Config, ConfigBuilder, ConfigBuilderError};
pub use dispatch::{MpcTlsFollower, MpcTlsLeader};
pub use error::MpcTlsError;

use std::{future::Future, pin::Pin, sync::Arc};

use mpz_memory_core::{
    Array,
    binary::{Binary, U8},
};
use mpz_vm_core::Vm as VmTrait;

use tokio::sync::Mutex;

pub(crate) type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send + Sync + 'static>>;
/// Virtual machine type.
pub type Vm = Arc<Mutex<dyn VmTrait<Binary> + Send + Sync + 'static>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Leader,
    Follower,
}

/// TLS session keys.
#[derive(Debug, Clone)]
pub struct SessionKeys {
    /// Client write key.
    pub client_write_key: Array<U8, 16>,
    /// Client write IV.
    pub client_write_iv: Array<U8, 4>,
    /// Server write key.
    pub server_write_key: Array<U8, 16>,
    /// Server write IV.
    pub server_write_iv: Array<U8, 4>,
    /// Server write MAC key.
    pub server_write_mac_key: Array<U8, 16>,
}

/// Helpers for executable production-handshake regression tests.
#[cfg(feature = "security-test-support")]
pub mod security_test_support {
    /// Runs valid and mutated handshake evidence through the active follower check.
    pub fn handshake_mutations() -> Vec<bool> {
        crate::tls13::handshake_mutations()
    }
}
