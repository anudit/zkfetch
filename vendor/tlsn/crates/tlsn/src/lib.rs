//! TLSNotary protocol implementation.
//!
//! This crate provides the core protocol for generating and verifying proofs
//! of TLS sessions. A prover can demonstrate to a verifier that specific data
//! was exchanged with a TLS server, without revealing the full transcript.
//!
//! # Overview
//!
//! The protocol involves two parties:
//!
//! - **Prover** ([`Prover`](prover::Prover)): connects to a TLS server and
//!   generates proofs about the session.
//! - **Verifier** ([`Verifier`](verifier::Verifier)): collaborates with the
//!   prover during the TLS session and verifies the resulting proofs.
//!
//! Both parties communicate through an established [`Session`].
//!
//! # Workflow
//!
//! The protocol has two main phases:
//!
//! **Commitment**: The prover and verifier collaborate to construct a TLS
//! transcript commitment from the prover's communication with a TLS server.
//! This authenticates the transcript for the verifier, without the verifier
//! learning the contents.
//!
//! **Selective Disclosure**: The prover selectively reveals portions of the
//! committed transcript to the verifier, proving statements about the data
//! exchanged with the server.
//!
//! ## Steps
//!
//! 1. Establish a communication channel between prover and verifier.
//! 2. Create a [`Session`] on each side from the channel.
//! 3. Create a [`Prover`](prover::Prover) or [`Verifier`](verifier::Verifier).
//! 4. Run the commitment phase: the prover connects to the TLS server and
//!    exchanges data to obtain a commitment to the TLS transcript.
//! 5. (Optional) Perform selective disclosure: the prover provably reveals
//!    selected data to the verifier.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod deps;
mod error;
pub(crate) mod ghash;
pub(crate) mod map;
pub(crate) mod msg;
pub mod prover;
mod proxy;
mod session;
pub(crate) mod tag;
pub(crate) mod transcript_internal;
pub mod verifier;

pub use error::Error;
pub use rangeset;
pub use session::{Session, SessionDriver, SessionHandle};
pub use tlsn_attestation as attestation;
pub use tlsn_core::{config, connection, hash, transcript, webpki};
pub use tlsn_mux::Stream;

/// Result type.
pub type Result<T, E = Error> = core::result::Result<T, E>;

use mpc_tls::SessionKeys;
use semver::Version;
use std::sync::LazyLock;
use tlsn_core::{
    config::tls_commit::{TlsCommitConfig, mpc::MpcTlsConfig, proxy::ProxyTlsConfig},
    transcript::TlsTranscript,
};

// Package version.
pub(crate) static VERSION: LazyLock<Version> = LazyLock::new(|| {
    Version::parse(env!("CARGO_PKG_VERSION")).expect("cargo pkg version should be a valid semver")
});

// Prefix for the proxy stream id between prover and verifier.
pub(crate) const PROXY_STREAM_PREFIX: &[u8] = b"proxy_stream";

/// The party's role in the TLSN protocol.
///
/// A Notary is classified as a Verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    /// The prover.
    Prover,
    /// The verifier.
    Verifier,
}

/// Output of a TLS session.
pub(crate) struct TlsOutput {
    pub(crate) keys: SessionKeys,
    pub(crate) tls_transcript: TlsTranscript,
}

/// Protocol variant.
pub trait ProtocolConfig: Clone + Into<TlsCommitConfig> + sealed::Sealed {
    /// TLS commitment protocol.
    type Commit;
}

impl ProtocolConfig for MpcTlsConfig {
    type Commit = Mpc;
}

impl ProtocolConfig for ProxyTlsConfig {
    type Commit = Proxy;
}

/// MPC-TLS commitment protocol.
#[derive(Debug)]
pub struct Mpc {}

/// Proxy-TLS commitment protocol.
#[derive(Debug)]
pub struct Proxy {}

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::MpcTlsConfig {}
    impl Sealed for super::ProxyTlsConfig {}
}

/// Test-only access to the production JSON grammar circuit.
#[cfg(feature = "security-test-support")]
pub mod security_test_support {
    /// Runs the pre-allocation commitment budget check used by the verifier.
    pub fn hash_budget(
        ranges: Vec<(crate::transcript::Direction, std::ops::Range<usize>)>,
        sent_len: usize,
        recv_len: usize,
    ) -> bool {
        let hashes: Vec<_> = ranges
            .into_iter()
            .map(|(direction, range)| {
                (
                    direction,
                    crate::rangeset::set::RangeSet::from(range),
                    crate::hash::HashAlgId::SHA256,
                )
            })
            .collect();
        crate::verifier::verify::check_hash_budget(hashes.iter(), sent_len, recv_len).is_ok()
    }
    /// Runs the production recording adapter against a bounded byte stream.
    pub fn proxy_records(wire: Vec<u8>, limit: usize) -> (bool, usize) {
        use futures::{AsyncReadExt, executor::block_on, io::Cursor};
        let mut captured = Vec::new();
        let accepted = {
            let mut reader =
                crate::proxy::InspectReader::new(Cursor::new(wire), &mut captured, limit);
            block_on(reader.read_to_end(&mut Vec::new())).is_ok()
        };
        (accepted, captured.len())
    }
    /// Runs mutations against the active MPC TLS 1.3 handshake check.
    pub fn handshake_mutations() -> Vec<bool> {
        mpc_tls::security_test_support::handshake_mutations()
    }
    /// Evaluates the production QuickSilver JSON string circuit in plaintext.
    pub fn json_string(data: &[u8]) -> bool {
        use tlsn_core::transcript::predicate::PredicateKind;
        if data.is_empty() {
            return true;
        }
        let circuit = crate::transcript_internal::predicate::build_circuit(
            data.len(),
            &PredicateKind::JsonStringContent,
        );
        let input: Vec<bool> = data
            .iter()
            .flat_map(|b| (0..8).map(move |i| (b >> i) & 1 == 1))
            .collect();
        circuit
            .evaluate(input)
            .expect("circuit evaluates")
            .iter()
            .enumerate()
            .fold(0u8, |acc, (i, &bit)| acc | (u8::from(bit) << i))
            == 1
    }
}
