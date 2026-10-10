//! Components for the TLS 1.3 MPC-TLS integration.
//!
//! Handshake record keys are public to both MPC participants. Application
//! records must use the MPC AEAD backend; this crate does not expose an
//! application-key API and is not yet wired into `zkFetch`.
pub mod handshake;
pub mod mpc_record;
pub mod record;
pub use zkf_tls13_schedule::{ApplicationKeys, HandshakeKeys, Mode, Role, Tls13KeySched};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod origo_validation;
