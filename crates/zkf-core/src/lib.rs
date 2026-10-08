//! Shared types, wire framing and transport used by the zkfetch prover,
//! notary and verifier.

pub mod transport;
pub mod types;

pub use types::*;

/// Attestation extension carrying the owner (user public key / address).
pub const EXT_OWNER: &[u8] = b"zkf.owner";
/// Attestation extension carrying a verifier-supplied context / challenge.
pub const EXT_CONTEXT: &[u8] = b"zkf.context";
/// Attestation extension set by the notary (never the prover): `mpc` or `proxy`.
pub const EXT_MODE: &[u8] = b"zkf.mode";
/// Attestation extension set by the notary in proxy mode: the host it dialed.
/// Verifiers require it to equal the proven server name, so a proxy session
/// to one host cannot be presented as another host's data.
pub const EXT_SERVER: &[u8] = b"zkf.server";

/// Default preprocessing limits (bytes). MPC cost scales with these.
pub const DEFAULT_MAX_SENT: usize = 1 << 12;
pub const DEFAULT_MAX_RECV: usize = 1 << 14;
/// Default response limit in proxy mode, where nothing is preprocessed but
/// proving cost still grows with the response (1.3 MB takes minutes).
pub const DEFAULT_PROXY_MAX_RECV: usize = 1 << 18;

/// Upper bound accepted by the notary for a single framed message.
pub const MAX_FRAME_LEN: usize = 16 << 20;

pub mod b64 {
    use base64::{Engine, engine::general_purpose::STANDARD};

    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        STANDARD.encode(bytes)
    }

    pub fn decode(s: &str) -> anyhow::Result<Vec<u8>> {
        Ok(STANDARD.decode(s.trim())?)
    }
}
