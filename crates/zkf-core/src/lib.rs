//! Shared types, wire framing and transport used by the zkfetch prover,
//! notary and verifier.

pub mod notary_auth;
pub mod parsing;
pub mod setup_pool;
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

/// Notary-owned SHA-256 of the verified TLS 1.3 certificate-binding transcript.
pub const EXT_HANDSHAKE: &[u8] = b"zkf.handshake";

/// Default preprocessing limits (bytes). MPC cost scales with these.
pub const DEFAULT_MAX_SENT: usize = 1 << 12;
pub const DEFAULT_MAX_RECV: usize = 1 << 14;
/// Default response limit in proxy mode, where nothing is preprocessed but
/// proving cost still grows with the response (1.3 MB takes minutes).
pub const DEFAULT_PROXY_MAX_RECV: usize = 1 << 18;

/// Upper bound accepted by the notary for a single framed message.
pub const MAX_FRAME_LEN: usize = 16 << 20;

/// Wire messages for v2 (D1) attestations between prover and notary.
pub mod d1 {
    use serde::{Deserialize, Serialize};

    /// Query parameter on the notary URL that selects a v2 attestation. The
    /// notary must know before the session which proof follows the TLS proof.
    pub const QUERY: (&str, &str) = ("attestation", "2");
    /// Mux stream carrying `SHA-256(binding) ‖ C_k(client) ‖ C_k(server)`,
    /// followed by a flow byte (7: profiled top-level signed claims/head, 8: profiled ciphertext-only) and any
    /// bounded metadata, before the combined key/framing proof.
    pub const KEYS_STREAM: &[u8] = b"zkfetch/d1/keys";
    pub const KEYS_FRAME_LEN: usize = 96;
    /// Same cap as the v1 owner/context extensions.
    pub const MAX_BINDING_LEN: usize = 256;

    /// The prover's attestation request, after the session proofs.
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct Request {
        pub owner: Option<String>,
        pub context: Option<String>,
    }
}

pub mod b64 {
    use base64::{Engine, engine::general_purpose::STANDARD};

    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        STANDARD.encode(bytes)
    }

    pub fn decode(s: &str) -> anyhow::Result<Vec<u8>> {
        Ok(STANDARD.decode(s.trim())?)
    }
}
