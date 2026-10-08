//! JSON-facing types shared with the TypeScript SDK. Binary blobs are base64.

use serde::{Deserialize, Serialize};

/// Parameters for a notarized fetch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizeParams {
    /// Notary WebSocket URL, e.g. `ws://127.0.0.1:7047`.
    pub notary_url: String,
    /// Target `https://` URL.
    pub url: String,
    #[serde(default)]
    pub method: Option<String>,
    /// Extra request headers. `Host`, `Connection` and `Accept-Encoding` are
    /// managed by zkfetch.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body: Option<String>,
    /// Dial this `host:port` instead of the URL's host (testing / fixtures).
    /// The URL host is still used for SNI and certificate verification.
    #[serde(default)]
    pub connect_addr: Option<String>,
    /// Additional trusted root CAs (base64 DER), e.g. the fixture CA.
    #[serde(default)]
    pub extra_root_certs: Vec<String>,
    #[serde(default)]
    pub max_sent: Option<usize>,
    #[serde(default)]
    pub max_recv: Option<usize>,
    /// Bound into the attestation as the `zkf.owner` extension.
    #[serde(default)]
    pub owner: Option<String>,
    /// Bound into the attestation as the `zkf.context` extension.
    #[serde(default)]
    pub context: Option<String>,
    /// Numeric predicates proven to the notary with QuickSilver during
    /// notarization (default backend) and signed into the attestation.
    #[serde(default)]
    pub predicates: Vec<PredicateSpec>,
    /// Also add per-leaf SHA-256 commitments so predicates can later be proven
    /// offline with Binius64 (opt-in; increases notarization cost).
    #[serde(default)]
    pub binius: bool,
    /// TLS version: "1.3", "1.2" or "auto" (default). "auto" tries TLS 1.3 and
    /// falls back to TLS 1.2 for idempotent requests (GET/HEAD/OPTIONS).
    #[serde(default)]
    pub tls_version: Option<String>,
    /// Commitment protocol: "mpc" (default) or "proxy". In proxy mode the
    /// notary dials the server and relays the prover's TLS traffic; the prover
    /// then proves the session keys in zero knowledge. Much less traffic than
    /// MPC, but trusts the notary-to-server network path.
    #[serde(default)]
    pub mode: Option<String>,
    /// Browser builds, MPC mode: WebSocket-to-TCP relay for the prover's
    /// connection to the server.
    #[serde(default)]
    pub relay_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpResponseView {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// Wall-clock milliseconds per notarization phase.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizeTimings {
    /// WebSocket connect to the notary.
    pub notary_connect_ms: f64,
    /// MPC setup + preprocessing (OT/garbling) before touching the server.
    pub setup_ms: f64,
    /// TCP connect, MPC-TLS handshake, request/response and decryption.
    pub tls_ms: f64,
    /// Transcript commitments proven to the notary (ZK).
    pub prove_ms: f64,
    /// Attestation request -> signed attestation -> local validation.
    pub attest_ms: f64,
    pub total_ms: f64,
}

/// Result of notarization. `secrets` is sensitive: it opens every commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizeOutput {
    pub attestation: String,
    pub secrets: String,
    pub response: HttpResponseView,
    pub notary_key: KeyView,
    pub timings: NotarizeTimings,
    /// Negotiated TLS version ("1.2" or "1.3").
    pub tls_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestReveal {
    /// Reveal the request target (path + query). Method, version and header
    /// names are always revealed.
    #[serde(default = "yes")]
    pub target: bool,
    /// Header names (case-insensitive) whose values are revealed.
    /// `host`, `accept-encoding` and `connection` are always revealed.
    #[serde(default)]
    pub headers: Vec<String>,
    #[serde(default)]
    pub body: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseReveal {
    /// Header names (case-insensitive) whose values are revealed. Framing
    /// headers (content-length, transfer-encoding, content-type) always are.
    #[serde(default)]
    pub headers: Vec<String>,
    /// Reveal the entire body.
    #[serde(default)]
    pub body: bool,
    /// Reveal `"key": value` for these dotted JSON paths (e.g. `meta.version`).
    #[serde(default)]
    pub json_paths: Vec<String>,
}

/// What to disclose in a presentation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealSpec {
    #[serde(default)]
    pub request: RequestReveal,
    #[serde(default)]
    pub response: ResponseReveal,
    /// Predicates over hidden unsigned JSON integers (at most 19 digits).
    #[serde(default)]
    pub prove: Vec<PredicateSpec>,
    /// Backend for `prove`. QuickSilver (default) discloses predicates the
    /// notary already verified at fetch time; Binius64 proves them now, offline.
    #[serde(default)]
    pub backend: PredicateBackend,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PredicateBackend {
    #[default]
    Quicksilver,
    Binius,
}

/// Decimal strings avoid JavaScript's loss of precision above 2^53.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decimal {
    String(String),
    Number(u64),
}

// JSON accepts strings or numbers; bincode needs an explicit enum tag.
impl Serialize for Decimal {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            return match self {
                Self::String(s) => serializer.serialize_str(s),
                Self::Number(n) => serializer.serialize_u64(*n),
            };
        }
        match self {
            Self::String(s) => serializer.serialize_newtype_variant("Decimal", 0, "String", s),
            Self::Number(n) => serializer.serialize_newtype_variant("Decimal", 1, "Number", n),
        }
    }
}

impl<'de> Deserialize<'de> for Decimal {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            #[derive(Deserialize)]
            #[serde(untagged)]
            enum JsonDecimal {
                String(String),
                Number(u64),
            }
            return Ok(match JsonDecimal::deserialize(deserializer)? {
                JsonDecimal::String(s) => Self::String(s),
                JsonDecimal::Number(n) => Self::Number(n),
            });
        }
        #[derive(Deserialize)]
        enum BinaryDecimal {
            String(String),
            Number(u64),
        }
        Ok(match BinaryDecimal::deserialize(deserializer)? {
            BinaryDecimal::String(s) => Self::String(s),
            BinaryDecimal::Number(n) => Self::Number(n),
        })
    }
}

impl Decimal {
    pub fn value(&self) -> Result<u64, String> {
        match self {
            Self::Number(n) => Ok(*n),
            Self::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
                s.parse().map_err(|_| "threshold exceeds u64".into())
            }
            _ => Err("threshold must be an unsigned decimal integer".into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PredicateSpec {
    pub json_path: String,
    pub predicate: NumericPredicate,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NumericPredicate {
    #[serde(default)]
    pub gte: Option<Decimal>,
    #[serde(default)]
    pub gt: Option<Decimal>,
}

impl Serialize for NumericPredicate {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let binary = !serializer.is_human_readable();
        let count =
            usize::from(binary || self.gte.is_some()) + usize::from(binary || self.gt.is_some());
        let mut s = serializer.serialize_struct("NumericPredicate", count)?;
        if binary || self.gte.is_some() {
            s.serialize_field("gte", &self.gte)?;
        }
        if binary || self.gt.is_some() {
            s.serialize_field("gt", &self.gt)?;
        }
        s.end()
    }
}

impl NumericPredicate {
    pub fn minimum(&self) -> Result<u64, String> {
        match (&self.gte, &self.gt) {
            (Some(n), None) => n.value(),
            (None, Some(n)) => n
                .value()?
                .checked_add(1)
                .ok_or("gt threshold exceeds u64".into()),
            _ => Err("predicate must specify exactly one of gte or gt".into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KeyView {
    pub alg: String,
    pub key: String,
}

/// Options for verifying a presentation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyOptions {
    /// Accepted notary keys (hex). Empty means "report, don't enforce".
    #[serde(default)]
    pub trusted_notary_keys: Vec<String>,
    /// Additional trusted root CAs (base64 DER).
    #[serde(default)]
    pub extra_root_certs: Vec<String>,
    #[serde(default)]
    pub expected_owner: Option<String>,
    #[serde(default)]
    pub expected_context: Option<String>,
    /// Required claims; prevents acceptance of a proof with missing/weaker predicates.
    #[serde(default)]
    pub expected_predicates: Vec<PredicateSpec>,
}

/// Verified, redacted view of a presentation. Unrevealed bytes are `X`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyOutput {
    pub server_name: String,
    pub time: u64,
    pub tls_version: String,
    pub notary_key: KeyView,
    pub notary_trusted: bool,
    pub sent: String,
    pub recv: String,
    pub owner: Option<String>,
    pub context: Option<String>,
    /// Claims checked against authenticated JSON paths and Binius64 ZK proofs.
    pub predicates: Vec<PredicateSpec>,
}

impl Default for RequestReveal {
    fn default() -> Self {
        Self {
            target: true,
            headers: Vec::new(),
            body: false,
        }
    }
}

fn yes() -> bool {
    true
}
