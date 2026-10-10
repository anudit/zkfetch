//! Presentation building: maps a [`RevealSpec`] onto transcript ranges.

use anyhow::{Context, Result, anyhow, bail};
use bincode::Options;
use tlsn::{
    attestation::{Attestation, CryptoProvider, Secrets, presentation::Presentation},
    rangeset::set::RangeSet,
};
use tlsn_formats::{
    http::{BodyContent, HttpTranscript},
    spansy::json::JsonValue,
};
use zkf_core::{PredicateBackend, RevealSpec, b64};
use zkf_predicates::quicksilver::AttestedPredicates;

/// Request headers zkfetch sets itself; their values carry no user data.
const MANAGED_REQUEST_HEADERS: &[&str] = &["host", "accept-encoding", "connection"];

/// Response headers always revealed so the verifier can parse the framing.
const FRAMING_HEADERS: &[&str] = &["content-length", "transfer-encoding", "content-type"];

/// Builds a base64 presentation from base64 attestation + secrets.
pub fn present(attestation_b64: &str, secrets_b64: &str, spec: &RevealSpec) -> Result<String> {
    let attestation: Attestation = decode_input(attestation_b64).context("invalid attestation")?;
    let secrets: Secrets = decode_input(secrets_b64).context("invalid secrets")?;

    zkf_core::parsing::check_http_json_nesting(secrets.transcript().sent())?;
    zkf_core::parsing::check_http_json_nesting(secrets.transcript().received())?;
    let transcript = HttpTranscript::parse(secrets.transcript())?;
    let mut builder = secrets.transcript_proof_builder();

    let shape_proofs = AttestedPredicates::from_attestation(&attestation)?.is_some();
    let units = disclosure_units(&transcript, spec, shape_proofs)?;
    let sent = units.sent();
    let recv = units.recv();
    if !sent.is_empty() {
        builder.reveal_sent(&sent).context(UNCOMMITTED)?;
    }
    if !recv.is_empty() {
        builder.reveal_recv(&recv).context(UNCOMMITTED)?;
    }
    #[cfg(feature = "legacy-binius")]
    let response = transcript
        .responses
        .first()
        .ok_or_else(|| anyhow!("no HTTP response"))?;

    let transcript_proof = builder.build().context(UNCOMMITTED)?;
    let provider = CryptoProvider::default();
    let predicate_data: Option<(Vec<zkf_predicates::ScalarClaim>, Vec<Vec<u8>>)> =
        if spec.prove.is_empty() {
            None
        } else {
            let commitments = zkf_predicates::commitments(&attestation)?;
            let mut partial = transcript_proof.clone().verify_with_provider(
                &provider.hash,
                &secrets.transcript().length(),
                &commitments,
            )?;
            match spec.backend {
                PredicateBackend::Quicksilver => {
                    // Predicates were proven to the notary at fetch time; the
                    // presentation only discloses the JSON skeleton.
                    let claims =
                    AttestedPredicates::from_attestation(&attestation)?.ok_or_else(|| {
                        anyhow!(
                            "attestation has no QuickSilver predicates; pass zkConfig.predicates \
                         when fetching, or use backend \"binius\""
                        )
                    })?;
                    partial.set_unauthed(b'X');
                    let proven = zkf_predicates::quicksilver::verify(&claims, &partial, true)?;
                    for wanted in &spec.prove {
                        // Same rule as the Binius backend: a predicate is about a
                        // hidden value, so its value must not also be disclosed.
                        if let Some(path) = claims
                            .paths
                            .iter()
                            .find(|p| p.json_path == wanted.json_path)
                        {
                            use tlsn::rangeset::ops::Set;
                            let idx = RangeSet::from(path.start..path.end);
                            if idx.intersection(partial.received_authed()).next().is_some() {
                                bail!("predicate value `{}` must remain hidden", wanted.json_path);
                            }
                        }
                        let minimum = wanted.predicate.minimum().map_err(anyhow::Error::msg)?;
                        let ok = proven.iter().any(|p| {
                            p.json_path == wanted.json_path
                                && p.predicate.minimum().is_ok_and(|m| m >= minimum)
                        });
                        if !ok {
                            bail!(
                                "predicate on `{}` (>= {minimum}) was not attested at fetch time",
                                wanted.json_path
                            );
                        }
                    }
                    None
                }
                #[cfg(feature = "legacy-binius")]
                PredicateBackend::Binius => {
                    let BodyContent::Json(doc) = &response.body.as_ref().unwrap().content else {
                        unreachable!()
                    };
                    Some(zkf_predicates::prepare(
                        &attestation,
                        &secrets,
                        &partial,
                        &doc.root,
                        &spec.prove,
                    )?)
                }
            }
        };
    let mut presentation = attestation.presentation_builder(&provider);
    presentation
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);
    let presentation: Presentation = presentation.build()?;

    let bytes = bincode::serialize(&presentation)?;
    let bytes = match predicate_data {
        Some((claims, witnesses)) => zkf_predicates::encode(bytes, claims, &witnesses)?,
        None => bytes,
    };
    Ok(b64::encode(bytes))
}

const UNCOMMITTED: &str = "the presentation discloses bytes that were not committed at fetch time; \
     a session fetched with `reveal` can disclose only what that spec selected, \
     or less by whole headers, fields, target or body";

/// What a [`RevealSpec`] discloses, as independently openable units per
/// direction. `present` reveals their union; a fetch with `reveal` commits
/// each unit separately, so a later presentation may drop whole units.
pub(crate) struct DisclosureUnits {
    pub(crate) sent: Vec<RangeSet<usize>>,
    pub(crate) recv: Vec<RangeSet<usize>>,
}

impl DisclosureUnits {
    fn sent(&self) -> RangeSet<usize> {
        union(&self.sent)
    }

    fn recv(&self) -> RangeSet<usize> {
        union(&self.recv)
    }

    /// Makes the units pairwise disjoint (each keeps only the bytes no
    /// earlier unit covers) and drops empty ones, so each byte is hashed once.
    pub(crate) fn disjoint(self) -> Self {
        Self {
            sent: disjoint_units(self.sent),
            recv: disjoint_units(self.recv),
        }
    }
}

fn union(units: &[RangeSet<usize>]) -> RangeSet<usize> {
    let mut all = RangeSet::default();
    for unit in units {
        all.union_mut(unit);
    }
    all
}

fn disjoint_units(units: Vec<RangeSet<usize>>) -> Vec<RangeSet<usize>> {
    use tlsn::rangeset::ops::Set;
    let mut seen = RangeSet::default();
    let mut out = Vec::new();
    for unit in units {
        let unit: RangeSet<usize> = unit.difference(&seen).collect();
        if !unit.is_empty() {
            seen.union_mut(&unit);
            out.push(unit);
        }
    }
    out
}

/// The JSON skeleton: body bytes that are not scalar leaves.
pub(crate) fn skeleton(body: &tlsn_formats::http::Body, doc: &JsonValue) -> RangeSet<usize> {
    use tlsn::rangeset::ops::Set;
    let mut structure = body.indices().clone();
    for leaf in zkf_predicates::leaves(doc) {
        structure = structure.difference(leaf.view().indices()).collect();
    }
    structure
}

/// Maps `spec` onto transcript ranges. The first unit of each direction is
/// what every presentation reveals (HTTP structure, method, header names,
/// managed and framing headers); the JSON skeleton, when needed, comes next.
pub(crate) fn disclosure_units(
    transcript: &HttpTranscript,
    spec: &RevealSpec,
    shape_proofs: bool,
) -> Result<DisclosureUnits> {
    // Request: structure, method, header names and managed headers are always revealed.
    let request = transcript
        .requests
        .first()
        .ok_or_else(|| anyhow!("no HTTP request"))?;
    let mut base: RangeSet<usize> = request.without_data().into();
    let mut sent = Vec::new();
    if spec.request.target {
        sent.push(request.request.target.indices().clone());
    }
    for header in &request.headers {
        let name = header.name.as_str().to_ascii_lowercase();
        if MANAGED_REQUEST_HEADERS.contains(&name.as_str()) {
            base.union_mut(header.indices());
        } else {
            base.union_mut(header.without_value().indices());
            if contains(&spec.request.headers, &name) {
                sent.push(header.indices().clone());
            }
        }
    }
    if spec.request.body
        && let Some(body) = &request.body
    {
        sent.push(body.indices().clone());
    }
    sent.insert(0, base);

    // Response: status line, structure and framing headers always revealed.
    let response = transcript
        .responses
        .first()
        .ok_or_else(|| anyhow!("no HTTP response"))?;
    let mut base: RangeSet<usize> = response.without_data().into();
    let mut recv = Vec::new();
    for header in &response.headers {
        let name = header.name.as_str().to_ascii_lowercase();
        if FRAMING_HEADERS.contains(&name.as_str()) {
            base.union_mut(header.indices());
        } else {
            base.union_mut(header.without_value().indices());
            if contains(&spec.response.headers, &name) {
                recv.push(header.indices().clone());
            }
        }
    }

    // With attested shape proofs, disclosing JSON fields also reveals the
    // skeleton (keys and punctuation, not values) so the verifier can prove
    // each value's path. Without it a disclosure proves bytes, not a path.
    anyhow::ensure!(
        !spec.response.byte_only || spec.prove.is_empty(),
        "byteOnly cannot be combined with path predicates"
    );
    let mut structure = None;
    if let Some(body) = &response.body {
        if !spec.prove.is_empty()
            || (shape_proofs && !spec.response.byte_only && !spec.response.json_paths.is_empty())
        {
            let BodyContent::Json(doc) = &body.content else {
                bail!("predicates require a JSON response");
            };
            structure = Some(skeleton(body, &doc.root));
        }
        if spec.response.body {
            recv.push(body.indices().clone());
        } else if !spec.response.json_paths.is_empty() {
            let BodyContent::Json(doc) = &body.content else {
                bail!("jsonPaths requested but the response body is not JSON");
            };
            zkf_predicates::validate_keys(&doc.root)?;
            for path in &spec.response.json_paths {
                recv.push(
                    json_key_value(&doc.root, path)
                        .ok_or_else(|| anyhow!("json path `{path}` not found"))?,
                );
            }
        }
    } else if spec.response.body || !spec.response.json_paths.is_empty() || !spec.prove.is_empty() {
        bail!("response has no body");
    }
    if let Some(structure) = structure.filter(|s| !s.is_empty()) {
        recv.insert(0, structure);
    }
    recv.insert(0, base);
    Ok(DisclosureUnits { sent, recv })
}

fn contains(list: &[String], name: &str) -> bool {
    list.iter().any(|h| h.eq_ignore_ascii_case(name))
}

/// Ranges for `"key": value` at a dotted path. Array elements (numeric
/// segments) reveal the value only.
fn json_key_value(root: &JsonValue, path: &str) -> Option<RangeSet<usize>> {
    let (parent, last) = match path.rsplit_once('.') {
        Some((parent, last)) => (root.get(parent)?, last),
        None => (root, path),
    };
    match parent {
        JsonValue::Object(obj) => obj
            .elems
            .iter()
            .find(|kv| kv.key == last)
            .map(|kv| kv.view().indices().clone()),
        JsonValue::Array(_) => parent.get(last).map(|v| v.view().indices().clone()),
        _ => None,
    }
}

fn decode_input<T: serde::de::DeserializeOwned>(encoded: &str) -> Result<T> {
    let limit = zkf_core::MAX_FRAME_LEN;
    anyhow::ensure!(
        encoded.len() <= limit.div_ceil(3) * 4,
        "session input too large"
    );
    let bytes = b64::decode(encoded)?;
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(limit as u64)
        .reject_trailing_bytes()
        .deserialize(&bytes)?)
}
