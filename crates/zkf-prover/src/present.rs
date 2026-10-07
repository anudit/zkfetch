//! Presentation building: maps a [`RevealSpec`] onto transcript ranges.

use anyhow::{Context, Result, anyhow, bail};
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
    let attestation: Attestation =
        bincode::deserialize(&b64::decode(attestation_b64)?).context("invalid attestation")?;
    let secrets: Secrets =
        bincode::deserialize(&b64::decode(secrets_b64)?).context("invalid secrets")?;

    let transcript = HttpTranscript::parse(secrets.transcript())?;
    let mut builder = secrets.transcript_proof_builder();

    // Request: structure, method, header names and managed headers are always revealed.
    let request = transcript
        .requests
        .first()
        .ok_or_else(|| anyhow!("no HTTP request"))?;
    builder.reveal_sent(request.without_data())?;
    if spec.request.target {
        builder.reveal_sent(request.request.target.indices().clone())?;
    }
    for header in &request.headers {
        let name = header.name.as_str().to_ascii_lowercase();
        if MANAGED_REQUEST_HEADERS.contains(&name.as_str())
            || contains(&spec.request.headers, &name)
        {
            builder.reveal_sent(header.indices().clone())?;
        } else {
            builder.reveal_sent(header.without_value().indices().clone())?;
        }
    }
    if spec.request.body
        && let Some(body) = &request.body
    {
        builder.reveal_sent(body.indices().clone())?;
    }

    // Response: status line, structure and framing headers always revealed.
    let response = transcript
        .responses
        .first()
        .ok_or_else(|| anyhow!("no HTTP response"))?;
    builder.reveal_recv(response.without_data())?;
    for header in &response.headers {
        let name = header.name.as_str().to_ascii_lowercase();
        if FRAMING_HEADERS.contains(&name.as_str()) || contains(&spec.response.headers, &name) {
            builder.reveal_recv(header.indices().clone())?;
        } else {
            builder.reveal_recv(header.without_value().indices().clone())?;
        }
    }

    if let Some(body) = &response.body {
        if !spec.prove.is_empty() {
            let BodyContent::Json(doc) = &body.content else {
                bail!("predicates require a JSON response");
            };
            let mut structure = body.indices().clone();
            use tlsn::rangeset::ops::Set;
            for leaf in zkf_predicates::leaves(&doc.root) {
                structure = structure.difference(leaf.view().indices()).collect();
            }
            if !structure.is_empty() {
                builder.reveal_recv(structure)?;
            }
        }
        if spec.response.body {
            builder.reveal_recv(body.indices().clone())?;
        } else if !spec.response.json_paths.is_empty() {
            let BodyContent::Json(doc) = &body.content else {
                bail!("jsonPaths requested but the response body is not JSON");
            };
            for path in &spec.response.json_paths {
                let ranges = json_key_value(&doc.root, path)
                    .ok_or_else(|| anyhow!("json path `{path}` not found"))?;
                builder.reveal_recv(ranges)?;
            }
        }
    } else if spec.response.body || !spec.response.json_paths.is_empty() || !spec.prove.is_empty() {
        bail!("response has no body");
    }

    let transcript_proof = builder.build()?;
    let provider = CryptoProvider::default();
    let predicate_data = if spec.prove.is_empty() {
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
