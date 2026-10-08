//! Predicate presentations: authenticated JSON structure + hidden scalar proofs.
//! The structure exposes keys, container shape and lengths, while values remain private.
mod circuit;
pub mod quicksilver;

use anyhow::{Context, Result, anyhow, bail, ensure};
use bincode::Options;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tlsn::{
    attestation::{Attestation, Secrets},
    hash::HashAlgId,
    rangeset::{ops::Set, set::RangeSet},
    transcript::{Direction, PartialTranscript, TranscriptCommitment, TranscriptSecret},
};
use tlsn_formats::{
    http::{BodyContent, parse_response},
    json::JsonValue,
};
use zkf_core::PredicateSpec;

pub const MAGIC: &[u8] = b"ZKFETCH-PREDICATES-V1\0";
pub const MAX_SCALARS: usize = 128;
pub const MAX_HIDDEN_BYTES: usize = 16 * 1024;
pub const MAX_PRESENTATION_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScalarKind {
    Atom,
    StringContent,
    UnsignedInteger,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalarClaim {
    pub idx: RangeSet<usize>,
    pub digest: [u8; 32],
    pub kind: ScalarKind,
    pub predicate: Option<PredicateSpec>,
}
impl ScalarClaim {
    pub fn len(&self) -> usize {
        self.idx.len()
    }
    pub fn is_empty(&self) -> bool {
        self.idx.is_empty()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Envelope {
    pub presentation: Vec<u8>,
    pub claims: Vec<ScalarClaim>,
    pub proof: Vec<u8>,
}

pub fn encode(
    presentation: Vec<u8>,
    claims: Vec<ScalarClaim>,
    witnesses: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let message = binding(&presentation, &claims)?;
    let proof = circuit::prove(&claims, witnesses, &message)?;
    let mut bytes = MAGIC.to_vec();
    bytes.extend(bincode::serialize(&Envelope {
        presentation,
        claims,
        proof,
    })?);
    ensure!(
        bytes.len() <= MAX_PRESENTATION_BYTES,
        "predicate presentation too large"
    );
    Ok(bytes)
}

pub fn decode(bytes: &[u8]) -> Result<Option<Envelope>> {
    if !bytes.starts_with(MAGIC) {
        return Ok(None);
    }
    ensure!(
        bytes.len() <= MAX_PRESENTATION_BYTES,
        "predicate presentation too large"
    );
    Ok(Some(
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_PRESENTATION_BYTES as u64)
            .reject_trailing_bytes()
            .deserialize(&bytes[MAGIC.len()..])
            .context("invalid predicate envelope")?,
    ))
}

fn binding(presentation: &[u8], claims: &[ScalarClaim]) -> Result<Vec<u8>> {
    let mut h = Sha256::new();
    h.update(MAGIC);
    h.update((presentation.len() as u64).to_be_bytes());
    h.update(presentation);
    h.update(bincode::serialize(claims)?);
    Ok(h.finalize().to_vec())
}

/// This serde adapter is deliberately isolated and pinned to alpha.15.
/// No unsafe layout assumptions or modifications to TLSNotary's cryptography.
pub fn commitments(attestation: &Attestation) -> Result<Vec<TranscriptCommitment>> {
    #[derive(Deserialize)]
    struct Field {
        data: TranscriptCommitment,
    }
    #[derive(Deserialize)]
    struct Body {
        transcript_commitments: Vec<Field>,
    }
    let body: Body = serde_json::from_value(serde_json::to_value(&attestation.body)?)?;
    Ok(body
        .transcript_commitments
        .into_iter()
        .map(|f| f.data)
        .collect())
}

fn commitment_secrets(secrets: &Secrets) -> Result<Vec<TranscriptSecret>> {
    #[derive(Deserialize)]
    struct View {
        transcript_commitment_secrets: Vec<TranscriptSecret>,
    }
    let view: View = serde_json::from_value(serde_json::to_value(secrets)?)?;
    Ok(view.transcript_commitment_secrets)
}

pub fn leaves<S: tlsn_formats::spansy::Store>(root: &JsonValue<S>) -> Vec<&JsonValue<S>> {
    match root {
        JsonValue::Object(o) => o.elems.iter().flat_map(|kv| leaves(&kv.value)).collect(),
        JsonValue::Array(a) => a.elems.iter().flat_map(leaves).collect(),
        _ => vec![root],
    }
}

pub fn structure<S: tlsn_formats::spansy::Store>(root: &JsonValue<S>) -> RangeSet<usize> {
    let mut idx = root.view().indices().clone();
    for value in leaves(root) {
        idx = idx.difference(value.view().indices()).collect();
    }
    idx
}

fn key(raw: &str) -> Result<String> {
    Ok(serde_json::from_str(&format!("\"{raw}\""))?)
}

pub fn validate_keys<S: tlsn_formats::spansy::Store>(root: &JsonValue<S>) -> Result<()> {
    match root {
        JsonValue::Object(o) => {
            let mut seen = std::collections::HashSet::new();
            for kv in &o.elems {
                ensure!(
                    seen.insert(key(&kv.key.view().as_str())?),
                    "duplicate JSON key"
                );
                validate_keys(&kv.value)?;
            }
        }
        JsonValue::Array(a) => {
            for v in &a.elems {
                validate_keys(v)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn resolve<'a, S: tlsn_formats::spansy::Store>(
    root: &'a JsonValue<S>,
    path: &str,
) -> Result<&'a JsonValue<S>> {
    ensure!(!path.is_empty(), "empty predicate path");
    let mut current = root;
    for part in path.split('.') {
        ensure!(!part.is_empty(), "empty path segment");
        current = match current {
            JsonValue::Object(o) => o
                .elems
                .iter()
                .find(|kv| key(&kv.key.view().as_str()).is_ok_and(|k| k == part))
                .map(|kv| &kv.value),
            JsonValue::Array(a) => part
                .parse::<usize>()
                .ok()
                .filter(|i| i.to_string() == part)
                .and_then(|i| a.elems.get(i)),
            _ => None,
        }
        .ok_or_else(|| anyhow!("JSON path `{path}` not found"))?;
    }
    Ok(current)
}

/// Prepare witnesses only for leaves not covered by the selected disclosure.
pub fn prepare(
    attestation: &Attestation,
    secrets: &Secrets,
    partial: &PartialTranscript,
    root: &JsonValue,
    specs: &[PredicateSpec],
) -> Result<(Vec<ScalarClaim>, Vec<Vec<u8>>)> {
    validate_keys(root)?;
    let commits = commitments(attestation)?;
    let blinders = commitment_secrets(secrets)?;
    let mut selected = std::collections::HashMap::new();
    for spec in specs {
        spec.predicate.minimum().map_err(anyhow::Error::msg)?;
        let value = resolve(root, &spec.json_path)?;
        ensure!(
            matches!(value, JsonValue::Number(_)),
            "predicate field must be a JSON number"
        );
        ensure!(
            selected
                .insert(value.view().indices().clone(), spec.clone())
                .is_none(),
            "duplicate predicate field"
        );
    }
    let mut claims = Vec::new();
    let mut witnesses = Vec::new();
    for value in leaves(root) {
        let idx = value.view().indices();
        if idx.is_empty() {
            continue;
        }
        if idx.is_subset(partial.received_authed()) {
            ensure!(
                !selected.contains_key(idx),
                "predicate value must remain hidden"
            );
            continue;
        }
        ensure!(
            idx.intersection(partial.received_authed()).next().is_none(),
            "partially revealed scalar"
        );
        let hash = commits
            .iter()
            .find_map(|c| match c {
                TranscriptCommitment::Hash(h)
                    if h.direction == Direction::Received
                        && h.idx == *idx
                        && h.hash.alg == HashAlgId::BLAKE3 =>
                {
                    Some(h)
                }
                _ => None,
            })
            .ok_or_else(|| {
                anyhow!("missing BLAKE3 commitment; fetch a new session to use Binius predicates")
            })?;
        let secret = blinders
            .iter()
            .find_map(|c| match c {
                TranscriptSecret::Hash(h)
                    if h.direction == Direction::Received
                        && h.idx == *idx
                        && h.alg == HashAlgId::BLAKE3 =>
                {
                    Some(h)
                }
                _ => None,
            })
            .ok_or_else(|| anyhow!("missing commitment blinder"))?;
        let predicate = selected.remove(idx);
        let kind = if predicate.is_some() {
            ScalarKind::UnsignedInteger
        } else if matches!(value, JsonValue::String(_)) {
            ScalarKind::StringContent
        } else {
            ScalarKind::Atom
        };
        let mut witness: Vec<_> = idx
            .iter()
            .flat_map(|r| secrets.transcript().received()[r].iter().copied())
            .collect();
        witness.extend_from_slice(secret.blinder.as_bytes());
        claims.push(ScalarClaim {
            idx: idx.clone(),
            digest: hash.hash.value.as_bytes().try_into()?,
            kind,
            predicate,
        });
        witnesses.push(witness);
    }
    ensure!(selected.is_empty(), "predicate value was not hidden");
    Ok((claims, witnesses))
}

/// Check signed digests, the complete JSON grammar, exact paths, then the ZK proof.
pub fn verify(
    envelope: &Envelope,
    attestation: &Attestation,
    partial: &PartialTranscript,
) -> Result<Vec<PredicateSpec>> {
    ensure!(
        !envelope.claims.is_empty() && envelope.claims.len() <= MAX_SCALARS,
        "invalid scalar count"
    );
    let commits = commitments(attestation)?;
    let mut claimed = RangeSet::default();
    let mut total_len = 0usize;
    let mut hidden = Vec::with_capacity(envelope.claims.len());
    for claim in &envelope.claims {
        total_len = total_len
            .checked_add(claim.len())
            .ok_or_else(|| anyhow!("length overflow"))?;
        ensure!(total_len <= MAX_HIDDEN_BYTES, "hidden data too large");
        ensure!(
            claim.idx.intersection(&claimed).next().is_none(),
            "overlapping scalar claims"
        );
        claimed.union_mut(&claim.idx);
        ensure!(commits.iter().any(|c| matches!(c, TranscriptCommitment::Hash(h)
            if h.direction == Direction::Received && h.idx == claim.idx && h.hash.alg == HashAlgId::BLAKE3
            && h.hash.value.as_bytes() == claim.digest)), "scalar is not bound to a signed BLAKE3 commitment");
        hidden.push(Hidden {
            idx: claim.idx.clone(),
            string: claim.kind == ScalarKind::StringContent,
        });
    }
    with_redacted_json(partial, &hidden, |root| {
        let mut used = std::collections::HashSet::new();
        for value in leaves(root) {
            let idx = value.view().indices();
            if idx.is_subset(partial.received_authed()) {
                continue;
            }
            let (i, claim) = envelope
                .claims
                .iter()
                .enumerate()
                .find(|(_, c)| c.idx == *idx)
                .ok_or_else(|| anyhow!("hidden JSON leaf lacks a scalar proof"))?;
            let string = matches!(value, JsonValue::String(_));
            ensure!(
                string == (claim.kind == ScalarKind::StringContent),
                "scalar type mismatch"
            );
            used.insert(i);
        }
        ensure!(
            used.len() == envelope.claims.len(),
            "claim outside response JSON body"
        );
        let mut predicates = Vec::new();
        let mut paths = std::collections::HashSet::new();
        for claim in &envelope.claims {
            if let Some(spec) = &claim.predicate {
                ensure!(paths.insert(&spec.json_path), "duplicate predicate path");
                ensure!(
                    resolve(root, &spec.json_path)?.view().indices() == &claim.idx,
                    "predicate path does not match signed scalar"
                );
                predicates.push(spec.clone());
            }
        }
        Ok(predicates)
    })
    .and_then(|predicates| {
        ensure!(
            !predicates.is_empty(),
            "predicate envelope contains no predicates"
        );
        circuit::verify(
            &envelope.claims,
            envelope.proof.clone(),
            &binding(&envelope.presentation, &envelope.claims)?,
        )?;
        Ok(predicates)
    })
}

/// A hidden JSON scalar: its received-transcript range and whether it is
/// string content (between quotes) or an atom.
pub(crate) struct Hidden {
    pub(crate) idx: RangeSet<usize>,
    pub(crate) string: bool,
}

/// Substitutes length-preserving, lexically valid placeholders for the hidden
/// scalars, then checks that everything else the parse depends on (HTTP
/// framing, header names, framing headers, the full JSON skeleton) is
/// authenticated, and finally hands the parsed JSON root to `f`.
///
/// Callers must already have established that each hidden range is a single
/// scalar of the stated kind (by ZK proof); that is what makes the
/// placeholder parse equal to the real parse.
pub(crate) fn with_redacted_json<T>(
    partial: &PartialTranscript,
    hidden: &[Hidden],
    f: impl FnOnce(&JsonValue<Vec<u8>>) -> Result<T>,
) -> Result<T> {
    let mut recv = partial.received_unsafe().to_vec();
    for h in hidden {
        ensure!(
            !h.idx.is_empty() && h.idx.end().unwrap_or(usize::MAX) <= recv.len(),
            "scalar range out of bounds"
        );
        ensure!(
            h.idx
                .intersection(partial.received_authed())
                .next()
                .is_none(),
            "scalar overlaps disclosed bytes"
        );
        // Length-preserving valid placeholders preserve exact span indices, including chunks.
        for r in h.idx.iter() {
            recv[r].fill(if h.string { b'x' } else { b'1' });
        }
    }
    // HTTP framing must itself be authenticated; verify this before trusting the parse.
    let len = recv.len();
    let response = parse_response::<Vec<u8>>(recv).context("invalid predicate response framing")?;
    ensure!(
        response.indices().end() == Some(len),
        "predicate response has trailing data"
    );
    ensure!(
        response.without_data().is_subset(partial.received_authed()),
        "unauthenticated response framing"
    );
    let mut framing_headers = std::collections::HashSet::new();
    for header in &response.headers {
        ensure!(
            header
                .without_value()
                .indices()
                .is_subset(partial.received_authed()),
            "unauthenticated header name"
        );
        if ["content-type", "content-length", "transfer-encoding"]
            .iter()
            .any(|n| header.name.as_str().eq_ignore_ascii_case(n))
        {
            ensure!(
                framing_headers.insert(header.name.as_str().to_ascii_lowercase()),
                "duplicate framing header"
            );
            ensure!(
                header.indices().is_subset(partial.received_authed()),
                "unauthenticated framing header"
            );
        }
    }
    ensure!(
        !(framing_headers.contains("content-length")
            && framing_headers.contains("transfer-encoding")),
        "ambiguous response framing"
    );
    let body = response
        .body
        .as_ref()
        .ok_or_else(|| anyhow!("missing JSON body"))?;
    let BodyContent::Json(doc) = &body.content else {
        bail!("predicate response must be JSON");
    };
    validate_keys(&doc.root)?;
    let mut skeleton = body.indices().clone();
    for leaf in leaves(&doc.root) {
        skeleton = skeleton.difference(leaf.view().indices()).collect();
    }
    ensure!(
        skeleton.is_subset(partial.received_authed()),
        "unauthenticated JSON structure"
    );
    f(&doc.root)
}

#[cfg(test)]
mod tests;
