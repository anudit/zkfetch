//! QuickSilver predicates (default backend).
//!
//! At notarization the prover proves to the notary, inside TLSNotary's
//! QuickSilver VM over the authenticated plaintext, that
//!
//! * every JSON leaf of the response is a lexically valid scalar (string
//!   content or atom), so any of them can later be hidden without changing how
//!   the visible JSON parses, and
//! * each requested numeric predicate holds (`value >= minimum`).
//!
//! The notary signs the verified claims as the [`EXT_QS`] attestation
//! extension. Presentations then only need to disclose the JSON skeleton;
//! verifiers bind predicates to paths offline with no further proof.
//!
//! Compared with the Binius64 backend, predicates must be chosen at fetch time
//! and are visible to anyone holding the attestation, but there is no
//! client-side SNARK and presentations stay small.

use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use tlsn::{
    attestation::Attestation,
    rangeset::{ops::Set, set::RangeSet},
    transcript::{
        Direction, PartialTranscript, PredicateKind, TranscriptPredicate,
        predicate::{MAX_PREDICATES, evaluate},
    },
};
use tlsn_formats::json::JsonValue;
use zkf_core::{Decimal, NumericPredicate, PredicateSpec};

use crate::{Hidden, leaves, resolve, validate_keys, with_redacted_json};

/// Attestation extension carrying [`AttestedPredicates`].
pub const EXT_QS: &[u8] = b"zkf.qs.v1";

/// Upper bound on the encoded extension.
pub const MAX_EXT_BYTES: usize = 1 << 20;

/// A requested predicate bound to a JSON path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathClaim {
    pub json_path: String,
    pub start: usize,
    pub end: usize,
    pub minimum: u64,
}

/// Claims proven to (and signed by) the notary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedPredicates {
    /// Exactly the predicates the notary verified, in order.
    pub predicates: Vec<TranscriptPredicate>,
    /// Requested numeric predicates and the paths they were resolved from.
    pub paths: Vec<PathClaim>,
}

impl AttestedPredicates {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let bytes = bincode::serialize(self)?;
        ensure!(bytes.len() <= MAX_EXT_BYTES, "predicate claims too large");
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        use bincode::Options;
        ensure!(bytes.len() <= MAX_EXT_BYTES, "predicate claims too large");
        Ok(bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_EXT_BYTES as u64)
            .reject_trailing_bytes()
            .deserialize(bytes)?)
    }

    /// Reads the claims from a verified attestation, if present.
    pub fn from_attestation(attestation: &Attestation) -> Result<Option<Self>> {
        attestation
            .body
            .extensions()
            .find(|e| e.id == EXT_QS)
            .map(|e| Self::decode(&e.value))
            .transpose()
    }
}

/// Plans the QuickSilver predicates for a JSON response body: a shape proof
/// for every non-empty leaf, with requested numeric predicates replacing the
/// shape proof of their leaf. `root` spans must be in received-transcript
/// coordinates and `recv` is the received transcript.
pub fn plan(root: &JsonValue, recv: &[u8], specs: &[PredicateSpec]) -> Result<AttestedPredicates> {
    validate_keys(root)?;
    let mut paths = Vec::with_capacity(specs.len());
    for spec in specs {
        let minimum = spec.predicate.minimum().map_err(anyhow::Error::msg)?;
        let value = resolve(root, &spec.json_path)?;
        ensure!(
            matches!(value, JsonValue::Number(_)),
            "predicate field `{}` must be a JSON number",
            spec.json_path
        );
        let range = single_range(value.view().indices())?;
        ensure!(
            !paths.iter().any(|p: &PathClaim| p.start == range.start),
            "duplicate predicate field `{}`",
            spec.json_path
        );
        let kind = PredicateKind::UintGte { minimum };
        ensure!(
            evaluate(&kind, &recv[range.clone()]),
            "predicate on `{}` does not hold (or the value is not an unsigned integer)",
            spec.json_path
        );
        paths.push(PathClaim {
            json_path: spec.json_path.clone(),
            start: range.start,
            end: range.end,
            minimum,
        });
    }

    let mut predicates = Vec::new();
    for leaf in leaves(root) {
        let idx = leaf.view().indices();
        if idx.is_empty() {
            continue; // empty string: nothing to hide
        }
        let range = single_range(idx)?;
        let kind = match paths.iter().find(|p| p.start == range.start) {
            Some(p) => PredicateKind::UintGte { minimum: p.minimum },
            None if matches!(leaf, JsonValue::String(_)) => PredicateKind::JsonStringContent,
            None => PredicateKind::JsonAtom,
        };
        ensure!(
            evaluate(&kind, &recv[range.clone()]),
            "JSON leaf at {range:?} is not a valid scalar"
        );
        predicates.push(TranscriptPredicate {
            direction: Direction::Received,
            range,
            kind,
        });
    }
    ensure!(
        predicates.len() <= MAX_PREDICATES,
        "response has too many JSON leaves for predicates ({} > {MAX_PREDICATES})",
        predicates.len()
    );
    Ok(AttestedPredicates { predicates, paths })
}

/// Verifies attested predicates against a disclosed transcript (unauthed
/// bytes must already be replaced, e.g. with `X`).
///
/// Predicates are reported only if every hidden leaf carries an attested shape
/// proof, the HTTP framing and JSON skeleton are authenticated, and every path
/// claim resolves to its attested range. With `strict == false` (verifiers) any
/// failure yields `Ok(vec![])`: nothing is reported, which is the safe outcome
/// because required predicates are enforced by policy. With `strict == true`
/// (the prover checking its own presentation) the cause is returned.
pub fn verify(
    claims: &AttestedPredicates,
    partial: &PartialTranscript,
    strict: bool,
) -> Result<Vec<PredicateSpec>> {
    if claims.paths.is_empty() {
        return Ok(Vec::new());
    }
    let shape = |range: &std::ops::Range<usize>| {
        claims
            .predicates
            .iter()
            .find(|p| p.direction == Direction::Received && p.range == *range)
            .map(|p| p.kind)
    };

    // Hidden ranges must each be a whole attested scalar.
    let authed = partial.received_authed();
    let mut hidden = Vec::new();
    for p in &claims.predicates {
        let idx = RangeSet::from(p.range.clone());
        if idx.is_subset(authed) {
            continue;
        }
        hidden.push(Hidden {
            idx,
            string: p.kind == PredicateKind::JsonStringContent,
        });
    }

    let result = with_redacted_json(partial, &hidden, |root| {
        for leaf in leaves(root) {
            let idx = leaf.view().indices();
            if idx.is_empty() || idx.is_subset(authed) {
                continue;
            }
            let range = single_range(idx)?;
            let kind =
                shape(&range).ok_or_else(|| anyhow!("hidden JSON leaf lacks an attested proof"))?;
            let string = matches!(leaf, JsonValue::String(_));
            ensure!(
                string == (kind == PredicateKind::JsonStringContent),
                "attested scalar type mismatch"
            );
        }
        let mut out = Vec::with_capacity(claims.paths.len());
        for path in &claims.paths {
            let range = path.start..path.end;
            ensure!(
                shape(&range)
                    == Some(PredicateKind::UintGte {
                        minimum: path.minimum
                    }),
                "path claim is not backed by a verified predicate"
            );
            ensure!(
                single_range(resolve(root, &path.json_path)?.view().indices())? == range,
                "predicate path does not match the attested range"
            );
            out.push(PredicateSpec {
                json_path: path.json_path.clone(),
                predicate: NumericPredicate {
                    gte: Some(Decimal::String(path.minimum.to_string())),
                    gt: None,
                },
            });
        }
        Ok(out)
    });

    match result {
        Ok(specs) => Ok(specs),
        Err(e) if strict => Err(e),
        Err(_) => Ok(Vec::new()),
    }
}

fn single_range(idx: &RangeSet<usize>) -> Result<std::ops::Range<usize>> {
    let mut it = idx.iter();
    let range = it.next().ok_or_else(|| anyhow!("empty JSON span"))?;
    ensure!(
        it.next().is_none(),
        "JSON scalar spans multiple ranges (chunked encoding split)"
    );
    Ok(range)
}
