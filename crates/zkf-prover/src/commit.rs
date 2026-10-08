//! Transcript commitment strategy.
//!
//! Same as tlsn's `DefaultHttpCommitter`, except JSON arrays also get a
//! commitment per element (tlsn alpha.15 commits arrays only as a whole; see the
//! TODO in `tlsn-formats` `commit_array`). Without this, nothing nested inside
//! an array (e.g. `users.0.username`) can be revealed on its own.

use tlsn::{
    hash::HashAlgId,
    transcript::{Direction, TranscriptCommitConfigBuilder, TranscriptCommitmentKind},
};
use tlsn_formats::{
    http::{Body, BodyContent, HttpCommit, HttpCommitError, MessageKind, Request, Response},
    json::{Array, JsonCommit, JsonCommitError, JsonValue},
};

#[derive(Default)]
pub struct JsonCommitter;

impl JsonCommit for JsonCommitter {
    fn commit_array(
        &mut self,
        builder: &mut TranscriptCommitConfigBuilder,
        array: &Array,
        direction: Direction,
    ) -> Result<(), JsonCommitError> {
        builder
            .commit(array, direction)
            .map_err(|e| JsonCommitError::new_with_source("failed to commit array", e))?;
        if array.elems.is_empty() {
            return Ok(());
        }
        builder
            .commit(array.without_values(), direction)
            .map_err(|e| JsonCommitError::new_with_source("failed to commit array structure", e))?;
        for value in &array.elems {
            self.commit_value(builder, value, direction)?;
        }
        Ok(())
    }
}

/// HTTP committer. The JSON skeleton (body minus scalar leaves) is always
/// committed as one range so presentations can disclose structure for
/// path-bound predicates; per-leaf BLAKE3 commitments are only added for the
/// opt-in Binius64 backend.
#[derive(Default)]
pub struct HttpCommitter {
    pub binius: bool,
}

fn commit_body(
    builder: &mut TranscriptCommitConfigBuilder,
    direction: Direction,
    kind: MessageKind,
    body: &Body,
    binius: bool,
) -> Result<(), HttpCommitError> {
    match &body.content {
        BodyContent::Json(doc) => {
            commit_json(builder, direction, kind, &doc.root)?;
            if direction == Direction::Received {
                let mut structure = body.indices().clone();
                use tlsn::rangeset::ops::Set;
                for value in zkf_predicates::leaves(&doc.root) {
                    structure = structure.difference(value.view().indices()).collect();
                    if binius && !value.view().indices().is_empty() {
                        builder
                            .commit_with_kind(
                                value.view().indices(),
                                direction,
                                TranscriptCommitmentKind::Hash {
                                    alg: HashAlgId::BLAKE3,
                                },
                            )
                            .map_err(|e| {
                                HttpCommitError::new_with_source(
                                    kind,
                                    "failed to commit scalar for predicates",
                                    e,
                                )
                            })?;
                    }
                }
                if !structure.is_empty() {
                    builder.commit(&structure, direction).map_err(|e| {
                        HttpCommitError::new_with_source(kind, "failed to commit JSON structure", e)
                    })?;
                }
            }
            Ok(())
        }
        _ => builder
            .commit(body, direction)
            .map(|_| ())
            .map_err(|e| HttpCommitError::new_with_source(kind, "failed to commit body", e)),
    }
}

fn commit_json(
    builder: &mut TranscriptCommitConfigBuilder,
    direction: Direction,
    kind: MessageKind,
    root: &JsonValue,
) -> Result<(), HttpCommitError> {
    JsonCommitter
        .commit_value(builder, root, direction)
        .map_err(|e| HttpCommitError::new_with_source(kind, "failed to commit to JSON body", e))
}

impl HttpCommit for HttpCommitter {
    fn commit_request_body(
        &mut self,
        builder: &mut TranscriptCommitConfigBuilder,
        direction: Direction,
        _parent: &Request,
        body: &Body,
    ) -> Result<(), HttpCommitError> {
        commit_body(builder, direction, MessageKind::Request, body, self.binius)
    }

    fn commit_response_body(
        &mut self,
        builder: &mut TranscriptCommitConfigBuilder,
        direction: Direction,
        _parent: &Response,
        body: &Body,
    ) -> Result<(), HttpCommitError> {
        commit_body(builder, direction, MessageKind::Response, body, self.binius)
    }
}
