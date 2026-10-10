//! Experimental HTTP/1.1 JSON presentation with offline parser context.
//!
//! The verifier rebuilds the complete relation from signed Bao ciphertext,
//! authenticated key commitments, public response headers and a caller's query.
//! Headers are disclosed in this first profile. Content-Length framing only:
//! chunking, compression, multiple responses and AES-256 sessions are rejected.
//! This API does not create a notary attestation or validate its TLS provenance.
use crate::{
    experimental::{self, Context},
    primitives::Parameters,
};
use anyhow::{ensure, Context as _, Result};
use bincode::Options;
use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::ops::Range;
use zkf_attestation::{records::Opening, Attestation, Bytes};
use zkf_ir::{byte_inputs, json_circuit::Selection, predicates::Comparison, Circuit};

// A conservative cap while the authenticated evaluator still retains all
// graph edges. Raising it requires a measured memory budget.
const MAX_DOCUMENT: usize = 1024;
const MAX_HEADERS: usize = 16384;

pub use zkf_attestation::response::RecordView;
pub use zkf_attestation::response::{JsonPathSegment, PathAnchor};

/// Public statement metadata. Positions disclose lengths, not hidden values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    pub headers: Vec<u8>,
    pub records: Vec<RecordView>,
    pub encoded_key: Vec<u8>,
    pub key: Range<usize>,
    pub colon: usize,
    pub value: Range<usize>,
    pub anchors: Vec<PathAnchor>,
    /// Public bound authenticated in the transcript; the verifier caps it at eight.
    pub max_depth: u8,
}

/// The relying party supplies this policy independently of the presentation.
/// Without `path`, `key` names a literal root member. Uniqueness is opt-in.
pub struct Query<'a> {
    pub server_name: &'a str,
    pub key: &'a str,
    pub path: &'a [JsonPathSegment],
    pub unique: bool,
    pub comparison: Comparison,
    pub constant: u64,
    pub nonce: [u8; 32],
}

/// Non-secret presentation components. Private keys are never serialized.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Presentation {
    pub statement: Statement,
    pub opening: Opening,
    pub proof: Vec<u8>,
}

const PRESENTATION_MAGIC: &[u8; 8] = b"zkf2prs\x06";

pub fn effective_path(q: &Query<'_>) -> Result<Vec<JsonPathSegment>> {
    let path = if q.path.is_empty() {
        vec![JsonPathSegment::Member(q.key.into())]
    } else {
        q.path.to_vec()
    };
    ensure!(
        path.len() <= 8
            && path.iter().all(|step| match step {
                JsonPathSegment::Member(name) => name.len() <= 1024,
                JsonPathSegment::Index(index) => *index < MAX_DOCUMENT,
            }),
        "JSON path exceeds depth or selector bounds"
    );
    ensure!(
        match path.last().unwrap() {
            JsonPathSegment::Member(name) => name == q.key,
            JsonPathSegment::Index(_) => q.key.is_empty(),
        },
        "key must match the path leaf (empty for an array index)"
    );
    Ok(path)
}
/// Bounds decoding before any proof work; proofs grow with the document.
pub const MAX_PRESENTATION_BYTES: usize = 32 << 20;

#[derive(Serialize, Deserialize)]
struct Wire {
    attestation: Vec<u8>,
    presentation: Presentation,
}

fn wire_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_PRESENTATION_BYTES as u64)
        .reject_trailing_bytes()
}

impl Presentation {
    /// `magic ‖ bincode(signed attestation envelope, presentation)`. The
    /// attestation travels with the proof; trust still comes from the verifier.
    pub fn encode(&self, signed_attestation: &[u8]) -> Result<Vec<u8>> {
        let mut out = PRESENTATION_MAGIC.to_vec();
        wire_options().serialize_into(
            &mut out,
            &Wire {
                attestation: signed_attestation.to_vec(),
                presentation: self.clone(),
            },
        )?;
        ensure!(
            out.len() <= MAX_PRESENTATION_BYTES,
            "presentation exceeds cap"
        );
        Ok(out)
    }

    /// Returns the signed attestation envelope and the presentation.
    pub fn decode(bytes: &[u8]) -> Result<(Vec<u8>, Self)> {
        ensure!(
            bytes.len() <= MAX_PRESENTATION_BYTES,
            "presentation exceeds cap"
        );
        let body = bytes
            .strip_prefix(PRESENTATION_MAGIC.as_slice())
            .ok_or_else(|| anyhow::anyhow!("not a v2 presentation"))?;
        let wire: Wire = wire_options()
            .deserialize(body)
            .context("invalid v2 presentation encoding")?;
        Ok((wire.attestation, wire.presentation))
    }

    /// Whether `bytes` carry the v2 presentation magic.
    pub fn is_v2(bytes: &[u8]) -> bool {
        bytes.starts_with(PRESENTATION_MAGIC)
    }
}

fn relation(
    a: &Attestation,
    statement: &Statement,
    opening: &Opening,
    query: &Query<'_>,
) -> Result<Circuit> {
    a.validate()?;
    ensure!(a.server.name == query.server_name, "server policy mismatch");
    ensure!(
        a.tls.suite == 0x1301,
        "SHA-384 session integration is not implemented"
    );
    ensure!(
        a.recv.complete && !a.recv.records.is_empty(),
        "complete response stream required"
    );
    ensure!(
        a.recv.records[0].seq == 0,
        "response must begin at application-epoch sequence zero"
    );
    ensure!(
        statement.records.len() == a.recv.records.len(),
        "record views must cover the signed stream"
    );
    ensure!(
        statement.headers.len() <= MAX_HEADERS,
        "response headers exceed cap"
    );
    ensure!(
        statement.encoded_key.len() <= 4096,
        "member encoding exceeds cap"
    );
    let path = effective_path(query)?;
    let path_profile = !query.path.is_empty() || query.unique;
    ensure!(
        statement.max_depth > 0 && statement.max_depth <= 8,
        "invalid JSON depth bound"
    );
    ensure!(
        path_profile || statement.max_depth == 4,
        "noncanonical root depth bound"
    );
    if path_profile {
        ensure!(
            path.len() <= statement.max_depth as usize,
            "path exceeds JSON depth bound"
        );
        ensure!(
            statement.anchors.len() == path.len(),
            "missing path anchors"
        );
        let last = statement.anchors.last().unwrap();
        ensure!(
            last.encoded_key == statement.encoded_key
                && last.key == statement.key
                && last.colon == statement.colon
                && last.value == statement.value,
            "leaf anchor mismatch"
        );
        for anchor in &statement.anchors {
            ensure!(
                anchor.value.start < anchor.value.end && anchor.value.end <= MAX_DOCUMENT,
                "path anchor outside document"
            );
        }
    } else {
        ensure!(statement.anchors.is_empty(), "unexpected path anchors");
    }
    if matches!(path.last(), Some(JsonPathSegment::Member(_))) {
        let decoded_key: String = serde_json::from_slice(&statement.encoded_key)?;
        ensure!(decoded_key == query.key, "member policy mismatch");
    }
    ensure!(
        opening.offset == 0 && opening.length == a.recv.len,
        "this context profile requires the whole ciphertext stream"
    );
    let ciphertext = opening.verify(&a.recv)?;
    let mut application_len = 0usize;
    for (record, view) in a.recv.records.iter().zip(&statement.records) {
        let inner_len = usize::from(record.len) - 16;
        ensure!(view.content_len < inner_len, "content type outside record");
        ensure!(
            matches!(view.inner_type, 0x15..=0x17),
            "unsupported inner record type"
        );
        if view.inner_type == 0x17 {
            application_len = application_len
                .checked_add(view.content_len)
                .ok_or_else(|| anyhow::anyhow!("response size overflow"))?;
        }
    }
    ensure!(
        application_len <= MAX_DOCUMENT + MAX_HEADERS,
        "response exceeds proof profile cap"
    );
    ensure!(
        application_len > statement.headers.len(),
        "missing JSON response body"
    );
    let body_len = application_len - statement.headers.len();
    ensure!(body_len <= MAX_DOCUMENT, "JSON document exceeds cap");
    verify_headers(&statement.headers, body_len)?;
    // Validate statement bounds before allocating the parser circuit.
    ensure!(
        (matches!(path.last(), Some(JsonPathSegment::Index(_)))
            || (statement.key.start < statement.key.end
                && statement.key.end <= body_len
                && statement.colon < body_len))
            && statement.value.start < statement.value.end
            && statement.value.end <= body_len,
        "member selection outside document"
    );
    let head = zkf_attestation::response::Head {
        headers: statement.headers.clone(),
        records: statement.records.clone(),
    };
    let signed_head = head.is_signed(&a.claims);
    // A mismatched reserved claim must fail, never fall back to another profile.
    ensure!(signed_head || !a.claims.iter().any(|claim| matches!(claim,
        zkf_attestation::Claim::Reveal {selector,..} if selector == zkf_attestation::response::HEAD_SELECTOR)), "signed response head differs");
    if path_profile {
        ensure!(
            statement.anchors.iter().all(|a| a.value.end <= body_len),
            "path anchor beyond body"
        );
    }
    zkf_ir::response::offline_relation_path(
        a.keys.c_server.0,
        &a.recv,
        &ciphertext,
        a.keys.iv_server.0,
        &head,
        signed_head,
        &Selection {
            encoded_key: &statement.encoded_key,
            key: statement.key.clone(),
            colon: statement.colon,
            value: statement.value.clone(),
        },
        query.comparison,
        query.constant,
        path_profile.then_some((
            path.as_slice(),
            statement.anchors.as_slice(),
            query.unique,
            statement.max_depth as usize,
        )),
    )
    .map_err(anyhow::Error::msg)
}

fn verify_headers(bytes: &[u8], body_len: usize) -> Result<()> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut response = httparse::Response::new(&mut headers);
    ensure!(
        response.parse(bytes)? == httparse::Status::Complete(bytes.len()),
        "incomplete or excess response headers"
    );
    ensure!(
        response.version == Some(1) && response.code == Some(200),
        "profile requires HTTP/1.1 200 response"
    );
    let mut length = None;
    let mut content_type = false;
    for header in response.headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            ensure!(length.is_none(), "duplicate Content-Length");
            let value = std::str::from_utf8(header.value)?;
            ensure!(
                !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
                "invalid Content-Length"
            );
            length = Some(value.parse::<usize>()?);
        } else if header.name.eq_ignore_ascii_case("content-type") {
            ensure!(!content_type, "duplicate Content-Type");
            let value = std::str::from_utf8(header.value)?;
            ensure!(
                value
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("application/json"),
                "JSON Content-Type required"
            );
            content_type = true;
        } else {
            ensure!(
                !header.name.eq_ignore_ascii_case("transfer-encoding")
                    && !header.name.eq_ignore_ascii_case("content-encoding"),
                "chunked or compressed response unsupported"
            );
        }
    }
    ensure!(
        content_type && length == Some(body_len),
        "response framing does not match complete JSON document"
    );
    Ok(())
}

/// Parses the wire name of a comparison ("eq", "ne", "lt", "le", "gt", "ge").
pub fn parse_comparison(op: &str) -> Result<Comparison> {
    Ok(match op {
        "eq" => Comparison::Eq,
        "ne" => Comparison::Ne,
        "lt" => Comparison::Lt,
        "le" => Comparison::Le,
        "gt" => Comparison::Gt,
        "ge" => Comparison::Ge,
        other => anyhow::bail!("unsupported comparison {other:?}"),
    })
}

fn context<'a>(a: &Attestation, q: &Query<'_>, binding: &'a [u8]) -> Result<Context<'a>> {
    Ok(Context {
        attestation_digest: a.digest()?,
        statement: binding,
        presentation_nonce: q.nonce,
    })
}
fn query_binding(q: &Query<'_>, statement: &Statement) -> Result<Vec<u8>> {
    let mut bytes = b"zkf/2/http-json/path-context-profile-6/bounded-depth-8\0".to_vec();
    for value in [q.server_name, q.key] {
        bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes.push(match q.comparison {
        Comparison::Eq => 0,
        Comparison::Ne => 1,
        Comparison::Lt => 2,
        Comparison::Le => 3,
        Comparison::Gt => 4,
        Comparison::Ge => 5,
    });
    bytes.extend_from_slice(&q.constant.to_le_bytes());
    let path = bincode::serialize(&q.path)?;
    bytes.extend_from_slice(&(path.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&path);
    bytes.push(u8::from(q.unique));
    let metadata = bincode::serialize(statement)?;
    bytes.extend_from_slice(&(metadata.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&metadata);
    Ok(bytes)
}

const SIGNED_CLAIM_PROOF: &[u8] = b"zkf/2/presentation/notary-signed-top-level-member/v2";
fn has_signed_claim(a: &Attestation, q: &Query<'_>) -> bool {
    let op = match q.comparison {
        Comparison::Eq => "eq",
        Comparison::Ne => "ne",
        Comparison::Lt => "lt",
        Comparison::Le => "le",
        Comparison::Gt => "gt",
        Comparison::Ge => "ge",
    };
    let claim = if q.path.is_empty() && !q.unique {
        zkf_attestation::response::member_claim(q.key, op, q.constant, q.nonce)
    } else {
        let Ok(path) = effective_path(q) else {
            return false;
        };
        zkf_attestation::response::path_member_claim(&path, q.unique, op, q.constant, q.nonce)
    };
    a.server.name == q.server_name && a.claims.contains(&claim)
}

/// Prove from a key kept locally after a verified D1 fetch. The caller still
/// owns the key and must zeroize its storage. This never generates an attestation.
pub fn prove(
    a: &Attestation,
    statement: Statement,
    opening: Opening,
    query: &Query<'_>,
    server_key: &[u8; 16],
    params: Parameters,
) -> Result<Presentation> {
    if has_signed_claim(a, query) {
        let head = zkf_attestation::response::Head {
            headers: statement.headers.clone(),
            records: statement.records.clone(),
        };
        ensure!(
            head.is_signed(&a.claims),
            "signed-claim response head mismatch"
        );
        let statement = Statement {
            headers: statement.headers,
            records: statement.records,
            encoded_key: Vec::new(),
            key: 0..0,
            colon: 0,
            value: 0..0,
            anchors: Vec::new(),
            max_depth: 4,
        };
        return Ok(Presentation {
            statement,
            opening: Opening {
                offset: 0,
                length: 0,
                proof: Vec::new(),
            },
            proof: SIGNED_CLAIM_PROOF.to_vec(),
        });
    }
    let mut profile = crate::profile::Lap::new();
    let c = relation(a, &statement, &opening, query)?;
    crate::profile::circuit(c.committed_bits(), c.constraint_count());
    profile.mark("present.relation");
    let witness = c.eval_checked(&byte_inputs(server_key))?;
    profile.mark("present.witness-evaluation");
    let binding = query_binding(query, &statement)?;
    let proof =
        experimental::prove_checked(&witness.checked(), params, &context(a, query, &binding)?)?;
    Ok(Presentation {
        statement,
        opening,
        proof,
    })
}

/// Verify with a pinned notary key and a separately supplied query/nonce.
/// Time/owner/context authorization is the relying party's existing policy.
pub fn verify(
    a: &Attestation,
    signature: &Bytes<64>,
    trusted_key: &VerifyingKey,
    presentation: &Presentation,
    query: &Query<'_>,
) -> Result<()> {
    a.verify_signature(signature, trusted_key)?;
    if presentation.proof == SIGNED_CLAIM_PROOF {
        ensure!(
            has_signed_claim(a, query),
            "signed session claim or verifier nonce mismatch"
        );
        ensure!(
            presentation.statement.encoded_key.is_empty()
                && presentation.statement.key == (0..0)
                && presentation.statement.colon == 0
                && presentation.statement.value == (0..0)
                && presentation.statement.anchors.is_empty(),
            "noncanonical signed-claim metadata"
        );
        let head = zkf_attestation::response::Head {
            headers: presentation.statement.headers.clone(),
            records: presentation.statement.records.clone(),
        };
        ensure!(
            head.is_signed(&a.claims),
            "signed-claim response head mismatch"
        );
        ensure!(
            presentation.opening.offset == 0
                && presentation.opening.length == 0
                && presentation.opening.proof.is_empty(),
            "noncanonical signed-claim opening"
        );
        a.validate()?;
        zkf_ir::response::body_len(&a.recv, &head).map_err(anyhow::Error::msg)?;
        return Ok(());
    }
    let mut profile = crate::profile::Lap::new();
    let c = relation(a, &presentation.statement, &presentation.opening, query)?;
    crate::profile::circuit(c.committed_bits(), c.constraint_count());
    profile.mark("verify.relation");
    let binding = query_binding(query, &presentation.statement)?;
    experimental::verify_profiled(&c, &presentation.proof, &context(a, query, &binding)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::{
        cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
        Aes128,
    };
    use aes_gcm::{
        aead::{Aead, Payload},
        Aes128Gcm, Nonce,
    };
    use k256::ecdsa::SigningKey;
    use zkf_attestation::{
        key_id, records::RecordStream, Binding, Handshake, Keys, Server, Tls, TranscriptHash,
    };
    use zkf_ir::{aes::ExpandedKey, tls};

    fn fixture() -> (Attestation, Statement, Opening, SigningKey) {
        fixture_body(br#"{"id":123}"#)
    }

    fn fixture_body(body: &[u8]) -> (Attestation, Statement, Opening, SigningKey) {
        fixture_body_padding(body, 0)
    }

    fn fixture_body_padding(
        body: &[u8],
        last_padding: u8,
    ) -> (Attestation, Statement, Opening, SigningKey) {
        let key = [7u8; 16];
        let native = Aes128::new_from_slice(&key).unwrap();
        let ck: Vec<_> = (1..=2)
            .flat_map(|i| {
                let mut block = GenericArray::clone_from_slice(&tls::commitment_block(i).unwrap());
                native.encrypt_block(&mut block);
                block.to_vec()
            })
            .collect();
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        let mut response = headers.clone();
        response.extend_from_slice(body);
        // Include a handshake control record before application data. It must
        // remain covered by the root/table and advance the nonce sequence.
        let contents = [
            (vec![4, 0, 0, 0], 0x16),
            (response[..40].to_vec(), 0x17),
            (response[40..].to_vec(), 0x17),
        ];
        let gcm = Aes128Gcm::new_from_slice(&key).unwrap();
        let mut records = Vec::new();
        let mut views = Vec::new();
        for (seq, (content, kind)) in contents.into_iter().enumerate() {
            views.push(RecordView {
                content_len: content.len(),
                inner_type: kind,
            });
            let mut inner = content;
            inner.push(kind);
            inner.extend_from_slice(&[if seq == 2 { last_padding } else { 0 }, 0]);
            let length = inner.len() + 16;
            let mut record = vec![23, 3, 3, (length >> 8) as u8, length as u8];
            let ciphertext = gcm
                .encrypt(
                    Nonce::from_slice(&tls::nonce([0; 12], seq as u64)),
                    Payload {
                        msg: &inner,
                        aad: &record,
                    },
                )
                .unwrap();
            record.extend_from_slice(&ciphertext);
            records.push(record);
        }
        let recv = RecordStream::new(&records, 0, true).unwrap();
        let signing = SigningKey::from_slice(&[3; 32]).unwrap();
        let a = Attestation {
            v: 2,
            alg: "secp256k1".into(),
            notary_key_id: key_id(signing.verifying_key()),
            sid: Bytes([1; 32]),
            time: 1234,
            mode: "proxy".into(),
            server: Server {
                name: "example.com".into(),
                dialed_ip: "1.1.1.1".into(),
                port: 443,
                spki_sha256: Bytes([2; 32]),
                chain_sha256: Bytes([3; 32]),
                cert_verified_by_notary: true,
            },
            tls: Tls {
                version: 0x0304,
                suite: 0x1301,
                group: 0x17,
                hrr: false,
            },
            handshake: Handshake {
                h_ch_sh: TranscriptHash::Sha256(Bytes([4; 32])),
                h_ch_sf: TranscriptHash::Sha256(Bytes([5; 32])),
            },
            sent: RecordStream::new(&[], 0, true).unwrap().direction,
            recv: recv.direction.clone(),
            keys: Keys {
                c_client: Bytes([0; 32]),
                c_server: Bytes(ck.try_into().unwrap()),
                iv_client: Bytes([0; 12]),
                iv_server: Bytes([0; 12]),
            },
            claims: vec![],
            binding: Binding {
                owner: None,
                context: None,
            },
        };
        let statement = Statement {
            headers,
            records: views,
            encoded_key: br#""id""#.to_vec(),
            key: 1..5,
            colon: 5,
            value: 6..9,
            anchors: Vec::new(),
            max_depth: 4,
        };
        let opening = recv.open(0, recv.direction.len).unwrap();
        (a, statement, opening, signing)
    }
    fn query() -> Query<'static> {
        Query {
            server_name: "example.com",
            key: "id",
            path: &[],
            unique: false,
            comparison: Comparison::Ge,
            constant: 100,
            nonce: [2; 32],
        }
    }

    fn path_statement(
        body: &[u8],
        mut statement: Statement,
        path: &[JsonPathSegment],
    ) -> Statement {
        let member = zkf_ir::json::values(body)
            .unwrap()
            .into_iter()
            .find(|v| v.path == path)
            .unwrap();
        let leaf = member.anchors.last().unwrap();
        statement.encoded_key = leaf.encoded_key.clone();
        statement.key = leaf.key.clone();
        statement.colon = leaf.colon;
        statement.value = leaf.value.clone();
        statement.max_depth = zkf_ir::json::required_depth(body).try_into().unwrap();
        statement.anchors = member.anchors;
        statement
    }

    #[test]
    #[ignore = "diagnostic benchmark, pre-soundness-margin"]
    fn benchmark_bounded_path_presentations() {
        let small = br#"{"streakData":{"longestStreak":{"length":123}},"other":{"longestStreak":{"length":123}},"length":999,"rows":[{"length":10},{"length":777}],"deep":{"a":{"b":{"c":{"d":{"e":{"f":{"g":456}}}}}}}}"#;
        // ZKF_PATH_BODY=1k: the claimed member sits after ~900 bytes of filler.
        let large = format!(
            r#"{{"pad":"{}","streakData":{{"longestStreak":{{"length":123}}}}}}"#,
            "x".repeat(950)
        );
        let body: &[u8] = if std::env::var("ZKF_PATH_BODY").as_deref() == Ok("1k") {
            large.as_bytes()
        } else {
            small
        };
        let path: Vec<_> = ["streakData", "longestStreak", "length"]
            .into_iter()
            .map(|s| JsonPathSegment::Member(s.into()))
            .collect();
        for signed in [false, true] {
            for unique in [false, true] {
                for params in [Parameters::Fast, Parameters::Small] {
                    let (mut a, base, opening, signing) = fixture_body(body);
                    if signed {
                        a.claims.push(
                            zkf_attestation::response::Head {
                                headers: base.headers.clone(),
                                records: base.records.clone(),
                            }
                            .claim(),
                        );
                    }
                    let signature = a.sign(&signing).unwrap();
                    let q = Query {
                        key: "length",
                        path: &path,
                        unique,
                        ..query()
                    };
                    let mut statement = path_statement(body, base, &path);
                    if !unique {
                        statement.max_depth = 3;
                    }
                    let c = relation(&a, &statement, &opening, &q).unwrap();
                    let started = std::time::Instant::now();
                    crate::profile::enable(std::env::var_os("ZKF_PATH_PROFILE").is_some());
                    let proof = prove(&a, statement, opening, &q, &[7; 16], params).unwrap();
                    let prove_ms = started.elapsed().as_secs_f64() * 1000.0;
                    if let Some(profile) = crate::profile::take() {
                        let stages: Vec<_> = profile.stages.iter().map(|s| format!("{}={:.1}", s.name, s.ms)).collect();
                        println!("path-profile {}", stages.join(" "));
                    }
                    let started = std::time::Instant::now();
                    verify(&a, &signature, signing.verifying_key(), &proof, &q).unwrap();
                    let verify_ms = started.elapsed().as_secs_f64() * 1000.0;
                    let signed_bytes =
                        zkf_attestation::SignedAttestation::sign(a.clone(), &signing)
                            .unwrap()
                            .encode()
                            .unwrap();
                    let encoded_bytes = proof.encode(&signed_bytes).unwrap().len();
                    println!("path-bench signed={signed} unique={unique} params={params:?} depth={} bits={} constraints={} proof_bytes={} presentation_bytes={} prove_ms={prove_ms:.3} verify_ms={verify_ms:.3}", proof.statement.max_depth, c.committed_bits(), c.constraint_count(), proof.proof.len(), encoded_bytes);
                }
            }
        }
    }

    #[test]
    fn nested_path_proof_binds_policy_ancestors_indices_and_uniqueness() {
        let body = br#"{"streakData":{"longestStreak":{"length":123}},"other":{"longestStreak":{"length":123}},"rows":[10,123]}"#;
        let path: Vec<_> = ["streakData", "longestStreak", "length"]
            .into_iter()
            .map(|s| JsonPathSegment::Member(s.into()))
            .collect();
        let (mut a, statement, opening, signing) = fixture_body(body);
        a.claims.push(
            zkf_attestation::response::Head {
                headers: statement.headers.clone(),
                records: statement.records.clone(),
            }
            .claim(),
        );
        let signature = a.sign(&signing).unwrap();
        let q = Query {
            key: "length",
            path: &path,
            unique: true,
            ..query()
        };
        let statement = path_statement(body, statement, &path);
        let proof = prove(&a, statement, opening, &q, &[7; 16], Parameters::Fast).unwrap();
        verify(&a, &signature, signing.verifying_key(), &proof, &q).unwrap();
        let other: Vec<_> = ["other", "longestStreak", "length"]
            .into_iter()
            .map(|s| JsonPathSegment::Member(s.into()))
            .collect();
        assert!(verify(
            &a,
            &signature,
            signing.verifying_key(),
            &proof,
            &Query { path: &other, ..q }
        )
        .is_err());
        assert!(verify(
            &a,
            &signature,
            signing.verifying_key(),
            &proof,
            &Query { unique: false, ..q }
        )
        .is_err());
        let mut changed_depth = proof.clone();
        changed_depth.statement.max_depth = 8;
        assert!(verify(&a, &signature, signing.verifying_key(), &changed_depth, &q).is_err());
        changed_depth.statement.max_depth = 9;
        assert!(verify(&a, &signature, signing.verifying_key(), &changed_depth, &q).is_err());
        let mut changed = proof.clone();
        changed.statement.anchors[0].value.start += 1;
        assert!(verify(&a, &signature, signing.verifying_key(), &changed, &q).is_err());
        let array_path = vec![
            JsonPathSegment::Member("rows".into()),
            JsonPathSegment::Index(1),
        ];
        let (a, statement, opening, signing) = fixture_body(body);
        let signature = a.sign(&signing).unwrap();
        let q = Query {
            key: "",
            path: &array_path,
            unique: false,
            ..query()
        };
        let proof = prove(
            &a,
            path_statement(body, statement, &array_path),
            opening,
            &q,
            &[7; 16],
            Parameters::Fast,
        )
        .unwrap();
        verify(&a, &signature, signing.verifying_key(), &proof, &q).unwrap();
        let wrong = vec![
            JsonPathSegment::Member("rows".into()),
            JsonPathSegment::Index(0),
        ];
        assert!(verify(
            &a,
            &signature,
            signing.verifying_key(),
            &proof,
            &Query { path: &wrong, ..q }
        )
        .is_err());
    }

    #[test]
    fn uniqueness_rejects_duplicate_path_names_with_alternative_escapes() {
        let body = br#"{"streakData":{"longestStreak":{"length":123,"\u006cength":123}}}"#;
        let path: Vec<_> = ["streakData", "longestStreak", "length"]
            .into_iter()
            .map(|s| JsonPathSegment::Member(s.into()))
            .collect();
        let (a, statement, opening, _) = fixture_body(body);
        let q = Query {
            key: "length",
            path: &path,
            unique: true,
            ..query()
        };
        assert!(prove(
            &a,
            path_statement(body, statement, &path),
            opening,
            &q,
            &[7; 16],
            Parameters::Fast
        )
        .is_err());
    }

    #[test]
    fn bounded_path_profiles_pin_the_complete_builder_graph() {
        let body = br#"{"streakData":{"longestStreak":{"length":123}}}"#;
        let path: Vec<_> = ["streakData", "longestStreak", "length"]
            .into_iter()
            .map(|s| JsonPathSegment::Member(s.into()))
            .collect();
        for depth in [3, 8] {
            for signed in [false, true] {
                for unique in [false, true] {
                    let (mut a, base, opening, _) = fixture_body(body);
                    if signed {
                        a.claims.push(
                            zkf_attestation::response::Head {
                                headers: base.headers.clone(),
                                records: base.records.clone(),
                            }
                            .claim(),
                        );
                    }
                    let mut statement = path_statement(body, base, &path);
                    statement.max_depth = depth;
                    let q = Query {
                        key: "length",
                        path: &path,
                        unique,
                        ..query()
                    };
                    let c = relation(&a, &statement, &opening, &q).unwrap();
                    assert_eq!(
                        c.profile(),
                        Some(if signed {
                            zkf_ir::response::OFFLINE_PATH_BODY_PROFILE
                        } else {
                            zkf_ir::response::OFFLINE_PATH_FULL_PROFILE
                        })
                    );
                    let digest = c
                        .digest()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>();
                    let expected = match (depth, signed, unique) {
                        (3, false, false) => {
                            "8f36128677e332104dc187c44e3abfde1211929b2bb28325f0f2106f5947096a"
                        }
                        (3, false, true) => {
                            "cc377b44db8ab64885e25ed0efe7342750afe282194211440ac6bafb391b643e"
                        }
                        (3, true, false) => {
                            "f3b99de28fef08663ced6fe1193382dfba88e14035c44bddd79b53c239b5c532"
                        }
                        (3, true, true) => {
                            "add44cdbcb42f0ada8b61a057373d00aaa20cd8db2611e65aa0286e8c216b5e0"
                        }
                        (8, false, false) => {
                            "1ce5559aafb9b086706922209fc219844f82b7168d56804754ba3109f252e3cb"
                        }
                        (8, false, true) => {
                            "47e6e3ba0760e4d19596a924c366c60a3094dad33327886c59822595de1c718c"
                        }
                        (8, true, false) => {
                            "a1fe3282ee52160a7c53f0ba9b4ccb09875620ce4698fe685aeba886712e5e16"
                        }
                        (8, true, true) => {
                            "72336809be44dff38729907738f2103cc37c4412adbdb81999427a92fa6b3d39"
                        }
                        _ => unreachable!(),
                    };
                    assert_eq!(digest, expected, "builder changed: bump its profile and review binding before updating the pin");
                }
            }
        }
    }

    #[test]
    fn registered_profiles_pin_the_complete_builder_graph() {
        let (mut a, statement, opening, _) = fixture();
        let c = relation(&a, &statement, &opening, &query()).unwrap();
        assert_eq!(
            c.profile(),
            Some("zkf/2/http-json/compact-aes/prefix/top-level/depth-4/full/v4")
        );
        assert_eq!(
            c.digest()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "4525481612bb09f664c2f57e77e6060ace44aa15ef5ecd556b9307b58f347f69",
            "builder changed: bump its profile and review the binding before updating the pin"
        );
        let head = zkf_attestation::response::Head {
            headers: statement.headers.clone(),
            records: statement.records.clone(),
        };
        a.claims.push(head.claim());
        let c = relation(&a, &statement, &opening, &query()).unwrap();
        assert_eq!(
            c.profile(),
            Some("zkf/2/http-json/compact-aes/prefix/top-level/depth-4/signed-head/v4")
        );
        assert_eq!(
            c.digest()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "ff26bc9f240e8d44f25214bf9247d5bdf2271c3c87bc9218100ec8f85120e258",
            "builder changed: bump its profile and review the binding before updating the pin"
        );
        let session = zkf_ir::response::session(
            a.keys.c_server.0,
            a.keys.c_server.0,
            &a.recv,
            &opening.verify(&a.recv).unwrap(),
            a.keys.iv_server.0,
            &head,
            &[],
        )
        .unwrap();
        assert_eq!(
            session.profile(),
            Some("zkf/2/session/standard-aes/prefix/member-or-path/v6")
        );
        assert_eq!(
            session
                .digest()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "f55898ef40695800d78bae29906245174e191db60bb40f59c5a9dea97bdaeb75",
            "builder changed: bump its profile and review the binding before updating the pin"
        );
        let keys = zkf_ir::tls::keys_commitment_statement([1; 32], [2; 32]);
        assert_eq!(
            keys.profile(),
            Some("zkf/2/session/standard-aes/both-key-commitments/v4")
        );
        assert_eq!(
            keys.digest()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "6bfc0ea7ab67386392728d42f551e56b3c368a40484cc1695c9f486cc27a07ef",
            "builder changed: bump its profile and review the binding before updating the pin"
        );
    }

    #[test]
    fn transcript_binds_offsets_even_for_identical_duplicate_values() {
        let body = br#"{"id":123,"id":123}"#;
        let (a, statement, opening, signing) = fixture_body(body);
        let mut p = prove(&a, statement, opening, &query(), &[7; 16], Parameters::Fast).unwrap();
        let second = zkf_ir::json::members(body).unwrap().pop().unwrap();
        p.statement.key = second.key_range.clone();
        p.statement.colon = second.key_range.end;
        p.statement.value = second.value_range;
        assert!(verify(
            &a,
            &a.sign(&signing).unwrap(),
            signing.verifying_key(),
            &p,
            &query()
        )
        .is_err());
    }

    #[test]
    fn session_claim_prefix_skips_tail_but_authenticates_record_padding() {
        let body = format!("{{\"id\":123,\"tail\":\"{}\"}}", "x".repeat(900));
        for padding in [0, 1] {
            let (a, statement, opening, _) = fixture_body_padding(body.as_bytes(), padding);
            let head = zkf_attestation::response::Head {
                headers: statement.headers.clone(),
                records: statement.records.clone(),
            };
            let claim = zkf_attestation::response::MemberClaim {
                member: "id".into(),
                op: "ge".into(),
                constant: 100,
                nonce: [31; 32],
                encoded_key: statement.encoded_key,
                key: statement.key,
                colon: statement.colon,
                value: statement.value,
                path: Vec::new(),
                unique: false,
                anchors: Vec::new(),
                max_depth: 4,
            };
            let c = zkf_ir::response::session(
                a.keys.c_server.0,
                a.keys.c_server.0,
                &a.recv,
                &opening.verify(&a.recv).unwrap(),
                a.keys.iv_server.0,
                &head,
                &[claim],
            )
            .unwrap();
            assert!(
                c.committed_bits() < 30_000,
                "session decrypted unselected tail: {} bits",
                c.committed_bits()
            );
            assert_eq!(c.eval_checked(&byte_inputs(&[7; 32])).is_ok(), padding == 0);
        }
    }

    #[test]
    fn nested_balance_cannot_satisfy_offline_or_signed_session_claim() {
        let body = br#"{"balance":10,"history":[{"balance":999999}]}"#;
        let (a, mut statement, opening, signing) = fixture_body(body);
        let q = Query {
            key: "balance",
            path: &[],
            unique: false,
            constant: 999999,
            ..query()
        };
        let members = zkf_ir::json::members(body).unwrap();
        for member in members.iter().filter(|m| m.key == "balance") {
            statement.encoded_key = body[member.key_range.clone()].to_vec();
            statement.key = member.key_range.clone();
            statement.colon = member.key_range.end;
            statement.value = member.value_range.clone();
            // The top-level value fails the threshold; the nested value fails depth.
            assert!(prove(
                &a,
                statement.clone(),
                opening.clone(),
                &q,
                &[7; 16],
                Parameters::Fast
            )
            .is_err());
            let head = zkf_attestation::response::Head {
                headers: statement.headers.clone(),
                records: statement.records.clone(),
            };
            let claim = zkf_attestation::response::MemberClaim {
                member: "balance".into(),
                op: "ge".into(),
                constant: 999999,
                nonce: q.nonce,
                encoded_key: statement.encoded_key.clone(),
                key: statement.key.clone(),
                colon: statement.colon,
                value: statement.value.clone(),
                path: Vec::new(),
                unique: false,
                anchors: Vec::new(),
                max_depth: 4,
            };
            let c = zkf_ir::response::session(
                a.keys.c_server.0,
                a.keys.c_server.0,
                &a.recv,
                &opening.verify(&a.recv).unwrap(),
                a.keys.iv_server.0,
                &head,
                &[claim],
            )
            .unwrap();
            assert!(c.eval(&byte_inputs(&[7; 32])).is_err());
            if member.object_depth == 0 {
                let low = Query { constant: 10, ..q };
                let proof = prove(
                    &a,
                    statement.clone(),
                    opening.clone(),
                    &low,
                    &[7; 16],
                    Parameters::Fast,
                )
                .unwrap();
                verify(
                    &a,
                    &a.sign(&signing).unwrap(),
                    signing.verifying_key(),
                    &proof,
                    &low,
                )
                .unwrap();
            }
        }
        // Old unscoped signed claims must not acquire top-level semantics.
        let mut old = a.clone();
        old.claims.push(zkf_attestation::Claim::Predicate {
            selector: format!("zkf/2/member/v1/{}/62616c616e6365", "02".repeat(32)),
            op: "ge".into(),
            constant: 999999,
            result: true,
        });
        assert!(!has_signed_claim(&old, &q));
    }

    #[test]
    fn signed_path_session_claim_binds_path_value_and_query() {
        let body = br#"{"streakData":{"longestStreak":{"length":123}},"other":{"longestStreak":{"length":7}}}"#;
        let path: Vec<_> = ["streakData", "longestStreak", "length"]
            .into_iter()
            .map(|s| JsonPathSegment::Member(s.into()))
            .collect();
        let (mut a, statement, opening, signing) = fixture_body(body);
        let head = zkf_attestation::response::Head {
            headers: statement.headers.clone(),
            records: statement.records.clone(),
        };
        let values = zkf_ir::json::values(body).unwrap();
        let find = |p: &[JsonPathSegment]| values.iter().find(|m| m.path == p).unwrap().clone();
        let claim_for = |member: &zkf_ir::json::Member, unique: bool, op: &str, constant: u64| {
            let leaf = member.anchors.last().unwrap().clone();
            zkf_attestation::response::MemberClaim {
                member: "length".into(),
                op: op.into(),
                constant,
                nonce: [9; 32],
                encoded_key: leaf.encoded_key.clone(),
                key: leaf.key.clone(),
                colon: leaf.colon,
                value: leaf.value.clone(),
                path: path.clone(),
                unique,
                anchors: member.anchors.clone(),
                max_depth: 3,
            }
        };
        let ciphertext = opening.verify(&a.recv).unwrap();
        let session = |claim: &zkf_attestation::response::MemberClaim| {
            zkf_ir::response::session(
                a.keys.c_server.0,
                a.keys.c_server.0,
                &a.recv,
                &ciphertext,
                a.keys.iv_server.0,
                &head,
                std::slice::from_ref(claim),
            )
            .and_then(|c| c.eval(&byte_inputs(&[7; 32])).map(|_| ()).map_err(|e| e.to_string()))
        };
        let selected = find(&path);
        for unique in [false, true] {
            let good = claim_for(&selected, unique, "eq", 123);
            session(&good).unwrap();
            assert!(session(&claim_for(&selected, unique, "eq", 124)).is_err());
        }
        // The sibling branch's anchors cannot satisfy the requested path.
        let mut sibling_path = path.clone();
        sibling_path[0] = JsonPathSegment::Member("other".into());
        let sibling = find(&sibling_path);
        assert!(session(&claim_for(&sibling, false, "eq", 7)).is_err());
        // A signed path claim answers exactly that path, nonce and uniqueness.
        let good = claim_for(&selected, true, "ge", 100);
        a.claims.push(head.claim());
        a.claims.push(good.claim());
        let q = Query {
            key: "length",
            path: &path,
            unique: true,
            comparison: Comparison::Ge,
            constant: 100,
            nonce: [9; 32],
            ..query()
        };
        assert!(has_signed_claim(&a, &q));
        let presentation = prove(&a, statement.clone(), opening.clone(), &q, &[7; 16], Parameters::Fast).unwrap();
        verify(&a, &a.sign(&signing).unwrap(), signing.verifying_key(), &presentation, &q).unwrap();
        assert!(!has_signed_claim(&a, &Query { unique: false, ..q }));
        assert!(!has_signed_claim(&a, &Query { nonce: [8; 32], ..q }));
        assert!(!has_signed_claim(&a, &Query { path: &sibling_path, ..q }));
    }

    #[test]
    fn prefix_skips_later_body_blocks_but_keeps_unsigned_suffix_checks() {
        let body = format!("{{\"id\":123,\"later\":\"{}\"}}", "a".repeat(900));
        let (a, statement, opening, signing) = fixture_body(body.as_bytes());
        let prefix = relation(&a, &statement, &opening, &query()).unwrap();
        let mut full = Circuit::default();
        let refs: Vec<_> = (0..16).map(|_| full.commit_byte()).collect();
        let key = ExpandedKey::new(&mut full, &refs).unwrap();
        let head = zkf_attestation::response::Head {
            headers: statement.headers.clone(),
            records: statement.records.clone(),
        };
        zkf_ir::response::decrypt(
            &mut full,
            &key,
            &a.recv,
            &opening.verify(&a.recv).unwrap(),
            a.keys.iv_server.0,
            &head,
            zkf_ir::response::Scope::Full,
        )
        .unwrap();
        assert!(prefix.committed_bits() < full.committed_bits() / 2);
        let proof = prove(
            &a,
            statement.clone(),
            opening.clone(),
            &query(),
            &[7; 16],
            Parameters::Fast,
        )
        .unwrap();
        verify(
            &a,
            &a.sign(&signing).unwrap(),
            signing.verifying_key(),
            &proof,
            &query(),
        )
        .unwrap();
        // Invalid padding in the last block must still fail even though that
        // block lies well after the selected value. Headers and views are unchanged.
        let (bad, bad_statement, bad_opening, _) = fixture_body_padding(body.as_bytes(), 1);
        assert!(relation(&bad, &bad_statement, &bad_opening, &query())
            .unwrap()
            .eval(&byte_inputs(&[7; 16]))
            .is_err());
    }

    #[test]
    fn signed_ciphertext_context_roundtrip_and_policy_mutations() {
        let (a, statement, opening, signing) = fixture();
        let signature = a.sign(&signing).unwrap();
        let p = prove(&a, statement, opening, &query(), &[7; 16], Parameters::Fast).unwrap();
        verify(&a, &signature, signing.verifying_key(), &p, &query()).unwrap();
        let mut q = query();
        q.nonce[0] ^= 1;
        assert!(verify(&a, &signature, signing.verifying_key(), &p, &q).is_err());
        let mut q = query();
        q.constant = 124;
        assert!(verify(&a, &signature, signing.verifying_key(), &p, &q).is_err());
        let mut q = query();
        q.key = "missing";
        assert!(verify(&a, &signature, signing.verifying_key(), &p, &q).is_err());
        let mut changed = a.clone();
        changed.recv.root.0[0] ^= 1;
        assert!(verify(&changed, &signature, signing.verifying_key(), &p, &query()).is_err());
        let mut bad = p;
        bad.opening.proof[8] ^= 1;
        assert!(verify(&a, &signature, signing.verifying_key(), &bad, &query()).is_err());
    }

    #[test]
    fn signed_head_saves_blocks_and_rejects_changed_views() {
        let (mut a, statement, opening, signing) = fixture();
        let baseline = relation(&a, &statement, &opening, &query())
            .unwrap()
            .committed_bits();
        let head = zkf_attestation::response::Head {
            headers: statement.headers.clone(),
            records: statement.records.clone(),
        };
        a.claims.push(head.claim());
        let optimized = relation(&a, &statement, &opening, &query())
            .unwrap()
            .committed_bits();
        assert!(optimized < baseline);
        let signature = a.sign(&signing).unwrap();
        let proof = prove(
            &a,
            statement.clone(),
            opening.clone(),
            &query(),
            &[7; 16],
            Parameters::Fast,
        )
        .unwrap();
        verify(&a, &signature, signing.verifying_key(), &proof, &query()).unwrap();
        let mut bad = statement;
        bad.records[0].content_len += 1;
        assert!(relation(&a, &bad, &opening, &query()).is_err());
    }
    #[test]
    fn signed_claim_is_bound_to_the_exact_query_and_nonce() {
        let (mut a, statement, opening, signing) = fixture();
        a.claims.push(
            zkf_attestation::response::Head {
                headers: statement.headers.clone(),
                records: statement.records.clone(),
            }
            .claim(),
        );
        a.claims.push(zkf_attestation::response::member_claim(
            "id",
            "ge",
            100,
            query().nonce,
        ));
        let signature = a.sign(&signing).unwrap();
        let p = prove(&a, statement, opening, &query(), &[7; 16], Parameters::Fast).unwrap();
        assert_eq!(p.proof, SIGNED_CLAIM_PROOF);
        verify(&a, &signature, signing.verifying_key(), &p, &query()).unwrap();
        let mut q = query();
        q.nonce[0] ^= 1;
        assert!(verify(&a, &signature, signing.verifying_key(), &p, &q).is_err());
        let mut q = query();
        q.constant += 1;
        assert!(verify(&a, &signature, signing.verifying_key(), &p, &q).is_err());
        let mut q = query();
        q.key = "other";
        assert!(verify(&a, &signature, signing.verifying_key(), &p, &q).is_err());
        let mut bad = p;
        bad.statement.colon = 1;
        assert!(verify(&a, &signature, signing.verifying_key(), &bad, &query()).is_err());
    }

    #[test]
    fn malformed_framing_wrong_key_and_record_omission_rejected() {
        let (a, statement, opening, _) = fixture();
        let c = relation(&a, &statement, &opening, &query()).unwrap();
        assert!(c.eval(&byte_inputs(&[8; 16])).is_err());
        let mut bad = statement.clone();
        bad.records.remove(0);
        assert!(relation(&a, &bad, &opening, &query()).is_err());
        let mut bad = statement.clone();
        bad.records[0].inner_type = 0x17;
        assert!(relation(&a, &bad, &opening, &query()).is_err());
        let mut bad = statement.clone();
        bad.headers.extend_from_slice(b"{}");
        assert!(relation(&a, &bad, &opening, &query()).is_err());
        for headers in [b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10\r\nContent-Length: 10\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10\r\nContent-Encoding: gzip\r\n\r\n"] {
            assert!(verify_headers(headers,10).is_err());
        }
    }
}
