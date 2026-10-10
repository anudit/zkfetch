//! Experimental v2 (D1) attestations.
//!
//! The notary signs ciphertext roots and AES commitments to the session's
//! application keys, `C_k = AES_k(ρ1) ‖ AES_k(ρ2)`, after the prover proves in
//! the session that each `C_k` opens to the key the TLS schedule derived. No
//! plaintext is committed. Claims are proven later, offline, with
//! VOLE-in-the-Head against the signed ciphertext ([`present_v2`]).

use aes::{
    Aes128,
    cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
};
use aes_gcm::{
    Aes128Gcm, Nonce,
    aead::{Aead, Payload},
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use bincode::Options;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tlsn::{
    SessionHandle, config::prove::ProveConfig, prover::Prover, prover::state::Committed,
    transcript::Direction,
};
use zeroize::{Zeroize, ZeroizeOnDrop};
use zkf_attestation::{SignedAttestation, records::RecordStream, session_binding};
use zkf_core::{PresentV2Request, b64, transport};
use zkf_voleith::{
    presentation::{self, Query, RecordView, Statement},
    primitives::Parameters,
};

const SECRETS_MAGIC: &[u8; 8] = b"zkf2sec\x01";
/// Two record streams at the 8 MiB stream cap, plus keys and framing.
const MAX_SECRETS_BYTES: u64 = 17 << 20;

/// What the prover keeps from a v2 session. As sensitive as v1 secrets: the
/// keys decrypt the recorded session.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct SecretsV2 {
    client_key: [u8; 16],
    server_key: [u8; 16],
    /// Complete application-epoch wire records, as relayed.
    sent: Vec<Vec<u8>>,
    recv: Vec<Vec<u8>>,
}

fn secrets_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_SECRETS_BYTES)
        .reject_trailing_bytes()
}

impl SecretsV2 {
    pub(crate) fn encode(&self) -> Result<String> {
        let mut out = SECRETS_MAGIC.to_vec();
        secrets_options().serialize_into(&mut out, self)?;
        let encoded = b64::encode(&out);
        out.zeroize();
        Ok(encoded)
    }

    fn decode(secrets_b64: &str) -> Result<Self> {
        let mut bytes = b64::decode(secrets_b64)?;
        let result = bytes
            .strip_prefix(SECRETS_MAGIC.as_slice())
            .ok_or_else(|| anyhow!("not v2 session secrets"))
            .and_then(|body| Ok(secrets_options().deserialize(body)?));
        bytes.zeroize();
        result
    }
}

/// `AES_k(ρ1) ‖ AES_k(ρ2)` with the fixed zero-counter blocks.
fn key_commitment(key: &[u8; 16]) -> [u8; 32] {
    let cipher = Aes128::new_from_slice(key).expect("16-byte key");
    let mut out = [0; 32];
    for (i, half) in out.chunks_mut(16).enumerate() {
        let mut block = GenericArray::from(
            zkf_ir::tls::commitment_block(i as u8 + 1).expect("fixed commitment index"),
        );
        cipher.encrypt_block(&mut block);
        half.copy_from_slice(&block);
    }
    out
}

/// The fields of the attestation this prover expects, from its own view.
pub(crate) struct Expected {
    sent: zkf_attestation::records::Direction,
    recv: zkf_attestation::records::Direction,
    iv_client: [u8; 12],
    iv_server: [u8; 12],
    hello_hash: [u8; 32],
    application_hash: [u8; 32],
    c_client: [u8; 32],
    c_server: [u8; 32],
    metadata: Option<zkf_attestation::response::SessionMetadata>,
}

/// The session part of a v2 fetch: prove the server identity (and with it the
/// TLS schedule), then prove both key commitments and public response framing
/// in one transcript-challenged relation within the batched proof flight.
pub(crate) async fn prove(
    prover: &mut Prover<Committed>,
    handle: &SessionHandle,
    low_latency: bool,
    params: &zkf_core::NotarizeParams,
) -> Result<(SecretsV2, Expected)> {
    let mut config = ProveConfig::builder(prover.transcript());
    config.server_identity();
    prover.prove(&config.build()?).await?;
    let _ = low_latency; // The combined proof remains in the batched flight.

    let epoch = prover
        .application_epoch_ciphertext()
        .ok_or_else(|| anyhow!("v2 attestations need a TLS 1.3 proxy session"))?;
    let sent = RecordStream::new(&epoch.sent, 0, true)?;
    let recv = RecordStream::new(&epoch.received, 0, true)?;
    let binding = session_binding(
        &sent.direction,
        &recv.direction,
        &epoch.iv_client,
        &epoch.iv_server,
        &epoch.hello_hash,
        &epoch.application_hash,
    );
    let keys = prover
        .application_key_secrets()
        .ok_or_else(|| anyhow!("application keys were not retained"))?;
    let secrets = SecretsV2 {
        client_key: *keys.key(Direction::Sent),
        server_key: *keys.key(Direction::Received),
        sent: epoch.sent.clone(),
        recv: epoch.received.clone(),
    };
    let metadata = if params.signed_response_head || !params.session_claims.is_empty() {
        let (head, body) = response_head(&secrets.recv, &secrets.server_key, epoch.iv_server)?;
        let mut claims = Vec::new();
        ensure!(params.session_claims.len() <= 16, "too many session claims");
        if !params.session_claims.is_empty() {
            let nonce = parse_nonce(
                params
                    .session_claim_nonce
                    .as_deref()
                    .ok_or_else(|| anyhow!("sessionClaims require sessionClaimNonce"))?,
            )?;
            let members = zkf_ir::json::members(&body)?;
            for predicate in &params.session_claims {
                ensure!(
                    predicate.path.is_empty() && !predicate.unique,
                    "path and uniqueness claims currently require offline presentation"
                );
                let member = members
                    .iter()
                    .find(|m| {
                        m.object_depth == 0
                            && m.key == predicate.key
                            && !body[m.value_range.clone()].is_empty()
                            && body[m.value_range.clone()].iter().all(u8::is_ascii_digit)
                    })
                    .ok_or_else(|| anyhow!("session member not found"))?;
                let colon = member.key_range.end
                    + body[member.key_range.end..]
                        .iter()
                        .position(|b| *b == b':')
                        .ok_or_else(|| anyhow!("member has no colon"))?;
                claims.push(zkf_attestation::response::MemberClaim {
                    member: predicate.key.clone(),
                    op: predicate.op.clone(),
                    constant: predicate.value.value().map_err(anyhow::Error::msg)?,
                    nonce,
                    encoded_key: body[member.key_range.clone()].to_vec(),
                    key: member.key_range.clone(),
                    colon,
                    value: member.value_range.clone(),
                });
            }
        }
        Some(zkf_attestation::response::SessionMetadata { head, claims })
    } else {
        None
    };
    let expected = Expected {
        sent: sent.direction,
        recv: recv.direction,
        iv_client: epoch.iv_client,
        iv_server: epoch.iv_server,
        hello_hash: epoch.hello_hash,
        application_hash: epoch.application_hash,
        c_client: key_commitment(&secrets.client_key),
        c_server: key_commitment(&secrets.server_key),
        metadata,
    };

    let mut frame = Sha256::digest(&binding).to_vec();
    frame.extend_from_slice(&expected.c_client);
    frame.extend_from_slice(&expected.c_server);
    frame.push(if expected.metadata.is_some() { 11 } else { 12 });
    if let Some(metadata) = &expected.metadata {
        frame.extend_from_slice(&bincode::serialize(metadata)?);
    }
    let mut stream = handle.application_stream(zkf_core::d1::KEYS_STREAM)?;
    transport::write_frame(&mut stream, &frame).await?;
    let ciphertext: Vec<_> = secrets.recv.iter().flatten().copied().collect();
    let statement = if let Some(metadata) = &expected.metadata {
        zkf_ir::response::session(
            expected.c_client,
            expected.c_server,
            &expected.recv,
            &ciphertext,
            expected.iv_server,
            &metadata.head,
            &metadata.claims,
        )
        .map_err(anyhow::Error::msg)?
    } else {
        zkf_ir::tls::keys_commitment_statement(expected.c_client, expected.c_server)
    };
    let mut keys = zeroize::Zeroizing::new(Vec::from(secrets.client_key));
    keys.extend_from_slice(&secrets.server_key);
    let witness = statement.eval(&zkf_ir::byte_inputs(&keys))?;
    let mut binding = binding;
    binding.extend_from_slice(&frame[32..96]);
    binding.push(if expected.metadata.is_some() { 11 } else { 12 });
    if let Some(metadata) = &expected.metadata {
        binding.extend_from_slice(&bincode::serialize(metadata)?);
    }
    prover
        .prove_application_keys_relation(&statement, &witness, &binding)
        .await
        .context("combined key-commitment proof failed")?;
    Ok((secrets, expected))
}

/// Decodes the notary's reply and checks it signs exactly this session.
pub(crate) fn accept(
    reply: &[u8],
    expected: &Expected,
    host: &str,
    request: &zkf_core::d1::Request,
    expected_notary_key: Option<&str>,
) -> Result<SignedAttestation> {
    let signed = SignedAttestation::decode(reply).context("invalid v2 attestation from notary")?;
    signed.verify(&signed.claimed_key)?;
    if let Some(pin) = expected_notary_key {
        ensure!(
            hex::decode(pin)? == signed.claimed_key.to_encoded_point(true).as_bytes(),
            "attestation key differs from the interactive notary pin"
        );
    }
    let a = &signed.attestation;
    a.validate()?;
    ensure!(
        a.server.name.eq_ignore_ascii_case(host)
            && a.sent == expected.sent
            && a.recv == expected.recv
            && a.keys.c_client.0 == expected.c_client
            && a.keys.c_server.0 == expected.c_server
            && a.keys.iv_client.0 == expected.iv_client
            && a.keys.iv_server.0 == expected.iv_server
            && a.handshake.h_ch_sh
                == zkf_attestation::TranscriptHash::Sha256(zkf_attestation::Bytes(
                    expected.hello_hash
                ))
            && a.handshake.h_ch_sf
                == zkf_attestation::TranscriptHash::Sha256(zkf_attestation::Bytes(
                    expected.application_hash
                ))
            && a.binding.owner == request.owner
            && a.binding.context == request.context
            && a.claims
                == expected
                    .metadata
                    .as_ref()
                    .map(|metadata| std::iter::once(metadata.head.claim())
                        .chain(metadata.claims.iter().map(|claim| claim.claim()))
                        .collect::<Vec<_>>())
                    .unwrap_or_default(),
        "notary returned an attestation inconsistent with this session"
    );
    Ok(signed)
}

/// The public response head is disclosed to the notary in the optimized
/// flow. Refuse cookies before sending it, rather than only at presentation.
fn response_head(
    raws: &[Vec<u8>],
    key: &[u8; 16],
    iv: [u8; 12],
) -> Result<(zkf_attestation::response::Head, zeroize::Zeroizing<Vec<u8>>)> {
    let gcm = Aes128Gcm::new_from_slice(key)?;
    let mut records = Vec::new();
    let mut application = zeroize::Zeroizing::new(Vec::new());
    for (seq, raw) in raws.iter().enumerate() {
        let inner = zeroize::Zeroizing::new(
            gcm.decrypt(
                Nonce::from_slice(&zkf_ir::tls::nonce(iv, seq as u64)),
                Payload {
                    msg: &raw[5..],
                    aad: &raw[..5],
                },
            )
            .map_err(|_| anyhow!("record decryption failed"))?,
        );
        let content_len = inner
            .iter()
            .rposition(|b| *b != 0)
            .ok_or_else(|| anyhow!("missing content type"))?;
        let inner_type = inner[content_len];
        if inner_type == 0x17 {
            application.extend_from_slice(&inner[..content_len]);
        }
        records.push(RecordView {
            content_len,
            inner_type,
        });
    }
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut parsed = httparse::Response::new(&mut headers);
    let httparse::Status::Complete(length) = parsed.parse(&application)? else {
        bail!("incomplete response head");
    };
    ensure!(
        !parsed
            .headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case("set-cookie")),
        "optimized v2 discloses response headers to the notary; Set-Cookie is refused"
    );
    let head = zkf_attestation::response::Head {
        headers: application[..length].to_vec(),
        records,
    };
    let body = zeroize::Zeroizing::new(application[length..].to_vec());
    Ok((head, body))
}

/// Builds a v2 presentation: a VOLE-in-the-Head proof that the signed
/// ciphertext decrypts, under the committed server key, to an HTTP/1.1 200
/// JSON response whose member `predicate.key` satisfies the comparison.
///
/// This first profile discloses the response head (status line and every
/// header) and nothing of the body or request. Content-Length framing only,
/// JSON bodies up to 1 KiB.
pub fn present_v2(
    attestation_b64: &str,
    secrets_b64: &str,
    request: &PresentV2Request,
) -> Result<String> {
    let signed_bytes = b64::decode(attestation_b64)?;
    let signed = SignedAttestation::decode(&signed_bytes)?;
    let a = &signed.attestation;
    let secrets = SecretsV2::decode(secrets_b64)?;

    let recv = RecordStream::new(&secrets.recv, 0, true)?;
    ensure!(
        recv.direction == a.recv,
        "these secrets do not belong to this attestation"
    );
    let gcm = Aes128Gcm::new_from_slice(&secrets.server_key).expect("16-byte key");
    let mut records = Vec::with_capacity(secrets.recv.len());
    let mut application = zeroize::Zeroizing::new(Vec::new());
    for (seq, raw) in secrets.recv.iter().enumerate() {
        let nonce = zkf_ir::tls::nonce(a.keys.iv_server.0, seq as u64);
        let inner = zeroize::Zeroizing::new(
            gcm.decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &raw[5..],
                    aad: &raw[..5],
                },
            )
            .map_err(|_| anyhow!("record {seq} does not decrypt under the session key"))?,
        );
        let content_len = inner
            .iter()
            .rposition(|&b| b != 0)
            .ok_or_else(|| anyhow!("record {seq} has no content type"))?;
        let inner_type = inner[content_len];
        if inner_type == 0x17 {
            application.extend_from_slice(&inner[..content_len]);
        }
        records.push(RecordView {
            content_len,
            inner_type,
        });
    }

    let mut parsed = [httparse::EMPTY_HEADER; 128];
    let mut response = httparse::Response::new(&mut parsed);
    let httparse::Status::Complete(head_len) = response.parse(&application)? else {
        bail!("incomplete HTTP response head");
    };
    if !request.allow_set_cookie
        && response
            .headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case("set-cookie"))
    {
        bail!(
            "this presentation discloses every response header, including Set-Cookie; \
             pass allowSetCookie to disclose them"
        );
    }
    let body = &application[head_len..];
    let nonce = parse_nonce(&request.nonce)?;
    let query = Query {
        server_name: &a.server.name,
        key: &request.predicate.key,
        path: &request.predicate.path,
        unique: request.predicate.unique,
        comparison: presentation::parse_comparison(&request.predicate.op)?,
        constant: request
            .predicate
            .value
            .value()
            .map_err(anyhow::Error::msg)?,
        nonce,
    };
    let path = presentation::effective_path(&query)?;
    let member = zkf_ir::json::values(body)?
        .into_iter()
        .find(|m| {
            m.path == path
                && !body[m.value_range.clone()].is_empty()
                && body[m.value_range.clone()].iter().all(u8::is_ascii_digit)
        })
        .ok_or_else(|| anyhow!("no selected JSON path with an unsigned integer value"))?;
    let leaf = member.anchors.last().unwrap();
    let statement = Statement {
        headers: application[..head_len].to_vec(),
        records,
        encoded_key: leaf.encoded_key.clone(),
        key: leaf.key.clone(),
        colon: leaf.colon,
        value: leaf.value.clone(),
        anchors: if request.predicate.path.is_empty() && !request.predicate.unique {
            Vec::new()
        } else {
            member.anchors
        },
    };

    let params = match request.parameters.as_deref().unwrap_or("fast") {
        "fast" => Parameters::Fast,
        "small" => Parameters::Small,
        other => bail!("parameters must be \"fast\" or \"small\", got {other:?}"),
    };
    let opening = recv.open(0, recv.direction.len)?;
    let proof = presentation::prove(a, statement, opening, &query, &secrets.server_key, params)?;
    Ok(b64::encode(proof.encode(&signed_bytes)?))
}

pub(crate) fn parse_nonce(hex_nonce: &str) -> Result<[u8; 32]> {
    hex::decode(hex_nonce)
        .ok()
        .and_then(|n| n.try_into().ok())
        .ok_or_else(|| anyhow!("nonce must be 32 bytes of hex"))
}
