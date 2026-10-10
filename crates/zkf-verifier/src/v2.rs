//! Verification of experimental v2 presentations: a notary-signed v2
//! attestation plus a VOLE-in-the-Head proof about its signed ciphertext.

use anyhow::{Result, anyhow, ensure};
use k256::ecdsa::VerifyingKey;
use zkf_attestation::{SignedAttestation, key_id};
use zkf_core::{KeyView, VerifyV2Options, VerifyV2Output, b64};
use zkf_voleith::presentation::{self, MAX_PRESENTATION_BYTES, Presentation, Query};

/// Whether a base64 presentation is a v2 presentation (cheap prefix check).
pub fn is_v2(presentation_b64: &str) -> bool {
    // The magic's first 6 bytes encode to a fixed 8-character prefix.
    let prefix = b64::encode(&b"zkf2prs\x01"[..6]);
    presentation_b64.trim_start().starts_with(&prefix)
}

/// Verifies a v2 presentation against the verifier's own policy: trusted
/// notary keys, server name, the claim and the nonce it issued.
pub fn verify_v2(presentation_b64: &str, opts: &VerifyV2Options) -> Result<VerifyV2Output> {
    ensure!(
        presentation_b64.len() <= MAX_PRESENTATION_BYTES.div_ceil(3) * 4,
        "presentation too large"
    );
    let bytes = b64::decode(presentation_b64)?;
    let (attestation_bytes, presentation) = Presentation::decode(&bytes)?;
    let signed = SignedAttestation::decode(&attestation_bytes)?;
    let a = &signed.attestation;

    let mut trusted = None;
    for hex_key in &opts.trusted_notary_keys {
        let key = VerifyingKey::from_sec1_bytes(&hex::decode(hex_key)?)
            .map_err(|_| anyhow!("invalid trusted notary key {hex_key}"))?;
        if key_id(&key) == a.notary_key_id {
            trusted = Some(key);
        }
    }
    let key =
        trusted.ok_or_else(|| anyhow!("attestation is not signed by a trusted notary key"))?;

    ensure!(
        a.server
            .name
            .eq_ignore_ascii_case(&opts.expected_server_name),
        "server name mismatch"
    );
    if let Some(max_age) = opts.max_age_secs {
        let now = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)?
            .as_secs();
        ensure!(a.time <= now, "attestation timestamp is in the future");
        ensure!(now - a.time <= max_age, "attestation is stale");
    }
    for (expected, actual, name) in [
        (&opts.expected_owner, &a.binding.owner, "owner"),
        (&opts.expected_context, &a.binding.context, "context"),
    ] {
        if let Some(expected) = expected {
            ensure!(actual.as_ref() == Some(expected), "{name} mismatch");
        }
    }

    let nonce: [u8; 32] = hex::decode(&opts.nonce)
        .ok()
        .and_then(|n| n.try_into().ok())
        .ok_or_else(|| anyhow!("nonce must be 32 bytes of hex"))?;
    let query = Query {
        server_name: &a.server.name,
        key: &opts.predicate.key,
        path: &opts.predicate.path,
        unique: opts.predicate.unique,
        comparison: presentation::parse_comparison(&opts.predicate.op)?,
        constant: opts.predicate.value.value().map_err(anyhow::Error::msg)?,
        nonce,
    };
    presentation::verify(a, &signed.signature, &key, &presentation, &query)?;

    Ok(VerifyV2Output {
        server_name: a.server.name.clone(),
        time: a.time,
        notary_key: KeyView {
            alg: a.alg.clone(),
            key: hex::encode(key.to_encoded_point(true).as_bytes()),
        },
        mode: a.mode.clone(),
        response_headers: String::from_utf8_lossy(&presentation.statement.headers).into_owned(),
        predicate: opts.predicate.clone(),
        owner: a.binding.owner.clone(),
        context: a.binding.context.clone(),
    })
}
