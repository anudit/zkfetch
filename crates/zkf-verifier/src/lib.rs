//! zkfetch presentation verifier.
//!
//! Checks the notary signature, the server identity proof and every revealed
//! byte against the attested commitments, then applies zkfetch policy
//! (trusted notary keys, owner/context binding).

use anyhow::{Context, Result, anyhow, bail};
use bincode::Options;
use tlsn::{
    attestation::{
        CryptoProvider,
        presentation::{Presentation, PresentationOutput},
    },
    verifier::ServerCertVerifier,
    webpki::{CertificateDer, RootCertStore},
};
use zkf_core::{
    EXT_CONTEXT, EXT_MODE, EXT_OWNER, EXT_SERVER, KeyView, VerifyOptions, VerifyOutput, b64,
};

/// Byte shown in place of undisclosed data.
pub const REDACTED: u8 = b'X';

/// Verifies a base64 presentation.
pub fn verify(presentation_b64: &str, opts: &VerifyOptions) -> Result<VerifyOutput> {
    if presentation_b64.len() > zkf_predicates::MAX_PRESENTATION_BYTES.div_ceil(3) * 4 {
        bail!("presentation too large");
    }
    let bytes = b64::decode(presentation_b64)?;
    let envelope = zkf_predicates::decode(&bytes)?;
    let presentation: Presentation = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(zkf_predicates::MAX_PRESENTATION_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(
            envelope
                .as_ref()
                .map_or(bytes.as_slice(), |e| e.presentation.as_slice()),
        )
        .context("invalid presentation encoding")?;

    let key = presentation.verifying_key();
    let notary_key = KeyView {
        alg: key.alg.to_string(),
        key: hex::encode(&key.data),
    };
    let notary_trusted = opts
        .trusted_notary_keys
        .iter()
        .any(|k| k.eq_ignore_ascii_case(&notary_key.key));
    if opts.trusted_notary_keys.is_empty() && !opts.allow_untrusted_notary {
        bail!(
            "no trusted notary keys configured: pass trustedNotaryKeys (or allowUntrustedNotary to inspect)"
        );
    }
    if !opts.trusted_notary_keys.is_empty() && !notary_trusted {
        bail!(
            "presentation signed by untrusted notary key {}",
            notary_key.key
        );
    }

    let mut roots = RootCertStore::mozilla();
    for cert in &opts.extra_root_certs {
        roots.roots.push(CertificateDer(b64::decode(cert)?));
    }
    let provider = CryptoProvider {
        cert: ServerCertVerifier::new(&roots)?,
        ..Default::default()
    };

    let PresentationOutput {
        attestation,
        server_name,
        connection_info,
        transcript,
        extensions,
        ..
    } = presentation
        .verify(&provider)
        .map_err(|e| anyhow!("presentation invalid: {e}"))?;

    let server_name =
        server_name.ok_or_else(|| anyhow!("presentation does not prove the server identity"))?;
    let mut transcript =
        transcript.ok_or_else(|| anyhow!("presentation does not disclose any transcript data"))?;
    transcript.set_unauthed(REDACTED);
    let mut predicates = match envelope {
        Some(envelope) => zkf_predicates::verify(&envelope, &attestation, &transcript)?,
        None => Vec::new(),
    };
    // QuickSilver predicates signed by the notary at fetch time (default backend).
    let qs_claims =
        zkf_predicates::quicksilver::AttestedPredicates::from_attestation(&attestation)?;
    // Disclosed fields at authenticated paths, when the shape proofs allow it.
    let json = qs_claims
        .as_ref()
        .and_then(|claims| zkf_predicates::quicksilver::disclosed_fields(claims, &transcript).ok())
        .unwrap_or_default()
        .into_iter()
        .map(|(path, value)| zkf_core::JsonField { path, value })
        .collect();
    if let Some(claims) = qs_claims {
        for spec in zkf_predicates::quicksilver::verify(&claims, &transcript, false)? {
            if !predicates.iter().any(|p| p.json_path == spec.json_path) {
                predicates.push(spec);
            }
        }
    }
    for expected in &opts.expected_predicates {
        let minimum = expected.predicate.minimum().map_err(anyhow::Error::msg)?;
        if !predicates.iter().any(|p| {
            p.json_path == expected.json_path
                && p.predicate.minimum().is_ok_and(|actual| actual >= minimum)
        }) {
            bail!(
                "required predicate missing or weaker than expected: {}",
                expected.json_path
            );
        }
    }

    let ext = |id: &[u8]| {
        extensions
            .iter()
            .find(|e| e.id == id)
            .map(|e| String::from_utf8_lossy(&e.value).into_owned())
    };
    // The notary signs the session mode and, in proxy mode, the host it dialed.
    // A proxy proof is only about that host: the TLS secrets are the prover's,
    // so the server's identity rests on the notary's own connection.
    let mode = ext(EXT_MODE).ok_or_else(|| {
        anyhow!("attestation has no signed session mode (issued by an older notary)")
    })?;
    match mode.as_str() {
        "mpc" => {}
        "proxy" => {
            if opts.reject_proxy {
                bail!("proxy-mode sessions are not accepted");
            }
            let dialed = ext(EXT_SERVER)
                .ok_or_else(|| anyhow!("proxy attestation does not name the dialed server"))?;
            let claimed = server_name.to_string();
            if !dialed.eq_ignore_ascii_case(&claimed) {
                bail!("proxy session connected to {dialed}, but the presentation claims {claimed}");
            }
        }
        other => bail!("unknown session mode {other:?}"),
    }
    let owner = ext(EXT_OWNER);
    let context = ext(EXT_CONTEXT);
    if let Some(expected) = &opts.expected_owner
        && owner.as_deref() != Some(expected.as_str())
    {
        bail!("owner mismatch");
    }
    if let Some(expected) = &opts.expected_context
        && context.as_deref() != Some(expected.as_str())
    {
        bail!("context mismatch");
    }

    Ok(VerifyOutput {
        server_name: server_name.to_string(),
        time: connection_info.time,
        tls_version: format!("{:?}", connection_info.version),
        notary_key,
        notary_trusted,
        mode,
        sent: String::from_utf8_lossy(transcript.sent_unsafe()).into_owned(),
        recv: String::from_utf8_lossy(transcript.received_unsafe()).into_owned(),
        sent_authed: transcript
            .sent_authed()
            .iter()
            .map(|r| [r.start, r.end])
            .collect(),
        recv_authed: transcript
            .received_authed()
            .iter()
            .map(|r| [r.start, r.end])
            .collect(),
        json,
        owner,
        context,
        predicates,
    })
}
