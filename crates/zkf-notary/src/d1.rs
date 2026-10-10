//! Experimental v2 (D1) attestations: after the TLS session proof, check that
//! the prover's key commitments open to the authenticated application keys,
//! then sign the ciphertext the notary relayed, not plaintext commitments.

use anyhow::{Context, Result, anyhow, ensure};
use bincode::Options;
use sha2::{Digest, Sha256};
use tlsn::{
    SessionHandle,
    transcript::TlsTranscript,
    verifier::{Verifier, state::Committed},
};
use zkf_attestation::{
    Attestation, Binding, Bytes, Handshake, Keys, Server, SignedAttestation, Tls, TranscriptHash,
    chain_sha256, key_id,
    records::{Direction, RecordStream},
    session_binding, spki_sha256,
};
use zkf_core::{d1, transport};

use crate::NotaryConfig;

/// What the notary verified and recorded itself, ready to sign.
pub(crate) struct Evidence {
    binding_hash: [u8; 32],
    sent: Direction,
    recv: Direction,
    iv_client: [u8; 12],
    iv_server: [u8; 12],
    hello_hash: [u8; 32],
    application_hash: [u8; 32],
    c_client: [u8; 32],
    c_server: [u8; 32],
    dialed_ip: std::net::IpAddr,
    metadata: Option<zkf_attestation::response::SessionMetadata>,
}

/// Runs after the session proof was accepted (identity verified).
pub(crate) async fn verify(
    verifier: &mut Verifier<Committed>,
    handle: &SessionHandle,
    dialed_ip: Option<std::net::IpAddr>,
) -> Result<Evidence> {
    let dialed_ip = dialed_ip.ok_or_else(|| anyhow!("v2 attestations need the dialed address"))?;
    let epoch = verifier
        .application_epoch_ciphertext()
        .ok_or_else(|| anyhow!("v2 attestations need a TLS 1.3 proxy session"))?;
    let sent = RecordStream::new(&epoch.sent, 0, true)?.direction;
    let recv = RecordStream::new(&epoch.received, 0, true)?.direction;
    let (iv_client, iv_server) = (epoch.iv_client, epoch.iv_server);
    let (hello_hash, application_hash) = (epoch.hello_hash, epoch.application_hash);
    let binding = session_binding(
        &sent,
        &recv,
        &iv_client,
        &iv_server,
        &hello_hash,
        &application_hash,
    );
    let binding_hash: [u8; 32] = Sha256::digest(&binding).into();

    let mut stream = handle.application_stream(d1::KEYS_STREAM)?;
    let frame = transport::read_frame(&mut stream).await?;
    ensure!(
        (frame.len() == 97 && frame[96] == 12)
            || (frame.len() > 97 && frame.len() <= 32768 && frame[96] == 11),
        "malformed key commitments"
    );
    ensure!(
        frame[..32] == binding_hash,
        "the prover recorded different ciphertext, IVs or handshake"
    );
    let c_client: [u8; 32] = frame[32..64].try_into().unwrap();
    let c_server: [u8; 32] = frame[64..96].try_into().unwrap();
    let metadata: Option<zkf_attestation::response::SessionMetadata> = if frame[96] == 11 {
        Some(
            bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .with_limit(32768)
                .reject_trailing_bytes()
                .deserialize(&frame[97..])?,
        )
    } else {
        None
    };
    let ciphertext: Vec<_> = epoch.received.iter().flatten().copied().collect();
    let statement = if let Some(metadata) = &metadata {
        zkf_ir::response::session(
            c_client,
            c_server,
            &recv,
            &ciphertext,
            iv_server,
            &metadata.head,
            &metadata.claims,
        )
        .map_err(anyhow::Error::msg)?
    } else {
        zkf_ir::tls::keys_commitment_statement(c_client, c_server)
    };
    let mut binding = binding;
    binding.extend_from_slice(&frame[32..96]);
    binding.push(frame[96]);
    if let Some(metadata) = &metadata {
        binding.extend_from_slice(&bincode::serialize(metadata)?);
    }
    verifier
        .verify_application_keys_relation(&statement, &binding)
        .await
        .context("combined key-commitment proof rejected")?;
    Ok(Evidence {
        binding_hash,
        sent,
        recv,
        iv_client,
        iv_server,
        hello_hash,
        application_hash,
        c_client,
        c_server,
        dialed_ip,
        metadata,
    })
}

/// Signs the v2 attestation for verified `evidence`; returns the envelope.
pub(crate) fn sign(
    config: &NotaryConfig,
    request_bytes: &[u8],
    transcript: &TlsTranscript,
    host: &str,
    evidence: Evidence,
) -> Result<Vec<u8>> {
    let request: d1::Request = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(4096)
        .reject_trailing_bytes()
        .deserialize(request_bytes)
        .context("invalid v2 attestation request")?;
    for value in [&request.owner, &request.context].into_iter().flatten() {
        ensure!(value.len() <= d1::MAX_BINDING_LEN, "binding value too long");
    }
    let chain = transcript
        .server_cert_chain()
        .filter(|chain| !chain.is_empty())
        .ok_or_else(|| anyhow!("missing server certificate chain"))?;
    let key = k256::ecdsa::SigningKey::from_bytes(&config.signing_key.into())?;
    let attestation = Attestation {
        v: 2,
        alg: "secp256k1".into(),
        notary_key_id: key_id(key.verifying_key()),
        // The binding covers fresh IVs and ciphertext, so it is unique.
        sid: Bytes(evidence.binding_hash),
        time: transcript.time(),
        mode: "proxy".into(),
        server: Server {
            name: host.to_ascii_lowercase(),
            dialed_ip: evidence.dialed_ip.to_string(),
            port: 443,
            spki_sha256: spki_sha256(&chain[0].0)?,
            chain_sha256: chain_sha256(chain.iter().map(|c| c.0.as_slice())),
            cert_verified_by_notary: true,
        },
        tls: Tls {
            version: 0x0304,
            suite: 0x1301,
            group: 0x0017,
            hrr: false,
        },
        handshake: Handshake {
            h_ch_sh: TranscriptHash::Sha256(Bytes(evidence.hello_hash)),
            h_ch_sf: TranscriptHash::Sha256(Bytes(evidence.application_hash)),
        },
        sent: evidence.sent,
        recv: evidence.recv,
        keys: Keys {
            c_client: Bytes(evidence.c_client),
            c_server: Bytes(evidence.c_server),
            iv_client: Bytes(evidence.iv_client),
            iv_server: Bytes(evidence.iv_server),
        },
        claims: evidence
            .metadata
            .as_ref()
            .map(|metadata| {
                std::iter::once(metadata.head.claim())
                    .chain(metadata.claims.iter().map(|claim| claim.claim()))
                    .collect()
            })
            .unwrap_or_default(),
        binding: Binding {
            owner: request.owner,
            context: request.context,
        },
    };
    SignedAttestation::sign(attestation, &key)?.encode()
}
