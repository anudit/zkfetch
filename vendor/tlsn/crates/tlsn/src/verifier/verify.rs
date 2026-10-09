use mpc_tls::SessionKeys;
use mpz_common::Context;
use mpz_memory_core::binary::Binary;
use mpz_vm_core::Vm;
use rangeset::set::RangeSet;
use tlsn_core::{
    VerifierOutput,
    config::prove::ProveRequest,
    connection::{HandshakeData, ServerName},
    transcript::{
        ContentType, Direction, PartialTranscript, Record, TlsTranscript, TranscriptCommitment,
    },
    webpki::ServerCertVerifier,
};

use crate::{
    Error, Result,
    transcript_internal::{
        TranscriptRefs,
        auth::{authenticate_suffixes, verify_plaintext},
        commit::hash::verify_hash,
        predicate::predicate_circuits,
    },
};

pub(crate) fn check_hash_budget<'a>(
    hashes: impl Iterator<Item = &'a (Direction, RangeSet<usize>, tlsn_core::hash::HashAlgId)>,
    sent_len: usize,
    recv_len: usize,
) -> Result<()> {
    let mut count = 0usize;
    let mut bytes = 0usize;
    for (direction, idx, _) in hashes {
        count += 1;
        bytes = bytes
            .checked_add(idx.len())
            .ok_or_else(|| Error::internal().with_msg("commitment budget overflow"))?;
        let len = match direction {
            Direction::Sent => sent_len,
            Direction::Received => recv_len,
        };
        if idx.iter().any(|r| r.end > len)
            || count > 2048
            || bytes > (1 << 20)
            || bytes > 2 * (sent_len + recv_len)
        {
            return Err(Error::internal()
                .with_msg("verification failed: hash commitments exceed the work budget"));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn verify<T: Vm<Binary> + Send + Sync>(
    ctx: &mut Context,
    vm: &mut T,
    keys: &SessionKeys,
    cert_verifier: &ServerCertVerifier,
    tls_transcript: &TlsTranscript,
    request: ProveRequest,
    handshake: Option<(ServerName, HandshakeData)>,
    transcript: Option<PartialTranscript>,
) -> Result<VerifierOutput> {
    let ciphertext_sent = collect_ciphertext(tls_transcript.sent());
    let ciphertext_recv = collect_ciphertext(tls_transcript.recv());

    let transcript = if let Some((auth_sent, auth_recv)) = request.reveal() {
        let Some(transcript) = transcript else {
            return Err(Error::internal().with_msg(
                "verification failed: prover requested to reveal data but did not send transcript",
            ));
        };

        if transcript.len_sent() != ciphertext_sent.len()
            || transcript.len_received() != ciphertext_recv.len()
        {
            return Err(
                Error::internal().with_msg("verification failed: transcript length mismatch")
            );
        }

        if transcript.sent_authed() != auth_sent {
            return Err(Error::internal().with_msg("verification failed: sent auth data mismatch"));
        }

        if transcript.received_authed() != auth_recv {
            return Err(
                Error::internal().with_msg("verification failed: received auth data mismatch")
            );
        }

        transcript
    } else {
        PartialTranscript::new(ciphertext_sent.len(), ciphertext_recv.len())
    };

    let server_name = if let Some((name, cert_data)) = handshake {
        // The prover's binding must match the version and server ephemeral key
        // this verifier observed in the MPC (zkfetch patch: TLS 1.3).
        match (tls_transcript.certificate_binding(), &cert_data.binding) {
            (
                tlsn_core::connection::CertBinding::V1_2(_),
                tlsn_core::connection::CertBinding::V1_2(_),
            )
            | (
                tlsn_core::connection::CertBinding::V1_3(_),
                tlsn_core::connection::CertBinding::V1_3(_),
            ) => {}
            _ => {
                return Err(Error::internal()
                    .with_msg("verification failed: certificate binding version mismatch"));
            }
        }
        if let (
            tlsn_core::connection::CertBinding::V1_3(observed),
            tlsn_core::connection::CertBinding::V1_3(claimed),
        ) = (tls_transcript.certificate_binding(), &cert_data.binding)
        {
            if observed.handshake_messages != claimed.handshake_messages {
                return Err(Error::internal().with_msg(
                    "verification failed: certificate transcript does not match verified handshake",
                ));
            }
        }
        cert_data
            .verify(
                cert_verifier,
                tls_transcript.time(),
                tls_transcript.certificate_binding().server_ephemeral_key(),
                &name,
            )
            .map_err(|e| {
                Error::internal()
                    .with_msg("verification failed: certificate verification failed")
                    .with_source(e)
            })?;

        Some(name)
    } else {
        None
    };

    let (mut commit_sent, mut commit_recv) = (RangeSet::default(), RangeSet::default());
    if let Some(commit_config) = request.transcript_commit() {
        check_hash_budget(
            commit_config.iter_hash(),
            ciphertext_sent.len(),
            ciphertext_recv.len(),
        )?;
        commit_config
            .iter_hash()
            .for_each(|(direction, idx, _)| match direction {
                Direction::Sent => commit_sent.union_mut(idx),
                Direction::Received => commit_recv.union_mut(idx),
            });
    }
    // Predicate operands are authenticated like commitments (zkfetch patch).
    for predicate in request.predicates() {
        predicate
            .validate(ciphertext_sent.len(), ciphertext_recv.len())
            .map_err(|e| {
                Error::internal()
                    .with_msg("verification failed: invalid predicate")
                    .with_source(e)
            })?;
        match predicate.direction {
            Direction::Sent => commit_sent.union_mut(&predicate.range),
            Direction::Received => commit_recv.union_mut(&predicate.range),
        }
    }
    if request.predicates().len() > tlsn_core::transcript::predicate::MAX_PREDICATES {
        return Err(Error::internal().with_msg("verification failed: too many predicates"));
    }
    // Aggregate budget (zkfetch P7): honest requests prove each JSON leaf about
    // once, so their operands add up to at most the transcript.
    let operand_bytes: usize = request.predicates().iter().map(|p| p.range.len()).sum();
    let budget = tlsn_core::transcript::predicate::MAX_PREDICATE_BYTES
        .min(2 * (ciphertext_sent.len() + ciphertext_recv.len()));
    if operand_bytes > budget {
        return Err(
            Error::internal().with_msg("verification failed: predicates exceed the work budget")
        );
    }
    let mut seen = std::collections::HashSet::new();
    if !request.predicates().iter().all(|p| seen.insert(p)) {
        return Err(Error::internal().with_msg("verification failed: duplicate predicate"));
    }

    let (sent_refs, sent_proof) = verify_plaintext(
        vm,
        keys.client_write_key,
        keys.client_write_iv,
        transcript.sent_unsafe(),
        &ciphertext_sent,
        tls_transcript
            .sent()
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData),
        transcript.sent_authed(),
        &commit_sent,
    )
    .map_err(|e| {
        Error::internal()
            .with_msg("verification failed during sent plaintext verification")
            .with_source(e)
    })?;
    let (recv_refs, recv_proof) = verify_plaintext(
        vm,
        keys.server_write_key,
        keys.server_write_iv,
        transcript.received_unsafe(),
        &ciphertext_recv,
        tls_transcript
            .recv()
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData),
        transcript.received_authed(),
        &commit_recv,
    )
    .map_err(|e| {
        Error::internal()
            .with_msg("verification failed during received plaintext verification")
            .with_source(e)
    })?;

    let transcript_refs = TranscriptRefs {
        sent: sent_refs,
        recv: recv_refs,
    };

    // TLS 1.3: authenticate the disclosed record suffixes (zkfetch patch).
    let suffix_proofs = if tls_transcript.version() == tlsn_core::connection::TlsVersion::V1_3 {
        Some((
            authenticate_suffixes(
                vm,
                keys.client_write_key,
                keys.client_write_iv,
                tls_transcript.sent(),
            ),
            authenticate_suffixes(
                vm,
                keys.server_write_key,
                keys.server_write_iv,
                tls_transcript.recv(),
            ),
        ))
    } else {
        None
    };

    let mut transcript_commitments = Vec::new();
    let mut hash_commitments = None;
    if let Some(commit_config) = request.transcript_commit()
        && commit_config.has_hash()
    {
        hash_commitments = Some(
            verify_hash(vm, &transcript_refs, commit_config.iter_hash().cloned()).map_err(|e| {
                Error::internal()
                    .with_msg("verification failed during hash commitment setup")
                    .with_source(e)
            })?,
        );
    }

    let predicates =
        predicate_circuits(vm, &transcript_refs, request.predicates()).map_err(|e| {
            Error::internal()
                .with_msg("verification failed during predicate setup")
                .with_source(e)
        })?;

    vm.execute_all(ctx).await.map_err(|e| {
        Error::internal()
            .with_msg("verification failed during zk execution")
            .with_source(e)
    })?;

    sent_proof.verify().map_err(|e| {
        Error::internal()
            .with_msg("verification failed: sent plaintext proof invalid")
            .with_source(e)
    })?;
    recv_proof.verify().map_err(|e| {
        Error::internal()
            .with_msg("verification failed: received plaintext proof invalid")
            .with_source(e)
    })?;
    if let Some((sent_suffixes, recv_suffixes)) = suffix_proofs {
        for proof in [sent_suffixes, recv_suffixes] {
            proof.and_then(|p| p.verify()).map_err(|e| {
                Error::internal()
                    .with_msg("verification failed: TLS 1.3 record suffix proof invalid")
                    .with_source(e)
            })?;
        }
    }

    if let Some(hash_commitments) = hash_commitments {
        for commitment in hash_commitments.try_recv().map_err(|e| {
            Error::internal()
                .with_msg("verification failed during hash commitment finalization")
                .with_source(e)
        })? {
            transcript_commitments.push(TranscriptCommitment::Hash(commitment));
        }
    }

    // Verdicts are only meaningful once the plaintext proofs have verified.
    let predicates = predicates.try_recv().map_err(|e| {
        Error::internal()
            .with_msg("verification failed: predicate does not hold")
            .with_source(e)
    })?;

    Ok(VerifierOutput {
        server_name,
        transcript: request.reveal().is_some().then_some(transcript),
        transcript_commitments,
        predicates,
    })
}

fn collect_ciphertext<'a>(records: impl IntoIterator<Item = &'a Record>) -> Vec<u8> {
    let mut ciphertext = Vec::new();
    records
        .into_iter()
        .filter(|record| record.typ == ContentType::ApplicationData)
        .for_each(|record| {
            // TLS 1.3 records exclude their public suffix (zkfetch patch).
            ciphertext.extend_from_slice(&record.ciphertext[..record.content_len()]);
        });
    ciphertext
}
