//! Experimental field relation bound to a real TLS 1.3 application key.
//! The legacy session proof is intentionally retained during this bridge test.
#![cfg(feature = "d1-experimental")]
use aes::{
    Aes128,
    cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
};
use futures::{AsyncReadExt, AsyncWriteExt};
use std::future::IntoFuture;
use tlsn::{
    Session,
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::proxy::ProxyTlsConfig, verifier::VerifierConfig,
    },
    connection::{ServerName, TlsVersion},
    transcript::Direction,
    verifier::VerifierCommitStart,
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};
use tokio_util::compat::TokioAsyncReadCompatExt;
use zkf_ir::{Circuit, aes::ExpandedKey, byte_inputs, tls};

fn circuit(ck: [u8; 32]) -> Circuit {
    let mut c = Circuit::default();
    let key: Vec<_> = (0..16).map(|_| c.commit_byte()).collect();
    let expanded = ExpandedKey::new(&mut c, &key).unwrap();
    for (wire, expected) in tls::key_commitment(&mut c, &expanded).into_iter().zip(ck) {
        c.assert_byte(wire, expected);
    }
    c
}
fn commitment(key: &[u8; 16]) -> [u8; 32] {
    let native = Aes128::new_from_slice(key).unwrap();
    let mut output = [0; 32];
    for i in 1..=2 {
        let mut block = GenericArray::clone_from_slice(&tls::commitment_block(i).unwrap());
        native.encrypt_block(&mut block);
        output[(i as usize - 1) * 16..i as usize * 16].copy_from_slice(&block);
    }
    output
}
fn roots() -> RootCertStore {
    RootCertStore {
        roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
    }
}

fn epoch_binding(epoch: &tlsn::ApplicationEpochCiphertext) -> Vec<u8> {
    use zkf_attestation::records::RecordStream;
    let sent = RecordStream::new(&epoch.sent, 0, false).unwrap();
    let received = RecordStream::new(&epoch.received, 0, false).unwrap();
    assert!(!sent.direction.records.is_empty());
    assert!(!received.direction.records.is_empty());
    let mut binding = sent.direction.root.0.to_vec();
    binding.extend_from_slice(&received.direction.root.0);
    binding.extend_from_slice(&epoch.iv_client);
    binding.extend_from_slice(&epoch.iv_server);
    binding.extend_from_slice(&epoch.hello_hash);
    binding.extend_from_slice(&epoch.application_hash);
    binding
}

async fn session(wrong_key: bool) -> anyhow::Result<()> {
    let (p_socket, v_socket) = tokio::io::duplex(2 << 23);
    let mut p_session = Session::new(p_socket.compat());
    let mut v_session = Session::new(v_socket.compat());
    let p = p_session.new_prover(ProverConfig::builder().build()?)?;
    let v = v_session.new_verifier(VerifierConfig::builder().root_store(roots()).build()?)?;
    let (p_driver, p_handle) = p_session.split();
    let (v_driver, v_handle) = v_session.split();
    let p_task = tokio::spawn(p_driver);
    let v_task = tokio::spawn(v_driver);
    let (client, server) = tokio::io::duplex(2 << 16);
    let fixture = tokio::spawn(tlsn_server_fixture::bind_tls13(server.compat()));
    let prover = async {
        let p = p
            .commit(
                ProxyTlsConfig::builder()
                    .server_name(SERVER_DOMAIN.try_into()?)
                    .tls_version(TlsVersion::V1_3)
                    .build()?,
            )
            .await?;
        let (mut connection, p) = p.connect(
            TlsClientConfig::builder()
                .server_name(ServerName::Dns(SERVER_DOMAIN.try_into()?))
                .root_store(roots())
                .build()?,
        )?;
        let task = tokio::spawn(p.into_future());
        connection
            .write_all(
                b"GET /formats/json HTTP/1.1\r\nHost: test-server.io\r\nConnection: close\r\n\r\n",
            )
            .await?;
        let mut response = Vec::new();
        connection.read_to_end(&mut response).await?;
        connection.close().await?;
        let mut p = task.await??;
        let probe = circuit(commitment(&[9; 16]));
        let probe_witness = probe.eval(&byte_inputs(&[9; 16]))?;
        anyhow::ensure!(
            p.prove_application_key_relation(
                Direction::Received,
                &probe,
                &probe_witness,
                b"premature"
            )
            .await
            .is_err(),
            "field proof must require identity/session acceptance"
        );
        let mut config = ProveConfig::builder(p.transcript());
        config.server_identity();
        p.prove(&config.build()?).await?;
        let mut wire = p_handle.application_stream(b"zkf/2/test/key-binding")?;
        let binding = epoch_binding(p.application_epoch_ciphertext().unwrap());
        wire.write_all(&binding).await?;
        wire.flush().await?;
        for direction in [Direction::Sent, Direction::Received] {
            let key = if wrong_key {
                [9; 16]
            } else {
                *p.application_key_secrets().unwrap().key(direction)
            };
            let ck = commitment(&key);
            wire.write_all(&ck).await?;
            wire.flush().await?;
            let c = circuit(ck);
            let witness = c.eval(&byte_inputs(&key))?;
            p.prove_application_key_relation(direction, &c, &witness, &binding)
                .await?;
        }
        p.close().await?;
        Ok::<_, anyhow::Error>(())
    };
    let verifier = async {
        let VerifierCommitStart::Proxy(v) = v.commit().await? else {
            anyhow::bail!("expected proxy");
        };
        let mut v = v.accept().await?.run(client.compat()).await?;
        anyhow::ensure!(
            v.verify_application_key_relation(Direction::Received, &circuit([0; 32]), b"premature")
                .await
                .is_err(),
            "field verification must require identity/session acceptance"
        );
        let (output, mut v) = v.verify().await?.accept().await?;
        anyhow::ensure!(output.server_name.is_some(), "identity must be checked");
        let mut wire = v_handle.application_stream(b"zkf/2/test/key-binding")?;
        let binding = epoch_binding(v.application_epoch_ciphertext().unwrap());
        let mut received_binding = vec![0; binding.len()];
        wire.read_exact(&mut received_binding).await?;
        anyhow::ensure!(
            received_binding == binding,
            "proxy ciphertext/IV/hash mismatch"
        );
        for direction in [Direction::Sent, Direction::Received] {
            let mut ck = [0; 32];
            wire.read_exact(&mut ck).await?;
            v.verify_application_key_relation(direction, &circuit(ck), &binding)
                .await?;
        }
        v.close().await?;
        Ok::<_, anyhow::Error>(())
    };
    let result = futures::future::try_join(prover, verifier).await;
    p_handle.close();
    v_handle.close();
    p_task.abort();
    v_task.abort();
    fixture.abort();
    result.map(|_| ())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls13_application_key_commitments_and_wrong_key_rejection() {
    tokio::time::timeout(std::time::Duration::from_secs(90), session(false))
        .await
        .unwrap()
        .unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(90), session(true))
            .await
            .unwrap()
            .is_err()
    );
}
