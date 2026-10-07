use crate::{
    HandshakeKeys,
    handshake::{self, HelloBinding},
    record::{self, CloseState, ContentType, Sequence},
};
use aes_gcm::{
    Aes128Gcm, KeyInit,
    aead::{Aead, Payload},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{
    io::Cursor,
    sync::{Arc, Mutex},
};
use tls_core::msgs::{
    codec::Reader,
    enums::ProtocolVersion,
    handshake::{HandshakeMessagePayload, HandshakePayload},
};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_CERT_DER, SERVER_DOMAIN, SERVER_KEY_DER};

#[derive(Debug, Default)]
struct Log(Mutex<std::collections::HashMap<String, Vec<u8>>>);
impl rustls::KeyLog for Log {
    fn log(&self, label: &str, _: &[u8], secret: &[u8]) {
        self.0
            .lock()
            .unwrap()
            .insert(label.to_string(), secret.to_vec());
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    let mut p = rustls::crypto::ring::default_provider();
    p.cipher_suites = vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256];
    p.kx_groups = vec![rustls::crypto::ring::kx_group::SECP256R1];
    Arc::new(p)
}

fn expand(secret: &[u8], label: &[u8], len: u8) -> Vec<u8> {
    let mut info = vec![0, len, (6 + label.len()) as u8];
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.extend_from_slice(&[0, 1]);
    let mut h = <Hmac<Sha256> as Mac>::new_from_slice(secret).unwrap();
    h.update(&info);
    h.finalize().into_bytes()[..len as usize].to_vec()
}

struct Capture {
    client_hello: Vec<u8>,
    server_hello: Vec<u8>,
    records: Vec<Vec<u8>>,
    client_share: Vec<u8>,
    server_share: Vec<u8>,
    keys: HandshakeKeys,
}
impl Capture {
    fn hello(&self) -> HelloBinding<'_> {
        HelloBinding {
            client_hello: &self.client_hello,
            server_hello: &self.server_hello,
            joint_client_share: &self.client_share,
            server_share: &self.server_share,
            server_name: SERVER_DOMAIN,
        }
    }
}

fn capture() -> Capture {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CA_CERT_DER.into()).unwrap();
    let log = Arc::new(Log::default());
    let mut client_config = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.key_log = log.clone();
    let server_config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![SERVER_CERT_DER.into()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(SERVER_KEY_DER.into()),
        )
        .unwrap();
    let mut client =
        rustls::ClientConnection::new(Arc::new(client_config), SERVER_DOMAIN.try_into().unwrap())
            .unwrap();
    let mut server = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
    let mut ch = Vec::new();
    client.write_tls(&mut ch).unwrap();
    server.read_tls(&mut Cursor::new(&ch)).unwrap();
    server.process_new_packets().unwrap();
    let mut flight = Vec::new();
    server.write_tls(&mut flight).unwrap();
    client.read_tls(&mut Cursor::new(&flight)).unwrap();
    client.process_new_packets().unwrap();
    let client_hello = ch[5..].to_vec();
    let mut server_hello = Vec::new();
    let mut records = Vec::new();
    let mut rest = flight.as_slice();
    while !rest.is_empty() {
        let len = 5 + u16::from_be_bytes([rest[3], rest[4]]) as usize;
        match rest[0] {
            22 => server_hello.extend_from_slice(&rest[5..len]),
            23 => records.push(rest[..len].to_vec()),
            20 => assert_eq!(&rest[5..len], &[1]),
            _ => panic!("unexpected record"),
        }
        rest = &rest[len..];
    }
    let c = HandshakeMessagePayload::read_version(
        &mut Reader::init(&client_hello),
        ProtocolVersion::TLSv1_3,
    )
    .unwrap();
    let HandshakePayload::ClientHello(c) = c.payload else {
        panic!()
    };
    let client_share = c.get_keyshare_extension().unwrap()[0].payload.0.clone();
    let s = HandshakeMessagePayload::read_version(
        &mut Reader::init(&server_hello),
        ProtocolVersion::TLSv1_3,
    )
    .unwrap();
    let HandshakePayload::ServerHello(s) = s.payload else {
        panic!()
    };
    let server_share = s.get_key_share().unwrap().payload.0.clone();
    let secrets = log.0.lock().unwrap();
    let cs = &secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"];
    let ss = &secrets["SERVER_HANDSHAKE_TRAFFIC_SECRET"];
    let keys = HandshakeKeys {
        client_write_key: expand(cs, b"key", 16).try_into().unwrap(),
        client_iv: expand(cs, b"iv", 12).try_into().unwrap(),
        server_write_key: expand(ss, b"key", 16).try_into().unwrap(),
        server_iv: expand(ss, b"iv", 12).try_into().unwrap(),
        client_finished_key: expand(cs, b"finished", 32).try_into().unwrap(),
        server_finished_key: expand(ss, b"finished", 32).try_into().unwrap(),
    };
    Capture {
        client_hello,
        server_hello,
        records,
        client_share,
        server_share,
        keys,
    }
}

fn verifier() -> tls_core::verify::WebPkiVerifier {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CA_CERT_DER.into()).unwrap();
    tls_core::verify::WebPkiVerifier::new(
        tls_core::anchors::RootCertStore { roots: roots.roots },
        None,
    )
}

fn encrypt(keys: &HandshakeKeys, content: &[u8], seq: u64) -> Vec<u8> {
    let inner = record::encode_inner(content, ContentType::Handshake, 0).unwrap();
    let aad = record::aad(inner.len() + 16).unwrap();
    let nonce = record::nonce(keys.server_iv, seq);
    let ciphertext = Aes128Gcm::new_from_slice(&keys.server_write_key)
        .unwrap()
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: &inner,
                aad: &aad,
            },
        )
        .unwrap();
    let mut wire = aad.to_vec();
    wire.extend(ciphertext);
    wire
}

#[test]
fn independently_authenticates_real_tls13_server_handshake() {
    let c = capture();
    let verified = handshake::verify_server(
        &c.hello(),
        &c.keys,
        &c.records,
        &verifier(),
        std::time::SystemTime::now(),
    )
    .unwrap();
    assert_eq!(verified.client_finished.len(), 36);
    assert_eq!(verified.cert_chain[0].0, SERVER_CERT_DER);
    assert_ne!(verified.hello_hash, verified.application_hash);
    // TLS handshake messages may be split across record boundaries.
    let plaintext = handshake::decrypt_server_records(&c.keys, &c.records).unwrap();
    let split = vec![
        encrypt(&c.keys, &plaintext[..13], 0),
        encrypt(&c.keys, &plaintext[13..], 1),
    ];
    handshake::verify_server(
        &c.hello(),
        &c.keys,
        &split,
        &verifier(),
        std::time::SystemTime::now(),
    )
    .unwrap();
}

#[test]
fn rejects_forged_certificate_verify_finished_and_tags() {
    let c = capture();
    let original = handshake::decrypt_server_records(&c.keys, &c.records).unwrap();
    let mut offset = 0;
    let mut targets = Vec::new();
    while offset < original.len() {
        let len = 4
            + ((original[offset + 1] as usize) << 16)
            + ((original[offset + 2] as usize) << 8)
            + original[offset + 3] as usize;
        if [15, 20].contains(&original[offset]) {
            targets.push(offset + len - 1);
        }
        offset += len;
    }
    assert_eq!(targets.len(), 2);
    for pos in targets {
        let mut forged = original.clone();
        forged[pos] ^= 1;
        let records = vec![encrypt(&c.keys, &forged, 0)];
        assert!(
            handshake::verify_server(
                &c.hello(),
                &c.keys,
                &records,
                &verifier(),
                std::time::SystemTime::now()
            )
            .is_err()
        );
    }
    let mut records = c.records.clone();
    *records[0].last_mut().unwrap() ^= 1;
    assert!(
        handshake::verify_server(
            &c.hello(),
            &c.keys,
            &records,
            &verifier(),
            std::time::SystemTime::now()
        )
        .is_err()
    );
    let mut wrong_share = c.hello();
    wrong_share.joint_client_share = &c.server_share;
    assert!(wrong_share.verify().is_err());
    let mut wrong_host = c.hello();
    wrong_host.server_name = "other.example";
    assert!(wrong_host.verify().is_err());
    let mut reordered = c.records.clone();
    reordered.reverse();
    if reordered != c.records {
        assert!(handshake::decrypt_server_records(&c.keys, &reordered).is_err());
    }
}

#[test]
fn record_nonce_padding_limits_and_close_notify() {
    assert_eq!(
        record::nonce([0xaa; 12], 1),
        [
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xab
        ]
    );
    let inner = record::encode_inner(b"hello", ContentType::ApplicationData, 5).unwrap();
    assert_eq!(
        record::decode_inner(&inner).unwrap(),
        (ContentType::ApplicationData, b"hello".as_slice())
    );
    assert_eq!(record::aad(inner.len() + 16).unwrap(), [23, 3, 3, 0, 27]);
    assert!(record::decode_inner(&[0; 32]).is_err());
    assert!(record::decode_inner(&[1, 20]).is_err());
    assert!(record::encode_inner(b"x", ContentType::Handshake, usize::MAX).is_err());
    assert!(
        record::encode_inner(
            &vec![0; record::MAX_CONTENT + 1],
            ContentType::ApplicationData,
            0
        )
        .is_err()
    );
    let mut seq = Sequence::default();
    assert_eq!(seq.take().unwrap(), 0);
    assert_eq!(seq.take().unwrap(), 1);
    let mut closed = CloseState::default();
    assert!(closed.finish(false).is_err());
    assert!(closed.accept(ContentType::Alert, &[2, 40]).is_err());
    closed.accept(ContentType::Alert, &[1, 0]).unwrap();
    assert!(closed.is_closed());
    closed.finish(false).unwrap();
    assert!(
        closed
            .accept(ContentType::ApplicationData, b"more")
            .is_err()
    );
}
