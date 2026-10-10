//! Synthetic public statements for coverage-guided fuzzing; no real secrets.
use zkf_attestation::{
    Attestation, Binding, Bytes, Handshake, Keys, Server, Tls, TranscriptHash,
    records::RecordStream,
};

fn main() -> anyhow::Result<()> {
    let root = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "fuzz/corpus".into());
    let root = std::path::Path::new(&root);
    for name in ["attestation_cbor", "record_table_bao", "json_anchors"] {
        std::fs::create_dir_all(root.join(name))?;
    }
    let mut record = vec![23, 3, 3, 0, 32];
    record.resize(37, 0x55);
    let stream = RecordStream::new(&[record], 0, false)?;
    let mut attestation = Attestation {
        v: 2,
        alg: "secp256k1".into(),
        notary_key_id: Bytes([1; 32]),
        sid: Bytes([2; 32]),
        time: 1000,
        mode: "proxy".into(),
        server: Server {
            name: "example.com".into(),
            dialed_ip: "192.0.2.1".into(),
            port: 443,
            spki_sha256: Bytes([3; 32]),
            chain_sha256: Bytes([4; 32]),
            cert_verified_by_notary: true,
        },
        tls: Tls {
            version: 0x0304,
            suite: 0x1301,
            group: 0x17,
            hrr: false,
        },
        handshake: Handshake {
            h_ch_sh: TranscriptHash::Sha256(Bytes([5; 32])),
            h_ch_sf: TranscriptHash::Sha256(Bytes([6; 32])),
        },
        sent: stream.direction.clone(),
        recv: stream.direction.clone(),
        keys: Keys {
            c_client: Bytes([7; 32]),
            c_server: Bytes([8; 32]),
            iv_client: Bytes([9; 12]),
            iv_server: Bytes([10; 12]),
        },
        claims: vec![],
        binding: Binding {
            owner: None,
            context: None,
        },
    };
    std::fs::write(
        root.join("attestation_cbor/valid.cbor"),
        attestation.encode()?,
    )?;
    attestation.tls.suite = 0x1302;
    attestation.handshake.h_ch_sh = TranscriptHash::Sha384(Bytes([5; 48]));
    attestation.handshake.h_ch_sf = TranscriptHash::Sha384(Bytes([6; 48]));
    std::fs::write(
        root.join("attestation_cbor/sha384.cbor"),
        attestation.encode()?,
    )?;
    let opening = stream.open(5, 16)?;
    let mut encoded = Vec::new();
    ciborium::into_writer(&(stream.direction.clone(), opening), &mut encoded)?;
    std::fs::write(root.join("record_table_bao/valid.cbor"), encoded)?;
    for (i, body) in [
        r#"{"a":"x", ": 7, hidden":0}"#,
        r#"{"\u0069d":1,"id":2,"nested":[{"id":"a\\\"b"}]}"#,
    ]
    .iter()
    .enumerate()
    {
        std::fs::write(root.join(format!("json_anchors/seed-{i}.json")), body)?;
    }
    Ok(())
}
