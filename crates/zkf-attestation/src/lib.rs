//! V2 signed-object primitives. These types do not establish a TLS key binding
//! on their own: the notary must first accept the complete in-session proof.
pub mod checkpoints;
pub mod records;

pub mod response;

use anyhow::{Result, bail, ensure};
use ciborium::Value;
use k256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::hazmat::{PrehashSigner, PrehashVerifier},
};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as DeError, Visitor},
};
use sha2::{Digest, Sha256};
use std::{fmt, io::Cursor};

const MAX_ATTESTATION_BYTES: usize = 2 << 20;

/// Fixed-width CBOR byte string. Arrays of integers are not an alternate wire
/// representation and are rejected by the decoder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bytes<const N: usize>(pub [u8; N]);

impl<const N: usize> Serialize for Bytes<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}
impl<'de, const N: usize> Deserialize<'de> for Bytes<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct BytesVisitor<const N: usize>;
        impl<'de, const N: usize> Visitor<'de> for BytesVisitor<N> {
            type Value = Bytes<N>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "exactly {N} bytes")
            }
            fn visit_bytes<E: DeError>(self, value: &[u8]) -> std::result::Result<Self::Value, E> {
                Ok(Bytes(
                    value
                        .try_into()
                        .map_err(|_| E::invalid_length(value.len(), &self))?,
                ))
            }
            fn visit_byte_buf<E: DeError>(
                self,
                value: Vec<u8>,
            ) -> std::result::Result<Self::Value, E> {
                self.visit_bytes(&value)
            }
        }
        deserializer.deserialize_bytes(BytesVisitor::<N>)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    pub name: String,
    pub dialed_ip: String,
    pub port: u16,
    pub spki_sha256: Bytes<32>,
    pub chain_sha256: Bytes<32>,
    pub cert_verified_by_notary: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub version: u16,
    pub suite: u16,
    pub group: u16,
    pub hrr: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Handshake {
    pub h_ch_sh: TranscriptHash,
    pub h_ch_sf: TranscriptHash,
}

/// Transcript hashes are byte strings whose width is selected by the TLS
/// cipher suite. The enum discriminant is not part of the signed encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TranscriptHash {
    Sha256(Bytes<32>),
    Sha384(Bytes<48>),
}

impl Serialize for TranscriptHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Sha256(hash) => hash.serialize(serializer),
            Self::Sha384(hash) => hash.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for TranscriptHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct HashVisitor;
        impl<'de> Visitor<'de> for HashVisitor {
            type Value = TranscriptHash;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a 32-byte SHA-256 or 48-byte SHA-384 byte string")
            }
            fn visit_bytes<E: DeError>(self, bytes: &[u8]) -> std::result::Result<Self::Value, E> {
                match bytes.len() {
                    32 => Ok(TranscriptHash::Sha256(Bytes(bytes.try_into().unwrap()))),
                    48 => Ok(TranscriptHash::Sha384(Bytes(bytes.try_into().unwrap()))),
                    _ => Err(E::invalid_length(bytes.len(), &self)),
                }
            }
            fn visit_byte_buf<E: DeError>(
                self,
                bytes: Vec<u8>,
            ) -> std::result::Result<Self::Value, E> {
                self.visit_bytes(&bytes)
            }
        }
        deserializer.deserialize_bytes(HashVisitor)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Keys {
    pub c_client: Bytes<32>,
    pub c_server: Bytes<32>,
    pub iv_client: Bytes<12>,
    pub iv_server: Bytes<12>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Claim {
    Reveal {
        selector: String,
        revealed_digest: Bytes<32>,
    },
    JsonPath {
        selector: String,
        revealed_digest: Bytes<32>,
    },
    Predicate {
        selector: String,
        op: String,
        constant: u64,
        result: bool,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub owner: Option<String>,
    pub context: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    pub v: u8,
    pub alg: String,
    pub notary_key_id: Bytes<32>,
    pub sid: Bytes<32>,
    pub time: u64,
    pub mode: String,
    pub server: Server,
    pub tls: Tls,
    pub handshake: Handshake,
    pub sent: records::Direction,
    pub recv: records::Direction,
    pub keys: Keys,
    pub claims: Vec<Claim>,
    pub binding: Binding,
}

impl Attestation {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.v == 2 && self.alg == "secp256k1" && self.mode == "proxy",
            "unsupported attestation protocol"
        );
        ensure!(
            self.tls.version == 0x0304 && matches!(self.tls.suite, 0x1301 | 0x1302),
            "unsupported TLS suite"
        );
        ensure!(!self.tls.hrr, "HRR is not supported by this schema profile");
        for hash in [&self.handshake.h_ch_sh, &self.handshake.h_ch_sf] {
            ensure!(
                matches!(
                    (self.tls.suite, hash),
                    (0x1301, TranscriptHash::Sha256(_)) | (0x1302, TranscriptHash::Sha384(_))
                ),
                "transcript hash width does not match TLS suite"
            );
        }
        ensure!(
            self.server.cert_verified_by_notary,
            "server certificate was not verified"
        );
        ensure!(
            self.server.port != 0 && !self.server.name.is_empty() && self.server.name.len() <= 253,
            "invalid server identity"
        );
        ensure!(
            self.server.dialed_ip.parse::<std::net::IpAddr>().is_ok(),
            "invalid dialed IP"
        );
        ensure!(self.claims.len() <= 256, "too many session claims");
        for claim in &self.claims {
            let selector = match claim {
                Claim::Reveal { selector, .. } | Claim::JsonPath { selector, .. } => selector,
                Claim::Predicate { selector, op, .. } => {
                    ensure!(
                        matches!(op.as_str(), "eq" | "ne" | "lt" | "le" | "gt" | "ge"),
                        "unsupported predicate"
                    );
                    selector
                }
            };
            ensure!(
                !selector.is_empty() && selector.len() <= 4096,
                "invalid claim selector"
            );
        }
        for value in [&self.binding.owner, &self.binding.context]
            .into_iter()
            .flatten()
        {
            ensure!(value.len() <= 4096, "binding exceeds cap");
        }
        self.sent.validate()?;
        self.recv.validate()?;
        Ok(())
    }

    /// RFC 8949 §4.2.1 core deterministic encoding: preferred integers,
    /// definite lengths, bytewise lexicographic map-key ordering.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut value = Value::serialized(self)?;
        canonicalize(&mut value)?;
        let mut bytes = Vec::new();
        ciborium::into_writer(&value, &mut bytes)?;
        ensure!(
            bytes.len() <= MAX_ATTESTATION_BYTES,
            "attestation exceeds cap"
        );
        Ok(bytes)
    }

    /// Reject unknown/duplicate fields, trailing data, tags, alternate integer
    /// widths, indefinite containers and alternate map orderings.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_ATTESTATION_BYTES,
            "attestation exceeds cap"
        );
        let mut cursor = Cursor::new(bytes);
        let value: Self = ciborium::from_reader(&mut cursor)?;
        ensure!(
            cursor.position() == bytes.len() as u64,
            "trailing attestation bytes"
        );
        ensure!(
            value.encode()? == bytes,
            "non-deterministic attestation encoding"
        );
        Ok(value)
    }

    pub fn digest(&self) -> Result<[u8; 32]> {
        let mut hash = Sha256::new();
        hash.update(b"zkf/2/attestation");
        hash.update(self.encode()?);
        Ok(hash.finalize().into())
    }

    /// The caller must accept the key-binding/claims proof before signing.
    pub fn sign(&self, key: &SigningKey) -> Result<Bytes<64>> {
        ensure!(
            self.notary_key_id == key_id(key.verifying_key()),
            "notary key identifier mismatch"
        );
        let signature: Signature = key.sign_prehash(&self.digest()?)?;
        Ok(Bytes(signature.to_bytes().into()))
    }

    /// `key` must come from the verifier's trust policy, never from the proof.
    /// Expiry, origin and claim policies remain the integrating verifier's job.
    pub fn verify_signature(&self, signature: &Bytes<64>, key: &VerifyingKey) -> Result<()> {
        ensure!(
            self.notary_key_id == key_id(key),
            "notary key identifier mismatch"
        );
        let signature = Signature::from_slice(&signature.0)?;
        ensure!(
            signature.normalize_s().is_none(),
            "non-canonical ECDSA signature"
        );
        key.verify_prehash(&self.digest()?, &signature)?;
        Ok(())
    }
}

pub fn key_id(key: &VerifyingKey) -> Bytes<32> {
    Bytes(Sha256::digest(key.to_encoded_point(true).as_bytes()).into())
}

/// What the prover and the notary bind into the in-session key-commitment
/// proofs: exactly the ciphertext roots, IVs and handshake hashes the
/// attestation will sign. Each side computes it from its own recording.
pub fn session_binding(
    sent: &records::Direction,
    recv: &records::Direction,
    iv_client: &[u8; 12],
    iv_server: &[u8; 12],
    hello_hash: &[u8; 32],
    application_hash: &[u8; 32],
) -> Vec<u8> {
    let mut out = b"zkf/2/session-binding\0".to_vec();
    for direction in [sent, recv] {
        out.extend_from_slice(&direction.root.0);
        out.extend_from_slice(&direction.len.to_le_bytes());
    }
    out.extend_from_slice(iv_client);
    out.extend_from_slice(iv_server);
    out.extend_from_slice(hello_hash);
    out.extend_from_slice(application_hash);
    out
}

/// SHA-256 over the DER chain the notary verified, leaf first, each
/// certificate length-prefixed.
pub fn chain_sha256<'a>(chain: impl IntoIterator<Item = &'a [u8]>) -> Bytes<32> {
    let mut hash = Sha256::new();
    hash.update(b"zkf/2/chain");
    for cert in chain {
        hash.update((cert.len() as u64).to_be_bytes());
        hash.update(cert);
    }
    Bytes(hash.finalize().into())
}

/// SHA-256 of the leaf certificate's DER `SubjectPublicKeyInfo` (the usual
/// SPKI pin). Walks only the fixed prefix of `TBSCertificate` (RFC 5280).
pub fn spki_sha256(cert: &[u8]) -> Result<Bytes<32>> {
    let (certificate, _) = der_element(cert, 0x30)?;
    let (tbs, _) = der_element(content(certificate)?, 0x30)?;
    let mut rest = content(tbs)?;
    if rest.first() == Some(&0xa0) {
        rest = der_element(rest, 0xa0)?.1;
    }
    // serialNumber, signature, issuer, validity, subject.
    for tag in [0x02, 0x30, 0x30, 0x30, 0x30] {
        rest = der_element(rest, tag)?.1;
    }
    let (spki, _) = der_element(rest, 0x30)?;
    Ok(Bytes(Sha256::digest(spki).into()))
}

/// Splits one DER element with `tag` off the front of `bytes`.
fn der_element(bytes: &[u8], tag: u8) -> Result<(&[u8], &[u8])> {
    ensure!(bytes.len() >= 2 && bytes[0] == tag, "unexpected DER element");
    let (header, len) = match bytes[1] {
        n @ 0..=0x7f => (2, n as usize),
        n @ 0x81..=0x84 => {
            let width = (n & 0x7f) as usize;
            ensure!(bytes.len() >= 2 + width, "truncated DER length");
            let len = bytes[2..2 + width]
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | b as usize);
            (2 + width, len)
        }
        _ => bail!("unsupported DER length"),
    };
    let end = header
        .checked_add(len)
        .filter(|&end| end <= bytes.len())
        .ok_or_else(|| anyhow::anyhow!("truncated DER element"))?;
    Ok((&bytes[..end], &bytes[end..]))
}

fn content(element: &[u8]) -> Result<&[u8]> {
    let header = match element[1] {
        0..=0x7f => 2,
        n => 2 + (n & 0x7f) as usize,
    };
    Ok(&element[header..])
}

const ENVELOPE_MAGIC: &[u8; 8] = b"zkf2att\x01";

/// An attestation as the notary returns it: the deterministic CBOR, its
/// signature and the key the notary *claims* to sign with. The claimed key
/// is a lookup hint only; [`SignedAttestation::verify`] takes the trusted key.
#[derive(Clone, Debug)]
pub struct SignedAttestation {
    pub attestation: Attestation,
    pub signature: Bytes<64>,
    pub claimed_key: VerifyingKey,
}

impl SignedAttestation {
    pub fn sign(attestation: Attestation, key: &SigningKey) -> Result<Self> {
        let signature = attestation.sign(key)?;
        Ok(Self {
            attestation,
            signature,
            claimed_key: *key.verifying_key(),
        })
    }

    /// `magic ‖ u32 BE length ‖ CBOR ‖ signature ‖ compressed SEC1 key`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let cbor = self.attestation.encode()?;
        let mut out = Vec::with_capacity(cbor.len() + 109);
        out.extend_from_slice(ENVELOPE_MAGIC);
        out.extend_from_slice(&u32::try_from(cbor.len())?.to_be_bytes());
        out.extend_from_slice(&cbor);
        out.extend_from_slice(&self.signature.0);
        out.extend_from_slice(self.claimed_key.to_encoded_point(true).as_bytes());
        Ok(out)
    }

    /// Strict decoding. Does not establish trust: call [`Self::verify`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() >= 12 && &bytes[..8] == ENVELOPE_MAGIC,
            "not a v2 attestation"
        );
        let len = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
        ensure!(len <= MAX_ATTESTATION_BYTES, "attestation exceeds cap");
        ensure!(
            bytes.len() == 12 + len + 64 + 33,
            "malformed attestation envelope"
        );
        let attestation = Attestation::decode(&bytes[12..12 + len])?;
        let signature = Bytes(bytes[12 + len..12 + len + 64].try_into().unwrap());
        let claimed_key = VerifyingKey::from_sec1_bytes(&bytes[12 + len + 64..])?;
        ensure!(
            attestation.notary_key_id == key_id(&claimed_key),
            "notary key identifier mismatch"
        );
        Ok(Self {
            attestation,
            signature,
            claimed_key,
        })
    }

    /// Checks the signature under a key taken from the verifier's trust policy.
    pub fn verify(&self, trusted: &VerifyingKey) -> Result<()> {
        self.attestation.verify_signature(&self.signature, trusted)
    }
}

fn canonicalize(value: &mut Value) -> Result<()> {
    match value {
        Value::Array(values) => {
            for value in values {
                canonicalize(value)?;
            }
        }
        Value::Map(entries) => {
            let mut keyed = Vec::with_capacity(entries.len());
            for (mut key, mut value) in std::mem::take(entries) {
                ensure!(matches!(key, Value::Text(_)), "map key must be text");
                canonicalize(&mut key)?;
                canonicalize(&mut value)?;
                let mut bytes = Vec::new();
                ciborium::into_writer(&key, &mut bytes)?;
                keyed.push((bytes, key, value));
            }
            keyed.sort_by(|a, b| a.0.cmp(&b.0));
            ensure!(
                !keyed.windows(2).any(|w| w[0].0 == w[1].0),
                "duplicate map key"
            );
            *entries = keyed
                .into_iter()
                .map(|(_, key, value)| (key, value))
                .collect();
        }
        Value::Float(_) | Value::Tag(_, _) => bail!("float/tag is not allowed in attestation"),
        Value::Integer(_) | Value::Bytes(_) | Value::Text(_) | Value::Bool(_) | Value::Null => {}
        _ => bail!("unsupported CBOR value"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(key: &SigningKey) -> Attestation {
        let direction = records::RecordStream::new(&[], 0, false).unwrap().direction;
        Attestation {
            v: 2,
            alg: "secp256k1".into(),
            notary_key_id: key_id(key.verifying_key()),
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
            sent: direction.clone(),
            recv: direction,
            keys: Keys {
                c_client: Bytes([6; 32]),
                c_server: Bytes([7; 32]),
                iv_client: Bytes([8; 12]),
                iv_server: Bytes([9; 12]),
            },
            claims: vec![Claim::Predicate {
                selector: "id".into(),
                op: "ge".into(),
                constant: 1000,
                result: true,
            }],
            binding: Binding {
                owner: None,
                context: Some("test".into()),
            },
        }
    }
    fn key() -> SigningKey {
        SigningKey::from_slice(&[1; 32]).unwrap()
    }
    #[test]
    fn deterministic_roundtrip_and_signature() {
        let key = key();
        let a = fixture(&key);
        let bytes = a.encode().unwrap();
        let b = Attestation::decode(&bytes).unwrap();
        assert_eq!(a, b);
        assert_eq!(b.encode().unwrap(), bytes);
        a.verify_signature(&a.sign(&key).unwrap(), key.verifying_key())
            .unwrap();
        let other = SigningKey::from_slice(&[2; 32]).unwrap();
        assert!(
            a.verify_signature(&a.sign(&key).unwrap(), other.verifying_key())
                .is_err()
        );
    }
    #[test]
    fn mutations_do_not_verify_and_trailing_bytes_rejected() {
        let key = key();
        let a = fixture(&key);
        let signature = a.sign(&key).unwrap();
        let bytes = a.encode().unwrap();
        for i in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[i] ^= 1;
            if let Ok(a) = Attestation::decode(&changed) {
                assert!(
                    a.verify_signature(&signature, key.verifying_key()).is_err(),
                    "mutation {i}"
                );
            }
        }
        let mut changed = bytes;
        changed.push(0);
        assert!(Attestation::decode(&changed).is_err());
        for i in 0..64 {
            let mut changed = signature.clone();
            changed.0[i] ^= 1;
            assert!(a.verify_signature(&changed, key.verifying_key()).is_err());
        }
    }
    #[test]
    fn unknown_duplicate_and_reordered_fields_rejected() {
        let a = fixture(&key());
        let mut v = Value::serialized(&a).unwrap();
        canonicalize(&mut v).unwrap();
        let mut variants = Vec::new();
        if let Value::Map(fields) = &mut v {
            fields.swap(0, 1);
            variants.push(v.clone());
        }
        if let Value::Map(fields) = &mut v {
            fields.push((Value::Text("unknown".into()), Value::Null));
            variants.push(v.clone());
        }
        if let Value::Map(fields) = &mut v {
            fields.pop();
            fields.push(fields[0].clone());
            variants.push(v.clone());
        }
        for value in variants {
            let mut bytes = Vec::new();
            ciborium::into_writer(&value, &mut bytes).unwrap();
            assert!(Attestation::decode(&bytes).is_err());
        }
    }
    #[test]
    fn spki_is_extracted_from_tbs_certificate() {
        fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            if content.len() < 0x80 {
                out.push(content.len() as u8);
            } else {
                out.push(0x82);
                out.extend_from_slice(&(content.len() as u16).to_be_bytes());
            }
            out.extend_from_slice(content);
            out
        }
        let spki = tlv(0x30, &[0x55; 200]);
        let mut tbs = tlv(0xa0, &tlv(0x02, &[2]));
        tbs.extend(tlv(0x02, &[1, 2, 3]));
        for _ in 0..4 {
            tbs.extend(tlv(0x30, &[0x11; 9]));
        }
        tbs.extend(&spki);
        tbs.extend(tlv(0xa3, &[0; 4]));
        let mut cert = tlv(0x30, &tbs);
        cert.extend(tlv(0x30, &[0; 3]));
        let cert = tlv(0x30, &cert);
        assert_eq!(spki_sha256(&cert).unwrap().0, <[u8; 32]>::from(Sha256::digest(&spki)));
        assert!(spki_sha256(&cert[..cert.len() - 1]).is_err());
        assert!(spki_sha256(&[0x30, 0x85, 0, 0, 0, 0, 0]).is_err());
        assert_ne!(chain_sha256([cert.as_slice()]), chain_sha256([cert.as_slice(), &[]]));
    }

    #[test]
    fn signed_envelope_roundtrip_and_tampering() {
        let key = key();
        let signed = SignedAttestation::sign(fixture(&key), &key).unwrap();
        let bytes = signed.encode().unwrap();
        let decoded = SignedAttestation::decode(&bytes).unwrap();
        assert_eq!(decoded.attestation, signed.attestation);
        decoded.verify(key.verifying_key()).unwrap();
        let other = SigningKey::from_slice(&[2; 32]).unwrap();
        assert!(decoded.verify(other.verifying_key()).is_err());
        for i in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[i] ^= 1;
            if let Ok(d) = SignedAttestation::decode(&changed) {
                assert!(d.verify(key.verifying_key()).is_err(), "mutation {i}");
            }
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(SignedAttestation::decode(&longer).is_err());
        // A claimed key that does not match the signed key id is rejected.
        let mut swapped = bytes[..bytes.len() - 33].to_vec();
        swapped.extend_from_slice(other.verifying_key().to_encoded_point(true).as_bytes());
        assert!(SignedAttestation::decode(&swapped).is_err());
    }

    #[test]
    fn flags_are_validated_before_signing() {
        let mut a = fixture(&key());
        a.server.cert_verified_by_notary = false;
        assert!(a.sign(&key()).is_err());
        let mut a = fixture(&key());
        a.tls.suite = 0x1303;
        assert!(a.encode().is_err());
    }

    #[test]
    fn transcript_hashes_match_cipher_suite() {
        let key = key();
        let mut a = fixture(&key);
        a.tls.suite = 0x1302;
        assert!(a.sign(&key).is_err());
        a.handshake.h_ch_sh = TranscriptHash::Sha384(Bytes([4; 48]));
        assert!(a.sign(&key).is_err());
        a.handshake.h_ch_sf = TranscriptHash::Sha384(Bytes([5; 48]));
        let encoded = a.encode().unwrap();
        assert_eq!(Attestation::decode(&encoded).unwrap(), a);
        a.verify_signature(&a.sign(&key).unwrap(), key.verifying_key())
            .unwrap();
        a.tls.suite = 0x1301;
        assert!(a.encode().is_err());
        for length in [0, 31, 33, 47, 49, 64] {
            let mut encoded = Vec::new();
            ciborium::into_writer(&Value::Bytes(vec![0; length]), &mut encoded).unwrap();
            assert!(ciborium::from_reader::<TranscriptHash, _>(encoded.as_slice()).is_err());
        }
    }
}
