//! Public HTTP response framing authenticated during a v2 session.
use crate::{Bytes, Claim};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ops::Range;

pub const HEAD_SELECTOR: &str = "zkf/2/response-head/v1";

/// A typed root-to-leaf selector. Strings name object members; integers index
/// arrays. A string containing a dot remains one literal member name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonPathSegment {
    Member(String),
    Index(usize),
}

/// Public byte locations of one path edge, authenticated by the JSON circuit.
/// Array edges have an empty encoded key, 0..0 key range and zero colon.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathAnchor {
    pub encoded_key: Vec<u8>,
    pub key: Range<usize>,
    pub colon: usize,
    pub value: Range<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordView {
    pub content_len: usize,
    pub inner_type: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Head {
    pub headers: Vec<u8>,
    pub records: Vec<RecordView>,
}

/// Numeric member claim selected before fetching: a root-object member, or
/// an exact root-to-leaf path (optionally with unique names along it). The
/// independent verifier nonce is signed as part of the selector; it cannot be
/// replaced later to turn an old signed result into a fresh presentation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberClaim {
    pub member: String,
    pub op: String,
    pub constant: u64,
    pub nonce: [u8; 32],
    pub encoded_key: Vec<u8>,
    pub key: Range<usize>,
    pub colon: usize,
    pub value: Range<usize>,
    /// Empty for a root-object member claim. Tagged encoding: the segment
    /// enum is untagged for JSON APIs, which binary codecs cannot decode.
    #[serde(with = "tagged_path")]
    pub path: Vec<JsonPathSegment>,
    pub unique: bool,
    /// One anchor per path edge; empty for a root-object member claim.
    pub anchors: Vec<PathAnchor>,
    /// Parser depth bound for path claims (1..=8); 4 for root members.
    pub max_depth: u8,
}

/// Selector for a signed path claim. The path is canonical JSON of the typed
/// segments, so `["a.b"]` and `["a","b"]` differ, as do member names and indices.
pub fn path_member_claim(
    path: &[JsonPathSegment],
    unique: bool,
    op: &str,
    constant: u64,
    nonce: [u8; 32],
) -> Claim {
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    let encoded = serde_json::to_vec(path).expect("path segments serialize");
    Claim::Predicate {
        selector: format!(
            "zkf/2/json-path-member/v1/{}/{}/{}",
            hex(&nonce),
            u8::from(unique),
            hex(&encoded)
        ),
        op: op.into(),
        constant,
        result: true,
    }
}

pub fn member_claim(member: &str, op: &str, constant: u64, nonce: [u8; 32]) -> Claim {
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    Claim::Predicate {
        selector: format!(
            "zkf/2/top-level-member/v2/{}/{}",
            hex(&nonce),
            hex(member.as_bytes())
        ),
        op: op.into(),
        constant,
        result: true,
    }
}
impl MemberClaim {
    pub fn is_path(&self) -> bool {
        !self.path.is_empty() || self.unique
    }
    pub fn claim(&self) -> Claim {
        if self.is_path() {
            path_member_claim(&self.path, self.unique, &self.op, self.constant, self.nonce)
        } else {
            member_claim(&self.member, &self.op, self.constant, self.nonce)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub head: Head,
    pub claims: Vec<MemberClaim>,
}

impl Head {
    /// Canonical lengths and ordered views prevent ambiguous body offsets.
    pub fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"zkf/2/response-head/v1\0");
        hash.update((self.headers.len() as u64).to_le_bytes());
        hash.update(&self.headers);
        hash.update((self.records.len() as u64).to_le_bytes());
        for record in &self.records {
            hash.update((record.content_len as u64).to_le_bytes());
            hash.update([record.inner_type]);
        }
        hash.finalize().into()
    }
    pub fn claim(&self) -> Claim {
        Claim::Reveal {
            selector: HEAD_SELECTOR.into(),
            revealed_digest: Bytes(self.digest()),
        }
    }
    pub fn is_signed(&self, claims: &[Claim]) -> bool {
        claims.iter().any(|claim| {
            matches!(claim, Claim::Reveal { selector, revealed_digest }
            if selector == HEAD_SELECTOR && revealed_digest.0 == self.digest())
        })
    }
}

mod tagged_path {
    use super::JsonPathSegment;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    #[derive(Serialize, Deserialize)]
    enum Tagged {
        Member(String),
        Index(u64),
    }
    pub fn serialize<S: Serializer>(path: &[JsonPathSegment], s: S) -> Result<S::Ok, S::Error> {
        path.iter()
            .map(|segment| match segment {
                JsonPathSegment::Member(name) => Tagged::Member(name.clone()),
                JsonPathSegment::Index(index) => Tagged::Index(*index as u64),
            })
            .collect::<Vec<_>>()
            .serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<JsonPathSegment>, D::Error> {
        Vec::<Tagged>::deserialize(d)?
            .into_iter()
            .map(|segment| match segment {
                Tagged::Member(name) => Ok(JsonPathSegment::Member(name)),
                Tagged::Index(index) => usize::try_from(index)
                    .map(JsonPathSegment::Index)
                    .map_err(serde::de::Error::custom),
            })
            .collect()
    }
}
