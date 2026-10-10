//! Public HTTP response framing authenticated during a v2 session.
use crate::{Bytes, Claim};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ops::Range;

pub const HEAD_SELECTOR: &str = "zkf/2/response-head/v1";

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

/// Numeric top-level object member claim selected before fetching. The independent
/// verifier nonce is signed as part of the selector; it cannot be replaced
/// later to turn an old signed result into a fresh presentation.
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
}

pub fn member_claim(member: &str, op: &str, constant: u64, nonce: [u8; 32]) -> Claim {
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    Claim::Predicate {
        selector: format!("zkf/2/top-level-member/v2/{}/{}", hex(&nonce), hex(member.as_bytes())),
        op: op.into(),
        constant,
        result: true,
    }
}
impl MemberClaim {
    pub fn claim(&self) -> Claim {
        member_claim(&self.member, &self.op, self.constant, self.nonce)
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
