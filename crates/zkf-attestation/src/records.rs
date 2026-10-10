//! Record tables bind every outer application-data record, including encrypted
//! tickets and alerts. Never infer the inner content type from the outer type.
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};

pub const MAX_STREAM_BYTES: usize = 8 << 20;
pub const MAX_RECORDS: usize = 16384;
pub const CHUNK_SIZE: u64 = 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub seq: u64,
    #[serde(rename = "type")]
    pub outer_type: u8,
    /// Ciphertext payload length, including the GCM tag.
    pub len: u16,
    /// Offset of the five-byte TLS record header in the committed byte stream.
    pub offset: u64,
}

/// Public summary signed by the notary. The record table is signed as well as
/// the root; it cannot be supplied independently by a presentation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Direction {
    pub root: crate::Bytes<32>,
    pub len: u64,
    pub records: Vec<Record>,
    pub complete: bool,
}

impl Direction {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.len <= MAX_STREAM_BYTES as u64,
            "record stream exceeds cap"
        );
        ensure!(
            self.records.len() <= MAX_RECORDS,
            "record count exceeds cap"
        );
        let mut offset = 0u64;
        for (i, record) in self.records.iter().enumerate() {
            ensure!(record.outer_type == 0x17, "unexpected outer record type");
            ensure!(
                (17..=16640).contains(&record.len),
                "invalid TLSCiphertext length"
            );
            ensure!(record.offset == offset, "non-contiguous record table");
            if i != 0 {
                ensure!(
                    self.records[i - 1].seq.checked_add(1) == Some(record.seq),
                    "non-monotonic record sequence"
                );
            }
            offset = offset
                .checked_add(5 + record.len as u64)
                .ok_or_else(|| anyhow::anyhow!("offset overflow"))?;
        }
        ensure!(offset == self.len, "record table does not cover stream");
        Ok(())
    }

    /// Resolve a touched plaintext block to its ciphertext payload bytes.
    /// GCM tag bytes and bytes beyond the record cannot be opened as plaintext.
    pub fn block_range(&self, record_index: usize, block_index: u32) -> Result<(u64, u64)> {
        self.validate()?;
        let record = self
            .records
            .get(record_index)
            .ok_or_else(|| anyhow::anyhow!("missing record"))?;
        let relative = u64::from(block_index) * 16;
        let plaintext_len = u64::from(record.len) - 16;
        ensure!(relative < plaintext_len, "block outside plaintext");
        Ok((
            record.offset + 5 + relative,
            (plaintext_len - relative).min(16),
        ))
    }
}

pub struct RecordStream {
    bytes: Vec<u8>,
    encoding: Vec<u8>,
    pub direction: Direction,
}

impl RecordStream {
    /// `first_sequence` is supplied from the authenticated application-key
    /// epoch. Every record in that epoch must be retained, including tickets.
    pub fn new(records: &[Vec<u8>], first_sequence: u64, complete: bool) -> Result<Self> {
        ensure!(records.len() <= MAX_RECORDS, "record count exceeds cap");
        let mut bytes = Vec::new();
        let mut table = Vec::with_capacity(records.len());
        for (i, raw) in records.iter().enumerate() {
            ensure!(raw.len() >= 5, "truncated record header");
            ensure!(
                raw[..3] == [0x17, 0x03, 0x03],
                "invalid TLS 1.3 outer header"
            );
            let len = u16::from_be_bytes([raw[3], raw[4]]);
            ensure!((17..=16640).contains(&len), "invalid TLSCiphertext length");
            ensure!(
                raw.len() == usize::from(len) + 5,
                "TLS record length mismatch"
            );
            ensure!(
                bytes
                    .len()
                    .checked_add(raw.len())
                    .is_some_and(|n| n <= MAX_STREAM_BYTES),
                "record stream exceeds cap"
            );
            table.push(Record {
                seq: first_sequence
                    .checked_add(i as u64)
                    .ok_or_else(|| anyhow::anyhow!("sequence overflow"))?,
                outer_type: 0x17,
                len,
                offset: bytes.len() as u64,
            });
            bytes.extend_from_slice(raw);
        }
        let (encoding, hash) = bao::encode::encode(&bytes);
        let direction = Direction {
            root: crate::Bytes(*hash.as_bytes()),
            len: bytes.len() as u64,
            records: table,
            complete,
        };
        direction.validate()?;
        Ok(Self {
            bytes,
            encoding,
            direction,
        })
    }

    /// Open whole 1 KiB chunks containing the requested range. Ciphertext
    /// outside the range remains public and carries no disclosed plaintext.
    pub fn open(&self, offset: u64, length: u64) -> Result<Opening> {
        let (start, len) = chunk_range(self.direction.len, offset, length)?;
        let mut extractor =
            bao::encode::SliceExtractor::new(Cursor::new(&self.encoding), start, len);
        let mut proof = Vec::new();
        extractor.read_to_end(&mut proof)?;
        Ok(Opening {
            offset: start,
            length: len,
            proof,
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn chunk_range(total: u64, offset: u64, length: u64) -> Result<(u64, u64)> {
    ensure!(length != 0, "empty opening");
    let end = offset
        .checked_add(length)
        .ok_or_else(|| anyhow::anyhow!("opening overflow"))?;
    ensure!(
        end <= total && total <= MAX_STREAM_BYTES as u64,
        "opening outside stream"
    );
    let start = offset / CHUNK_SIZE * CHUNK_SIZE;
    let end = end
        .div_ceil(CHUNK_SIZE)
        .checked_mul(CHUNK_SIZE)
        .ok_or_else(|| anyhow::anyhow!("opening overflow"))?
        .min(total);
    Ok((start, end - start))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Opening {
    pub offset: u64,
    pub length: u64,
    pub proof: Vec<u8>,
}

impl Opening {
    pub fn verify(&self, direction: &Direction) -> Result<Vec<u8>> {
        direction.validate()?;
        let (start, len) = chunk_range(direction.len, self.offset, self.length)?;
        ensure!(
            start == self.offset && len == self.length,
            "opening is not chunk aligned"
        );
        // A Bao tree with an 8 MiB cap needs fewer than 14 levels. Bound the
        // encoded opening before invoking the decoder, including path nodes.
        let chunks = len.div_ceil(CHUNK_SIZE);
        ensure!(
            self.proof.len() as u64 <= len + 8 + (chunks + 28) * 64,
            "oversized Bao proof"
        );
        ensure!(self.proof.len() >= 8, "truncated Bao header");
        ensure!(
            u64::from_le_bytes(self.proof[..8].try_into().unwrap()) == direction.len,
            "Bao stream length mismatch"
        );
        let hash = blake3::Hash::from(direction.root.0);
        let mut cursor = Cursor::new(&self.proof);
        let mut decoder =
            bao::decode::SliceDecoder::new(&mut cursor, &hash, self.offset, self.length);
        let mut bytes = Vec::new();
        decoder.read_to_end(&mut bytes)?;
        drop(decoder);
        ensure!(bytes.len() as u64 == len, "wrong decoded opening length");
        if cursor.position() != self.proof.len() as u64 {
            bail!("trailing Bao proof bytes");
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(fill: u8, len: u16) -> Vec<u8> {
        let mut raw = vec![23, 3, 3];
        raw.extend_from_slice(&len.to_be_bytes());
        raw.resize(5 + len as usize, fill);
        raw
    }
    #[test]
    fn openings_bind_boundaries_length_and_root() {
        let stream = RecordStream::new(&[record(1, 1200), record(2, 1200)], 0, true).unwrap();
        for (offset, len) in [(0, 16), (1023, 16), (1205, 16), (2400, 10)] {
            let opening = stream.open(offset, len).unwrap();
            let decoded = opening.verify(&stream.direction).unwrap();
            assert_eq!(
                decoded,
                stream.bytes[opening.offset as usize..(opening.offset + opening.length) as usize]
            );
            let mut wrong_root = stream.direction.clone();
            wrong_root.root.0[0] ^= 1;
            assert!(opening.verify(&wrong_root).is_err());
            let mut trailing = opening.clone();
            trailing.proof.push(0);
            assert!(trailing.verify(&stream.direction).is_err());
            for i in 0..opening.proof.len() {
                let mut bad = opening.clone();
                bad.proof[i] ^= 1;
                assert!(
                    bad.verify(&stream.direction).is_err(),
                    "accepted mutation {i}"
                );
            }
        }
    }
    #[test]
    fn record_reordering_duplication_and_offsets_rejected() {
        let stream = RecordStream::new(&[record(1, 32), record(2, 32)], 5, true).unwrap();
        let mut bad = stream.direction.clone();
        bad.records.swap(0, 1);
        assert!(bad.validate().is_err());
        let mut bad = stream.direction.clone();
        bad.records[1].seq = bad.records[0].seq;
        assert!(bad.validate().is_err());
        let mut bad = stream.direction.clone();
        bad.records[1].offset += 1;
        assert!(bad.validate().is_err());
        assert_eq!(stream.direction.block_range(0, 0).unwrap(), (5, 16));
        assert!(stream.direction.block_range(0, 1).is_err());
        assert!(stream.open(u64::MAX, 1).is_err());
        assert!(RecordStream::new(&[record(1, 16)], 0, true).is_err());
        assert!(RecordStream::new(&[record(1, 17), record(1, 17)], u64::MAX, true).is_err());
    }
    #[test]
    fn empty_stream_has_root_but_no_opening() {
        let stream = RecordStream::new(&[], 0, true).unwrap();
        assert_eq!(stream.direction.root.0, *blake3::hash(&[]).as_bytes());
        assert!(stream.open(0, 1).is_err());
    }
}
