//! RFC 8446 §5.2–5.3. TLS 1.3 has no explicit nonce in the wire record.
use anyhow::{Result, bail, ensure};

pub const TAG_LEN: usize = 16;
pub const MAX_CONTENT: usize = 1 << 14;
pub const MAX_CIPHERTEXT: usize = MAX_CONTENT + 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentType {
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

/// Nonce = static_iv XOR (32 zero bits || uint64_be(sequence)).
pub fn nonce(iv: [u8; 12], sequence: u64) -> [u8; 12] {
    let mut nonce = iv;
    for (out, byte) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
        *out ^= byte;
    }
    nonce
}

pub fn aad(ciphertext_len: usize) -> Result<[u8; 5]> {
    ensure!(
        (TAG_LEN + 1..=MAX_CIPHERTEXT).contains(&ciphertext_len),
        "invalid TLS 1.3 ciphertext length"
    );
    let len = (ciphertext_len as u16).to_be_bytes();
    Ok([23, 3, 3, len[0], len[1]])
}

pub fn encode_inner(content: &[u8], typ: ContentType, padding: usize) -> Result<Vec<u8>> {
    ensure!(
        content.len() <= MAX_CONTENT,
        "TLS content exceeds 2^14 bytes"
    );
    let len = content
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_add(padding))
        .ok_or_else(|| anyhow::anyhow!("inner plaintext length overflow"))?;
    aad(len
        .checked_add(TAG_LEN)
        .ok_or_else(|| anyhow::anyhow!("ciphertext length overflow"))?)?;
    let mut inner = content.to_vec();
    inner.push(typ as u8);
    inner.resize(len, 0);
    Ok(inner)
}

pub fn decode_inner(inner: &[u8]) -> Result<(ContentType, &[u8])> {
    ensure!(
        inner.len() + TAG_LEN <= MAX_CIPHERTEXT,
        "TLS inner plaintext too large"
    );
    let pos = inner
        .iter()
        .rposition(|&b| b != 0)
        .ok_or_else(|| anyhow::anyhow!("missing inner content type"))?;
    ensure!(pos <= MAX_CONTENT, "TLS content exceeds 2^14 bytes");
    let typ = match inner[pos] {
        21 => ContentType::Alert,
        22 => ContentType::Handshake,
        23 => ContentType::ApplicationData,
        _ => bail!("invalid TLS 1.3 inner content type"),
    };
    ensure!(
        pos > 0 || typ == ContentType::ApplicationData,
        "empty handshake/alert record"
    );
    Ok((typ, &inner[..pos]))
}

/// Independent counters per direction and key epoch. Exhaustion fails closed.
#[derive(Default)]
pub struct Sequence {
    next: Option<u64>,
    initialized: bool,
}
impl Sequence {
    pub fn take(&mut self) -> Result<u64> {
        if !self.initialized {
            self.next = Some(0);
            self.initialized = true;
        }
        let sequence = self
            .next
            .ok_or_else(|| anyhow::anyhow!("TLS record sequence exhausted"))?;
        self.next = sequence.checked_add(1);
        Ok(sequence)
    }
}

/// Tracks authenticated close_notify for one direction.
#[derive(Default)]
pub struct CloseState {
    closed: bool,
}
impl CloseState {
    pub fn accept(&mut self, typ: ContentType, content: &[u8]) -> Result<()> {
        ensure!(!self.closed, "record received after close_notify");
        if typ == ContentType::Alert {
            ensure!(content.len() == 2, "invalid TLS alert");
            // TLS 1.3 ignores the level for close_notify (RFC 8446 §6.1).
            ensure!(content[1] == 0, "peer sent fatal/unsupported TLS alert");
            self.closed = true;
        }
        Ok(())
    }
    pub fn is_closed(&self) -> bool {
        self.closed
    }
    pub fn finish(&self, complete_http_framing: bool) -> Result<()> {
        ensure!(
            self.closed || complete_http_framing,
            "truncated TLS stream without complete HTTP framing"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sequence_exhaustion_cannot_wrap() {
        let mut sequence = Sequence {
            next: Some(u64::MAX),
            initialized: true,
        };
        assert_eq!(sequence.take().unwrap(), u64::MAX);
        assert!(sequence.take().is_err());
        assert!(sequence.take().is_err());
    }
}
