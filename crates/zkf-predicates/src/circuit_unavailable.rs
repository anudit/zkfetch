//! Legacy zkf/1 envelopes are recognized but cannot prove/verify without opt-in.
use crate::ScalarClaim;
use anyhow::{Result, bail};

pub fn prove(_: &[ScalarClaim], _: &[Vec<u8>], _: &[u8]) -> Result<Vec<u8>> {
    bail!("legacy Binius prover disabled; enable legacy-binius for zkf/1")
}
pub fn verify(_: &[ScalarClaim], _: Vec<u8>, _: &[u8]) -> Result<()> {
    bail!("legacy Binius verifier disabled; enable legacy-binius for zkf/1")
}

#[cfg(test)]
mod tests {
    #[test]
    fn legacy_proofs_cannot_fall_through_to_another_backend() {
        assert!(super::prove(&[], &[], &[]).is_err());
        assert!(super::verify(&[], vec![], &[]).is_err());
    }
}
