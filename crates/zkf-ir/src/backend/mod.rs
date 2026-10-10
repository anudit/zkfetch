//! Check algebra shared by future interactive and offline backends.
//! This is not a transcript protocol and does not generate a ZK proof.
pub mod check;
/// Experimental authenticated bridge to an existing MPZ binary VM.
#[cfg(feature = "mpz-backend")]
pub mod mpz;
