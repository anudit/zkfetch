//! Experimental strict VM; production protocol negotiation must select it explicitly.
mod prover;
mod verifier;
pub use mpz_zk_core::auth::ZkDelta;
pub use prover::Prover;
pub use verifier::Verifier;
