//! Generalized VOLE-in-the-head backend under development. No production
//! presentation API is exposed until the full relation/transcript is tested.
pub use faest::zkfetch as primitives;
/// Experimental general-relation protocol. Not wired into production until
/// statement construction, malicious tests and composition review pass.
pub mod experimental;
/// Experimental signed-ciphertext HTTP/JSON presentation profile.
pub mod presentation;

/// Opt-in public stage timings, without witness or transcript contents.
pub mod profile;
