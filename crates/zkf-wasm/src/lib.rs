//! wasm-bindgen surface for browsers, web workers and extension service
//! workers. Like `zkf-napi`, every function takes and returns JSON strings
//! matching the camelCase types in `zkf-core`.
//!
//! MPC runs on the calling thread (no `SharedArrayBuffer` or worker threads
//! are needed); call it from a web worker to keep a page responsive.

use wasm_bindgen::prelude::*;
use zkf_core::{NotarizeParams, RevealSpec, VerifyOptions};

fn err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

/// Runs a notarized fetch. Input: `NotarizeParams` JSON. Output: `NotarizeOutput` JSON.
#[wasm_bindgen]
pub async fn notarize(params_json: String) -> Result<String, JsError> {
    let params: NotarizeParams = serde_json::from_str(&params_json).map_err(err)?;
    let output = zkf_prover::notarize(params)
        .await
        .map_err(|e| err(format!("{e:#}")))?;
    serde_json::to_string(&output).map_err(err)
}

/// Builds a presentation (base64) from an attestation, its secrets and a `RevealSpec` JSON.
#[wasm_bindgen]
pub fn present(attestation: String, secrets: String, spec_json: String) -> Result<String, JsError> {
    let spec: RevealSpec = serde_json::from_str(&spec_json).map_err(err)?;
    zkf_prover::present(&attestation, &secrets, &spec).map_err(|e| err(format!("{e:#}")))
}

/// Verifies a presentation (base64). Input: `VerifyOptions` JSON. Output: `VerifyOutput` JSON.
#[wasm_bindgen]
pub fn verify(presentation: String, options_json: String) -> Result<String, JsError> {
    let opts: VerifyOptions = serde_json::from_str(&options_json).map_err(err)?;
    let output = zkf_verifier::verify(&presentation, &opts).map_err(|e| err(format!("{e:#}")))?;
    serde_json::to_string(&output).map_err(err)
}
