//! wasm-bindgen surface for browsers, web workers and extension service
//! workers. Like `zkf-napi`, every function takes and returns JSON strings
//! matching the camelCase types in `zkf-core`.
//!
//! MPC runs on the calling thread (no `SharedArrayBuffer` or worker threads
//! are needed); call it from a web worker to keep a page responsive. Builds
//! with the `threads` feature also export `initThreadPool`, which spreads the
//! parallel OT work across web workers in a cross-origin isolated context.

use wasm_bindgen::prelude::*;
use zkf_core::{NotarizeParams, PresentV2Request, RevealSpec, VerifyOptions, VerifyV2Options};

#[cfg(all(feature = "threads", target_arch = "wasm32"))]
pub use wasm_bindgen_rayon::init_thread_pool;

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

/// A notary session prepared ahead of a request (connection and MPC
/// preprocessing). Pass it to `notarizePrepared`, which consumes it; call
/// `free()` to discard it and close the session.
#[wasm_bindgen]
pub struct PreparedSession(zkf_prover::Prepared);

/// Prepares a session for a later `notarizePrepared` call. Input:
/// `NotarizeParams` JSON for the upcoming request (headers and body unused).
#[wasm_bindgen]
pub async fn prepare(params_json: String) -> Result<PreparedSession, JsError> {
    let params: NotarizeParams = serde_json::from_str(&params_json).map_err(err)?;
    let prepared = zkf_prover::prepare(&params)
        .await
        .map_err(|e| err(format!("{e:#}")))?;
    Ok(PreparedSession(prepared))
}

/// Runs a notarized fetch on a prepared session. Input: `NotarizeParams`
/// JSON. Output: `NotarizeOutput` JSON.
#[wasm_bindgen(js_name = notarizePrepared)]
pub async fn notarize_prepared(session: PreparedSession, params_json: String) -> Result<String, JsError> {
    let params: NotarizeParams = serde_json::from_str(&params_json).map_err(err)?;
    let output = zkf_prover::notarize_prepared(session.0, params)
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

/// Builds a v2 presentation (base64) from a v2 attestation, its secrets and a
/// `PresentV2Request` JSON. Experimental; proving takes seconds, so call it
/// from a worker.
#[wasm_bindgen(js_name = presentV2)]
pub fn present_v2(attestation: String, secrets: String, request_json: String) -> Result<String, JsError> {
    let request: PresentV2Request = serde_json::from_str(&request_json).map_err(err)?;
    zkf_prover::present_v2(&attestation, &secrets, &request).map_err(|e| err(format!("{e:#}")))
}

/// Verifies a v2 presentation. Input: `VerifyV2Options` JSON. Output: `VerifyV2Output` JSON.
#[wasm_bindgen(js_name = verifyV2)]
pub fn verify_v2(presentation: String, options_json: String) -> Result<String, JsError> {
    let opts: VerifyV2Options = serde_json::from_str(&options_json).map_err(err)?;
    let output = zkf_verifier::verify_v2(&presentation, &opts).map_err(|e| err(format!("{e:#}")))?;
    serde_json::to_string(&output).map_err(err)
}

/// Enable opt-in v2 stage timing; values and credentials are never recorded.
#[wasm_bindgen(js_name = setV2Profiling)]
pub fn set_v2_profiling(enabled: bool) { zkf_voleith::profile::enable(enabled); }
/// Return and clear stage timings from this worker.
#[wasm_bindgen(js_name = takeV2Profile)]
pub fn take_v2_profile() -> Result<String, JsError> {
    serde_json::to_string(&zkf_voleith::profile::take()).map_err(err)
}
