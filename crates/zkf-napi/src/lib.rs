//! Node-API surface. Every function takes and returns JSON strings matching
//! the camelCase types in `zkf-core`, keeping the binding layer thin.

use napi::{Error, Result};
use napi_derive::napi;
use zkf_core::{NotarizeParams, PresentV2Request, RevealSpec, VerifyOptions, VerifyV2Options};

fn err(e: impl std::fmt::Display) -> Error {
    Error::from_reason(e.to_string())
}

/// A move-only prepared session. Taking or disposing it burns the lease.
#[napi]
pub struct PreparedSession {
    inner: std::sync::Mutex<Option<zkf_prover::Prepared>>,
}

#[napi]
impl PreparedSession {
    #[napi]
    pub async fn notarize(&self, params_json: String) -> Result<String> {
        let params: NotarizeParams = serde_json::from_str(&params_json).map_err(err)?;
        let session = self
            .inner
            .lock()
            .map_err(err)?
            .take()
            .ok_or_else(|| err("prepared session already consumed or disposed"))?;
        let output = zkf_prover::notarize_prepared(session, params)
            .await
            .map_err(|e| err(format!("{e:#}")))?;
        serde_json::to_string(&output).map_err(err)
    }

    #[napi]
    pub fn dispose(&self) -> Result<()> {
        self.inner.lock().map_err(err)?.take();
        Ok(())
    }
}

/// Establish request-independent setup without sending the HTTP request.
#[napi]
pub async fn prepare(params_json: String) -> Result<PreparedSession> {
    let params: NotarizeParams = serde_json::from_str(&params_json).map_err(err)?;
    let session = zkf_prover::prepare(&params)
        .await
        .map_err(|e| err(format!("{e:#}")))?;
    Ok(PreparedSession {
        inner: std::sync::Mutex::new(Some(session)),
    })
}

/// Runs a notarized fetch. Input: `NotarizeParams` JSON. Output: `NotarizeOutput` JSON.
#[napi]
pub async fn notarize(params_json: String) -> Result<String> {
    let params: NotarizeParams = serde_json::from_str(&params_json).map_err(err)?;
    let output = zkf_prover::notarize(params)
        .await
        .map_err(|e| err(format!("{e:#}")))?;
    serde_json::to_string(&output).map_err(err)
}

/// Builds a presentation (base64) from an attestation, its secrets and a `RevealSpec` JSON.
#[napi]
pub fn present(attestation: String, secrets: String, spec_json: String) -> Result<String> {
    let spec: RevealSpec = serde_json::from_str(&spec_json).map_err(err)?;
    zkf_prover::present(&attestation, &secrets, &spec).map_err(|e| err(format!("{e:#}")))
}

/// Verifies a presentation (base64). Input: `VerifyOptions` JSON. Output: `VerifyOutput` JSON.
#[napi]
pub fn verify(presentation: String, options_json: String) -> Result<String> {
    let opts: VerifyOptions = serde_json::from_str(&options_json).map_err(err)?;
    let output = zkf_verifier::verify(&presentation, &opts).map_err(|e| err(format!("{e:#}")))?;
    serde_json::to_string(&output).map_err(err)
}

/// Builds a v2 presentation (base64) from a v2 attestation, its secrets and a
/// `PresentV2Request` JSON. Experimental; proving takes seconds.
#[napi(js_name = "presentV2")]
pub async fn present_v2(
    attestation: String,
    secrets: String,
    request_json: String,
) -> Result<String> {
    let request: PresentV2Request = serde_json::from_str(&request_json).map_err(err)?;
    napi::tokio::task::spawn_blocking(move || {
        zkf_prover::present_v2(&attestation, &secrets, &request)
    })
    .await
    .map_err(err)?
    .map_err(|e| err(format!("{e:#}")))
}

/// Verifies a v2 presentation. Input: `VerifyV2Options` JSON. Output: `VerifyV2Output` JSON.
#[napi(js_name = "verifyV2")]
pub async fn verify_v2(presentation: String, options_json: String) -> Result<String> {
    let opts: VerifyV2Options = serde_json::from_str(&options_json).map_err(err)?;
    let output =
        napi::tokio::task::spawn_blocking(move || zkf_verifier::verify_v2(&presentation, &opts))
            .await
            .map_err(err)?
            .map_err(|e| err(format!("{e:#}")))?;
    serde_json::to_string(&output).map_err(err)
}

// Workaround for an ld-27037 (macOS 27 SDK) bug: when a dylib has an odd number
// of indirect symbols the linker leaves the LINKEDIT string pool 4-byte aligned
// and dyld refuses to load it. Importing one extra data symbol (one GOT entry)
// flips the parity. `packages/native/scripts/copy-binary.ts` enables this cfg
// only when the first link comes out misaligned.
#[cfg(zkf_pad_indirect)]
mod pad_indirect {
    unsafe extern "C" {
        static optarg: *const std::ffi::c_char;
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn zkf_pad_indirect() -> usize {
        &raw const optarg as usize
    }
}
