//! Fixed-cardinality counters: no URLs, identities, credentials or witnesses.
use std::sync::atomic::{AtomicU64, Ordering};
pub(crate) static ACCEPTED: AtomicU64 = AtomicU64::new(0);
pub(crate) static COMPLETED: AtomicU64 = AtomicU64::new(0);
pub(crate) static FAILED: AtomicU64 = AtomicU64::new(0);
pub(crate) static REJECTED: AtomicU64 = AtomicU64::new(0);
pub(crate) static ACTIVE: AtomicU64 = AtomicU64::new(0);
/// Prometheus text for the private health listener.
pub fn text() -> String {
    let mut output: String = [
        ("zkf_sessions_accepted_total", &ACCEPTED),
        ("zkf_sessions_completed_total", &COMPLETED),
        ("zkf_sessions_failed_total", &FAILED),
        ("zkf_admission_rejected_total", &REJECTED),
        ("zkf_sessions_active", &ACTIVE),
    ]
    .iter()
    .map(|(name, counter)| format!("{name} {}\n", counter.load(Ordering::Relaxed)))
    .collect();
    output.push_str(&format!(
        "zkf_vole_budget_units_active {}\n",
        crate::resources::active_units()
    ));
    output
}
