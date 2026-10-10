//! Process-wide allocation metrics. No witness values or identifiers are
//! collected. Enable only for isolated benchmarks; counters aggregate all
//! prover VMs and are not session attribution or actual consumed OT counts.
use mpz_vm_core::Call;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
};

#[derive(Clone, Debug, Default, Serialize)]
pub struct CircuitAllocation {
    pub input_bits: usize,
    pub output_bits: usize,
    pub and_gates_per_call: usize,
    pub xor_gates_per_call: usize,
    pub calls: usize,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Snapshot {
    /// Inputs marked private, excluding public inputs and auxiliary AND masks.
    pub private_input_bits: usize,
    pub allocated_and_gates: usize,
    pub circuits: Vec<CircuitAllocation>,
}

#[derive(Default)]
struct Metrics {
    private_input_bits: usize,
    circuits: BTreeMap<(usize, usize, usize, usize), usize>,
}

fn state() -> &'static Mutex<Metrics> {
    static STATE: OnceLock<Mutex<Metrics>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(Metrics::default()))
}

pub(crate) fn record_call(call: &Call) {
    let c = call.circ();
    let key = (
        c.inputs().len(),
        c.outputs().len(),
        c.and_count(),
        c.xor_count(),
    );
    *state()
        .lock()
        .expect("metrics poisoned")
        .circuits
        .entry(key)
        .or_default() += 1;
}
pub(crate) fn record_private(bits: usize) {
    state().lock().expect("metrics poisoned").private_input_bits += bits;
}

pub fn snapshot() -> Snapshot {
    let state = state().lock().expect("metrics poisoned");
    Snapshot {
        private_input_bits: state.private_input_bits,
        allocated_and_gates: state
            .circuits
            .iter()
            .map(|((_, _, ands, _), calls)| ands * calls)
            .sum(),
        circuits: state
            .circuits
            .iter()
            .map(
                |(&(input_bits, output_bits, and_gates_per_call, xor_gates_per_call), &calls)| {
                    CircuitAllocation {
                        input_bits,
                        output_bits,
                        and_gates_per_call,
                        xor_gates_per_call,
                        calls,
                    }
                },
            )
            .collect(),
    }
}

/// Reset only when there are no other prover VMs running in this process.
pub fn reset() {
    *state().lock().expect("metrics poisoned") = Metrics::default();
}
