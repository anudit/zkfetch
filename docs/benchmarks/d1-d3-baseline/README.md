# Native fixture baseline

Collected on macOS/aarch64 against the unchanged D4 protocol. Each scenario
contains one cold session and two sessions using the warm VOLE pool. Counters
cover allocations, excluding check masks; they do not measure actual VOLE
consumption or process peak RAM. These are three-sample measurements on
localhost, not hosted or browser benchmarks.

Reproduce each command sequentially on an otherwise idle machine:

```sh
cargo test --release -p zkf-prover --features circuit-metrics --test e2e d1_d3_native_baseline -- --ignored --nocapture
ZKF_D1_D3_SCENARIO=quicksilver cargo test --release -p zkf-prover --features circuit-metrics --test e2e d1_d3_native_baseline -- --ignored --nocapture
ZKF_D1_D3_SCENARIO=reveal cargo test --release -p zkf-prover --features circuit-metrics --test e2e d1_d3_native_baseline -- --ignored --nocapture
python3 scripts/d1-d3-summary.py
cargo run --release -p zkf-ir --example gadget_counts > docs/benchmarks/d1-d3-baseline/ir-gadgets.json
```

- `binius`: full plaintext commitments and a later Binius predicate proof.
- `quicksilver`: full commitments with a signed fetch-time predicate.
- `reveal`: only selected disclosure commitments with a signed fetch-time
  predicate. Its later presentation cannot choose arbitrary new fields.

`summary.json` aggregates the raw measurements. Binius proof bytes are measured
separately from the complete presentation. Zero offline proof bytes in the
QuickSilver scenarios means the predicate was signed during the session, not
that an arbitrary offline predicate has been proved for free.

`ir-gadgets.json` describes unintegrated reference gadgets, not production
session gate counts. `fuzz.json` records short preliminary primitive fuzz runs;
the complete W7 release CPU budget and protocol fuzzing remain outstanding.
