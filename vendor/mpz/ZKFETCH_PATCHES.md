# zkfetch patches to vendored mpz

Base: `v0.1.0-alpha.6` (6ebfe61). `mpz-common`, `mpz-core`, `mpz-zk-core`, and
`clmul`, `mpz-ot`, and `mpz-ot-core` are vendored.

## P1: single-threaded executor runner

`Executor::local_runner()` returns a `LocalRunner` whose `poll_run(cx, budget)`
drains the executor's global queue on the current thread. Scheduling a task
wakes the registered waker. Built with `num_threads(0)`, the executor spawns no
threads, so MPC runs inside a Cloudflare Worker (wasm32, no threads). The
threaded path is unchanged apart from one extra `AtomicWaker::wake` per
schedule.

## P2: stable ARM64 PMULL enabled by default

`clmul` automatically compiles its existing ARM64 hardware backend on stable
Rust. The obsolete `feature(stdsimd)` gate and opt-in `clmul_armv8` requirement
are removed. Its existing runtime CPU detection and constant-time software
fallback remain; `clmul_force_soft` still forces software. x86 hardware
selection is unchanged. Explicit unsafe blocks make the old intrinsics code
compatible with Rust 2024 linting. The multiply enables `neon,aes` so `vmull_p64` inlines on
aarch64 Linux, where `aes` is not a baseline feature. Added tests compare
10,000 random products and reductions against software and an independent
polynomial reference.

## P3: Ferret LPN encoder batching and local accumulators

`mpz-core::lpn::LpnEncoder` encrypts two original four-row PRP groups together
and gathers into a local XOR accumulator, then writes each output once.
PRP plaintexts, row ordering, index reduction, density, seeds, and LPN
parameters are unchanged. Four-row and individual-row tails preserve the
original global positions. Rayon and sequential implementations use the same
kernel. Differential tests cover six densities and 3,930 combinations of
table size, seed, and output length, including short tails.

## P4: QuickSilver check with lazy GF(2^128) reduction

`mpz-zk-core::check` accumulates unreduced carry-less products per segment
and reduces each sum once, as EMP's `vector_inn_prdt_sum_no_red` does. GCM
reduction is linear, so `U`, `V` and `W` are bit-identical: the prover does
3 multiplies and 1 reduction per AND gate instead of 3 and 3, and the
verifier shares one reduction between `x*y` and `delta*z`. Challenge
generation and transcript order are unchanged. A differential test checks
both roles against the original code across segment boundaries.

Measurements and reproducible profiling commands are in
[`docs/quicksilver-hotspots-2026-10-08.md`](../../docs/quicksilver-hotspots-2026-10-08.md).


## P5: persistent Ferret setup and setup profiling

`mpz-ot` is vendored to instrument base OT, KOS extension, Ferret bootstrap
and each tree/check round. `mpz-common::io::SetupStep` records elapsed time,
serialized bytes (including length framing), and logical-stream direction
changes. Parent spans include child traffic; do not sum both. These counters
are not physical network RTT counts and framed read-ahead can attribute a few
bytes to the preceding sub-step.

`mpz-ot-core` now retires allocations served directly from buffered output;
otherwise a warm pool accumulated already consumed allocations. The parameter
selector still chooses the smallest reviewed parameter set that can satisfy
actual allocated circuit gates and check masks. No LPN security parameters
were reduced. `ferret_batch` logs requested/missing/retained counts and n/k/t.

Consumed bootstrap/output tails are wiped before truncation. Retained Ferret,
SPCOT and KOS buffers wipe on drop; KOS delta uses `Zeroizing`. AES PRG expanded
keys enable AES's zeroize feature and its buffered output wipes on drop. OT
transfer IDs fail on overflow. The protocol's cryptographic messages are
unchanged; TLSN negotiates pool leases outside these primitives.

Regression: `cargo test --manifest-path vendor/mpz/ot-core/Cargo.toml ferret::tests`.
