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

### D1/D3 baseline counters (opt-in)

`mpz-zk`'s `circuit-metrics` feature counts allocated circuit calls grouped by
input/output bit lengths and AND/XOR counts, plus successfully marked private
input bits. It records no witness values. Counters are process-wide and must
be reset only in isolated benchmarks with no other prover VMs running.
These allocations exclude check-mask correlations and are not a measurement
of all consumed VOLE, peak memory or physical RTTs. The feature is disabled by
default and adds no instrumentation to normal builds. It changes no proof
equations or protocol messages; field/degree-3 protocol support remains a
separate, unfinished D1/D3 task.

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


## D4: statement-bound QuickSilver and pool reserve sizing

Vendored `zk` runtime at mpz `6ebfe619` adds explicit length-delimited statement
binding and absorbs the serialized commitment flush on both sides when FLOW3
is enabled. Legacy transcripts retain their original behavior. Existing
Fiat–Shamir challenges and independent ChaCha coefficients remain unchanged.

Ferret configuration adds a minimum retained correlation count independent of
initial bootstrap cost. Proxy pools retain 160,000 unused seed correlations,
sufficient to select the existing regular 4M parameter tier directly. This
avoids repeated small tree iterations after a smaller ORIGO circuit consumes
most of a batch. It changes neither the vetted LPN parameters nor the
single-use lease, zeroization or fresh-OT fallback rules.

`vendor/tlsn-mux` and its test helper `vendor/quickcheck-ext` are pinned copies
from tlsn-utils `64722f7`. FLOW3 mutually configures a 2 MiB per-stream starting
credit. Connection window limits and dynamic flow-control accounting apply to
that configured baseline; legacy streams retain 256 KiB.

FLOW3 pipelines the unchanged Ferret messages through the authenticated opening
and a consistency-check stream. The OT wrapper exposes its existing core state
for this transport scheduling; a temporary prefill allocation can be released
once satisfied. TLSN enforces the declared allocation budget, waits for the
consistency check before using outputs, and burns failed leases. No correlations
are copied or restored. The mux collects a bounded final flight and drains all
stream queues before transmitting it; tests verify one underlying write and
that no bytes escape before release.

The experimental `crates/zkf-ir/src/backend/mpz.rs` adapter reuses this VM's
existing authenticated bit MACs/keys, including references to existing TLS key
outputs. GF-byte and GF128 commitments are linear lifts of those bit rows.
It checks degree-three homogeneous constraints using fresh degree-dependent
masks and a post-commitment verifier challenge. No MPZ bit authentication or
Ferret soundness parameters change. D4 batching and authenticated streaming
remain outstanding; the default binary VM remains the production backend.


### Combined v2 key/framing proof

The optimized D1 caller can borrow both original application-key references
in one degree-three relation. Its Fiat–Shamir seed is domain-separated from
the VM transcript after canonical statement and commitment flush absorption.
The relation covers both key OWFs and optional public HTTP framing/member
claims, including independent claim nonces. The verifier signs only after
acceptance. The interactive single-key reference bridge remains available.
See [binding and soundness conditions](../../docs/v2-presentation-optimizations.md).

### Completion-plan session coefficient stream

The degree-three bridge derives a domain-separated ChaCha8 seed from the
post-commitment challenge and the length-delimited full binding once, then
expands individual field coefficients. This replaces one SHA-256 hash over the
whole binding per constraint; coefficients are not powers of a field seed.
Binding domain v2 and D1 key-frame flows 11/12 require coordinated clients and
notary. Secret verifier rows/checks are now zeroized. The exact security margin
is NOT certified: see `docs/v2-soundness.md`, including MPZ's pointer-bit Δ domain.

The TLSN mux release barrier also rechecks newly registered streams and pending
commands under the same lock that publishes release. A deterministic race test
queues the attestation stream between the driver's first queue poll and release;
it must be included in the same underlying proof write.

### Bounded parked pools and authenticated size classes

FLOW4 retains the three-exchange flow and negotiates seed-only parking. On a
successful lease, both Ferret cores zeroize unused output correlations, retain
exactly the configured bootstrap reserve, and shrink their buffers. Transfer IDs,
PRG state and consistency transcript remain monotone; burned correlations are
never restored. Compaction refuses an active extension or outstanding allocation.
Legacy pool openings keep their existing behavior. Class changes (1M/2M/3.5M)
are authenticated by the setup signature and forbidden on live leases.
Paired tests cover class changes, compacted warm extensions, matching correlations,
budget overflow and tampering. The notary queues weighted allocations before
preprocessing and upstream forwarding; cancellation burns checked-out state.
The allocation bound is eight units (8/4/2 small/medium/large extensions);
sixteen admitted requests can queue. Sixteen simultaneous warm extensions
exceeded the hosted 1.5 GiB service limit, so connection count alone is not a
safe allocation bound. SPCOT vectors are wiped after checks and their empty
scratch allocations are released when parking; tree counters are preserved.
