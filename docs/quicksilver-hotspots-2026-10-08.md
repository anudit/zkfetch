# Ferret LPN and QuickSilver gate evaluation: research and measurements

PMULL and the measured LPN optimization are now enabled in the production
codebase. A normal stable-Rust build needs no custom compiler flags.

On this Apple M2 Max, the LPN change improves typical full proxy notarization
by about **5% beyond the PMULL-only baseline**. The encoder microbenchmarks
improve by **41–44%**. This is a local TLS 1.3 fixture result, not a prediction
for live Duolingo or the Mumbai container.

## Production changes

The root Cargo manifest and lockfile now select two additional vendored
crates from MPZ `v0.1.0-alpha.6`, commit
`6ebfe619490c3155a589fc6a3be83b0976de19dc`:

- [`clmul`](../vendor/mpz/clmul/src/backend.rs) compiles the existing ARM64
  PMULL backend by default. The obsolete nightly `stdsimd` feature gate is
  removed; runtime CPU detection and constant-time software fallback remain.
  `clmul_force_soft` still forces the portable backend. x86 keeps its existing
  hardware detection. Rust 2024 unsafe-operation warnings in the ARM backend
  are fixed with explicit unsafe blocks.
- [`mpz-core`](../vendor/mpz/core/src/lpn.rs) encrypts two original four-row
  PRP groups in one eight-row batch. It reads generated indices without
  rewriting them, accumulates each output locally, and stores it once. The
  matrix, seeds, global row positions, index reduction, density, and LPN
  security parameters remain identical. Short tails retain their original
  four-row or individual-row encoding. Both Rayon and sequential paths use
  the optimization.

The QuickSilver VM evaluator remains upstream code. The experiments below
are isolated under `.zkf/profiles/qs-hotspots/experiment`; the production
manifest has no experimental paths or VM cfg flags.

## Follow-up: lazy reduction in the QuickSilver check

A second pass over [emp-toolkit](https://github.com/emp-toolkit) looked for
changes that keep every byte on the wire identical, so old and new clients
and notaries stay interoperable.

`Check::check_prover` and `check_verifier` performed a full `gfmul`
(multiply plus reduction) three times per AND gate. GCM reduction is linear,
so the check now accumulates unreduced 256-bit products and reduces once
per segment, as in emp-tool's `vector_inn_prdt_sum_no_red`. The prover keeps
one reduction per gate for `x*y`, which feeds a further multiply. The
verifier reduces `x*y ^ delta*z` together. Outputs are bit-identical; a
differential test compares both roles against the original code for 1 to
1,553 triples, across segment boundaries.

A/B/A/B, 20 measured sessions and 2 warm-ups per block, PMULL + LPN baseline:

| Mode / build | Measured | Total mean | Total median | SD | Prove mean |
| --- | ---: | ---: | ---: | ---: | ---: |
| Proxy, PMULL + LPN | 40 | 190.6 ms | 190.3 ms | 5.1 ms | 115.8 ms |
| Proxy, + lazy reduction | 40 | 185.6 ms | 185.0 ms | 2.1 ms | 112.5 ms |
| MPC, PMULL + LPN | 40 | 310.9 ms | 308.2 ms | 18.8 ms | 96.5 ms |
| MPC, + lazy reduction | 40 | 305.3 ms | 307.1 ms | 5.7 ms | 94.1 ms |

Proxy improves **2.6% by mean and 2.8% by median**; both new blocks
(185.2, 186.0 ms) beat both baseline blocks (192.1, 189.1 ms). MPC moves
1.8% by mean but only 0.4% by median, within its noise. All 160 sessions
verified. New client with old notary, and old client with new notary,
verified in both modes.

Ideas examined and not taken:

- **Challenge generation.** ChaCha12 `generate_and_set` is about 12% of
  sampled client CPU, all in the check's `chi` stream. emp-zk derives
  challenges as powers of one seed, which would remove that cost, but both
  parties must derive the same `chi`, so it needs a protocol version bump.
  It is mostly an ARM cost: `ppv-lite86` has AVX2 on x86 but no NEON path.
- **Half-tree (cGGM) SPCOT.** emp-ot's cGGM roughly halves GGM AES calls but
  changes the Ferret transcript. Protocol change.
- **LPN batch and prefetch.** Covered above. EMP's tuner found batch-size
  wins are microarchitecture-specific and prefetch never cleared its
  variance gate. The eight-row choice was swept only on the M2 Max; the x86
  notary containers have not been measured.

## Research that informed the experiments

EMP's current tuning guidance distinguishes local layout optimizations from
protocol agreement settings and security parameters. It recommends
interleaving runs and testing real table sizes. Its multi-machine sweep
found modest, architecture-dependent batch-size gains; gather prefetching
failed its variance threshold and was removed. These findings support a
local batching experiment, but do not justify reducing LPN parameters or
adding prefetching universally.
[EMP performance tuning](https://github.com/emp-toolkit/emp-ot/blob/2fca139ff1974c039422af545bd4681e8d55acc1/docs/performance-tuning.md).

EMP's current encoder combines AES index generation with batched gathers
and local accumulators. Its power-of-two indexing differs from MPZ's
mask-and-subtract indexing, so transplanting its kernel directly would
change the matrix. This experiment preserves MPZ's original inputs instead.
[EMP encoder source](https://github.com/emp-toolkit/emp-ot/blob/2fca139ff1974c039422af545bd4681e8d55acc1/emp-ot/common/lpn.h).

The current MPZ development source inspected at commit
`eaca5f9d9f30167c9525716e8f0aa9e33d886e5e` still uses the same four-row
encoder structure as the pinned version.
[MPZ encoder source](https://github.com/tlsnotary/mpz/blob/eaca5f9d9f30167c9525716e8f0aa9e33d886e5e/crates/core/src/lpn.rs).
For the underlying constructions, see the primary
[Ferret paper](https://eprint.iacr.org/2020/924) and
[QuickSilver paper](https://eprint.iacr.org/2021/076).

## Method

Apple M2 Max, 12 CPU cores, 64 GiB RAM, macOS 27.0.1, Rust 1.98.1,
release builds with thin LTO. Client, production notary, and HTTPS fixture
run as separate loopback processes. Each measured session fetches the same
722-byte JSON response, proves a QuickSilver predicate, presents selective
disclosures, verifies the presentation, and checks that hidden data stays
hidden. A stronger un-attested claim is rejected.

Each full-session comparison uses A/B/A/B blocks, 20 measured sessions per
block and two excluded warm-ups. There are 40 measured sessions per build
per comparison. No builds or other benchmarks run concurrently with these
blocks. Machine speed drift was substantial across the overall investigation,
which is why the comparisons below stay within their respective interleaved
sweeps.

## Full sessions

### Initial isolated LPN sweep, with PMULL enabled on both builds

Means in milliseconds:

| Mode / build | Setup | Prove | Total | Total median | Total standard deviation |
| --- | ---: | ---: | ---: | ---: | ---: |
| Proxy, PMULL only | 46.14 | 116.50 | 190.21 | 189.56 | 2.30 |
| Proxy, PMULL + LPN | 42.37 | 110.49 | 180.44 | 180.05 | 1.79 |
| MPC, PMULL only | 175.90 | 100.18 | 317.01 | 314.34 | 20.42 |
| MPC, PMULL + LPN | 171.18 | 96.59 | 308.36 | 304.17 | 19.22 |

Proxy improves **5.1% by mean and 5.0% by median**, consistently in both
paired blocks. MPC improves 2.7% by mean, but its variation is much larger;
this supports a small improvement, not a confident universal speedup.
Presentation contents and sizes are unchanged: 14,448 bytes in proxy mode
and 14,450 bytes in MPC mode. All sessions verified.

### Final normal production build, without RUSTFLAGS

A fresh comparison after enabling the durable vendor patches:

| Proxy build | Measured sessions | Total mean | Total median | Standard deviation |
| --- | ---: | ---: | ---: | ---: |
| Preserved PMULL-only baseline | 40 | 224.64 ms | 217.50 ms | 25.28 ms |
| Normal production build | 40 | 207.08 ms | 207.06 ms | 2.04 ms |

The median improvement is **4.8%**. The mean improvement is 7.8%, inflated
by baseline outliers; use approximately 5% as the typical benefit here.
A separate 20-run production confirmation averaged 207.11 ms. Absolute
numbers from this later sweep should not be compared with the earlier
190/180 ms sweep as if the machine were in the same state.

The earlier PMULL investigation separately measured about 371 → 197 ms
in proxy mode. Those historical numbers are in
[the first profiling report](quicksilver-profile-2026-10-08.md).

## LPN microbenchmarks

Density ten, the pinned regular-LPN shapes, 12 Rayon threads. Each round
rotates variant order; one warm-up round is excluded and six measured rounds
remain. Values below are median milliseconds per complete encoding.

| n / k | Original four rows | Local accumulator, four rows | Eight rows | Sixteen rows | Thirty-two rows | Sixty-four rows |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 256,000 / 13,249 | 0.565 | 0.366 | 0.333 | 0.362 | 0.353 | 0.361 |
| 512,000 / 22,653 | 1.026 | 0.649 | 0.577 | 0.640 | 0.623 | 0.617 |
| 1,024,000 / 38,737 | 1.971 | 1.201 | 1.119 | 1.278 | 1.231 | 1.197 |
| 2,048,000 / 69,559 | 3.823 | 2.382 | 2.199 | 2.499 | 2.442 | 2.405 |

The local accumulator/read-only indices account for most of the improvement.
Eight-row batches provide another modest gain. Larger batches lose that
advantage on this machine. Microbenchmark gains do not translate directly
into full-session gains because the protocol has other work and parallel
critical paths.

## Instruments traces and flamegraphs

Matching captures use 40 sessions plus two warm-ups. Instruments Time
Profiler supplies running-thread samples; samply supplies exact binary
metadata for Rust symbolication. Saved executable paths and UUIDs pin
symbol resolution to the captured binaries. Profiles cover the client;
notary work affects the full-session timings but is not included in these
client CPU totals. We did not collect hardware cache-miss or branch-miss
counters.

| Client CPU sample attribution | PMULL only | PMULL + LPN |
| --- | ---: | ---: |
| Total sampled running CPU | 20.818 s | 18.095 s |
| LPN encoder leaf | 4.200 s / 20.2% | 1.898 s / 10.5% |
| Hardware AES leaf, all callers | 2.327 s / 11.2% | 1.589 s / 8.8% |
| `ProverIter::next` leaf | 2.575 s / 12.4% | 2.733 s / 15.1% |

The LPN leaf contribution drops 55%; overall sampled client CPU drops 13%.
The VM's share rises because other work became cheaper. Its absolute sampled
CPU did not improve. The AES row includes callers beyond LPN.

Saved local artifacts:

- [Baseline flamegraph](../.zkf/profiles/qs-hotspots/pmull-instruments.svg)
  and [leaf-first view](../.zkf/profiles/qs-hotspots/pmull-instruments.reversed.svg).
- [Optimized flamegraph](../.zkf/profiles/qs-hotspots/lpn-instruments.svg)
  and [leaf-first view](../.zkf/profiles/qs-hotspots/lpn-instruments.reversed.svg).
- [Baseline trace](../.zkf/profiles/qs-hotspots/profile-pmull/client.trace),
  [optimized trace](../.zkf/profiles/qs-hotspots/profile-lpn/client.trace),
  and [summary JSON](../.zkf/profiles/qs-hotspots/summary.json).
- [Gate-evaluator disassembly](../.zkf/profiles/qs-hotspots/prover-iter-next.asm).

These artifacts are local and git-ignored. The flamegraphs were visually
inspected; hover labels retain full Rust function names.

## QuickSilver VM experiments

The isolated microbenchmark evaluates the actual AES-128 and SHA-256
compression circuits with deterministic MAC/mask inputs. It measures the
iterator separately from execution allocation and `finish`. Interleaved
runs below have 14 measured windows per circuit/build, excluding warm-ups.

| VM build | AES iterator / complete execution | SHA-256 iterator / complete execution |
| --- | ---: | ---: |
| Original | 0.16086 / 0.19217 ms | 0.62309 / 0.72873 ms |
| Forced inlining | 0.16216 / 0.19365 ms | 0.62235 / 0.72772 ms |
| Pre-sized, indexed triples | 0.15536 / 0.19240 ms | 0.61081 / 0.73649 ms |

Pre-sizing adjustment bits in a separate initial trial was also effectively
flat: AES iterator 0.13338 → 0.13604 ms, SHA-256 0.50679 → 0.50719 ms.
These earlier absolute timings are from a different machine state.

Indexed triples reduce some iterator overhead, but initialization cancels
that gain in complete execution. Inlining alone provides no useful gain.

Disassembly shows 32-byte gate records, repeated index checks, and scalar
copies around MAC pointer-bit updates and triple construction. An additional
safe block-XOR experiment preserved the pointer-bit operation but regressed:
AES iterator 0.16103 → 0.17503 ms and SHA-256 0.62247 → 0.64563 ms in its own
interleaved comparison. Complete execution regressed as well. None of these
VM experiments are enabled in production.

The next useful experiments are more structural, rather than another inline
attribute. These are code-review hypotheses, **not measured speedups**:

1. Cache a validated circuit representation with compact 32-bit wire indices,
   reducing each gate from 32 to 16 bytes where wire counts fit. Measure the
   validation/conversion cost and amortize it over cached circuit reuse.
2. Add a nonrecursive batch evaluator that fills the stored adjustment bits
   and serializes existing batches directly. Preserve the 8,000-AND message
   boundaries and the mandatory trailing free-gate evaluation. The current
   caller rebuilds a packed bit vector from each iterator batch while the
   iterator also stores those bits.
3. Reduce cloning and copying of gate MACs, masks, and triples between
   execution and the consistency-check store. Preserve ownership, ordering,
   challenge timing, and the check equations; measure full sessions and RSS.

Blindly removing bounds checks is not appropriate: `Circuit` supports
serialization, and today's type does not provide the validated invariant
required by unchecked indexing. The measured trace identifies the function,
not the exact proportion of time spent on checks, dispatch, or memory traffic.

## Validation

- Default hardware clmul tests: seven pass, including 10,000 random products
  and reductions compared with software and an independent polynomial
  reference.
- Forced-software clmul tests: four pass, including the same independent
  differential test.
- LPN Rayon tests: two pass. The new test compares the original naive encoder
  and optimized encoder across six densities and 3,930 table/seed/length
  combinations. The initial kernel sweep adds 420 candidate comparisons.
- Sequential core tests: all 18 pass, including the same differential test.
- Production QuickSilver predicate acceptance and false-predicate rejection:
  both end-to-end tests pass.
- Production proxy TLS 1.2 and TLS 1.3: both end-to-end tests pass.
- Updated client with old notary, and old client with updated notary: all
  four proxy/MPC combinations pass, four sessions each including warm-up.
- `cargo check -p zkf-wasm --target wasm32-unknown-unknown`: passes.
- Normal production release build and all measured full sessions: pass.

An attempted `--no-default-features` core test exposed an existing upstream
unit-test dependency on optional `rand_chacha`. The sequential check above
uses the crate's normal default features, without Rayon; no unrelated feature
changes were made.

## Reproduce

```sh
cargo build --release -p zkf-notary -p zkf-fixture -p zkf-prover \
  --bins --example profile_quicksilver

python3 scripts/profile-quicksilver.py \
  --out .zkf/profiles/qs-repeat --runs 20 --warmup 2

python3 scripts/profile-quicksilver.py \
  --out .zkf/profiles/qs-repeat-mpc --mode mpc --runs 20 --warmup 2

python3 scripts/profile-quicksilver.py \
  --out .zkf/profiles/qs-repeat-instruments --profiler xctrace --runs 40

cargo test --release --manifest-path vendor/mpz/clmul/Cargo.toml --lib

cargo test --release --manifest-path vendor/mpz/core/Cargo.toml \
  --config 'patch."https://github.com/privacy-ethereum/mpz".clmul.path="vendor/mpz/clmul"' \
  --features rayon --lib lpn::tests

cargo test --release -p zkf-prover --test e2e quicksilver
cargo test --release -p zkf-prover --test e2e proxy
cargo check -p zkf-wasm --target wasm32-unknown-unknown
```

Run commands from the repository root. The profiler helper cleans up its
owned local servers. Crypto unit tests use standalone vendored manifests
because vendor crates are excluded from the application workspace. A
standalone Cargo test may generate a local lockfile; the application's
production resolution is controlled by the root lockfile.

Raw timings, experimental source, saved executables, symbol sources, trace
exports, and flamegraphs are under `.zkf/profiles/qs-hotspots/`. The preserved
PMULL-only binaries are under `.zkf/profiles/quicksilver-local/pmull-bin/`.
Use `--binary-dir` to interleave that baseline with `target/release`; avoid
comparing isolated runs taken at different machine states.
