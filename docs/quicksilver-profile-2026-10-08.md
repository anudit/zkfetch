> Follow-up: PMULL and eight-row LPN batching are now enabled in production.
> See [the hotspot investigation](quicksilver-hotspots-2026-10-08.md). The
> restoration notes below describe the state at the end of this earlier run.

QuickSilver local profiling — 2026-10-08
========================================

QuickSilver has a substantial ARM acceleration opportunity in its existing
cryptographic implementation. An isolated PMULL experiment reduced TLS 1.3
proxy notarization from **370.86 ms to 197.16 ms (46.8%)**, including setup
from **100.52 ms to 47.96 ms (52.3%)**. MPC notarization improved from
**530.79 ms to 334.94 ms (36.9%)**. These are full sessions with a local
notary, authenticated HTTPS, hidden predicate, presentation and verification.

The production dependency configuration and normal release binaries were
restored after the experiment. The repository changes are the benchmark,
profiling tools and this report. The candidate source, patch, executables and
raw captures are preserved locally under `.zkf/profiles/quicksilver-local/`.
Those artifacts are ignored by Git.

**Workload and measurement conditions**

Apple M2 Max, 12 logical CPUs, 64 GiB RAM; macOS 27.0.1; Rust 1.98.1;
release profile with thin LTO. Base commit:
`bf6708fd56607c89e4351c568a85b8422ba0f520`.

The production `zkf-notary` executable and HTTPS fixture run in separate
processes on loopback. The fixture serves `/formats/json`, with a 722-byte
JSON body. The client requests TLS 1.3, uses QuickSilver with Binius disabled,
proves `id >= 1000`, and keeps the actual value hidden. Both proxy and MPC
modes use fresh sessions, keys and proof randomness. The notary process stays
warm; circuit/session initialization is included in each measured session.

Each main timing case has two excluded warmups and twenty measured sessions.
The baseline and PMULL client CPU traces each have two warmups and forty
sessions. Profiling runs are separate from the primary wall-clock baseline.
No live Duolingo request or network latency is included, so these figures
cannot be directly substituted into the Mumbai-container measurements.

**Full session timings**

Mean milliseconds, excluding warmups; `total` is notarization only.

| Mode / build | Connect | Setup | TLS | Prove | Attest | Total | Present | Verify |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| TLS 1.3 proxy, baseline | 1.03 | 100.52 | 32.68 | 233.41 | 3.23 | **370.86** | 0.50 | 0.37 |
| TLS 1.3 proxy, PMULL | 0.41 | 47.96 | 26.35 | 120.41 | 2.04 | **197.16** | 0.49 | 0.36 |
| TLS 1.3 MPC, baseline | 0.37 | 269.02 | 49.82 | 208.18 | 3.40 | **530.79** | 0.49 | 0.37 |
| TLS 1.3 MPC, PMULL | 0.28 | 183.26 | 40.63 | 108.43 | 2.33 | **334.94** | 0.51 | 0.37 |

Values are rounded to two decimal places. Each total includes all recorded
phases, with small bookkeeping costs.

| Case | Median | p95¹ | Minimum | Maximum |
|---|---:|---:|---:|---:|
| Proxy baseline | 365.49 | 388.84 | 358.52 | 400.99 |
| Proxy PMULL | 197.34 | 203.48 | 191.13 | 203.62 |
| MPC baseline | 527.77 | 554.03 | 510.46 | 558.22 |
| MPC PMULL | 327.77 | 387.49 | 317.15 | 400.85 |

¹ Linear interpolation over twenty observations; an empirical summary, not
a production tail-latency estimate. No outliers were removed.

Every main measured session verified successfully. The proxy presentation
was 14,448 bytes; the MPC presentation was 14,450 bytes. Presentation and
verification remained below one millisecond on average. The original proxy
build was rerun after restoring dependencies and averaged **372.94 ms**,
within 0.6% of the first baseline. Matched Instruments runs averaged
371.25 ms before and 196.20 ms after.

**What the flamegraphs show**

Samply collected Rust stacks at 1 kHz, and Instruments Time Profiler supplied
an independent capture of running-thread CPU samples. Function names were
resolved against preserved executable UUIDs. The primary before/after CPU
comparison below includes the client only; the notary runs separately.
An initial combined-process capture also covered the notary and verifier.

| Leaf function / work | Baseline client CPU | PMULL client CPU |
|---|---:|---:|
| Software carryless multiplication, `clmul::backend::soft::U64x2::clmul` | **31.1%** | No samples |
| Ferret LPN encoder | 12.7% | **20.1%** |
| QuickSilver VM gate evaluator, `ProverIter::next` | 7.9% | **12.8%** |
| Hardware AES block encryption | 6.9% | 10.8% |
| ChaCha PRNG | 5.9% | 9.4% |
| `swtch_pri` / Rayon yielding | 7.3% | 10.3% |
| Memory copy / zeroing | 5.6% | 8.7% |

Percentages describe sampled CPU, not wall time, and the denominator shrinks
after acceleration. For example, the LPN encoder's sampled time stayed near
4.3 CPU seconds across the forty-session captures; its share rose because
other work disappeared. The combined-process baseline attributed 35.4% of
running-thread samples to software carryless multiplication.

Samply samples parked threads too. Its CPU deltas can attribute preceding
work to a subsequently blocked stack, so its large condition-wait bars must
not be interpreted as cryptographic computation. The percentages above use
Instruments running-thread samples.

- [Baseline client flamegraph](../.zkf/profiles/quicksilver-local/baseline-client-instruments.svg)
  and [leaf-function view](../.zkf/profiles/quicksilver-local/baseline-client-instruments.reversed.svg).
- [PMULL client flamegraph](../.zkf/profiles/quicksilver-local/pmull-instruments.svg)
  and [leaf-function view](../.zkf/profiles/quicksilver-local/pmull-instruments.reversed.svg).
- Instruments traces: [baseline](../.zkf/profiles/quicksilver-local/separate-baseline-instruments/client.trace)
  and [PMULL](../.zkf/profiles/quicksilver-local/pmull-proxy-instruments/client.trace).
- Self-contained samply profiles: [baseline](../.zkf/profiles/quicksilver-local/separate-baseline-flamegraph.symbolicated.json)
  and [PMULL](../.zkf/profiles/quicksilver-local/pmull-samply.symbolicated.json).

**Acceleration candidates, ordered by evidence**

1. **Enable ARM PMULL in `clmul`.** The pinned MPZ dependency defaults to
   software on ARM. Its runtime-detected hardware backend requires
   `--cfg clmul_armv8`, but enabling that flag fails on Rust 1.98.1 because
   it activates the obsolete `feature(stdsimd)` attribute. The experiment
   copied the pinned crate, removed that attribute, applied a temporary Cargo
   override, and built both client and notary with the flag. No proving
   algorithm, circuit, security parameter, predicate or commitment was changed.
   The runtime detection and software fallback remain. The
   [one-line upstream compatibility patch](../.zkf/profiles/quicksilver-local/clmul-stable-arm64.patch)
   is saved. This is an ARM result; x86 already has an enabled hardware path,
   and wasm has different capabilities. A maintained dependency patch or
   upstream update is needed before adopting this in production.

2. **Size MPC transcript budgets for known endpoints.** The current defaults
   reserve 4 KiB sent and 16 KiB received. For this fixture, 512 bytes sent and
   2 KiB received reduced baseline setup from **269.02 to 145.71 ms** and total
   from **530.79 to 408.77 ms**. Combined with PMULL, setup was **96.60 ms**
   and total **244.05 ms**. These controls used ten measured sessions each.
   Proxy mode does not use these MPC bounds. Real endpoints need room for
   HTTP headers, authorization and their largest expected response; these
   fixture-specific limits are not proposed as new global defaults.

3. **Next investigate Ferret/LPN and VM memory traffic.** After PMULL, LPN,
   PRNG, hardware AES and gate evaluation account for most remaining compute.
   Batch/SIMD improvements and buffer/circuit-template reuse are plausible
   follow-ups, but no speedup for them was demonstrated here. Client peak RSS
   stayed around 1.07 GB for the twenty-session proxy runs, so PMULL improves
   compute rather than memory footprint. Cache immutable templates or pool
   scheduling machinery while generating fresh per-session cryptographic state.

Simply reducing Rayon parallelism did not help. In separate-process PMULL
runs, four Rayon threads averaged **233.08 ms**, eight averaged **208.28 ms**,
and the default twelve averaged **197.16 ms**. The initial combined-process
baseline controls also slowed down with one or four threads. The samply
capture shows twelve new MPZ executor workers per client session in addition
to the long-lived Tokio and Rayon pools, but pooling those workers remains
an untested hypothesis.

Removing all predicates in the initial combined-process control barely
changed proving time (about 233 versus 237 ms). This also removes shape
proofs and changes presentation behavior. It suggests that the tiny numeric
comparison is not the main cost: transcript authentication, commitments and
QuickSilver/Ferret machinery dominate this workload.

**Validation and reproduction**

The PMULL experiment passed seven arithmetic tests, including 10,000 seeded
random multiplication comparisons against the software backend and GCM
reductions checked against independent polynomial long division. Existing
`quicksilver_false_predicate_rejected`, `quicksilver_predicate_default`,
`proxy_tls12_notarize_present_verify` and `proxy_tls13_notarize_present_verify`
tests passed. The full-session harness checks identity, trusted notary,
required predicates, hidden numeric value, and rejection of a stronger claim.
This validates the measured candidate on this machine; it is not a security audit.

```sh
cargo build --release -p zkf-notary -p zkf-fixture -p zkf-prover \
  --bins --example profile_quicksilver

python3 scripts/profile-quicksilver.py \
  --out .zkf/profiles/qs-new-baseline --runs 20

python3 scripts/profile-quicksilver.py \
  --out .zkf/profiles/qs-new-mpc --mode mpc --runs 20

python3 scripts/profile-quicksilver.py \
  --out .zkf/profiles/qs-new-cpu --profiler samply --runs 40

python3 scripts/profile-quicksilver.py \
  --out .zkf/profiles/qs-new-instruments --profiler xctrace --runs 40

# Run the preserved candidate without changing production dependencies:
python3 scripts/profile-quicksilver.py \
  --binary-dir .zkf/profiles/quicksilver-local/pmull-bin \
  --out .zkf/profiles/qs-candidate-repeat --runs 20
```

For offline viewing, load a saved symbolicated profile with
`samply load --no-open PROFILE`. For a new raw profile, the analyzer takes
the `symbolServer` URL printed by `samply load`:

```sh
python3 scripts/analyze-quicksilver-profile.py PROFILE.json \
  --symbol-server URL --out .zkf/profiles/qs-analysis
```

The complete primary timing records are in
[baseline proxy](../.zkf/profiles/quicksilver-local/separate-baseline/measurements.json),
[baseline MPC](../.zkf/profiles/quicksilver-local/separate-mpc-baseline/measurements.json),
[PMULL proxy](../.zkf/profiles/quicksilver-local/pmull-proxy/measurements.json), and
[PMULL MPC](../.zkf/profiles/quicksilver-local/pmull-mpc/measurements.json).
