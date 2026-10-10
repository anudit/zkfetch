# Session AES encoding and authenticated liveness

10 October 2026, local release build, real MPZ MAC checks with ideal OT.
The representative relation encrypts 52 AES-128 blocks under one authenticated
key. Both encodings use registered benchmark profiles, so neither hashes the
full circuit. These are CPU microbenchmarks, not end-to-end session timings.

```sh
cargo test --locked --release -p zkf-ir --features mpz-backend --offline \
  benchmark_session_aes_encodings -- --ignored --nocapture
```

| Encoding | Committed bits | Constraints | Combined MAC check median, five runs |
|---|---:|---:|---:|
| Standard | 67,008 | 17,552 | 110.1 ms |
| Compact norm | 50,368 | 17,552 | 126.7 ms |

Compact uses 25% fewer bits but costs 15% more CPU here. Constraint counts are
equal; the norm constraints have different algebra and more expensive terms.
The production session retains standard encoding while offline proofs retain
compact encoding. This is an explicit measured tradeoff, not completion of the
plan's norm-encoding-everywhere exit.

The authenticated streaming evaluator has the same prover polynomials and
verifier checks as the materialized evaluator, indexed in original transcript
order even when the liveness schedule executes checks in a different order.

| Encoding | Full authenticated wire values | Streaming frontier | Full prover checks | Streaming prover checks |
|---|---:|---:|---:|---:|
| Standard | 802,560 | 1,585 | 28.2 ms | 12.5 ms |
| Compact norm | 769,280 | 1,731 | 40.4 ms | 23.8 ms |

The latter CPU observations are single runs, exclude schedule construction,
and include differential assertions in the streaming callback. A prover wire
holds four 16-byte field coefficients; a verifier wire holds one. Released
secret slots are zeroized and reused. This API is not yet wired into production
proof aggregation. Caller-owned full witnesses and VOLE columns, plus the public
circuit and liveness schedule, still scale with circuit size; these figures do
not establish the 16 KiB body's total wasm RAM target.

Raw output: `session-aes-encoding.txt`. Tests separately check every emitted
constraint against the materialized evaluator for both encodings and reject
changed authenticated keys, wrong lengths and foreign witnesses.
