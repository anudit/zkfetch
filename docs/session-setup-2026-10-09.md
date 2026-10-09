# Session setup: persistent Ferret pool

Measured on 9 October 2026, native macOS arm64, release build, local TLS 1.3
fixture (`/formats/json`, 722-byte JSON response), QuickSilver `id >= 1000`,
reveal-scoped commitments. The prover and notary run on separate runtimes in
one process. A TCP relay delays each chunk by 16.5 ms in each direction,
preserving within-flight streaming. These are simulated 33 ms RTT measurements,
not measurements on the hosted Mumbai server or in Chrome.

One warmup and ten measured sessions per configuration, sequential fresh and
pooled blocks, with compilation completed before measurement. Every presentation
was verified. This is a local regression benchmark, not the architecture plan's
full A/B/A/B multi-RTT/mobile benchmark gate.

| Median (10 measured runs each) | Fresh OT | Warm pool | Change |
| --- | ---: | ---: | ---: |
| Setup | 513.45 ms | 137.73 ms | −73.2% |
| End to end, excluding local presentation/verification | 963.45 ms | 585.05 ms | −39.3% |
| Notary connect + key authentication | 75.00 ms | 75.13 ms | approximately unchanged |
| Total upstream traffic | 673,934 B | 224,392 B | −66.7% |
| Total downstream traffic | 1,644,500 B | 1,159,564 B | −29.5% |
| Total traffic | 2.21 MiB | 1.32 MiB | −40.3% |
| TCP relay direction changes per session | 44 | 24 | not a count of RTTs |

Warm setup ranged from 134.85 to 151.07 ms. Fresh setup ranged from 476.76 to
520.49 ms. Raw public fixture results:
[fresh OT](session-setup-2026-10-09/fresh-rtt33.json),
[warm pool](session-setup-2026-10-09/pool-rtt33.json).

## Sub-step findings

`RUST_LOG=zkfetch::setup=info` reports elapsed time, sent/received bytes and
logical-stream direction changes for `base_ot`, `ot_extension`,
`ferret_bootstrap`, `ferret_tree_round`, `ferret_total` and
`notary_key_challenge`. `ferret_batch` reports allocated/missing/retained
correlations and the selected n/k/t. Counters include length framing but exclude
WebSocket/TCP framing; nested spans include their children and must not be
summed together. Framed read-ahead can move a small amount of traffic between
adjacent sub-step counters. The relay's per-session totals include HTTP upgrade
and WebSocket framing.

Representative cold setup, from the prover's direction:

| Sub-step | Sent | Received |
| --- | ---: | ---: |
| Base OT | 4,144 B | 4,108 B |
| KOS extension | 442,536 B | 20 B |
| First Ferret tree round (n=256,000) | 1,866 B | 480,056 B |
| Second tree round (n=1,024,000) | 2,366 B | 608,056 B |
| Ferret total, including initialization | 450,932 B | 1,092,240 B |

Base OT is only about 8 KiB. KOS contributes about 432 KiB, while the two tree
rounds contribute about 1.04 MiB. Thus the hypothesis that base OT dominates
bytes was incorrect. A warm pool skips base OT, KOS and the initial smaller tree
round. Its remaining setup tree exchange is 546,170–610,422 B (about
0.52–0.58 MiB), depending on buffered stock and the selected reviewed batch.

The 100–150 ms setup target is approximately achieved in this local native
latency experiment. The 0.2–0.4 MB setup and 0.6–0.9 MB whole-session traffic
targets are not achieved. The surviving tree traffic is the next limitation;
reducing it requires another protocol change such as Half-Tree, or a smaller
circuit. Browser and hosted performance remain unmeasured for this change.

## Implemented flow and invariants

1. A client removes its cached state before opening a new connection. A random
   device identifier, random pool ticket and monotonic lease generation travel
   alongside a fresh 192-bit challenge in the authenticated opening. The signed
   response binds the request, selected ticket, generation and resume decision.
2. The admitted notary removes the matching `(capability scope, device, ticket)`
   entry under one lock before signing its response. Concurrent or stale requests
   cannot obtain that state again. A cache miss gets a new random ticket and
   fresh OT. A stale generation burns the old entry.
3. The signed opening digest is checked in the TLSN setup transcript before the
   proxy configuration is accepted. Configuration and Ferret initialization are
   pipelined; negotiated pool sessions omit the separate acceptance reply.
4. Each session gets a new QuickSilver VM and SharedRCOT facade over the retained
   inner Ferret state, including its delta, PRGs, SPCOT state and transfer counter.
   Retaining the inner instance does not add an idle adaptive-barrier participant.
   An atomic guard prevents two VMs from leasing that inner state concurrently.
5. Only reserved bootstrap and unconsumed inner Ferret output survive. Output
   handed to a VM is removed permanently. Consumed pool tails are wiped before
   truncation; retained Ferret/SPCOT/KOS buffers, delta, AES PRG key schedules and
   buffered PRG output wipe on drop. Lease and transfer indices cannot wrap.
6. Both sides publish the next generation only after the proof and attestation
   exchange succeed. Failure, cancellation, eviction or restart discards the
   state. The client retains at most four pools; the notary at most sixteen.
   Entries expire after ten idle minutes and are purged on cache access. Nothing
   is serialized to disk or browser storage, so restart cannot restore old state.

Circuit sizing already follows actual VM allocations. The implementation keeps
Ferret's existing reviewed parameter table and fixes buffered-output allocation
accounting so consumed requests cannot accumulate into future batch sizes. It
does not lower LPN parameters or remove cryptographic consistency checks.

`persistentVole: false` retains the original setup flow. A successfully verified
legacy authentication response enables reconnecting with that flow; an invalid
pin or signature cannot enable fallback. Native admission scopes include the
validated URL capability. Embedders with their own admission layer should call
`notarize_scoped` with a distinct authenticated tenant scope.

## Reproduction and validation

```sh
cargo build --release -p zkf-prover --example profile_quicksilver
RUST_LOG=zkfetch::setup=info target/release/examples/profile_quicksilver \
  --reveal --rtt-ms 33 --runs 10 --warmup 1 --out /tmp/pool.json
RUST_LOG=zkfetch::setup=info target/release/examples/profile_quicksilver \
  --reveal --fresh-ot --rtt-ms 33 --runs 10 --warmup 1 --out /tmp/fresh.json

cargo test -p zkf-core -p zkf-prover -p zkf-notary
cargo test --manifest-path vendor/mpz/ot-core/Cargo.toml ferret::tests
cargo check -p zkf-wasm --target wasm32-unknown-unknown
bun run typecheck
```

Tests cover four consecutive warm sessions with verified presentations, cancelled
prepared sessions, failed predicates, fresh-OT mode, stale/replayed/concurrent
leases, tenant isolation, expiration, counter exhaustion, signed device/ticket/
generation/freshness binding, pinned legacy fallback, and buffered allocation
accounting with the actual Ferret correlation relation.

The provided Mumbai instance (`i-09ffb3cc5032b11ec`, `65.0.251.237`) answered its
public health check. Its binary was not changed during implementation.
