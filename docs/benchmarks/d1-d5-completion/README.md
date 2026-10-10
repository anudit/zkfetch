# D4-1 v2 relay measurements — 10 October 2026

Baseline `00c9be5` plus the uncommitted v2 benchmark harness. macOS ARM64,
12 logical CPUs; native release builds, separate prover/notary runtimes within
one process. Synthetic TLS 1.3 fixture, 722-byte JSON body, root `id >= 1000`.
One cold warmup and four warm sessions per case, all independently verified.
These are local fixture measurements, not hosted or Chrome results and not
1 KiB presentation-target certification.

```sh
cargo build --locked --release -p zkf-prover --example profile_quicksilver
python3 scripts/bench-v2-flow.py
```

Median notarization milliseconds (includes connection; excludes presentation):

| Profile | 0 ms RTT | 33 ms RTT | 100 ms RTT | RTT slope, 0→100 ms |
|---|---:|---:|---:|---:|
| v1 | 241.1 | 384.0 | 662.3 | 4.21 |
| ciphertext-only | 83.7 | 224.5 | 501.8 | 4.18 |
| signed-head | 155.2 | 294.1 | 586.5 | 4.31 |
| session-claim | 628.3 | 795.2 | 1049.6 | 4.21 |

All **60/60 sessions** verified: 12 cold warmups plus 48 warm samples. Warm
samples resumed their single-use pools. All delayed warm traces have **seven
transitions, or eight alternating flights**. That corresponds to WebSocket
upgrade plus three protocol exchanges. The architecture's “eight direction
changes” should be read as eight flights, rather than eight transitions.
Zero-delay traces have additional interleavings; use delayed traces to assess
network dependencies, rather than treating every TCP read as a round trip.

WebSocket framing observations confirm **one large binary proof message** in
every warm sample. Some final flights include four additional small mux control
messages (≤64 payload bytes each). Their counts are recorded separately in
`summary.json`; one proof write does not mean exactly one total transport write.
No frame payloads or session secrets are exported.

Signed-head is below the v1 FLOW3 session median at both delayed RTTs on this
fixture. This passes the local session comparison, not the hosted/Chrome gate
for changing defaults. Ciphertext-only is faster still. Session claims keep the
same exchange structure but increase proving/verification computation: at
zero delay, roughly 345 ms prover phase and 256 ms attestation phase, versus
31/29 ms ciphertext-only and 71/54 ms signed-head. This motivates D3-4 before
making broader performance claims.

Ferret refill can vary across warm generations: the first resumed sample can
use reserved capacity while later samples extend it. Keep per-run bytes and
`voleResumed`, rather than treating the smallest run as steady-state traffic.
The relay adds half the requested RTT in each direction and preserves streaming
within a flight. It is loopback-only. Raw JSON includes per-connection TCP
reads and WebSocket frame metadata; summary medians retain all four warm runs.
