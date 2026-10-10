# D1–D5 completion progress

The Option A follow-up is tracked in [v2-option-a-progress.md](v2-option-a-progress.md).
The new dual-lane kernel, VM, bridge and paired Ferret preprocessing are locally
tested and selected by the FLOW5 driver for v2 attestations. The deployed FLOW4
snapshot still uses legacy authentication. D1 and D3-2
remain incomplete. The prior source is checkpointed as `fa9b761`.

Started 10 October 2026 from `00c9be5`, following
`comptest/zkfetch-d1-d5-completion-plan.md`. Status describes evidence gathered
in this milestone, not revised percentage guesses.

| Item | Status | Evidence / remaining exit work |
|---|---|---|
| Week 1 decisions | Recorded | `v2-decisions.md`; production defaults stay gated |
| D2-1 compression accounting | Complete | Architecture §6.4.3 reconciled outside this repo; `v2-origo-accounting.md` documents the actual 16-compression relation and boundaries |
| D2-4 validation | Implemented and locally passing; CI publication pending | RFC 8448, four legacy differentials, 224 intermediate-byte mutations with class-specific expectations; `scripts/check-origo.sh`. `.github/` remains excluded as previously requested, so no hosted CI run is claimed |
| D4-1 v2 exchanges | Local measurement complete | Three v2 profiles plus v1 at 0/33/100 ms; 60/60 verified. Seven transitions/eight flights in delayed warm traces; one large proof message, separately reported mux control messages |
| D4-4 hosted deployment/matrix | Final 12-case retry passes; one earlier timeout retained | Fresh Mumbai native/systemd deployment; native and real Chrome 1/8-thread fresh/warm/prepared plus v1 baselines independently verify. Final scratch-release retry verifies 12/12; eight-thread fresh is 3.02 s and prepared 1.13 s, excluding presentation. The earlier incomplete run is retained; these are single observations, not medians |
| D4-3 budgets/admission | Bounded admission and both capacity profiles verified | Authenticated 1M/2M/3.5M classes; eight weighted notary units before preprocessing, permitting 8/4/2 active extensions and queueing additional requests. Six-wave ciphertext-only run verifies 180/180 (96/96 at sixteen clients), without OOM/restart; sixteen simultaneous warm extensions had failed before this bound. FLOW4 parks bootstrap seeds and releases completed SPCOT scratch. Final scratch-release ciphertext-only and signed-head profiles each verify 180/180 across six waves at 2/4/8/16 clients, with no new OOM/restart. Sixteen-client sampled peaks are 1,199/1,383 MiB and warm medians 2.82/6.32 s respectively. Automatic overflow retry without refetch remains unfinished; no latency-regression exit is claimed |
| D5-0 split design | Drafted and internally checked | `v2-split-design.md` specifies routing, reveal order, authentication and attack gates; external review deferred by user |
| D3-2 soundness derivation | Lower-bound obstruction reproduced; authentication upgrade required | `soundness.py --require-release` fails closed. The delta-guess attack already has probability at least 2^-127. Coefficient repetition at the same delta cannot close it; wider authentication or independently bound complete lanes and composition analysis are required |
| D3-7 default Binius removal | Implemented and locally validated | Optional `legacy-binius` feature retains v1 support; default `cargo tree` has no Binius; disabled requests fail before I/O |
| D3-4 coefficient generation/prefix | Implemented and measured | Domain-separated ChaCha8 stream and session claim-prefix relation (key frames 11/12). Final seed-pool fixture median claim session 271/410/696 ms at 0/33/100 ms, versus original 628/795/1050 ms. Standard session AES and exact soundness margin still pending |
| D3-5 authenticated streaming | Production prover rebuilt and measured; full-buffer streaming remains unfinished | Prover polynomial and verifier MAC-key evaluators use the liveness schedule and preserve original constraint indices. Differential tests cover both AES encodings, mutation, constant-only checks and foreign witnesses. A 52-block benchmark retains 1,585/1,731 authenticated wire values instead of 802,560/769,280. Large production prover relations now use the streaming evaluator; native, single/threaded WASM, extension and ARM64 notary have been rebuilt and redeployed from the same source snapshot; the first hosted matrix passes 12/12. Full witness, VOLE columns and public graph/schedule still scale with circuit size; flat total wasm memory is not claimed |
| D1-10 composition write-up | Review draft available | `v2-security.md` states the conditional binding lemma, root-member/prefix semantics, trust boundary and unsupported features; does not certify unresolved cryptographic terms |
| Native prepared sessions | Implemented and hosted-verified | NAPI exposes the existing move-only Rust preparation; native and browser prepared sessions reject second use |
| D3-3 nightly mutations | Local exhaustive check passes; seven-day gate pending | Daily workflow drafted in excluded `.github/`; cannot claim seven consecutive hosted runs yet |
| D2-2 SHA-384 support | Compression gadget tested; schedule/TLS integration pending | SHA-512/SHA-384 compression and padding-boundary differentials pass; this does not yet enable AES-256/SHA-384 TLS or ORIGO |
| D5-4 GCM gadget | IR relation and authenticated bridge test pass; split integration pending | AES-128/256, NIST vectors, partial blocks, tampered key/ciphertext/AAD/nonce/tag rejection |
| Remaining D1–D5 items | Pending | Follow the completion plan dependency order; no default flip or claim of protocol completion |

Validation for this milestone: all 15 `zkf-tls13` unit/integration tests pass,
the relay's fragmented/coalesced WebSocket framing regression passes, release
benchmark compilation passes, and the 12-case latency matrix verifies every
session. Stronger-predicate substitution is also rejected in each case.

The Option A follow-up completes both synthetic hosted path matrices (24/24),
including Chrome with eight threads. The user confirms successful verification of the live authenticated Duolingo flow (one warm eight-thread sample: 881 ms notarization, 942 ms presentation, 458 ms verification).
Next: rebuild and deploy FLOW5 from one snapshot, complete adversarial integration
and close the composition and offline soundness reductions. Both hosted capacity profiles have completed.
Depth-8 typed paths, array indices and optional semantic key uniqueness pass
IR, offline proof and native API e2e regressions; the signed-in Duolingo extension run also verifies, with user-reported timings recorded in `option-a/duolingo-live-user-reported.json`. Presentation parameter tuning remains paused pending soundness. Soundness margins, full streaming integration, broader
TLS/JSON/HTTP support and the full split protocol remain implementation work.
External review is deferred; seven nightly days and the fuzz CPU budget remain
unfulfilled release gates. The whole completion plan is not complete.
