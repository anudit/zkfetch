# Option A implementation progress

The user selected two independent full-entropy authentication lanes and asked
for D1 and D3-2 completion. This follows `zkfetch-d1-d5-plan-v2.md`.

The prior work is checkpointed as `fa9b761` on `v2-completion`. The restored
Mumbai notary at `13-202-74-218.sslip.io` initially served that checkpoint protocol;
it now serves FLOW5 from `7066a4a`.
All 947 recorded Rust source hashes match the commit. The restored binary hash
and instance identity are in
`benchmarks/d1-d5-completion/option-a/restored-checkpoint-provenance.json`.
That restoration evidence predates the FLOW5 deployment recorded below.

## Implemented foundations

- A distinct `ZkDelta` preserves all 128 bits. It has no conversion from the
  garbler's pointer-bit delta. Boolean values live separately from MAC tags.
- Two-lane XOR, NOT, AND, public values, circuit execution and multiplication
  checks preserve full-width tags. Independent lane weights bind a joint
  transcript and batch count. Fresh masking correlations are consumed by the VM.
- Dual memory adjustments and openings authenticate the same disclosed bits
  under both lanes. Opening hashes bind addresses and lane identity. Malformed
  correction/opening lengths are refused before indexing.
- A strict VM implements the existing memory/call/execute interfaces. Its
  degree-three IR bridge borrows both lanes of existing VM values and commits
  only additional witnesses and independent masks. It does not substitute a
  newly assigned key for an authenticated TLS key.
- A move-only pair of full-entropy Ferret pools performs cold and folded warm
  preprocessing. A detected preprocessing failure burns the whole pair; it
  cannot be parked or resumed. Existing garbling/legacy constructors remain
  separate.

These APIs are experimental. **The current FLOW5 source selects the dual-lane
VM and pool for v2 attestations; the deployed snapshot is now `7066a4a`.**
Secret-memory zeroization audit and synchronized release remain required. Tests establish functional identities, not an adaptive security proof.

Validation: seven authentication-core tests; two strict VM/bridge integration
tests; paired cold/warm Ferret test; 60 IR tests; 14 offline-proof tests; 18
native API e2e tests. The Ferret test covers even and odd deltas, two warm waves,
single-use correlations and rejection of a corrupted second-lane reply.

## Bounded JSON paths

The legacy Boolean parser's depth cap is eight. The path parser already used
eight before this change. The measured path blowup was primarily repeated
byte-class construction in the semantic-key matcher, not a 64-level path stack.
Stable byte-class wires are now reused across compiler checkpoints in path
relations. Expression IDs remain checkpoint-local to avoid stale-ID reuse.

Path statements carry an authenticated depth bound of 1–8. Non-unique statements
can bound the consumed prefix; uniqueness statements must cover the entire
checked document. The verifier enforces the bound and the path length. Path
construction profiles advance to v7 and the presentation envelope to version 6.
Root-member construction profiles remain separately pinned.

The native diagnostic reports the complete presentation envelope, including the
signed attestation and openings. On the existing 192-byte fixture:

| Profile | Full presentation | Prove | Verify |
|---|---:|---:|---:|
| Ciphertext, non-unique, Fast | 43,331 B | 144 ms | 112 ms |
| Ciphertext, unique, Fast | 169,043 B | 727 ms | 637 ms |
| Signed head, non-unique, Small | 21,608 B | 129 ms | 124 ms |
| Signed head, unique, Small | 108,035 B | 685 ms | 664 ms |

These are single native observations **before the required soundness margin**,
not Chrome measurements or release-target signoffs. Uniqueness remains far
above the target. Raw cases are in `option-a/bounded-path-native.json`.

## Required closure

1. Rebuild and validate the integrated FLOW5 dual-lane session on hosted Chrome;
   finish secret-memory zeroization and adversarial integration tests.
2. Derive adaptive joint-transcript composition, audit malicious OT and current
   regular-LPN attacks, and close the generalized offline Fiat–Shamir reduction.
   A conditional root bound alone cannot certify the release.
3. Select and benchmark the offline margin, then finish presentation performance,
   complete-buffer streaming and the 16 KiB body gate.
4. Finish D1 HTTP completeness/chunking, disclosure, richer claims, AES-256,
   cipher fallback measurements and removal of unnecessary v1 session work.
5. Rebuild client/server/extension from one committed snapshot and deploy it;
   repeat the hosted Chrome 8-thread matrix and authenticated Duolingo run
   after the stronger protocol upgrade. The existing snapshot passes both.
6. Flip defaults only after the gates pass. External review remains deferred;
   no successful release certificate or completed D1/D3-2 is claimed.

`scripts/build-all.sh` refuses dirty build inputs and records artifact hashes,
commit/tree identity and toolchain versions. This is provenance, not a claim of
bit-identical output across toolchains.

## Rebuilt deployment and audit evidence

Commit `3405827` produced native, single-threaded WASM, threaded WASM, the
extension and the ARM64 notary; the build manifest records 24 artifact hashes.
The rebuilt binary is deployed to the existing instance. Strict authentication
is still not selected by the production driver.

The shipped extension worker verifies its public top-level example in real
Chrome with one and eight threads, rejects changed nonce/path policy, and is
recorded in `option-a/hosted-extension-top-level.json`. These are fresh single
observations, not warm medians or signed-in Duolingo validation.

The regular-LPN audit is partial. MPZ's estimator describes its basis as
ePrint 2022/712; the parameter table cannot certify coverage of later attacks.
The authors' regular-ISD permutation and CCJ linearization estimates span
153–183 bits for the eight current sets. None meets the sufficient polynomial
regime criterion in the 2025 algebraic-analysis abstract. This does not establish
a minimum work factor: algebraic, enumeration, representation, sparse-matrix
and composition analyses remain. Sources:
[regular-ISD estimator](https://github.com/Memphisd/Regular-ISD),
[2023 algebraic attack](https://eprint.iacr.org/2023/176),
[2024 regular-ISD analysis](https://eprint.iacr.org/2023/1568), and
[2025 algebraic analysis](https://eprint.iacr.org/2025/415).

## Hosted path matrix completed

The rebuilt snapshot passes both 12-case synthetic path matrices: native and
Chrome with one/eight threads, fresh/warm/prepared sessions and v1 baselines.
Array-index and depth-eight proofs pass; changed ancestor/path, uniqueness and
nonce policy are rejected; prepared sessions cannot be reused. The fixture is
public synthetic data, not an authenticated Duolingo response.

Eight-thread Chrome warm observations (one sample each):

| Unique path profile | Full presentation | Present | Verify |
|---|---:|---:|---:|
| Ciphertext-only, Fast | 194,371 B | 1,441 ms | 1,009 ms |
| Signed head, Fast | 157,986 B | 1,196 ms | 942 ms |

Both matrices have `complete: true` in `option-a/hosted-paths-*.json`. The old
incomplete runs remain as historical evidence. These observations are still
before the soundness margin and do not meet the presentation gates.

Remote binary SHA-256 matches the synchronized build:
`ccb17098fe81f2a817688139ac2d48b64329aafee651c4bc965f98895a066f3c`.
The temporary Caddy fixture was restored byte-for-byte; both systemd services
remain active. The build manifest is `option-a/build-3405827.json`.

The benchmark runner now marks its two-case extension and eight-case browser-only
modes correctly, and hashes the actual deployed notary artifact instead of an
older fixed checkpoint path. Typecheck and all 22 extension tests pass.

## Authenticated Duolingo observation

The user ran the signed-in nested-streak v2 example against the rebuilt hosted
notary and confirmed successful local verification. One warm eight-thread Chrome
observation: 880.9 ms notarization, 942.1 ms presentation, 458.3 ms verification
and 1.83 s displayed total. The raw displayed timings and provenance are recorded
in `option-a/duolingo-live-user-reported.json`; no account response or proof was
exported. This completes the live functional check for this snapshot, while the
150 ms path presentation target remains unmet. The run uses legacy session
authentication, before Option A activation and the required offline margin.

The session VM adapter now routes TLS schedule operations and the application-key
IR bridge to the chosen legacy or strict implementation. Paired pool session and
prefill handles share failure state, so corrupting either lane through a handle
burns its owning pool too. Both paired Ferret tests and all 18 native API e2e
tests pass. Authenticated production negotiation is the next integration step.

## FLOW5 session integration

The source now negotiates one legacy or two full-width lanes in the signed setup
opening. V2 requires two lanes and rejects legacy fallback before TLS forwarding;
v1 remains single-lane. Both client cache keys and notary tenant scopes separate
authentication modes. Cold pools enable the pair before OT, while warm pools
validate their mode before extension. Both TLS schedule circuits and the
application-key relation use the selected VM. Admission charges 2/4/8 units for
strict 1M/2M/3.5M per-lane budgets, allowing at most 4/2/1 active sessions under
the current eight-unit allowance. This is an admission rule, not measured RSS.

Validation: 18/18 native API e2e tests, 10/10 setup-authentication tests, and the
weighted admission and pre-forwarding downgrade tests pass. Cold/warm v2 proofs, signed-head proofs, signed
session claims and offline verification pass. Authentication-mode signature
tampering and unsupported lane counts are rejected. The hosted notary and
extension were synchronously rebuilt from `7066a4a` and deployed; all 24
artifact hashes are recorded in `option-a/build-7066a4a.json`. The
soundness gate still fails closed: this integration does not supply the
adaptive composition or generalized offline proof reduction.

The new remote ARM64 binary matches SHA-256
`c20e1f0436e1bd2f71fd7e28e783b115a95e024bc318653cb537de52c0a8e9ed`;
both systemd services are active. The shipped extension worker passes in real
Chrome with one and eight threads, including nonce/path substitution rejection.
All 48 local warm measurements (four per profile at 0/33/100 ms RTT) verify and
retain one large message in the final proof flight. Ciphertext-only notarization
medians are 289/463/699 ms, signed-head 485/618/905 ms, and known session claim
609/739/1,025 ms. These are native synthetic-fixture measurements; the offline
margin is not yet implemented. Reports are in `option-a/flow5-local-flow/`.

Both FLOW5 hosted path matrices pass 12/12 (24/24 total), including array and
depth-eight proofs, substituted policy rejection and prepared-session single use.
The temporary Caddy fixture was removed after both completed. Eight-thread Chrome
unique-path warm observations: ciphertext-only 194,371 B / 1,389 ms present /
1,015 ms verify; signed-head 157,986 B / 1,163 ms present / 949 ms verify. Warm
notarization wall times were 3.22/4.47 s; prepared notarization wall times were
846/903 ms. These are one sample each and do not establish median performance
or target closure. The signed-in Duolingo validation above belongs to the
previous FLOW4 snapshot and needs repeating after reloading the FLOW5 extension.
