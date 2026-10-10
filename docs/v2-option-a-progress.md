# Option A implementation progress

The user selected two independent full-entropy authentication lanes and asked
for D1 and D3-2 completion. This follows `zkfetch-d1-d5-plan-v2.md`.

The prior work is checkpointed as `fa9b761` on `v2-completion`. The restored
Mumbai notary at `13-202-74-218.sslip.io` serves that checkpoint protocol.
All 947 recorded Rust source hashes match the commit. The restored binary hash
and instance identity are in
`benchmarks/d1-d5-completion/option-a/restored-checkpoint-provenance.json`.
This does not mean that the new strict protocol is deployed.

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

These APIs are experimental. **The production session driver still selects the
single-lane VM and pool.** Protocol negotiation, lease/cache binding, accounting
for twice the correlations, TLS integration, secret-memory zeroization audit and synchronized release remain
required. Tests establish functional identities, not an adaptive security proof.

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

1. Negotiate and activate both lanes across every TLS schedule check and the
   IR bridge, bind the mode into pool leases, and double resource accounting.
2. Derive adaptive joint-transcript composition, audit malicious OT and current
   regular-LPN attacks, and close the generalized offline Fiat–Shamir reduction.
   A conditional root bound alone cannot certify the release.
3. Select and benchmark the offline margin, then finish presentation performance,
   complete-buffer streaming and the 16 KiB body gate.
4. Finish D1 HTTP completeness/chunking, disclosure, richer claims, AES-256,
   cipher fallback measurements and removal of unnecessary v1 session work.
5. Rebuild client/server/extension from one committed snapshot and deploy it;
   finish the hosted Chrome 8-thread matrix and authenticated Duolingo run.
   The user must run the authenticated Duolingo flow in their signed-in browser.
6. Flip defaults only after the gates pass. External review remains deferred;
   no successful release certificate or completed D1/D3-2 is claimed.

`scripts/build-all.sh` refuses dirty build inputs and records artifact hashes,
commit/tree identity and toolchain versions. This is provenance, not a claim of
bit-identical output across toolchains.
