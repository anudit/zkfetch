# D1/D3 implementation and design review

Source plan: `/Users/anudit/Documents/GitHub/comptest/zkfetch-d1-d3-plan.md`.
Research and implementation started 2026-10-09. This document records actual
status. The current session and presentation protocol has **not** been replaced
by these reference primitives. No D1/D3 production release is certified.

## Research corrections

1. **FAEST v2 already handles zero S-box inputs.** Specification §6.2,
   Proposition 6.4 gives `x²y=x` and `xy²=y`. With bit decompositions, squaring
   is GF(2)-linear, so this pair uses degree-2 checks. Degree-3 is needed for
   the optimized two-round field-norm encoding (§6.7), not just for zero-safe
   inversion. The plan's assertion that FAEST v2 must resample every key with
   a zero S-box input is incorrect. The reference gadget currently commits
   full inverse bytes; the optimized norm encoding is still outstanding.
   Source: <https://faest.info/faest-spec-v2.0.pdf>.
2. **Quote parity does not establish JSON membership.** A valid counterexample
   is `{"a":"x", ": 7, hidden":0}`. The substring `", ": 7,` has unescaped
   quotes and looks like a member named comma-space with value 7. Its first
   quote actually closes a string value and its second opens the following
   member name. That member does not exist. A test preserves this example.
   Either an offline parser-state proof or an authenticated session anchor
   is required. An unchecked flag claiming a window begins outside a string
   would simply move the unsoundness to the flag.
3. **AES-256 TLS is a SHA-384 schedule.** RFC 8446 Appendix B.4 specifies
   `TLS_AES_256_GCM_SHA384`; the current ORIGO implementation is SHA-256 and
   produces 16-byte keys. A tested AES-256 gadget does not constitute TLS
   AES-256 support. SHA-384 circuit support and differential vectors remain
   required. Source: <https://www.rfc-editor.org/rfc/rfc8446.html>.
4. **Nominal security and an exact soundness bound differ.** FAEST §6.1,
   Lemma 6.3 gives a degree-d bound `d/2^λ`. For d=3 and λ=128 this bound
   alone cannot certify the plan's exact total error ≤2^-128. It does not
   imply an attack achieving that bound. The specification's full security
   analysis, grinding, query budget and other error terms must be instantiated
   for the generalized statement. No script should silently call λ=128 a
   certificate of the stronger inequality. The user selected nominal 128-bit
   security: use the FAEST-128 parameter family, state constant factors and
   query assumptions, and analyze the generalized relation separately.
5. **Two-block AES-256 commitment is computational binding, not uniqueness.**
   Under the ideal-cipher counting model, 256 output bits for a 256-bit key
   do not make the expected number of additional preimages negligible. This
   does not itself refute 128-bit computational binding: the generic collision
   search has about 128-bit cost. The security write-up must state the actual
   assumption and distinguish those claims. We retain the planned two-block
   construction in reference gadgets, pending composition review.
6. **The FAEST signature API is not a general statement prover.** The reviewed
   upstream is `ait-crypto/faest-rs`, commit
   `9ccc68c06f2db762b91afc06b20826d5836d477a`, package `faest` 0.3.0.
   Its BAVC/VOLE interfaces rely on compile-time witness lengths and its
   proof checks AES-specific constraints. Signing a presentation with a FAEST
   signing key would not prove CTR decryption or predicates. No such shortcut
   is used. Source: <https://github.com/ait-crypto/faest-rs>.
7. **Milestone A's Binius compatibility needs an explicit transition.** Existing
   Binius proofs open signed plaintext hash commitments. Removing those
   commitments while retaining the old offline prover leaves it without its
   public binding. V1 fetches can keep that path; a D1 fetch requires a new
   offline statement/backend before arbitrary later disclosures work.

## Decisions implemented in the reference layer

The user selected **nominal 128-bit security** and **offline JSON-context
proofs** on 2026-10-09. JSON parser state must be constrained starting at an
authenticated document boundary, not supplied by the prover or taken from a
fetch-time anchor. Arbitrary later member selection remains a requirement.
Full-path/uniqueness semantics remain outside T2. The additional context work
must be included in proof-size/time measurements; the original targets are
not assumed to survive this correction.

- GF(2^128) is represented in little-endian polynomial order, reduced modulo
  z^128+z^7+z^2+z+1. Byte lifting uses FAEST Appendix A.1's exact generator
  `053d8555a9979a1ca13fe8ac5560ce0d`. All 65,536 byte products are checked
  against independent GF(2^8) multiplication.
- A byte consists of eight bit edges. Public and linear edges consume no new
  commitments. Products and auxiliary inverse bytes get consistency constraints.
  The IR contains no witness values. Witness buffers are zeroized on drop.
- A reference streaming schedule assigns reusable slots from each edge's last
  operation/constraint use. It checks constraints as soon as their dependencies
  exist and erases released slots. A 10,000-edge chain uses two resident values;
  AES matches the full evaluator while retaining fewer than half its edges.
  Public graph metadata still scales with the circuit size. Authenticated
  tags/keys and VOLE buffers do not yet use this schedule, so this is not a
  claim of bounded production prover memory.
- The reference IR handles polynomials of degree at most three. Check-algebra
  tests use `q=m+Δw` and homogenize constraints to degree three. This module
  is algebra, not a protocol: there is no ZK proof API, Fiat–Shamir shortcut,
  or claim that callers can send unmasked coefficients.
- AES key expansion is shared across blocks, for 16-byte and 32-byte keys.
  FIPS-197, SP 800-38A, randomized differential AES, exhaustive zero-safe inverse
  uniqueness, and altered auxiliary witness checks are included.
- Commitment blocks are exactly
  `SHA256(b"zkf/2/ck" || one_byte_index)[0..12] || 00000000`, indices 1 and 2.
  Data CTR blocks use RFC 8446 sequence-nonce XOR and counters starting at 2.
  Content-type constraints cover a declared type position and **the entire
  suffix** after it. Integrating code must bind that suffix to the record end.
- Ciphertext stream roots cover concatenated complete TLS wire records,
  including five-byte headers. Table offsets point to those headers. Every
  record in the application-key epoch must be included, including tickets and
  alerts; only a proof establishes its inner content type. Sequence indices
  must be contiguous within the epoch. Key updates are not supported.
- Bao openings disclose complete 1 KiB chunks. Opening validation checks the
  signed stream length, range, root, length caps and trailing bytes. Block
  lookup excludes GCM tag bytes and out-of-record offsets.
- Signed-object encoding uses RFC 8949 §4.2.1 core deterministic CBOR, ordered
  by encoded map-key bytes. Fixed-width hashes/IVs are CBOR byte strings.
  Handshake hashes are 32 bytes for suite 0x1301 and 48 bytes for 0x1302;
  mismatched widths are rejected. Schema support does not implement SHA-384
  in the session circuit.
  Re-encoding equality rejects alternate widths, tags, indefinite containers,
  map orders, unknown fields, duplicates and trailing data. Secp256k1 signatures
  use `SHA256(b"zkf/2/attestation" || cbor)`, low-S encoding and a trusted,
  caller-supplied verification key. These primitives do not validate a TLS
  session; the notary must accept the complete proof before calling `sign`.
- The JSON reference parser preserves duplicate members and records exact key
  and value spans across nested objects. T2 means existence of a particular
  structural member, without asserting a path or uniqueness. The parser is
  **not** a ZK gadget and is not used to authenticate hidden client statements.

## Experimental protocol integration

The generalized offline backend now exists in `zkf-voleith/experimental.rs`.
It uses the vendored FAEST-128f/128s BAVC, dynamic VOLE vectors, universal
hash consistency check, two degree-three masks, challenge grinding and a
strict fixed-layout proof decoder. Both parties bind the canonical IR digest,
attestation digest, statement and verifier nonce. The dynamic adapter is
differentially tested against upstream's compile-time vectors. This adaptation
has not inherited the full FAEST signature security theorem merely by reusing
its primitives, and still needs the composition/parameter analysis.

`zkf-ir/backend/mpz.rs`, behind `mpz-backend`, performs authenticated degree-three
checks with real MPZ bit MACs. A borrowed prefix is the **original** VM reference,
not a fresh commitment to a caller-supplied key. Remaining witness values and
two random masks use fresh correlations from the same VM. The verifier sends
a random challenge after commitment, then checks three masked coefficients.
This initial bridge adds an exchange; folding it into the D4 flow remains work.
The full authenticated graph is retained; bounded-memory streaming remains work.

TLSNotary's `d1-experimental` feature exposes those checks on client/server
application-key references after the TLS session proof is accepted. It retains
local native application keys in a non-serializable, non-debuggable zeroizing
type, and captures both raw application-epoch ciphertext streams **before**
suffix filtering. The capture includes control records and alerts, full IVs,
and both handshake hashes. A real TLS 1.3 fixture test compares the endpoints'
Bao roots/IVs/hashes, proves both key commitments, and rejects a commitment made
with another key. This follows the existing tag/suffix proof; it does not yet
remove that work or activate D1 in the SDK/notary server.

`zkf-ir/json_circuit.rs` now constrains a private JSON parser starting at the
document boundary, including nesting, escapes, Unicode, numbers and complete
value extents. The statement does not accept a client-supplied parser state.
`zkf-voleith/presentation.rs` connects that circuit to a signed attestation,
verified Bao ciphertext, Ck, sequence-derived CTR counters and full record
content-type/padding tails. Its first HTTP profile discloses response headers,
requires HTTP/1.1 200 with Content-Length and application/json, and rejects
chunking, compression, duplicate lengths and incomplete framing. All received
epoch records are covered, including encrypted control records; arbitrary
later structural-member selection is supported in this profile. The initial
JSON body cap is 1 KiB while the graph is retained in memory. AES-256, general
byte-range reveals, hidden headers, larger bodies, presentation serialization
and production API integration remain work.

The offline HTTP tests use genuine AES-GCM ciphertext under a synthetic signed
fixture attestation. They do not constitute a production notary fetch. They
reject wrong keys, swapped policies/nonces, ciphertext/root mutation, record
omission and malformed framing. The backend compiles for wasm32; this is not
a browser timing or browser-execution result.

A single synthetic AES-128/CTR/private-JSON sample (55-byte body, k=8) measured
93,812 committed bits, a 191,013-byte proof, approximately 368 ms prove and
186 ms verify locally. Those timings exclude a TLS session, attestation and
HTTP-header proof. The user accepted current prototype timings for now; this
does **not** mark the original size/time release targets as met. The raw sample
is retained in `docs/benchmarks/d1-d3-baseline/experimental-json-k8.json`.

## Production integration (opt-in)

v2 attestations are now selectable per request with `attestationV2: true`
(`zkConfig.attestationV2` in the SDK). Default fetches are unchanged, and the
v1 wire format is byte-identical, so existing clients work with an updated
notary. The `d1-experimental` cargo feature is on by default in `zkf-prover`
and `zkf-notary`; the name records that the construction is unreviewed.

Flow (proxy mode, TLS 1.3, AES-128-GCM; anything else is refused before I/O):

1. The prover appends `attestation=2` to the notary URL, so the notary knows
   before the session that key-commitment proofs follow the TLS proof.
2. The prover proves the server identity (and with it the ORIGO schedule)
   with no transcript commitments and no session predicates. In the D4
   low-latency flow the proof flight is released here, because the next step
   waits for the notary's challenge: **one extra exchange** versus v1 D4.
3. On `zkfetch/d1/keys` the prover sends `SHA-256(binding) ‖ C_k(client) ‖
   C_k(server)`. The binding covers both Bao roots and stream lengths, both IVs
   and both handshake hashes, each side computed from its own recording; a
   mismatch fails before any proof. Two authenticated degree-3 relations then
   show each `C_k` opens to the VM's application-key reference.
4. The notary signs a deterministic-CBOR v2 attestation: dialed IP, leaf SPKI
   and chain hashes, both record tables and roots, key commitments, IVs,
   handshake hashes and owner/context. `sid` is the binding hash. The reply is
   `magic ‖ len ‖ CBOR ‖ signature ‖ claimed key`; the claimed key is a lookup
   hint, never trust.
5. The prover checks every signed field against its own view before
   returning. Its secrets are the two application keys plus the recorded
   ciphertext (as sensitive as v1 secrets).
6. `presentV2` decrypts locally, builds the context-profile statement and
   proves a member predicate with VOLE-in-the-Head, bound to the verifier's
   nonce. `verifyV2` requires trusted keys, server name, predicate and nonce.

The first profile discloses the whole response head and refuses `Set-Cookie`
responses unless `allowSetCookie` is set.

Measured on the local fixture (M2 Max, release, 0 ms RTT, ~0.9 KB JSON body):

| | Cold | Warm (resumed pool) |
|---|---:|---:|
| Session total | 251–274 ms | 127–132 ms |
| Prove phase (TLS proof + two `C_k` relations) | 121–126 ms | 121–127 ms |
| Presentation (base64) | 3.19 MB | 3.19 MB |
| `presentV2` prove / `verifyV2` | 5.6 s / 2.9 s | 5.6 s / 2.9 s |

The session no longer hashes plaintext, but presentations are far from the
plan's ≤ 40 KiB / ≤ 40 ms targets: the offline JSON parser context runs over
the whole document. Shrinking it (optimized AES norm encoding, streaming, a
smaller context) is the next performance item.

Tests: `attestation_v2` in `crates/zkf-prover/tests/e2e.rs` (cold and warm,
nonce/claim/trust/server/context mutations, false claims, v1/v2 confusion)
and the SDK test "attestationV2: zkFetch -> presentV2 -> verifyV2".

## Measured validation

- ORIGO passes the final RFC 8448 §3 known-answer vector, including handshake
  traffic secrets, application keys and IVs.
- Four direct ideal-VM differentials against the full legacy normal schedule
  pass. Seven revealed intermediate classes, a private witness mutation and
  a transcript mutation are covered. Handshake-only mutations must be rejected
  by actual Finished authentication, not by an application-pad comparison.
- The native fixture baseline command measures one cold and two resumed
  sessions for each of Binius, full-commitment QuickSilver and reveal modes,
  plus presentation proving/verification and encoded sizes.
  With the optional feature, it records circuit call shapes, AND allocations
  and private input allocations. These are allocation counters, **not** a
  measurement of all consumed correlations or peak memory.
- Measured allocations including private inputs, excluding check masks, are
  2,516,656 bits for full commitments/Binius, 2,667,549 for full commitments
  with session predicates and 1,152,317 for reveal with session predicates.
  The 16 ORIGO SHA-256 compressions account for 361,168 AND gates in each.
  Binius presentation median prove/verify is approximately 437/379 ms, with
  a 568,512-byte offline proof and 592,235-byte complete presentation. These
  are baseline measurements, not D1/D3 gains.
- All new primitive tests and ORIGO tests pass; the existing release e2e suite
  passes (19 tests, baseline ignored). The new crates pass strict Clippy and
  compile for wasm32. No headless-browser execution has been performed.
- Preliminary coverage-guided fuzz runs exercise the attestation decoder,
  record tables/Bao openings and reference JSON parser. Budgets and execution
  counts are recorded in `docs/benchmarks/d1-d3-baseline/fuzz.json`. This is
  not the full W7 protocol fuzz budget.

```
cargo test --release -p zkf-prover --features circuit-metrics --test e2e \
  d1_d3_native_baseline -- --ignored --nocapture
ZKF_D1_D3_SCENARIO=quicksilver cargo test --release -p zkf-prover --features circuit-metrics --test e2e d1_d3_native_baseline -- --ignored --nocapture
ZKF_D1_D3_SCENARIO=reveal cargo test --release -p zkf-prover --features circuit-metrics --test e2e d1_d3_native_baseline -- --ignored --nocapture
python3 scripts/d1-d3-summary.py
cargo run --release -p zkf-ir --example gadget_counts
cargo test -p zkf-ir -p zkf-attestation -p zkf-tls13
```

The baseline JSON contains no attestation secrets, keys, tokens or response
bodies. Presentation timings include parsing and transcript proof building.
It measures localhost/native, not 33 ms relay, wasm, Chrome or hosted performance.

## Completion checklist

| Workstream | Actual status |
|---|---|
| W0 ORIGO known answers/differential/intermediate classes | Implemented; ideal-VM checks do not replace external cryptographic review |
| W0 baseline | Native fixture capture implemented; allocation counters optional; hosted/wasm and peak-memory measurements remain |
| W1 field, graph, plain evaluator, inverse/AES/CTR/suffix/scalar/SHA-256 gadgets | Reference implementation and tests present |
| W1 reference liveness/streaming evaluator | Implemented and tested; authenticated backend memory is still outstanding |
| W1 optimized norm encoding | Outstanding |
| W1 constrained JSON parser state | Implemented; private full-context parser with malicious grammar/extent tests |
| W2 common degree-3 check algebra | Reference equations and differential tests present |
| W2 authenticated MPZ field input/degree-3 protocol integration | Experimental bridge and real TLS key-reference tests implemented; D4 folding, streaming and replacement of session AES remain |
| W3 Bao record roots, deterministic signed-object primitives | Implemented and tested in a separate crate |
| W3 session integration, secrets v2, touched-only claims, fallback | Opt-in `attestationV2` session path, notary signing and secrets v2 implemented end to end; no session claims yet; one extra exchange in the D4 flow |
| W4 generalized VOLEitH and strict proof decoder | Experimental implementation, both parameter families, byte mutation/replay tests and dynamic/upstream differentials implemented |
| W4 parameter analysis, optimized encoding, streaming, external review | Outstanding; nominal 128-bit security selected; upstream BAVC/VOLE KATs pass |
| W5 presentation v2, verifier, nonce APIs, Chrome/playground | `presentV2`/`verifyV2` with serialization and nonce in Rust, napi, wasm and the SDK; broader response support, presentation size and the Chrome/playground flow remain |
| W6 Binius removal | Outstanding; retained to keep current presentations verifiable |
| W7 primitive fuzzing | Preliminary runs pass; complete CPU budget and protocol decoder targets outstanding |
| W7 browser/hosted matrix, composition review | Outstanding |
| §8 circuit-sized VOLE/admission | Explicit follow-up in the source plan; not implemented here |

All size, latency, concurrency and browser exit targets remain unverified.
The release gate must not mark this work complete until the outstanding
protocol implementation and validation are finished.
