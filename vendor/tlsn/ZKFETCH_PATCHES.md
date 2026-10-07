# zkfetch patches to vendored tlsn

Base: `v0.1.0-alpha.15` (47aee45). Each patch is self-contained and intended for upstream.

## P1: QuickSilver transcript predicates

Lets a prover prove properties of hidden plaintext to the verifier inside the
same QuickSilver VM that authenticates the transcript. The verifier learns
only that each property holds.

- `core/src/transcript/predicate.rs` (new): `TranscriptPredicate`
  `{ direction, range, kind }` with kinds:
  - `UintGte { minimum }`: canonical unsigned decimal (≤ 19 digits) `>= minimum`
  - `JsonStringContent`: valid JSON string content (escapes closed, no raw
    quotes/control chars), so hiding it cannot change the surrounding parse
  - `JsonAtom`: JSON number or `true`/`false`/`null`
  Also the cleartext reference `evaluate()` and limits.
- `core/src/config/prove.rs`: `ProveConfigBuilder::predicate`, carried in
  `ProveRequest::predicates()`.
- `core/src/lib.rs`: `ProverOutput::predicates`, `VerifierOutput::predicates`.
- `tlsn/src/transcript_internal/predicate.rs` (new): boolean circuits (digit
  parsing + 64-bit accumulator + comparator; one-hot DFAs for the JSON shapes),
  invoked over the authenticated plaintext references; only the verdict bit is
  decoded. Tests check circuits against `evaluate()` exhaustively for single
  bytes, on edge cases, and on 3,000 random inputs.
- `tlsn/src/prover/prove.rs`, `tlsn/src/verifier/verify.rs`: predicate ranges
  join the authenticated plaintext set; verdicts are checked after the
  plaintext proofs verify.

The wire format of `ProveRequest` changes (new field), so prover and verifier
must both run this patch.

## P2: TLS 1.3 MPC-TLS transport

- `components/hmac-sha256`: explicitly enables the SHA-256 hash feature so
  standalone vendored tests do not depend on zkfetch feature unification.
  Fixed-size slices in HMAC, key exchange and GHASH use `as_chunks`, and record
  buffer drains use `mem::take`, satisfying Rust 1.98 Clippy without changing
  circuit order or byte order.
- `components/tls13-schedule` (new): alpha.15 port of PR #1001's HKDF schedule;
  application key references available before preprocessing; repeated handshake
  flushes assign the public HKDF context only once.
- `core`: configurable TLS version, `CertBindingV1_3` and CertificateVerify
  checks over exact handshake bytes, content-only record lengths and suffixes.
  The transcript builder treats TLS 1.3 application-epoch records separately
  from TLS 1.2 Finished records.
- `tls/client`: raw handshake bytes, TLS 1.3 backend hooks, record layer activation
  and the two transcript hashes consumed by the MPC schedule.
- `mpc-tls`: version dispatch; existing leader/follower remain TLS 1.2;
  `tls13.rs` implements handshake/application epochs, public handshake keys and
  IVs, deferred commit, suffix exchange and closure. Preprocessing runs key
  exchange, record layer and VM concurrently with owned `try_join3` closures.
  Finish drops backend VM references and shared OT registrations before DEAP
  finalization, preventing the shared OT barrier from waiting on inactive users.
- `mpc-tls/record_layer`: TLS 1.3 XOR nonce, outer-header AAD and no explicit
  nonce on the wire, reusing MPC AES-GCM; explicit record/content length and
  sequence exhaustion checks.
- `tlsn`: version-specific client config, received tag proofs with TLS 1.3 AAD,
  AES-CTR authentication of public suffixes, and content-only transcript indices.
  Both peers allocate suffix circuits before hash commitments.
- `attestation`: offline presentations reject disagreement between the signed
  connection version and certificate binding version.
- `server-fixture`: explicit TLS 1.2-only and TLS 1.3-only bind helpers for tests.

This changes MPC configuration and record representations; both peers must use
this patch. TLS 1.3 currently supports AES-128-GCM/SHA-256 and P-256 only, without
resumption, 0-RTT, HelloRetryRequest or key updates. The notary does not verify
server handshake records independently: the implementation relies on MPC tag
checks and the offline CertificateVerify binding. Public handshake secrets and
IVs and the suffix proof construction need security review. P2 is local and
has not been submitted upstream.
