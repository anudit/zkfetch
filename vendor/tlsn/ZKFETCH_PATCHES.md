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

## P3: single-threaded executor (wasm without threads)

- `tlsn/src/session.rs`: on `wasm32` without the `web` feature the executor is
  built with zero threads and the session driver runs queued MPC tasks on the
  polling thread (`mpz_common::LocalRunner`, see `vendor/mpz/ZKFETCH_PATCHES.md`).
  Native and `web` builds are unchanged.

## P4: TLS 1.3 proxy mode

- `core`: `ProxyTlsConfig::tls_version` (serde default TLS 1.2, so older peers
  keep working).
- `tlsn/src/proxy/tls13.rs` (new): the prover runs a TLS_AES_128_GCM_SHA256 /
  P-256 rustls client through the verifier's relay. After the connection
  closes, both parties run `tls13-schedule` in the ZK VM with the ECDHE shared
  secret as a private prover input. `H(ClientHello || ServerHello)` is computed
  by each party from the relayed plaintext; the handshake traffic secrets are
  decoded. Each party decrypts the relayed handshake itself: the server
  records' AEAD tags bind the private shared secret to the server's key
  exchange, the server and client Finished MACs are checked, and
  `H(ClientHello ..= server Finished)` feeds the application key schedule.
  Application keys stay in the VM and their IVs are decoded; records use the
  P2 nonce mapping, so tag and suffix proofs are shared with MPC TLS 1.3. The
  prover discloses record suffixes, proven during proving. The certificate is
  bound offline through `CertBindingV1_3` (ClientHello ..= Certificate, the
  CertificateVerify signature and the server key share), as in P2.
  Optional CertificateRequest / client Certificate messages are accepted.
  No PSK, 0-RTT, HelloRetryRequest or key updates.
- `tlsn/src/prover/client/proxy`: version-aware rustls config; a P-256
  key-exchange wrapper records the shared secret keyed by the client share;
  the key log also captures the TLS 1.3 application traffic secrets.
- `tlsn/src/verifier.rs`: TLS 1.2 Finished VM checks only run for TLS 1.2.
- Latency (fewer prover-verifier round trips):
  - `tls13-schedule`: `assign_all` / `finish_all` assign every HKDF context up
    front so the whole TLS 1.3 schedule runs in one VM execution (Normal mode
    only assigns public contexts). The prover derives its handshake keys
    natively from the TLS client, computes `H(ClientHello ..= server Finished)`
    and the record suffixes, and sends them in one message before the
    execution. The verifier decrypts the relayed handshake with the revealed
    keys and rejects the session if its own hash differs from the claim; the
    application keys were derived from the claimed hash, so a false claim also
    fails the tag proofs. The prover checks the proven keys against rustls's.

Proxy mode (both versions) trusts that nobody can intercept the network path
between the verifier and the server. P4 needs the same security review as P2.

## P5: fail when the server closes during the handshake

A server that closes the TCP connection during the handshake without an alert
(for example one without TLS 1.3 support answering a TLS 1.3-only ClientHello)
made `MpcTlsClient::poll` recurse between `Active` and `Busy` until the stack
overflowed, and left the proxy client pending forever.

- `tlsn/src/prover/client/mpc.rs`: after the server closes, the client
  processes the remaining received data once; if the handshake is still
  incomplete it returns "server closed the connection during the TLS
  handshake".
- `tlsn/src/prover/client/proxy/mod.rs`: the handshaking state returns the same
  error once the server has closed.

zkfetch's `auto` now chooses TLS 1.3 and never retries an attempted session. Regression tests: `*_server_hangup_during_handshake_fails` in
`crates/zkf-prover/tests/e2e.rs`.

## P6: bounded proxy traffic

`tlsn/src/proxy.rs`: `InspectReader` records at most `PROXY_MAX_SENT_BYTES`
(128 KiB) from the prover and `PROXY_MAX_RECV_BYTES` (2 MiB) from the server,
including handshake records, and fails the relay at the first excess byte
instead of buffering it. `tlsn/src/verifier.rs`: a prover that closes the proxy
stream without sending anything gets an error instead of a panic.

## P7: aggregate predicate budget

`core/src/transcript/predicate.rs`, `tlsn/src/verifier/verify.rs`: the summed
operand length of all predicates in a request may not exceed
`MAX_PREDICATE_BYTES` (256 KiB) or twice the transcript, and exact duplicates
are rejected, so repeated or overlapping long operands cannot multiply the
verifier's circuit work.

## P8: TLS 1.3 shared secrets expire

`tlsn/src/prover/client/proxy/mod.rs`: captured ECDHE secrets of handshakes
that never finish (cancelled sessions) are dropped after five minutes, and
every entry is zeroed when it is removed.


## Security remediation — 9 October 2026

The active TLS 1.3 follower reconstructs the public server handshake, checks
Finished before application key derivation, and compares the certificate-binding
prefix. The notary signs `zkf.handshake` for offline identity consistency. Proxy
ClientHello SNI must match the dialed hostname. Both parties must use matching
builds; this changes interactive wire messages. A fresh notary-key challenge
also precedes session setup in first-party transport code.

Hash commitments have aggregate count/byte budgets before VM allocation; the
first-party committer partitions overlapping ranges. Proxy recording checks
record count, plaintext handshake bytes and record headers. QuickSilver string
circuits enforce strict UTF-8 and paired surrogate escapes. Captured/key-log
secrets use zeroizing buffers; dropping a cancelled proxy client immediately
removes its shared-secret registry entry. These changes have regression evidence,
but do not replace an independent malicious-security review of these protocols.


## Persistent proxy setup — 9 October 2026

`vole_pool` exposes move-only prover/notary Ferret holders. Each fresh ZK VM
gets a fresh SharedRCOT facade over the exclusively leased inner Ferret state,
so retaining the pool does not add an idle participant to its adaptive barrier.
An atomic lease guard rejects concurrent use. The correlation delta and Ferret
PRG/SPCOT/transfer state remain paired; output consumed by a session is never
returned to the pool. There is no serialization or snapshot restore path.

The first-party authenticated opening signs device, ticket, monotonic lease
index and a fresh nonce. Its digest is sent in the TLSN setup transcript and
checked before accepting a proxy configuration. Pooled setup pipelines the
configuration and Ferret initialization without waiting for a separate
acceptance reply. Only negotiated pool sessions use this flow; legacy sessions
retain their original wire messages. Rejections close the session and burn
its lease. The host application retains pools only after successful proof and
attestation exchange, with bounded per-capability caches and fresh-OT fallback.


## P5: FLOW3 round-trip reduction and ORIGO schedule (D4 / D2)

`ZKFFLOW3` is authenticated by the notary opening signature, including a
length-delimited public ClientHello and destination. The proxy validates the
entire opening and enforces admission/destination policy before forwarding.
Warm FLOW3 also binds its correlation budget and first Ferret exchange into
that signature, derives the session configuration from the signed host, and
overlaps the Ferret consistency check with TLS. The final proof and attestation
request are collected into one bounded mux flight. Both VMs await successful
prefill before proving; budget overflow burns the lease and cannot trigger a
new interactive extension. Fresh pools bootstrap before TLS.
FLOW3 uses a 2 MiB negotiated mux window, omits the proof-configuration ACK and
peer close synchronization, and returns the attestation inside the live mux.
TLS 1.3 schedule, tag, disclosure and predicate circuits execute as one batch;
claimed handshake keys and IVs are checked before any attestation is signed.

The proxy schedule uses ORIGO Figure 10 with a private dHS inner-hash witness.
Only HS outer pad, the two handshake inner digests, and the dHS/MS/application
inner pad states are disclosed. All downstream outer pads and application
secrets remain private. Both application keys and IVs use 16 SHA-256
compressions; the IV checks account for two compressions beyond the plan's
14-key-only estimate. This requires the compression-function assumptions in
ORIGO, not just the previous full-schedule relation. See
[security analysis](../../docs/d4-d2-security.md). No independent security review
is implied. `protocolV2: false` selects the full schedule and old flow.

QuickSilver binds the signed pool lease, proxy configuration, observed TLS
bytes, all preprocessing/public-key claims, and the complete proof request.
The mpz runtime also absorbs each canonical commitment flush before deriving
its subsequent check challenge. Independent ChaCha coefficients remain in use;
no powers-of-one-seed optimization changes the error bound.
