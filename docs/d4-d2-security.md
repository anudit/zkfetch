# FLOW3 and ORIGO security boundary

FLOW3 negotiates D4 transport changes and the D2 ORIGO schedule through the
`ZKFFLOW3` marker in the signed opening. It is the default for pooled proxy
sessions. `zkConfig.protocolV2: false` selects the existing full TLS key schedule
and legacy flow. TLS 1.2 and MPC continue using their existing schedules.
The extension and notary must be updated together. Unsupported peers only
trigger fresh-OT fallback after a valid signature under the configured key pin.

## D4 transcript and policy checks

The notary signs the fresh nonce, pool device/ticket/generation, resume result,
the declared correlation budget, the first Ferret request/reply,
and the length-delimited public opening. That signature's digest binds the VM
session. QuickSilver additionally absorbs the proxy configuration, both observed
TLS byte streams, the complete TLS claim and ORIGO preprocessing, and the full
proof request, including selectors and predicates. Each canonical commitment
flush, including its view, adjustments and MAC proof, is absorbed before the
subsequent gate-check challenge. The verifier's correlation delta stays secret.
Existing independent ChaCha coefficients are retained, preserving the existing
check's coefficient distribution instead of introducing a degree-dependent
error bound through powers of one field seed.

A pipelined first flight contains only one bounded, full TLS 1.3 ClientHello.
The notary rejects extra records/messages, duplicate extensions, PSK, early
data, ECH, incompatible key shares and SNI/destination disagreement. Admission
and destination/DNS/IP checks occur before any bytes are forwarded. No private
request bytes are sent until the notary key pin has been authenticated.

For a resumed immediate session, the signed host and FLOW3 marker select the
TLS 1.3 proxy configuration directly. No second configuration message gates the
server flight. Warm Ferret extension starts in the opening; its consistency
check overlaps TLS. Both VMs wait for successful prefill completion before
constructing the final proof. A 3,500,000-correlation declaration bounds the
three-flight workload: allocations beyond that budget fail and burn the lease,
instead of silently introducing an interactive extension after TLS. Larger
workloads can explicitly select the legacy protocol. Cold pools bootstrap
before TLS; this initial work is outside the warm three-flight guarantee.

The prover collects all mux proof frames and the attestation request into one
flight, bounded at 32 MiB. Release drains every application queue first; it
handles partial underlying writes without introducing a peer dependency.
Internal QuickSilver check batches keep their independent coefficients and
are transported in this one flight. The notary verifies the proof before
reading and signing the attestation request. The 2 MiB per-stream initial
credit fits the bounded circuit class without waiting for window updates;
the existing 1 GiB aggregate receive-window ceiling remains enforced.

FLOW3 removes the configuration acknowledgment and mux close acknowledgment.
It defers key-schedule and tag verification into the final proof batch. A
recorded transcript or a decoded public handshake key is therefore provisional:
all schedule, tag, identity, commitment and predicate checks must pass before
`sign_attestation` executes. Errors close the session and burn its lease. The
next unused pool generation is published before sending a successful
attestation, so an immediate subsequent session can resume without a race.

## D2 disclosed and private values

The implementation follows Figure 10 of
[ORIGO, PoPETs 2025](https://petsymposium.org/popets/2025/popets-2025-0069.pdf).
For SHA-256, `inner(K)` and `outer(K)` denote the compression states after
processing the 64-byte padded key XOR ipad or opad. Only the following values
are disclosed:

| Value | Purpose |
| --- | --- |
| `outer(HS)` | Complete the disclosed handshake HMACs outside the circuit. |
| Client/server handshake HMAC inner digests | Derive handshake traffic secrets and authenticate the observed encrypted handshake and Finished. |
| `inner(dHS)`, `inner(MS)` | Compute public-message inner digests outside the circuit. |
| `inner(client_application_secret)`, `inner(server_application_secret)` | Compute key/IV label inner digests outside the circuit. |
| Handshake keys, Finished keys, and application IVs | Existing public authentication and nonce values, checked against the proven relation. |

The sole initial private witness is the inner digest of
`HMAC(HS, HKDFLabel("derived", SHA256(""), 32) || 0x01)`. It is not disclosed.
The circuit computes its outer compression under public `outer(HS)` to obtain
private dHS. It proves every disclosed downstream inner pad from the resulting
private key, while computing each outer pad privately. Private outer
compressions derive MS, both application traffic secrets, both application
keys and both IVs. Downstream outer pads, application secrets and keys never
leave the VM. Both an inner and an outer state for any application secret must
never be disclosed: together they would allow deriving application keys.

There are 16 circuit compressions: dHS outer (1); dHS pads and MS outer (3);
MS pads and two traffic-secret outers (4); two traffic-secret pad pairs (4);
and key/IV outers for both directions (4). The plan's 14 estimate omitted the
two IV outer compressions. Removing those checks would leave nonce derivation
unbound. Native preprocessing temporary secrets and the private witness are
zeroized after assignment.

The full schedule proved ECDHE-to-application-key derivation directly. ORIGO
instead links the public HS outer state to the real server via the observed
authenticated handshake, and proves application-key consistency from that
state and the private dHS inner digest. The argument relies on the additional
SHA compression-function assumptions used by ORIGO (including its random-oracle
model), TLS key independence, certificate/Finished authentication, and the
proxy's authoritative capture of server bytes. It does not provide a
notary-independent guarantee against fabricated origin traffic.

Tests compare both keys, IVs and handshake secrets with independent native TLS
HKDF and reject each mutated public pad or private witness. End-to-end tests
cover both TLS versions, MPC, false predicates, trusted key pins, prepared
sessions, cancelled/failed leases and presentation verification. These tests
are implementation checks. They are not an independent cryptographic audit;
that review remains required for the new relation.

## Persistent pool

Device/capability-scoped leases remain single use. Ticket and monotonic
generation are signed and transcript bound; checkout removes state before use.
Replay, cancellation, failures, expiry and restart consume or discard the
lease. Missing state falls back to fresh OT. Pool state is process memory only;
there is no snapshot restore. A 160,000-correlation reserve reduces additional
Ferret tree rounds without changing initial base OT or the vetted LPN parameter
sets. The reserve is not allocated as reusable proof material.
