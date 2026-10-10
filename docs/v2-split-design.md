# Split-key protocol design and implementation gates

10 October 2026. D5-0 internal design; external review deferred by the user.
This specifies the implementation boundary, not a claim that split mode exists.

## Roles and circuit

P builds the ClientHello. N relays it only after admission, destination and
key-share checks; N does not run an independent TLS client. Start with TLS 1.3,
AES-128-GCM, one request and one response. Existing zkf/1 DEAP stays separate.

The shared ECDHE secret is a private circuit input. The key-schedule circuit
must derive the handshake secret from that input, so the proxy ORIGO revealed
boundary cannot replace its prefix. The estimate is approximately 26 SHA-256
compressions plus both AES key commitments; measure the compiled circuit rather
than hardcoding a claimed gate count. Hybrid adds the prover-private ML-KEM
shared secret to the HKDF IKM, in the negotiated group's specified order.

Output routing:

| Output | P | N |
|---|---|---|
| Handshake traffic secrets | Available for independent Finished check | Available for independent Finished check |
| Client application key and IV | Key available; IV public | Key remains authenticated/blind; IV public |
| Server application key | Masked key only until response lock | Holds fresh mask; key remains authenticated/blind |
| Server IV | Public | Public |
| Both key commitments | Public authenticated outputs | Public authenticated outputs |

N samples a fresh 128-bit server-key mask independent of all labels, OT and
VOLE seeds. Its value is an N-private GC input; the masked output is delivered
to P. P must never receive unmasked server-key output labels or a decoding map
before the response lock. Handshake-key disclosure is intentional, not a
permission to disclose application-key wire labels.

## State and reveal order

1. **Prepared:** GC, ECtF/MtA and input-label OT are ready; all preprocessing is
   single-use and bound to device, tenant, generation and session nonce.
2. **Opened:** validate policy and ClientHello; bind the negotiated group, suite,
   target, shares and all public circuit inputs before evaluation.
3. **Handshake authenticated:** both participants check the captured handshake;
   P checks server Finished before releasing its Finished or application request.
   Abort without producing any attestation on failure.
4. **Response captured:** N records the complete response wire bytes and record
   sequence. Disable subsequent request/response reuse of this connection.
5. **Response locked:** bind immutable sent/received Bao roots, record tables,
   key commitments, negotiated parameters and session identity. N must durably
   fix this lock before releasing the mask. P cannot propose the observed root
   in place of N's independently captured root.
6. **Mask released:** release the mask for this lock only. Close the upstream
   connection; there is no keep-alive or additional response acceptance.
7. **Consistency checked:** N reveals its ECDHE share and garbling seed. P checks
   the committed garbling against the fixed circuit and public inputs. P proves
   private-input consistency and every required GCM tag using the authenticated
   key references. N verifies everything before signing the final attestation.

Any exception or cancellation burns preprocessing and clears keys, labels and
masks. A lock is not itself a successful attestation. Restart recovery may
resume neither a partially revealed mask nor an unverified GC session.

## GC to authenticated IR bridge

Reuse DEAP's committed-output/garble-then-prove mechanism, not just its AES
helper. Commit the actual GC input/output values in the same authenticated VM
that verifies the schedule consistency. The client/server key arrays borrowed
by the IR must be those authenticated GC outputs. A newly assigned plaintext
copy of the key is insufficient, even if its public key commitment matches.

The IR GCM relation computes H=AES_k(0), AES_k(J0), and GHASH over the complete
AAD and ciphertext, including independent padding of each and their 64-bit
lengths. GHASH's network-bit convention must be converted explicitly to the
IR polynomial basis. One degree-two field multiplication per Horner block
costs 128 committed bits. Check all records when claiming completeness; checking
only a selected block does not authenticate its record or establish framing.
`crates/zkf-ir/src/gcm.rs` supplies this relation. Integration still needs the
captured-root/record binding and GC output references.

## Group and hybrid constraints

P-256 can reuse the existing MtA/ECtF path. X25519 needs a separately checked
Wei25519 implementation. The affine x-coordinate conversion is u=x−486662/3
mod p. It does not alone solve share generation, scalar clamping, cofactor,
point lifting or invalid/twist inputs. Require compatible subgroup points,
explicit encoding rules and differential vectors against X25519 before using
that conversion. Check all-zero shared-secret rejection. P-256 may be the first
split implementation, but that does not complete the preferred hybrid gate.

P generates ML-KEM keys and decapsulates locally. Bind the actual negotiated
public key/ciphertext and private decapsulation secret through GC consistency;
a guessed or substituted secret must fail Finished. Later quantum compromise
of ECDHE should not expose the ML-KEM secret to N or a recorder. Online split
soundness still assumes ECDHE cannot be broken during the session. Classical
server certificate authentication remains a separate limitation.

## Malicious behavior and internal design review

- **Selective failure:** authenticated input-label OT and committed garbling
  must prevent N learning P's input from chosen invalid labels. Match DEAP's
  checks and abort behavior; ordinary semi-honest garbling is insufficient.
- **Output leakage:** inspect each output decoding map; do not expose SATK or
  permit its mask to be reconstructed from committed wire labels.
- **Malicious garbling:** commit the garbling seed and circuit identity before
  P supplies inputs. After root lock, reveal and validate every gate/output
  routing rule, not a subset sampled by the garbler.
- **Replacement keys:** borrowing authenticated outputs is mandatory. Tests
  must reject changing CATK, SATK or ss_mlkem while retaining the captured root.
- **Early mask:** use an explicit state transition that cannot release a mask
  before the independently observed root is frozen. Test races, cancellation,
  replay and restart, not only the happy-path call order.
- **Injected records:** a relay knowing CATK must not create accepted server
  records before SATK reveal. After reveal, the fixed root must reject every
  injected byte even if its GCM tag is valid.
- **Soundness:** independently derive the GC/ECtF, authenticated-check and
  record-dependent terms; inherited nominal security labels are not a bound.

Internal review outcome: this order prevents post-reveal records from entering
the signed transcript, provided the lock is immutable and independently
captured. GC output authentication and malicious ECtF require reusing and
validating the full existing protocols. Those are implementation gates, not
assumptions silently fulfilled by the output-routing table. External review
remains outstanding before GA.

## Measurements before enabling the mode

Record preprocessing bytes (≤15 MB three-halves target), evaluation time per
100k AND, online bytes (≤100 KB), exchanges (≤6, aiming 4–5), and native/Chrome
memory. Prepare garbling and OT ahead, piggyback online rounds on the existing
open/server flights, and enforce `requireSplit` in the verifier. Prepared Chrome
8-thread split must be ≤proxy+0.5 s at 33 ms RTT. Proxy remains default; automatic
split selection is allowed only when verifier policy explicitly requires it.
