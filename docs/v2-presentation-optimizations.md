# Optimized v2 presentations

The optimized D1 flow retains offline claims while moving public HTTP framing
checks into the session when `signedResponseHead: true` is selected. The
default ciphertext-only flow keeps that work offline. Both require coordinated client/notary updates.

## Current snapshot: October 10, 2026

Registered offline and session relations bind a versioned profile plus every
public builder input. Offline bindings include the complete serialized statement
(headers, record views, encoded key and offsets), query, attestation digest,
nonce, AES/scope profile and parameter set. Session bindings explicitly include
both key commitments and canonical head/claim metadata. Generic backend APIs
retain the full graph hash; mutation invalidates registered profiles. Tests pin
full graph digests for representative registered builders.

Public key-expansion and AES-block templates are cached; witness values are never
cached. Repeated AES hint polynomials share immutable storage. Presentation
proving reuses the witness validation capability produced during evaluation.

Real Chrome, eight threads, medians of three warm local-fixture runs:

| Mode | Presentation | Verification | Encoded presentation size |
|---|---:|---:|---:|
| Previous compact/prefix Fast | 745 ms | 521 ms | 66.6 KiB |
| Profiled/template Fast | 350 ms | 145 ms | 66.6 KiB |
| Profiled/template Small | 490 ms | 279 ms | 46.9 KiB |
| Signed-head Fast | 112 ms | 73 ms | 27.4 KiB |
| Signed-head Small | 205 ms | 158 ms | 20.1 KiB |

Circuit construction fell from about 224 to 58 ms; transcript binding fell from
about 218 to 3 ms. These are fixture measurements, not hosted end-to-end gains.
Signed-head modes move framing checks into notarization. Small alone does not
meet 40 KiB on this fixture; the 100 ms proving target remains unmet.
Raw results are in `docs/benchmarks/d1-d3-baseline/wasm-profile-profiled-*.json`.

Both offline and signed session claims require root-object membership. Duplicate
root keys and undisclosed suffix validity are still outside the claim. The
extension refuses Duolingo's nested streak claim in v2 until explicit path proofs
are supported; v1 remains available. The latest profile/protocol snapshot needs
coordinated deployment and hosted testing. Earlier measurements below are
historical and do not establish completion of the current deployment.

## Implemented changes

1. The JSON circuit uses Boolean state hints and degree-2/3 transition
   constraints. The presentation parses from the document start through the
   selected value and its delimiter, with a private stack of at most four
   levels. It asserts root-object member existence, not a nested JSON path,
   uniqueness, or validity of the undisclosed suffix. The presentation magic
   is `zkf2prs\x04`; the query domain names the prefix/depth profile explicitly.
2. With `signedResponseHead: true`, the notary verifies the disclosed response headers and each record's inner
   content-type position and padding against its recorded ciphertext and
   authenticated server key. It signs a domain-separated digest of those
   headers and ordered record views. Offline proofs use that exact signed
   digest to skip header-only AES blocks and record suffix checks. A boundary
   block containing both headers and body is still decrypted. A mismatched
   reserved head claim fails; it cannot silently select the old profile.
3. AES encryption uses round pairs inspired by [FAEST v2 §6.7](https://faest.info/faest-spec-v2.0.pdf).
   The first round commits four inverse-norm bits per byte, and the second
   eight inverse bits. Quadratic intermediate states feed cubic checks
   directly. This implementation uses **960 bits per AES-128 block**, versus
   1,280 before: a measured circuit reduction of **25%**, not a claimed 50%.
   This compact encoding is used for offline key commitments and full-response
   or body-only decryption. Body blocks after the selected value delimiter are
   skipped, while unsigned headers and all unsigned record suffixes remain
   checked. Session checks retain the original 1,280-bit encoding;
   using compact AES for signed headers regressed hosted Chrome notarization
   to about four seconds. Shared key expansion remains unchanged. Zero-safe equations constrain
   both inverse and inverse-norm hints. Field multiplication uses MPZ's
   constant-time carry-less multiplication backend, with a reference test.
4. The threaded WASM feature expands and reconstructs the independent VOLE
   trees with Rayon. Authenticated-row reconstruction and independent constraint
   checks also run in parallel. Indexed collection preserves transcript order. Secret
   prover columns and scratch buffers are zeroized. The serial feature
   retains serial scheduling. An immutable checked-witness handle avoids repeating
   validation when packing commitments and constructing constraint polynomials;
   it is bound to the original circuit. Polynomial multiplication skips only
   coefficients whose zero values follow from public degree bounds.
5. One combined field relation borrows both existing TLS application-key MAC
   references in client/server order. It proves their OWFs and the response
   head together. The challenge is derived from the authenticated VM
   transcript after all statement and commitment corrections, without a
   verifier challenge exchange. The proof and attestation request share the
   existing FLOW2 batch. The key frame carries flow byte 7 with bounded public
   metadata, or flow byte 8 for ciphertext-only sessions.
   Older v2 peers reject it rather than accepting another relation.
6. Optional `sessionClaims` are numeric top-level-member predicates known
   before fetching. They require `sessionClaimNonce`, an independently issued
   32-byte verifier challenge in hex. The session checks their parser context
   and numeric comparison and signs the exact member/operator/threshold/nonce.
   Session claims enable signed framing automatically. An exact matching presentation opens this signed assertion without a new
   VOLE-in-the-Head proof. Later claims or other nonces use the offline path.

The signed-head/offline HTTP profile requires HTTP/1.1 200, JSON Content-Type, uncompressed
Content-Length framing, a body of at most 1 KiB, and headers of at most 16 KiB.
Response headers are disclosed to the notary during fetch only in signed-head
mode. Set-Cookie responses are refused before disclosing the head. In the default
ciphertext-only mode the existing presentation-time Set-Cookie guard applies. Request authorization headers remain
private. Session claims use member names, never dotted-path semantics.

## Browser measurements and remaining gap

On October 9, 2026, three real Chrome extension v2 presentations were generated
and independently verified against the hosted notary. With eight WASM threads,
presentation took 913.0 ms on the first run and 883.5 / 884.4 ms on warm runs.
The previous warm runs took approximately 1,030 ms: about a 14% reduction.
Verification still took 705–721 ms. The default ciphertext-only proof remains
about 180 KiB, above the 40 KiB target, and presentation remains above 100 ms.
These targets are **not complete**.

Network timings varied substantially in this run (notarization 0.88–1.92 s),
so the data does not establish an end-to-end session speedup.
[Chrome results](benchmarks/d1-d3-baseline/extension-v2-parallel-checks-2026-10-09.json)
include successful verification and credential-redaction checks.

After deploying the matching ARM64 binary, a second Chrome run verified v1 and
all three v2 proofs again. Warm v2 presentation took 911.0 / 913.4 ms; total
generation was 1.84 / 1.54 s. This supports a presentation improvement of roughly
11–14% over the earlier ~1.03 s runs, rather than a stable end-to-end comparison.
[Final deployment results](benchmarks/d1-d3-baseline/extension-v2-final-deployment-2026-10-09.json)
record the deployed binary checksum. Circuit/backend tests passed (44 IR, six
VOLEitH; the exhaustive proof-byte mutation test remains explicitly ignored),
as did the TLS v2 integration test, 21 extension tests and TypeScript checking.

V1's presentation opens commitments to a result already checked during the
session; default v2 instead constructs a new offline AES and JSON-context proof.
Optional signed headers reduce the offline proof to about 31 KiB for the tested
response, but hosted native tests added enough in-session work to make total
generation slower. Signed session claims make a matching presentation almost
instant, at the cost of doing that predicate work during notarization and binding
the exact claim and verifier nonce before the fetch. Neither option is enabled
by default in the extension. Later claims retain the offline proving path.

## Combined field-check soundness note

The prover and verifier rebuild the same circuit independently. Their binding
contains the registered builder profile (generic relations retain the full
circuit digest), the captured ciphertext roots, record tables,
IVs, handshake hashes, both key commitments through the circuit constants, and
the canonical head/claim metadata including every signed claim nonce. The VM
absorbs this binding and canonical commitment corrections before computing the
domain-separated Fiat–Shamir seed. The seed expands to separate field weights
for all constraints. A client-supplied seed or graph is never accepted.

Both borrowed keys retain their original authenticated rows. Auxiliary bits and
the two degree-check masks use fresh single-use VM correlations. The verifier
evaluates the degree-three check at its secret delta and signs only after this
check and the TLS schedule/identity checks succeed. The delta is never exposed
by the transcript digest. Failures discard the session. Pool reuse protections
remain necessary; this flow does not authorize reusing consumed correlations.

Fiat–Shamir soundness relies on the random-oracle treatment of the transcript
hash and the secrecy of the verifier delta. Degree-three checks have a
degree-dependent statistical bound, rather than an exact 2^-128 bound. The
offline proof continues to use the selected FAEST nominal 128-bit parameter
family. These adaptations need independent cryptographic review; implementing
and testing them is not a claim that the FAEST signature security theorem
automatically covers this application protocol.

Signed-claim presentations authenticate the exact independent nonce through
the notary signature. They cannot wrap an old signed assertion in a new nonce.
The verifier still pins the notary key and enforces origin, age, owner/context
and its own query policy. Owner/context strings are signed metadata, not proof
of an owner's identity or possession.
