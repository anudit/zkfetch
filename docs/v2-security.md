# v2 proxy composition and JSON semantics

10 October 2026. Review draft for the D1–D5 completion plan. This describes the
implemented proxy relation and its conditional security argument. It does not
certify the unresolved concrete bounds in `v2-soundness.md` or the unimplemented
split protocol in `v2-split-design.md`. External review is deferred by the user.

## Parties, trust and statement

The prover P requests an HTTPS resource through notary N. The relying verifier V
chooses an independent 32-byte nonce and an expected origin and predicate. V
trusts a pinned notary signing key, its admission policy, clock policy and its
network path to the server. Proxy mode does not protect soundness against a
malicious notary or an attacker controlling that path. P must validate the TLS
server certificate and Finished independently. A network recorder learns record
sizes and timing. Signed-head presentations additionally disclose the response
headers to N and V; they can contain identifying metadata or cookies.

The signed attestation binds the TLS handshake, negotiated suite, application-key
commitments, ciphertext record tables and Bao roots. The offline statement binds
the public headers, record plaintext lengths and content types, selected key and
value offsets, encoded member spelling, and authenticated ciphertext openings.
The query binds the expected server name, numeric comparison, constant and V's
nonce. These inputs and the versioned construction profile determine the circuit;
V reconstructs it rather than accepting a graph supplied by P.

## Conditional composition lemma

Assume (i) the notary signs only an authenticated captured session and accepts
the ORIGO/key-commitment relation soundly, (ii) its signature is unforgeable,
(iii) the key commitment is binding for the applicable suite, (iv) Bao openings
bind the record bytes and positions to the signed roots, (v) the offline proof
system is sound for the reconstructed relation, and (vi) that relation correctly
implements TLS CTR decryption, record framing and the JSON predicate below.
Then an accepted presentation establishes the selected predicate over the
captured response under the committed TLS application key, except with the sum
of those failure probabilities.

The reduction separates failure cases. A different attestation requires a
signature forgery or an accepted malicious session. A different record, position
or ciphertext requires a record-table or Bao-opening violation. An alternative
key opening violates key-commitment binding. Given the same key and ciphertext,
counter-mode decryption is deterministic. A wrong decrypted member or comparison
therefore requires either an offline proof forgery or a bug in the specified
relation. Parser correctness is a separate obligation, rather than a consequence
of cryptographic soundness. Numeric bounds, record counts and all hash/PRG terms
must be included in the concrete union bound; no unknown term is assigned zero.

ORIGO reveals particular HMAC intermediate values. The relation checks the
revealed pads and derivation boundaries against the borrowed handshake secrets
and authenticated transcript. RFC 8448, legacy differentials and mutation tests
support functional correctness but do not establish a privacy theorem for those
reveals. The 16-compression accounting and reveal classes are documented in
`v2-origo-accounting.md`. A checked symbolic model and external review remain
release obligations.

## Ordering and domain separation

N validates admission, proxy destination policy and ClientHello before forwarding
upstream. The session opening signature binds its capability scope, pool lease,
generation and setup declaration. Failed or cancelled leases are burned. Warm
correlations are move-only and currently in memory; process restart uses fresh
OT. FLOW4 peers park only the reserved bootstrap prefix: unused outputs are
zeroized and discarded, and buffers are shrunk. The PRG, transfer IDs and check
transcript continue forward. Legacy openings retain their earlier behavior.
Authenticated allocation classes and weighted notary admission bound simultaneous
preprocessing before upstream forwarding. Cancellation while queued destroys the
checked-out lease. Their durable encrypted storage is not implemented.

The key-commitment frame distinguishes metadata-bearing flow 11 from
ciphertext-only flow 12. The authenticated relation uses a domain-separated
ChaCha8 coefficient stream bound to its statement and check seed. Session claims
use the `zkf/2/session/standard-aes/prefix/top-level/depth-4/v5` construction
profile. Offline profile labels, parameters and the entire public statement/query
are bound into Fiat–Shamir. Construction changes require a version bump and
fixture review; tests retain the full graph digest for that purpose.

V supplies the expected nonce independently. Reading an embedded nonce and then
using it as policy would allow replay. Time limits supplement nonce binding;
they do not replace it. Neither a v1 presentation nor a signed session claim is
an offline zero-knowledge proof of a new, later predicate.

## Implemented JSON and HTTP meaning

`key` means a member of the root JSON object. It does not mean a nested path or
unique member. The parser starts at the document boundary and constrains the
grammar and stack state through the selected value and its delimiter. Selection
requires depth one; a nested `history[].balance` cannot satisfy root `balance`.
Keys use checked JSON string encoding. The value is a bounded unsigned integer,
with the requested comparison applied to it. Hidden prefix bytes remain private.
Public offsets disclose lengths and position. The current stack bound is four
and the body cap is 1 KiB. Exact paths, arrays, optional duplicate-key rejection
and a depth-eight parser remain unfinished.

Parsing stops after the selected delimiter. The statement therefore asserts a
structurally valid selected prefix, not that the undisclosed suffix forms a fully
valid JSON document or contains no duplicate member. Circuit construction never
uses an unauthenticated string-search anchor as a substitute for grammar context.
Applications requiring JSON-document validity or uniqueness need those additional
relations before relying on this API for that meaning.

Current HTTP support is an uncompressed HTTP/1.1 200 response with an exact
Content-Length framing. Signed-head session checks decrypt the head and
authenticate record content types and padding. Known-at-fetch claims additionally
decrypt through the last selected delimiter; unselected body tail blocks are
skipped while final record padding is still checked. Ciphertext-only offline
proofs authenticate the head themselves. Chunked framing, close-notify-based
completeness and arbitrary request/response range disclosures are not implemented.
The current completeness flag must not be interpreted as support for those forms.

## Concrete security and release boundary

The authenticated MPZ delta has 127 variable bits. A generic degree-three
root-count bound is `3 / 2^127`, and two coefficient streams sharing that delta
do not generically square it. The offline degree-three adaptation also needs its
own BAVC/Fiat–Shamir reduction and explicit margin. Consequently the current
code is not certified to the plan's exact 128-bit requirement. The release
certificate command fails closed until these derivations and margins exist.

The proxy client currently supports v2 AES-128-GCM sessions. Hybrid ML-KEM,
AES-256/SHA-384 and split mode are future implementation work. TLS certificate
authentication and the notary signature remain classical; an eventual hybrid
key exchange alone would not constitute PQ security at every layer. The new GCM
IR tests establish arithmetic correctness, not provenance or a complete split
composition theorem. Production default changes remain gated on these security,
compatibility and performance checks.
