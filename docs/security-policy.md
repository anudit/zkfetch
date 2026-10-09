# Application verification and notary operations

A valid presentation authenticates the disclosed bytes and signed predicates.
Applications must configure a trusted notary key, expected server, request method
and target, response status, freshness, and required predicates before using it
for authorization. Redacted `sent`/`recv` strings are display output: inspect
`sentAuthed`, `recvAuthed`, `json`, and `jsonPathsAuthenticated` for evidence.

```ts
const result = verify(presentation, {
  trustedNotaryKeys: [currentNotaryKey],
  expectedServerName: "api.example.com",
  expectedMethod: "GET",
  expectedTarget: "/account",
  expectedStatus: 200,
  maxAgeSecs: 120,
  expectedContext: challenge.context,
  expectedOwner: authenticatedWalletAddress,
  expectedPredicates: requiredClaims,
  requireCompleteResponse: true,
  requireJsonPaths: true,
  rejectProxy: true,
});
```

`owner` is an arbitrary signed label. It does not prove possession of a wallet
key. Verify a separate wallet signature and bind its address to `expectedOwner`.
Issue a random 256-bit challenge after authenticating the user. Store the
application origin, action, expected owner and expiration with it. Serialize
those fields canonically into `context`, and compare the exact value. After
verification, atomically consume the challenge in the application's database
in the same transaction as the authorized action. A reused or expired challenge
must fail; an in-memory map is insufficient across workers or process restarts.
`maxAgeSecs` uses the verifier's own system clock and rejects future timestamps.

`requireCompleteResponse` currently accepts authenticated Content-Length framing
whose exact body length matches the signed transcript. EOF-delimited and chunked
responses are rejected by this strict policy. A normal inspection can authenticate
a response prefix; it must not treat that prefix as a complete response.

A fetch with `zkConfig.reveal` commits only to what that spec discloses, one
BLAKE3 commitment per unit (the always-revealed HTTP structure, the JSON skeleton,
each selected header, JSON field, target or body). Bytes outside those units are
not committed, so the attestation carries no blinded digest of them, and no later
presentation can disclose them; `present` fails closed instead. Soundness is
unchanged: the same signed hash commitments and in-session plaintext
authentication apply. The prover's application decides `reveal`; derive it from
the verifier's policy, not from untrusted input, or it may over-disclose.

JSON path authentication exposes object keys, punctuation, structure and scalar
lengths. `response.byteOnly: true` skips skeleton disclosure and returns byte
proofs; it cannot be combined with numeric path predicates. Binius sessions
provide no general JSON path-authenticated output: applications requiring it
must use QuickSilver and `requireJsonPaths`. QuickSilver planning fails on
unsupported JSON instead of silently dropping claims. Empty object keys, keys
containing periods (including escaped periods), and duplicate decoded keys are
rejected because dotted paths cannot represent them unambiguously. Numeric
object keys are interpreted using the current container type; array indices
must be canonical decimal numbers. More than 1,024 leaves is unsupported.

TLS `auto` chooses TLS 1.3. Failed attempts and failed prepared sessions are not
retried. Choose `tlsVersion: "1.2"` explicitly for a known compatibility need.
Remote notaries and relays require WSS. Loopback WS remains available for local
fixtures. Set `expectedNotaryKey` to a signing key obtained through a trusted
channel before connecting; it is required for remote sessions. A fresh,
domain-separated signed challenge checks key possession before MPC setup, and
the final attestation must use that key. Prepared sessions retain the pin.
CLI: `--notary-key HEX` or `ZKF_NOTARY_KEY`. WSS still authenticates the transport;
a key challenge alone does not replace it. The TLS 1.3 protocol now transmits public handshake evidence and signs
`zkf.handshake`; deploy matching prover/notary builds. New verifiers reject old
TLS 1.3 attestations lacking this verified binding.

## Admission and resource controls

Public native listeners require `ZKF_CAPABILITIES`, a JSON array of records:

```json
[{"tokenHash":"<SHA-256 of a lowercase 64-character random hex token>","expires":1791504000,"maxSessions":2,"startsPerMinute":10}]
```

Each capability is an independently provisioned tenant identity. Provision one
active capability per tenant so multiple credentials cannot multiply its quota.
Generate tokens from 32 random bytes. Give them short expirations (for example,
one hour), and supply them only to authorized clients. Pass the token as the
`capability` query parameter in the WSS notary URL. Browser WebSockets cannot
set arbitrary Authorization headers. Treat the entire URL as a credential:
disable URL/query logging in reverse proxies, tracing, analytics and clients.
The transport's connection errors omit the URL; notary failure logs omit the
protocol error chain. Capability configuration contains hashes, never raw tokens.
Expired or unknown tokens fail before WebSocket/MPC allocation. Redeploy without
a hash to revoke it. Anonymous admission is allowed only on loopback listeners.

Global/per-IP/tenant session permits cover preprocessing, idle prepared sessions,
active requests and proof completion. Sixteen separate setup permits and 256
pending-head permits cap opening work. Opening/configuration deadlines are 15 s.
Tenant start quotas count reconnect attempts even when concurrency is exhausted.
Hash commitments are capped at 2,048 and 2 MiB summed bytes and twice the
transcript; the prover partitions overlapping commitments into disjoint spans.
Predicate operands retain the 256 KiB aggregate budget. Proxy recording is
bounded to 128 KiB sent / 2 MiB received, 4,096 records per direction and 128 KiB
plaintext handshake bytes. TLS 1.3 decrypted handshake flights have a 128 KiB cap.

For AWS deployment, set `ZKF_CAPABILITIES_FILE` to the private JSON file. The
script uploads it through SSH into a root-only environment file. The notary
container has a 1.5 GiB hard memory cap, no swap expansion, a PID cap and no Linux
capabilities. Host forwarding rules reject internal/special IPv4 destinations
and permit only new outbound HTTPS; the Docker network must have IPv6 disabled.
Application resolution still validates once and dials only that address list.
`ZKF_DESTINATION_ALLOWLIST` optionally limits hostnames (comma-separated exact
names). Firewall and cgroup settings require validation on the deployed host;
local unit tests do not prove infrastructure isolation. Synchronous crypto work
still requires independent process isolation for cancellation without affecting
other sessions; the watchdog currently restarts the service on a stuck session.

## Offline trust, rotation and compromise

Distribute pinned public keys over an authenticated application configuration
channel. Record issuance and retirement dates. During planned rotation, distribute
the new public key first, then change the notary signing key; retain the old key
only for explicitly allowed historical attestations. Apply a timestamp window
for each key in the application's policy. Do not fetch a replacement trust key
from the untrusted proof itself.

On suspected compromise, immediately remove the key from every verifier's
allowlist, revoke active capabilities, stop signing and invalidate outstanding
challenges. Issue a new key after investigating the host and build artifacts.
A revoked key must fail even for historical offline claims unless a separately
trusted archive policy explicitly accepts that risk. Offline verifiers must
refresh a signed trust/revocation manifest before authorization; define its
maximum age and fail closed when it expires. Rotation cannot retroactively make
claims signed under a compromised key trustworthy.

## Assurance still required

The executable handshake checks close specific equality gaps; they are not an
independent composable-security proof. Specialized MPC/OT/VOLE, malicious-notary,
colluding replay-endpoint, Binius and proxy-construction reviews remain required.
FLOW3 also enables the ORIGO TLS 1.3 schedule by default in pooled proxy
sessions. Its compression-function assumptions, intermediate disclosures and
required pre-signing checks are described in [the D4/D2 security boundary](d4-d2-security.md).
That relation still needs independent cryptographic review. Select
`zkConfig.protocolV2: false` to retain the full schedule and legacy flow.
The CI dependency gate intentionally flags unmaintained dependencies (bincode,
derivative, paste and rustls-pemfile) even when RustSec reports no vulnerability.
Do not silently ignore those notices; migrate them or record a reviewed exception.

The private health listener exposes `/metrics` with fixed-cardinality admission,
active, completed and failed counters. Example Prometheus alert rules are in
`infra/monitoring/notary-alerts.yml`; load them into the deployment's monitoring
stack and validate notifications. No URL, tenant token, request body or witness
is used as a metric label. Alerts are defined but not activated by local changes.
