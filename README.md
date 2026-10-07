# zkfetch

**Goal:** `fetch` with a proof. A user's device makes an HTTPS request as one half of a 3-party TLS session (MPC-TLS) with a notary. Afterwards, the user picks which parts of the request and response to disclose (URL, headers, JSON fields), or proves predicates over hidden values. The result is a presentation that anyone can verify offline. The notary never sees private data, and the user can't forge server data. Target: TLS 1.3 and TLS 1.2, local proving on the device, and a low-latency notary at the Cloudflare edge.

Built on [TLSNotary](https://github.com/tlsnotary/tlsn) (pinned `v0.1.0-alpha.15`).

`zkFetch` supports TLS 1.3 and TLS 1.2 through a vendored TLSNotary transport.
QuickSilver predicates are the default; Binius64 is opt-in. `tlsVersion: "auto"`
tries TLS 1.3 first and retries TLS 1.2 only for GET/HEAD/OPTIONS; explicit
versions never fall back. The TLS 1.3 design still needs security review.
See [implementation notes](docs/m2-m4.md) and the
[vendored patch log](vendor/tlsn/ZKFETCH_PATCHES.md).

```ts
import { zkFetch, verify } from "zkfetch";

const res = await zkFetch("https://api.example.com/me", {
  headers: { Authorization: `Bearer ${token}` },             // stays hidden
  zkConfig: { notaryUrl: "wss://notary.example", tlsVersion: "auto", owner: "0xabc", context: challenge },
});

await res.json();                                             // a normal Response
const presentation = res.zk.present({ response: { jsonPaths: ["user.id"] } });
verify(presentation, { trustedNotaryKeys: [NOTARY_KEY], expectedContext: challenge });
```

## Quickstart

Requires Bun and Rust 1.98.1 (selected by `rust-toolchain.toml`).

```sh
bun install
bun run build          # release binaries + native addon (packages/native/zkf.node)
bun run test           # Bun + Rust end-to-end tests (ZKF_LIVE=1 adds a public-API test)

bun zkfetch dev        # local notary + HTTPS fixture, prints the commands below
bun zkfetch fetch https://test-server.io/formats/json --connect 127.0.0.1:<port> -H "Authorization: Bearer x"
bun zkfetch reveal session.zkf.json            # interactive: pick headers / JSON fields
bun zkfetch verify presentation.txt --notary-key <hex>
```

## Hidden-value predicates (M4)

```ts
const claim = {
  jsonPath: "streakData.longestStreak.length",
  predicate: { gte: "365" },
};
const res = await zkFetch("https://api.example.com/me", {
  zkConfig: { notaryUrl: "wss://notary.example", context: challenge, predicates: [claim] },
});
const presentation = res.zk.present({
  response: { jsonPaths: ["username"] },
  prove: [claim],
});
const result = verify(presentation, {
  trustedNotaryKeys: [NOTARY_KEY],
  expectedContext: challenge,
  expectedPredicates: [claim],
});
console.log(result.predicates); // authenticated claim; streak value stays hidden
```

Use `gte` or `gt` over a hidden unsigned JSON integer of at most 19 digits.
Use a decimal string above JavaScript's safe integer range. Required predicates
reject stripped proofs and weaker thresholds. Predicate mode discloses JSON
keys, container structure and scalar byte lengths; all unselected scalar values
remain hidden. QuickSilver claims must be declared in `zkConfig.predicates` at
fetch time. To choose new thresholds after fetching, set `zkConfig.backend: "binius"`
and use `present({ prove: [claim] })`; this opts into extra
SHA-256 commitments and separate Binius64 proving.
The default is `backend: "quicksilver"`. The session remembers the backend,
including after `restoreResponse()`, so presentation does not need a second toggle.

```sh
bun zkfetch fetch https://test-server.io/formats/json --connect 127.0.0.1:<port> --tls-version 1.3 --gte id=1000000000
bun zkfetch present session.zkf.json --gte id=1000000000 -o predicate.txt
bun zkfetch verify predicate.txt --notary-key <hex> --require-gte id=1000000000
```

## Playground: Duolingo longest streak

`packages/playground` proves a Duolingo username and longest streak with `zkFetch`, running three times each with QuickSilver and Binius. Each backend prints individual measurements and arithmetic averages for every timing phase and proof size, verified TLS/cipher details, a sample verified disclosure, and overhead against the average plain `fetch` baseline. Set `ZKF_STREAK_MINIMUM` to compare hidden-value predicate proofs; otherwise both backends use selective disclosure only.

```sh
cp .env.example .env   # set DUOLINGO_JWT = your `jwt_token` cookie from duolingo.com
bun run playground     # starts a local notary unless ZKF_NOTARY_URL is set
# Optional: prove the threshold while hiding the streak itself.
ZKF_STREAK_MINIMUM=365 bun run playground
PLAYGROUND_TLS_MATRIX=1 ZKF_STREAK_MINIMUM=365 bun run playground
```

With `DUOLINGO_JWT` set, it proves the private `/users/<id>` endpoint (401 without auth) and the token stays hidden. Without it, it falls back to the public lookup, where Duolingo hides `streakData`. Sample run with a local notary, live `www.duolingo.com` over TLS 1.2, median of 3:

| Phase | Median |
|---|---|
| MPC setup + preprocessing | 256 ms |
| MPC-TLS session (handshake, request/response) | 833 ms |
| Commitment proofs (ZK to notary) | 125 ms |
| Attestation | 4 ms |
| Present + verify | < 1 ms |
| **End to end** | **1.21 s** (plain fetch: 0.74 s) |

The notary ran on the same machine. These M1 measurements predate the additional
predicate proofs and exclude Binius64 proving. A remote notary adds
round-trip-dependent MPC cost, which is what the edge milestone (M6) targets.

## Layout

| Path | What |
|---|---|
| `crates/zkf-core` | Shared JSON types, WebSocket transport, framing |
| `crates/zkf-prover` | MPC-TLS client, commitments, attestation request, `RevealSpec` → presentation |
| `crates/zkf-notary` | Notary server (WebSocket): MPC-TLS verifier, limits, extensions, secp256k1 signer |
| `crates/zkf-verifier` | Presentation verification + policy (trusted keys, owner, context) |
| `crates/zkf-napi` | Node-API addon used by Bun |
| `crates/zkf-fixture` | Local HTTPS test server with test CA |
| `crates/zkf-predicates` | QuickSilver claims, optional Binius64 proofs, authenticated JSON structure and signed commitments |
| `vendor/tlsn/crates/components/tls13-schedule` | Port of TLSNotary PR #1001 to the alpha.15 MPC VM |
| `crates/zkf-tls13` | TLS 1.3 hello/handshake checks, record framing and MPC AES-GCM components |
| `packages/native` | Typed loader for the addon + build script |
| `packages/sdk` | `zkfetch`: `zkFetch()`, `res.zk.present()`, `verify()`, dev helpers |
| `apps/cli` | `zkfetch` CLI: `fetch`, `reveal`, `present`, `verify`, `dev` |
| `packages/playground` | Duolingo latency playground |

## Status

### Done (M1: TLS 1.2 end to end)
- [x] Bun + Cargo monorepo; TLSNotary pinned by tag
- [x] Notary server over WebSocket: MPC-TLS verifier, preprocessing caps, rejects proxy mode, signs attestations (secp256k1)
- [x] Attestation extensions `zkf.owner` / `zkf.context`, validated by the notary and enforced by the verifier
- [x] Prover: notarized fetch (method, headers, string body; GET tested), commits to the whole HTTP transcript
- [x] Selective disclosure: request target, header values, body; response headers, body, JSON `"key": value` by dotted path
- [x] Always disclosed: request line, Host and other zkfetch-managed headers, all header names, status line, framing headers
- [x] Verifier: notary signature, server certificate identity, commitment openings, trusted-key, owner and context policy
- [x] `zkFetch(url, init)` with the same shape as `fetch` (`init.zkConfig`), returning a standard `Response` plus `res.zk`
- [x] Sessions serialize, so the reveal can be decided later
- [x] CLI with an interactive reveal picker
- [x] Tests: Rust and Bun end to end, covering tampered bytes, untrusted notary key and wrong context
- [x] Live check: real TLS 1.2 API (`jsonplaceholder.typicode.com`) notarized and verified
- [x] Per-phase notarization timings (`res.zk.timings`) and the Duolingo latency playground
- [x] JSON commitments per array element (tlsn's default commits arrays only as a whole), so nested fields like `users.0.username` can be revealed
- [x] macOS 27 linker workaround for the native addon (see `packages/native/scripts/build-native.ts`)

### M4: QuickSilver default; Binius64 opt-in
- [x] QuickSilver JSON shape and unsigned comparison proofs in the transcript VM
- [x] Notary signs only verified claims (`zkf.qs.v1`); offline path and required-predicate checks
- [x] Opt-in SHA-256 commitments over every JSON scalar, using TLSNotary's 16-byte blinders
- [x] Combined ZK circuit: commitment openings, JSON scalar syntax, unsigned parsing and `gte` / `gt`
- [x] Authenticated structure, decoded unique keys, exact dotted paths and canonical array indices
- [x] Offline verification of signed commitments and required-predicate policy
- [x] Bun SDK, restored sessions, CLI flags and optional hidden-streak playground mode
- [x] Negative tests: false claims, malformed numbers/UTF-8, forged structure, changed digests, paths, session binding and proof bytes
- [ ] Browser/mobile predicate clients (M5)

### M2/M3: TLS 1.3 transport
- [x] MPC TLS 1.3 HKDF port from [tlsn PR #1001](https://github.com/tlsnotary/tlsn/pull/1001), reference vectors and two-party private-share tests
- [x] Both parties obtain handshake traffic keys; application keys remain VM references
- [x] Independent certificate, CertificateVerify and Finished checks against a real Rustls TLS 1.3 fixture
- [x] Joint-share/hello binding, AES-128-GCM/P-256 restrictions, no PSK or early data
- [x] 12-byte XOR nonce, inner content type, padding/length limits, sequence exhaustion and close_notify helpers
- [x] MPC AES-GCM encryption, decryption and GHASH/tag checks with private key shares
- [x] Version dispatch, TLS 1.3 client state machine and leader/follower messages
- [x] TLS 1.3 transcript authentication, authenticated suffixes, deferred processing and CertificateVerify identity binding
- [x] TLS 1.3-only Rust fixture → disclosure/predicates → offline verification; tamper and identity negatives
- [x] SDK/CLI/playground version selection, actual session version and safe-method auto fallback
- [x] Bun SDK/CLI and live public API interoperability over explicit TLS 1.2 and 1.3
- [x] Full Rust regression suite, GET-only fallback/POST single-attempt test, both predicate backends over TLS 1.3
- [x] Vendored tests reject forged suffixes, signed version mismatches and sequence exhaustion
- [ ] TLS 1.3 security review
- [ ] Upstream PRs / maintainer coordination ([tlsn#859](https://github.com/tlsnotary/tlsn/issues/859), [tlsn#978](https://github.com/tlsnotary/tlsn/issues/978))

### Other work
- [ ] M5: Browser (WASM prover) and mobile (uniffi) clients; web demo
- [ ] M6: Cloudflare edge: Worker + Durable Object + Container notary, warm pool, browser WebSocket→TCP relay with non-Cloudflare fallback
- [ ] M7: Hardening: TEE notary tier, notary key registry, audits, fuzzing, interop suite
- [ ] General structural JSON reveal mode, array/regex selectors, chunked-response tests
- [ ] Notary: auth (JWT) and rate limits, `wss://`, key management (KMS), metrics
- [ ] Encrypted-at-rest session storage in the SDK
- [ ] CI (GitHub Actions: Rust + Bun + live tests)

## Security notes
- `session.zkf.json` (`res.zk.toJSON()`) holds the secrets that open every commitment. Treat it like a credential.
- TLS 1.3 is a local protocol patch without a security review. See the server-flight, public key/IV and suffix assumptions in [implementation notes](docs/m2-m4.md).
- Verifiers must pin trusted notary keys (`trustedNotaryKeys`). Without them the result only reports the key.
- A user colluding with the notary can forge data. Mitigations are planned: TEE tier, key registry, multi-notary.
