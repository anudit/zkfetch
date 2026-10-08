<p align="center">
  <img src="zkfetch.svg" alt="zkfetch" width="140">
</p>

<h1 align="center">zkfetch</h1>

<p align="center"><code>fetch</code> with a proof.</p>

zkfetch makes an HTTPS request together with a notary and returns a normal
`Response` plus a signed attestation. Afterwards the user chooses what to
reveal (URL, headers, JSON fields) or proves facts about hidden values, such as
`longestStreak >= 365`. The result is a presentation anyone can verify offline.
The notary never sees private data such as auth tokens, and the user cannot
forge what the server sent.

It is built on [TLSNotary](https://github.com/tlsnotary/tlsn) (pinned
`v0.1.0-alpha.15`, vendored and patched), with a Rust core, a Bun/Node SDK and
a notary that runs on Cloudflare.

## On top of TLSNotary

| Addition | What it does |
| --- | --- |
| **TLS 1.3 (MPC)** | MPC-TLS over TLS 1.3 (AES-128-GCM, P-256): an HKDF key schedule in MPC, public handshake keys, private application keys, authenticated record suffixes. |
| **Proxy mode, TLS 1.2 and 1.3** | The notary relays the connection and the prover proves the session keys in zero knowledge. Kilobytes of traffic instead of ~66 MB of MPC preprocessing. For TLS 1.3 the notary decrypts and checks the handshake it relayed. |
| **QuickSilver predicates** | Numeric (`gte`, `gt`) and JSON-shape proofs over hidden plaintext, checked by the notary during the session and signed into the attestation. The default backend. |
| **Binius64 predicates** | Opt-in. Per-leaf SHA-256 commitments let the user prove new predicates later, offline, without the notary. |
| **JSON selective disclosure** | Reveal by dotted path (`users.0.username`), including array elements, with the JSON structure kept authenticated. |
| **Session binding** | `zkf.owner` / `zkf.context` attestation extensions for wallet binding and verifier challenges. |
| **`fetch`-shaped SDK** | `zkFetch(url, init)` returns a standard `Response`. Sessions serialize, so the reveal can be decided later. |
| **Automatic version and backend** | `tlsVersion: "auto"` prefers TLS 1.3 and falls back to 1.2 only for idempotent requests. One `backend` switch configures commitments and proofs. |
| **Single-threaded MPC** | A patched executor runs MPC without OS threads, for wasm hosts such as Workers. |
| **Cloudflare notary** | A Rust Worker routes to a Durable Object that runs the native notary in a Cloudflare Container, in US, EU and APAC regions. |

The protocol patches are listed in
[`vendor/tlsn/ZKFETCH_PATCHES.md`](vendor/tlsn/ZKFETCH_PATCHES.md) and
[`vendor/mpz/ZKFETCH_PATCHES.md`](vendor/mpz/ZKFETCH_PATCHES.md). The TLS 1.3
and proxy-mode patches have not had a security review yet.

## Request lifecycle

```mermaid
sequenceDiagram
    autonumber
    participant App as App (zkFetch)
    participant Prover as Prover (Rust, native addon)
    participant Worker as Cloudflare Worker (Rust)
    participant DO as Durable Object (location hint)
    participant Notary as Notary container (Rust)
    participant Server as HTTPS server

    App->>Prover: zkFetch(url, { zkConfig })
    Prover->>Worker: wss:// /notarize
    Worker->>DO: route to the regional notary
    DO->>Notary: start the container if asleep, proxy the WebSocket
    Prover->>Notary: commit: mode, TLS version, limits

    alt MPC mode
        Note over Prover,Notary: MPC preprocessing (OT, garbled circuits)
        Prover->>Server: TLS connection (the prover dials)
        Note over Prover,Notary: Prover and notary jointly run the TLS client:<br/>keys are secret-shared, plaintext stays with the prover
    else Proxy mode
        Notary->>Server: TCP to the server name, port 443 (the notary dials)
        Prover->>Server: TLS through the notary's relay
        Note over Prover,Notary: Notary records the ciphertext. The prover proves<br/>the key schedule in ZK. For TLS 1.3 the notary checks<br/>the handshake records and Finished messages itself
    end

    Prover->>Notary: hash commitments, QuickSilver predicate proofs
    Notary-->>Prover: signed attestation (secp256k1)
    Prover-->>App: Response + res.zk (attestation and secrets)
    App->>App: res.zk.present({ reveal, prove })
    Note over App: Presentation goes to any verifier, which checks it offline:<br/>notary key, server certificate, commitments, predicates
```

## SDK

```sh
npm install @omnid/zkfetch
```

```ts
import { zkFetch, verify } from "@omnid/zkfetch";

const res = await zkFetch("https://api.example.com/me", {
  headers: { Authorization: `Bearer ${token}` }, // never revealed
  zkConfig: {
    notaryUrl: "wss://zkfetch-notary-sea.anudit.workers.dev/notarize",
    mode: "mpc",           // or "proxy": much less traffic, trusts the notary-to-server path
    tlsVersion: "auto",    // "1.3" | "1.2" | "auto"
    backend: "quicksilver",// or "binius" for offline predicates later
    predicates: [{ jsonPath: "streak.length", predicate: { gte: "365" } }],
    context: challenge,    // verifier nonce bound into the attestation
  },
});

await res.json();          // a normal Response

// Reveal one field, prove the hidden streak is at least 365 days.
const presentation = res.zk.present({
  response: { jsonPaths: ["username"] },
  prove: [{ jsonPath: "streak.length", predicate: { gte: "365" } }],
});

// Anyone, offline.
const result = verify(presentation, {
  trustedNotaryKeys: [NOTARY_PUBLIC_KEY],
  expectedContext: challenge,
});
console.log(result.serverName, result.recv);
```

| API | Purpose |
| --- | --- |
| `zkFetch(url, init)` | A notarized `fetch`. Returns `Response & { zk: ZkSession }`. |
| `res.zk.present(spec)` | Builds a presentation that discloses only what `spec` selects and proves `spec.prove`. |
| `res.zk.timings` | Per-phase latency: connect, setup, TLS, proving, attestation. |
| `res.zk.toJSON()` / `restoreResponse(data)` | Save a session and present it later. The JSON holds secrets; treat it like a credential. |
| `verify(presentation, opts)` | Offline verification against pinned notary keys, the expected context and the required predicates. |
| `startNotary()` / `startFixture()` | A local notary and HTTPS fixture for development and tests. |

## Runtimes

`import { zkFetch } from "@omnid/zkfetch"` resolves to the right prover through
conditional exports:

| Runtime | Prover | Notes |
| --- | --- | --- |
| Node.js ≥ 22 / Bun (servers) | Native Rust addon | Multi-threaded and fastest. Both modes. Prebuilt for macOS arm64 for now; other platforms fall back to the wasm prover automatically (`runtime` reports which). |
| Browsers, web workers | wasm (`browser` condition) | Single-threaded, no `SharedArrayBuffer` or cross-origin isolation needed. Run it in a worker to keep the page responsive. Call `await init()` before `present()`/`verify()`. |
| Chrome extensions (MV3) | wasm, in the service worker | Needs `"wasm-unsafe-eval"` in the extension CSP; `init(chrome.runtime.getURL("zkf_bg.wasm"))`. See [`examples/chrome-extension`](examples/chrome-extension). |

Browsers cannot open TCP sockets. Proxy mode works everywhere because the
notary dials the server. MPC mode in a browser needs `zkConfig.relayUrl`, a
WebSocket-to-TCP relay. React Native gets its own package later.

## Quickstart

Requires Bun and Rust 1.98.1 (selected by `rust-toolchain.toml`).

```sh
bun install
bun run build            # release binaries + native addon
bun run test             # Bun + Rust end-to-end tests
bun run playground       # Duolingo longest-streak demo (see .env.example)

cd infra/cloudflare && bun run deploy   # US, EU and APAC notaries
```
