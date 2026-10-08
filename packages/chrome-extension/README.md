# Duolingo side panel

A minimal Chrome MV3 extension that detects your Duolingo bearer token, proves
your username and longest streak with zkfetch, and verifies the presentation
locally with a separate **Verify proof** button.

From the repository root:

```sh
bun install
bun run --cwd packages/chrome-extension build
```

If the WASM SDK has not been built yet, run
`bun run --cwd packages/wasm build` first (requires Rust and wasm-pack). For
the multi-threaded prover also run `bun run --cwd packages/wasm build:threads`
(nightly Rust with `rust-src`); without it the extension uses one thread.

Speed: the manifest makes the panel cross-origin isolated, so the prover
worker runs the threaded build (up to 8 threads). When the panel opens the
worker loads the prover and, once a token is detected, prepares a notary
session (connection and setup) in the background. **Generate proof** then only
waits for the TLS request, proofs and attestation; the timings mark setup as
"(ahead)". A prepared session expires after 80 s and is replaced at most twice
without use, and closing the panel closes it, because each holds a notary
session slot.

1. Open `chrome://extensions`, enable **Developer mode**, choose **Load unpacked**,
   and select `packages/chrome-extension/dist`. After building, loading
   `packages/chrome-extension` also works; its manifest points into `dist/`.
2. Click the extension's toolbar action to open the side panel. It opens Duolingo
   if there is no existing Duolingo tab. Sign in normally.
3. When the notary and relay are live and the token is detected, click
   **Generate proof**. The panel shows the streak, proof presentation, total
   generation time, and individual SDK timings. Values remain **Unverified**.
4. Click **Verify proof** to check the presentation against the pinned notary key
   and Duolingo server. The verified transcript and verification time appear.

After changing source files, run the build again and click **Reload** on the
extension in `chrome://extensions`. A missing background script can cause
`Service worker registration failed. Status code: 3`; the source folder and
the standalone `dist` folder both resolve their built background script now.

Defaults: the Mumbai (ap-south-1) EC2 notary in `infra/aws/deployment.json`
(see [`infra/aws`](../../infra/aws)), proxy transport, automatic TLS selection,
and the SDK's QuickSilver backend. The build writes that notary's host into
the dist manifest's host permissions and CSP, so after `infra/aws/up.sh`
replaces the instance, rebuild and reload the extension. In proxy mode the notary also provides the
relay. **Notary** checks `/health` and the pinned public key; **Relay** checks
WebSocket connectivity. Reaching Duolingo through that relay is tested by the
actual proof request. There is no separate relay server to configure.

The `jwt_token` cookie (including HttpOnly cookies) is read automatically.
Bearer headers on Duolingo tab requests are also observed. The user ID comes
from the token's `sub` claim or the observed API request; if neither is present,
the playground's default username, `anudit`, is used for ID lookup. No token
input or configuration form is needed.

Tokens stay in Chrome's in-memory session storage, clear on browser restart or
logout, and are never rendered in the panel. The presentation discloses only
the username and longest streak, hiding the Authorization value. Proof work
runs in a dedicated worker while the panel stays open; closing the panel stops
the operation. Generation time includes account lookup, notarization, and
presentation, excluding WASM initialization. Verification runs offline.

```sh
bun run --cwd packages/chrome-extension typecheck
bun run --cwd packages/chrome-extension test
```
