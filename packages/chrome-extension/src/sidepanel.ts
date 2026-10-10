import { NOTARY } from "./defaults";
import type { BackgroundReply, BackgroundRequest, Proof, ProofVersion, ProverReply, ProverRequest, Status } from "./messages";
import { verifierNonce } from "./v2";

function element<T extends HTMLElement>(id: string): T {
  const value = document.getElementById(id);
  if (!value) throw new Error(`Missing panel element: ${id}`);
  return value as T;
}

const prove = element<HTMLButtonElement>("prove");
const verify = element<HTMLButtonElement>("verify");
const proofVersion = element<HTMLSelectElement>("proof-version");
const version = (): ProofVersion => proofVersion.value === "1" ? 1 : 2;
const target = () => proofVersion.value === "2-example" ? "top-level" as const : "duolingo" as const;
const progress = element("progress");
const error = element("error");
let status: Status = { tabOpen: false, hasToken: false };
let notaryLive = false;
let relayLive = false;
let busy = false;
let proof: Proof | undefined;
let challenge: string | undefined;
let worker: Worker | undefined;
let operation: { finish(cause?: string): void } | undefined;
let checkingServices = false;
let checkingSession = false;
// Pre-warming: the worker keeps one prepared notary session while the panel
// is visible. Each one holds a notary slot, so stop after a few unused ones.
let prepareState: "idle" | "preparing" | "ready" = "idle";
let unusedPrepares = 0;
const MAX_UNUSED_PREPARES = 2;

const duration = (ms: number) => ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${ms.toFixed(1)} ms`;

// The toolbar icon has no background, so it follows the OS theme: a dark
// mark on light themes, a white mark on dark themes.
function checkTheme() {
  const isDarkMode = window.matchMedia("(prefers-color-scheme: dark)").matches;
  void chrome.runtime.sendMessage({ type: "theme", theme: isDarkMode ? "dark" : "light" } satisfies BackgroundRequest);
}

// Check on initial load.
checkTheme();

// Listen for system theme changes in real-time.
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", checkTheme);

function indicator(id: string, text: string, state: "live" | "offline" | "checking") {
  const output = element(id);
  output.textContent = text;
  output.dataset.state = state;
}

function showError(text: string) {
  error.textContent = text;
  error.hidden = false;
}

function render() {
  maybePrepare();
  prove.disabled = busy || (target() === "duolingo" && !status.hasToken) || !notaryLive || !relayLive;
  verify.disabled = busy || !proof;
  proofVersion.disabled = busy;
  element("format-note").textContent = version() === 2
    ? target() === 'top-level' ? 'V2 proves top-level id = 1 from jsonplaceholder.typicode.com/todos/1. No login needed.' : 'V2 proves the exact streakData.longestStreak.length path and rejects duplicate keys along it.'
    : "V1 verifies your username and the full longest-streak path.";
  prove.textContent = busy && !proof ? "Generating proof…" : "Generate proof";
  prove.title = prepareState === "ready" ? "Notary session ready" : prepareState === "preparing" ? "Preparing notary session…" : "";
  indicator("tab", status.tabOpen ? "Open" : "Closed", status.tabOpen ? "live" : "checking");
  indicator("token", status.hasToken ? "Detected" : "Waiting", status.hasToken ? "live" : "checking");
  element("hint").textContent = target() === "top-level" ? "Public example: no bearer token is needed." : status.hasToken
    ? `Token detected from ${status.source === "bearer" ? "a Duolingo request" : "your Duolingo session"}. Ready to prove.`
    : "Sign in to Duolingo. Your token is detected automatically.";
}

async function request(message: BackgroundRequest): Promise<Extract<BackgroundReply, { ok: true }>> {
  const reply = await chrome.runtime.sendMessage(message) as BackgroundReply | undefined;
  if (!reply) throw new Error("The extension background is unavailable. Reload the extension.");
  if (!reply.ok) throw new Error(reply.error);
  status = reply.status;
  render();
  return reply;
}

async function refreshSession() {
  if (checkingSession) return;
  checkingSession = true;
  try {
    await request({ type: "status" });
  } catch (cause) {
    status = { tabOpen: false, hasToken: false };
    render();
    showError(cause instanceof Error ? cause.message : String(cause));
  } finally {
    checkingSession = false;
  }
}

function checkRelay(): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(NOTARY.url);
    const timeout = setTimeout(() => finish(new Error("Relay WebSocket timed out.")), 15_000);
    let settled = false;
    function finish(cause?: Error) {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      socket.onopen = socket.onerror = socket.onclose = null;
      socket.close();
      cause ? reject(cause) : resolve();
    }
    socket.onopen = () => finish();
    socket.onerror = () => finish(new Error("Relay WebSocket is unavailable."));
    socket.onclose = () => finish(new Error("Relay WebSocket closed before connecting."));
  });
}

async function refreshServices() {
  if (checkingServices || busy) return;
  checkingServices = true;
  const refresh = element<HTMLButtonElement>("refresh");
  refresh.disabled = true;
  indicator("notary", "Checking…", "checking");
  indicator("relay", "Checking…", "checking");
  const results = await Promise.allSettled([
    (async () => {
      const response = await fetch(NOTARY.health, { cache: "no-store", signal: AbortSignal.timeout(15_000) });
      if (!response.ok) throw new Error(`Notary health returned HTTP ${response.status}.`);
      const metadata = await response.json() as { publicKey?: string };
      if (metadata.publicKey !== NOTARY.publicKey) throw new Error("Notary public key does not match the pinned deployment key.");
    })(),
    checkRelay(),
  ]);
  notaryLive = results[0].status === "fulfilled";
  relayLive = results[1].status === "fulfilled";
  for (const [index, id] of ["notary", "relay"].entries()) {
    const result = results[index]!;
    indicator(id, result.status === "fulfilled" ? "Live" : "Offline", result.status === "fulfilled" ? "live" : "offline");
    element(id).title = result.status === "rejected" ? String(result.reason) : (id === "notary" ? NOTARY.health : "Proxy relay WebSocket is reachable; the Duolingo connection is tested when generating a proof.");
  }
  refresh.disabled = false;
  checkingServices = false;
  render();
}

function showProof(reply: Proof) {
  proof = reply;
  element("result").hidden = false;
  element("claim-label").textContent = proof.version === 2 ? `JSON ${proof.predicate.path?.join('.') || proof.predicate.key}` : "Longest streak";
  element("claim-unit").textContent = proof.version === 2 ? "" : "days";
  element("streak").textContent = String(proof.version === 2 ? proof.predicate.value : proof.longestStreak);
  element("username").textContent = proof.version === 2 ? proof?.version === 2 && proof.target === "top-level" ? "JSONPlaceholder · top-level id = 1" : "Duolingo · exact nested streak path" : `@${proof.username}`;
  element("elapsed").textContent = duration(proof.elapsedMs);
  element("verify-time").textContent = "—";
  // Export the verifier challenge and claim with v2, not just an opaque proof.
  element("presentation-label").textContent = proof.version === 2 ? "Presentation + claim + challenge · JSON" : "Presentation · base64";
  element<HTMLTextAreaElement>("proof").value = proof.version === 2
    ? JSON.stringify({ version: 2, target: proof.target, presentation: proof.presentation, predicate: proof.predicate, nonce: proof.nonce })
    : proof.presentation;
  const ahead = proof.timings.prewarmed ? " (ahead)" : "";
  const pool = proof.timings.voleResumed ? "warm VOLE pool" : "fresh OT";
  const phases = [
    [`Notary connect${ahead}`, proof.timings.notaryConnectMs],
    [`Setup${ahead}`, proof.timings.setupMs],
    ["TLS request", proof.timings.tlsMs],
    ["Commitment proofs", proof.timings.proveMs],
    ["Attestation", proof.timings.attestMs],
    ["Notarize total", proof.timings.totalMs],
    ["Presentation", proof.presentMs],
  ] as const;
  const threads = proof.threads ? `${proof.threads} threads` : "1 thread";
  const engine = proof.version === 2 ? "v2 · QuickSilver session · VOLEitH presentation" : "v1 · QuickSilver";
  element("timings").textContent = `TLS ${proof.tlsVersion ?? "auto"} · ${engine} · proxy · ${threads} · ${pool}\n\n${phases.map(([label, ms]) => `${label.padEnd(19)}${duration(ms)}`).join("\n")}`;
  indicator("verification", "Unverified", "checking");
}

function onReply(event: MessageEvent<ProverReply>) {
  const reply = event.data;
  switch (reply.type) {
    case "loaded":
      maybePrepare();
      break;
    case "prepared":
      if (reply.version !== version() || reply.target !== target()) break;
      prepareState = reply.ok ? "ready" : "idle";
      render();
      break;
    case "prepared-expired":
      prepareState = "idle";
      unusedPrepares++;
      maybePrepare();
      render();
      break;
    case "progress":
      progress.textContent = reply.text;
      break;
    case "error":
      operation?.finish(reply.error);
      break;
    case "proof":
      if (reply.proof.version !== version() || (reply.proof.version === 2 && (reply.proof.nonce !== challenge || reply.proof.target !== target()))) {
        operation?.finish("The proof does not match the requested format or verifier challenge.");
        break;
      }
      showProof(reply.proof);
      operation?.finish();
      break;
    case "verified":
      if (reply.version === 2) {
        element("streak").textContent = String(reply.verified.predicate.value);
        element("username").textContent = proof?.version === 2 && proof.target === "top-level" ? "JSONPlaceholder · top-level id = 1" : "Duolingo · exact nested streak path";
        element("transcript").textContent = `${reply.verified.serverName}\nAttestation v2 · proxy\n${new Date(reply.verified.time * 1000).toISOString()}\nTrusted notary: ${reply.verified.notaryKey.key}\nProven JSON member: ${reply.verified.predicate.path?.join(".") || reply.verified.predicate.key} ${reply.verified.predicate.op} ${reply.verified.predicate.value}\n\n${reply.verified.responseHeaders}`;
      } else {
      element("streak").textContent = String(reply.longestStreak);
      element("username").textContent = `@${reply.username}`;
      element("transcript").textContent = `${reply.verified.serverName}\nTLS ${reply.verified.tlsVersion}\n${new Date(reply.verified.time * 1000).toISOString()}\nTrusted notary: ${reply.verified.notaryKey.key}\n\n${reply.verified.sent}\n${reply.verified.recv}`;
      }
      element("verify-time").textContent = duration(reply.elapsedMs);
      element("verified-details").hidden = false;
      indicator("verification", "Verified", "live");
      operation?.finish();
      break;
  }
}

/** The panel's prover worker, created once and reused. */
function proverWorker(): Worker {
  if (worker) return worker;
  worker = new Worker(new URL("prover.js", import.meta.url), { type: "module" });
  const activeWorker = worker;
  worker.onmessage = event => { if (worker === activeWorker) onReply(event); };
  worker.onerror = event => {
    if (worker !== activeWorker) return;
    event.preventDefault();
    resetWorker();
    operation?.finish("The prover worker failed. Rebuild the extension and reload it.");
  };
  const message: ProverRequest = {
    type: "init",
    wasmUrl: new URL("zkf_bg.wasm", import.meta.url).href,
    // The panel is cross-origin isolated (manifest), so threads are available.
    threadsUrl: new URL("wasm-threads/zkf.js", import.meta.url).href,
  };
  worker.postMessage(message);
  return worker;
}

function resetWorker() {
  const previous = worker;
  previous?.postMessage({ type: "dispose" } satisfies ProverRequest);
  if (previous) setTimeout(() => previous.terminate(), 0);
  worker = undefined;
  prepareState = "idle";
}

/** Starts a prepared session if one is useful now. */
function maybePrepare() {
  if (prepareState !== "idle" || busy || (target() === "duolingo" && !status.hasToken) || !notaryLive) return;
  if (document.visibilityState !== "visible" || unusedPrepares >= MAX_UNUSED_PREPARES) return;
  prepareState = "preparing";
  proverWorker().postMessage({ type: "prepare", version: version(), target: target() } satisfies ProverRequest);
}

function startOperation(message: ProverRequest) {
  busy = true;
  error.hidden = true;
  render();
  // The notary limits sessions to 120 seconds, with possible TLS fallback.
  const timeout = setTimeout(() => {
    resetWorker();
    finish("Proof operation timed out. Refresh status and try again.");
  }, 300_000);

  function finish(cause?: string) {
    clearTimeout(timeout);
    operation = undefined;
    busy = false;
    progress.textContent = "";
    if (cause) {
      showError(cause);
      if (message.type === "verify") indicator("verification", "Failed", "offline");
    }
    render();
  }

  operation = { finish };
  if ((message.type === "prove" || message.type === "prove-example")) {
    // The worker hands its prepared session (if any) to this request.
    prepareState = "idle";
    unusedPrepares = 0;
  }
  proverWorker().postMessage(message);
}

prove.addEventListener("click", async () => {
  if (busy) return;
  busy = true;
  error.hidden = true;
  render();
  try {
    const auth = target() === "duolingo" ? (await request({ type: "auth" })).auth : undefined;
    if (target() === "duolingo" && !auth) throw new Error("No bearer token detected. Open Duolingo and sign in.");
    proof = undefined;
    element("result").hidden = true;
    element("verified-details").hidden = true;
    element<HTMLTextAreaElement>("proof").value = "";
    element("transcript").textContent = "";
    if (version() === 2) {
      challenge = verifierNonce();
      startOperation(target() === "top-level"
        ? { type: "prove-example", version: 2, nonce: challenge }
        : { type: "prove", auth: auth!, version: 2, nonce: challenge });
    } else {
      challenge = undefined;
      startOperation({ type: "prove", auth: auth!, version: 1 });
    }
  } catch (cause) {
    busy = false;
    render();
    showError(cause instanceof Error ? cause.message : String(cause));
  }
});

verify.addEventListener("click", () => {
  if (!proof || busy) return;
  if (proof.version === 2 && (!challenge || proof.nonce !== challenge)) {
    showError("The verifier challenge is unavailable. Generate a new proof.");
    return;
  }
  element("verified-details").hidden = true;
  indicator("verification", "Verifying…", "checking");
  startOperation(proof.version === 2
    ? { type: "verify", version: 2, target: proof.target, presentation: proof.presentation, predicate: proof.predicate, nonce: proof.nonce }
    : { type: "verify", version: 1, presentation: proof.presentation });
});

proofVersion.addEventListener("change", () => {
  proof = undefined;
  challenge = undefined;
  element("result").hidden = true;
  element("verified-details").hidden = true;
  error.hidden = true;
  unusedPrepares = 0;
  resetWorker();
  render();
});

element("open").addEventListener("click", () => {
  request({ type: "open-duolingo", focus: true }).catch(cause => showError(String(cause)));
});
element("refresh").addEventListener("click", () => {
  error.hidden = true;
  void Promise.allSettled([refreshSession(), refreshServices()]);
});

// Opening the panel ensures Duolingo exists, without refocusing an existing tab.
request({ type: "open-duolingo" }).catch(cause => showError(String(cause)));
// Load the prover now so compiling the wasm is not part of the first proof.
proverWorker();
void refreshServices();
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") {
    unusedPrepares = 0;
    maybePrepare();
  }
});
const sessionInterval = setInterval(() => void refreshSession(), 2000);
const healthInterval = setInterval(() => void refreshServices(), 30_000);
window.addEventListener("pagehide", () => {
  clearInterval(sessionInterval);
  clearInterval(healthInterval);
  // Close the prepared notary session promptly rather than at its timeout.
  worker?.postMessage({ type: "dispose" } satisfies ProverRequest);
  setTimeout(resetWorker, 0);
});
