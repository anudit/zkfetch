import { init, prepare, threads, verify, verifyV2, zkFetch, type ZkPrepared } from "@omnid/zkfetch";
import { tokenUserId } from "./auth";
import { claimsFromFields, readClaims } from "./claims";
import { API, DEFAULT_USERNAME, DISCLOSURES, NOTARY } from "./defaults";
import type { ProofVersion, ProverReply, ProverRequest } from "./messages";
import { streakMember, v2VerificationPolicy } from "./v2";

const send = (message: ProverReply) => self.postMessage(message);
// Proxy mode binds a prepared session to the notary and host only, so it can
// be set up before the user ID and token are known.
const ZK_CONFIG = { notaryUrl: NOTARY.url, expectedNotaryKey: NOTARY.publicKey, mode: "proxy", tlsVersion: "1.3", protocolV2: true, persistentVole: true } as const;
const config = (version: ProofVersion) => ({ ...ZK_CONFIG, attestationV2: version === 2 });
const DISCLOSURE = { response: { jsonPaths: DISCLOSURES } };

let loading: Promise<void> | undefined;
let prepared: ZkPrepared | undefined;
let preparedVersion: ProofVersion | undefined;
let expiry: ReturnType<typeof setTimeout> | undefined;

function load(message: Extract<ProverRequest, { type: "init" }>) {
  // Threads need the cross-origin isolated panel; otherwise one thread.
  loading ??= init(message.wasmUrl, message.threadsUrl ? { threads: { module: message.threadsUrl } } : {})
    .then(() => send({ type: "loaded", threads: threads() }));
  return loading;
}

function discard() {
  clearTimeout(expiry);
  prepared?.dispose();
  prepared = undefined;
  preparedVersion = undefined;
}

async function startPrepare(version: ProofVersion) {
  await loading;
  if (prepared?.usable && preparedVersion === version) return;
  discard();
  const started = performance.now();
  const session = prepare(`${API}/users`, config(version));
  prepared = session;
  preparedVersion = version;
  expiry = setTimeout(() => {
    if (prepared !== session) return;
    discard();
    send({ type: "prepared-expired" });
  }, session.expiresAt - Date.now());
  const ok = await session.ready();
  if (prepared === session) send({ type: "prepared", version, ok, setupMs: performance.now() - started });
}

async function prove(message: Extract<ProverRequest, { type: "prove" }>) {
  const started = performance.now();
  send({ type: "progress", text: "Loading prover…" });
  await loading;
  const { token } = message.auth;
  send({ type: "progress", text: "Finding your Duolingo account…" });
  // JWT claims are used only to route the request. Displayed verified values
  // always come from the cryptographically verified response transcript.
  let userId = tokenUserId(token) ?? message.auth.userId;
  if (!userId) {
    const response = await fetch(`${API}/users?username=${DEFAULT_USERNAME}&fields=users%7Bid%7D`, {
      signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok) throw new Error(`Duolingo account lookup failed (HTTP ${response.status}).`);
    const data = await response.json() as { users?: { id: number }[] };
    userId = data.users?.[0]?.id?.toString();
  }
  if (!userId || !/^\d+$/.test(userId)) throw new Error("Could not find a Duolingo user ID. Open Duolingo and sign in again.");
  const v2 = message.version === 2;
  if (v2) streakMember(""); // Reject unsupported nested-path claims before notarization.
  send({ type: "progress", text: v2 ? "Notarizing encrypted Duolingo response…" : "Notarizing username and longest streak…" });
  // Hand over the prepared session (still preparing is fine: it is further
  // along than a new one). The SDK falls back to a fresh session if needed.
  if (preparedVersion !== message.version) discard();
  const session = prepared;
  prepared = undefined;
  preparedVersion = undefined;
  clearTimeout(expiry);
  const fields = v2 ? "streakData%7BlongestStreak%7Blength%7D%7D" : "username,streakData%7BlongestStreak%7D";
  const response = await zkFetch(`${API}/users/${userId}?fields=${fields}`, {
    headers: { Authorization: `Bearer ${token}` },
    zkConfig: { ...config(message.version), prepared: session, ...(v2 ? {} : { reveal: DISCLOSURE }) },
  });
  if (!response.ok) throw new Error(`Duolingo returned HTTP ${response.status}. Sign in again and retry.`);
  const body = await response.text();
  send({ type: "progress", text: v2 ? "Proving the numeric claim offline…" : "Building the proof…" });
  const presentStarted = performance.now();
  if (message.version === 2) {
    if (response.zk.attestationVersion !== 2) throw new Error("The notary did not return a v2 attestation.");
    const predicate = streakMember(body);
    v2VerificationPolicy(predicate, message.nonce, NOTARY.publicKey);
    // Keep the cookie-disclosure guard enabled. No downgrade to v1 on failure.
    const presentation = await response.zk.presentV2({ predicate, nonce: message.nonce });
    send({ type: "proof", proof: {
      version: 2, presentation, predicate, nonce: message.nonce,
      elapsedMs: performance.now() - started, presentMs: performance.now() - presentStarted,
      timings: response.zk.timings, tlsVersion: response.zk.tlsVersion, threads: threads(),
    } });
    return;
  }
  const claims = readClaims(body);
  const presentation = response.zk.present(DISCLOSURE);
  send({
    type: "proof",
    proof: {
      version: 1, presentation, ...claims, elapsedMs: performance.now() - started,
      presentMs: performance.now() - presentStarted,
      timings: response.zk.timings, tlsVersion: response.zk.tlsVersion, threads: threads(),
    },
  });
}

async function verifyProof(message: Extract<ProverRequest, { type: "verify" }>) {
  send({ type: "progress", text: "Loading prover…" });
  await loading;
  send({ type: "progress", text: "Verifying proof locally…" });
  const started = performance.now();
  if (message.version === 2) {
    const verified = await verifyV2(message.presentation, v2VerificationPolicy(message.predicate, message.nonce, NOTARY.publicKey));
    if (!/^HTTP\/1\.[01] 200\b/.test(verified.responseHeaders)) throw new Error("The proof does not contain a successful Duolingo response.");
    send({ type: "verified", version: 2, verified, elapsedMs: performance.now() - started });
    return;
  }
  const verified = verify(message.presentation, { trustedNotaryKeys: [NOTARY.publicKey] });
  if (!verified.notaryTrusted || verified.serverName !== "www.duolingo.com") {
    throw new Error("Proof does not match the trusted notary and Duolingo server.");
  }
  if (!/^HTTP\/1\.[01] 200\b/.test(verified.recv)) throw new Error("The proof does not contain a successful Duolingo response.");
  send({ type: "verified", version: 1, verified, elapsedMs: performance.now() - started, ...claimsFromFields(verified.json) });
}

self.onmessage = (event: MessageEvent<ProverRequest>) => {
  const message = event.data;
  // Errors from the prover can include HTTP details; never forward a token.
  const token = message.type === "prove" ? message.auth.token : undefined;
  const fail = (error: unknown) => {
    let text = error instanceof Error ? error.message : String(error);
    if (token) text = text.split(token).join("[redacted]");
    send({ type: "error", error: text });
  };
  switch (message.type) {
    case "init": load(message).catch(fail); break;
    case "prepare": startPrepare(message.version).catch(() => send({ type: "prepared", version: message.version, ok: false })); break;
    case "dispose": discard(); break;
    case "prove": prove(message).catch(fail); break;
    case "verify": verifyProof(message).catch(fail); break;
  }
};
