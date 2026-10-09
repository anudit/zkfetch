// Playground: prove your Duolingo username + longest streak with zkfetch and
// run three times each with QuickSilver and Binius, averaging each phase.
//
//   bun run playground            (from the repo root; reads ./.env)
//
// Env (see .env.example):
//   DUOLINGO_JWT        private auth token (the `jwt_token` cookie). With it, the
//                       private /users/<id> endpoint is proven (401 without auth)
//                       and the token stays hidden in the presentation.
//                       Without it, the public username lookup is proven instead.
//   DUOLINGO_USERNAME   default `anudit`
//   DUOLINGO_USER_ID    optional; resolved from the username if unset
//   ZKF_NOTARY_URL      optional; a local notary is started if unset
//   ZKF_TLS_VERSION     auto (default), 1.2 or 1.3
//   ZKF_STREAK_MINIMUM  optional; prove longestStreak >= N without revealing it
//   ZKF_MODE            mpc (default) or proxy
//   ZKF_REVEAL          1 (default): commit only what the presentation discloses
//                       (zkConfig.reveal); 0: commit every header and JSON node
import { startNotary, verify, zkFetch, type NotarizeMode, type NotarizeTimings, type PredicateSpec, type TlsVersionPreference, type VerifyOutput } from "@omnid/zkfetch";
import { writeFileSync } from "node:fs";

const API = "https://www.duolingo.com/2017-06-30";
const username = process.env.DUOLINGO_USERNAME ?? "anudit";
const jwt = process.env.DUOLINGO_JWT?.trim() || undefined;
const tlsVersion = (process.env.ZKF_TLS_VERSION ?? "auto") as TlsVersionPreference;
if (!["1.2", "1.3", "auto"].includes(tlsVersion)) throw new Error("ZKF_TLS_VERSION must be 1.2, 1.3 or auto");
const tlsVersions: TlsVersionPreference[] = process.env.PLAYGROUND_TLS_MATRIX === "1" ? ["1.3", "1.2"] : [tlsVersion];
const mode = (process.env.ZKF_MODE?.trim() || "mpc") as NotarizeMode;
if (!["mpc", "proxy"].includes(mode)) throw new Error("ZKF_MODE must be mpc or proxy");
const declareReveal = process.env.ZKF_REVEAL !== "0";
const minimum = process.env.ZKF_STREAK_MINIMUM?.trim() || undefined;
if (minimum && !/^\d+$/.test(minimum)) throw new Error("ZKF_STREAK_MINIMUM must be an unsigned decimal integer");
if (minimum && !jwt) throw new Error("ZKF_STREAK_MINIMUM requires DUOLINGO_JWT to access longest streak");
const predicates: PredicateSpec[] = minimum
  ? [{ jsonPath: "streakData.longestStreak.length", predicate: { gte: minimum } }]
  : [];
// QuickSilver proves predicates to the notary during fetch; Binius proves them
// locally during presentation. Each backend needs its own notarized request.
const backends = ["quicksilver", "binius"] as const;
const runs = 3;
type Backend = (typeof backends)[number];
const backendNames: Record<Backend, string> = { quicksilver: "QuickSilver", binius: "Binius" };

async function resolveUserId(): Promise<string> {
  if (process.env.DUOLINGO_USER_ID) return process.env.DUOLINGO_USER_ID;
  const res = await fetch(`${API}/users?username=${encodeURIComponent(username)}&fields=users%7Bid%7D`);
  const id = ((await res.json()) as { users?: { id: number }[] }).users?.[0]?.id;
  if (!id) throw new Error(`could not resolve Duolingo user id for ${username}`);
  return String(id);
}

const fields = "username,streakData%7BlongestStreak%7D";
const target = jwt
  ? {
      mode: "private (authenticated /users/<id>)",
      url: `${API}/users/${await resolveUserId()}?fields=${fields}`,
      headers: { Authorization: `Bearer ${jwt}` } as Record<string, string>,
      reveal: minimum ? ["username"] : ["username", "streakData.longestStreak"],
    }
  : {
      mode: "public (no DUOLINGO_JWT: username only; Duolingo hides streakData without auth)",
      url: `${API}/users?username=${encodeURIComponent(username)}&fields=users%7B${fields}%7D`,
      headers: {} as Record<string, string>,
      reveal: ["users.0.username", "users.0.streakData"],
    };

const notary = process.env.ZKF_NOTARY_URL
  ? { url: process.env.ZKF_NOTARY_URL, publicKey: process.env.ZKF_NOTARY_PUBLIC_KEY || undefined, proc: undefined }
  : await startNotary();

console.log(`zkfetch playground — Duolingo longest streak`);
console.log(`mode     ${target.mode}`);
console.log(`TLS preferences ${tlsVersions.join(", ")}`);
if (minimum) console.log(`claim    longest streak >= ${minimum} days (value hidden)`);
else console.log(`claim    selective disclosure only; set ZKF_STREAK_MINIMUM with DUOLINGO_JWT to compare predicate proofs`);
console.log(`notary   ${notary.url.split("?")[0]}${notary.proc ? " (local)" : ""} · ${mode} mode`);
console.log(`commit   ${declareReveal ? "declared disclosure only (zkConfig.reveal)" : "every header and JSON node (ZKF_REVEAL=0)"}`);
console.log(`runs     ${runs} QuickSilver + ${runs} Binius (arithmetic averages)\n`);
// Give native sampling tools time to attach before the measured workload.
if (process.env.PLAYGROUND_PROFILE_DELAY_MS) await Bun.sleep(Number(process.env.PLAYGROUND_PROFILE_DELAY_MS));

type Row = NotarizeTimings & {
  tlsVersion: string;
  baselineMs: number;
  presentMs: number;
  verifyMs: number;
  e2eMs: number;
  attestationBytes: number;
  presentationBytes: number;
};

type RunResult = { row: Row; verified: VerifyOutput; user: string; streak?: number };

function average(values: number[]) {
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function displayTlsVersion(version: string) {
  return version === "V1_3" ? "1.3" : version === "V1_2" ? "1.2" : version;
}

function fmt(ms: number) {
  return ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${ms.toFixed(1)} ms`;
}

function report(backend: Backend, results: RunResult[], tlsVersion: TlsVersionPreference) {
  const rows = results.map(result => result.row);
  const { verified: v, user, streak } = results[results.length - 1]!;
  const negotiatedVersion = displayTlsVersion(v.tlsVersion);
  const versions = [...new Set(rows.map(row => displayTlsVersion(row.tlsVersion)))];
  console.log(`\n=== ${backendNames[backend]} breakdown (${results.length} verified runs) ===`);
  console.log(`TLS      ${rows.map((row, i) => `run ${i + 1}: ${displayTlsVersion(row.tlsVersion)}`).join(" · ")} (verified; requested ${tlsVersion})`);
  // These algorithms are fixed by the vendored MPC backends, rather than
  // negotiated metadata exposed by the SDK. TLS 1.2 allows RSA or ECDSA auth;
  // its exact suite is not exported, so do not guess it from the TLS version.
  if (versions.every(version => version === "1.2" || version === "1.3")) {
    console.log(`cipher   AES-128-GCM (128-bit key, 128-bit authentication tag; MPC backend)`);
    console.log(`hash     SHA-256`);
    console.log(`exchange ECDHE · secp256r1 (P-256)`);
    for (const version of versions) {
      console.log(version === "1.3"
        ? `suite    TLS 1.3: TLS_AES_128_GCM_SHA256 (0x1301; enforced by TLS 1.3 backend)`
        : `suite    exact TLS 1.2 suite not exposed by SDK (RSA or ECDSA authentication)`);
    }
  }
  const phases: [string, Exclude<keyof NotarizeTimings, "prewarmed"> | "presentMs" | "verifyMs" | "e2eMs" | "baselineMs"][] = [
    ["notary connect (WebSocket)", "notaryConnectMs"],
    ["MPC setup + preprocessing", "setupMs"],
    ["MPC-TLS session (handshake, req/resp)", "tlsMs"],
    [backend === "quicksilver" && minimum ? "commitment + QuickSilver predicate proofs" : "commitment proofs (ZK to notary)", "proveMs"],
    ["attestation (sign + validate)", "attestMs"],
    ["= notarize total", "totalMs"],
    [backend === "binius" && minimum ? "present (disclosure + Binius proofs)" : "present (selective disclosure)", "presentMs"],
    ["verify (offline)", "verifyMs"],
    ["= END-TO-END", "e2eMs"],
    ["plain fetch baseline (no proof)", "baselineMs"],
  ];
  console.log(`\n${"phase".padEnd(44)}${rows.map((_, i) => `run ${i + 1}`.padStart(12)).join("")}${"average".padStart(12)}`);
  for (const [label, key] of phases) {
    const values = rows.map(row => row[key]);
    console.log(`${label.padEnd(44)}${values.map(value => fmt(value).padStart(12)).join("")}${fmt(average(values)).padStart(12)}`);
  }
  for (const [label, key] of [["attestation size", "attestationBytes"], ["presentation size", "presentationBytes"]] as const) {
    const values = rows.map(row => row[key]);
    console.log(`${label.padEnd(44)}${values.map(value => `${value} B`.padStart(12)).join("")}${`${average(values).toFixed(1)} B`.padStart(12)}`);
  }
  console.log(`\noverhead vs plain fetch (average e2e / average baseline): ${(average(rows.map(row => row.e2eMs)) / average(rows.map(row => row.baselineMs))).toFixed(1)}×`);
  console.log(
    minimum
      ? `\n✔ verified: ${v.serverName} says user "${user}" has a longest streak >= ${minimum} days (value hidden)`
      : streak === undefined
      ? `\n✔ verified: ${v.serverName} says user "${user}" exists (longest streak needs DUOLINGO_JWT)`
      : `\n✔ verified: ${v.serverName} says user "${user}" has a longest streak of ${streak} days`,
  );
  console.log(`  TLS ${negotiatedVersion}, ${new Date(v.time * 1000).toISOString()}, notary ${v.notaryKey.key.slice(0, 16)}…${v.notaryTrusted ? " (trusted)" : ""}`);
  console.log(`\n--- what the verifier sees (run ${results.length}; X = undisclosed) ---`);
  console.log(v.sent.trimEnd());
  console.log("");
  // Response headers are long and fully redacted except framing; show status line + body.
  const [head, body] = v.recv.split("\r\n\r\n");
  console.log(head!.split("\r\n")[0]);
  console.log("…");
  console.log(body);
}

async function run(backend: Backend, tlsVersion: TlsVersionPreference): Promise<RunResult> {
  // Baseline: the same request with plain fetch (no proof), on a fresh
  // connection so it pays for its own TLS handshake like zkFetch does.
  let t = performance.now();
  const plain = await fetch(target.url, { headers: { ...target.headers, Connection: "close" }, keepalive: false });
  await plain.arrayBuffer();
  const baselineMs = performance.now() - t;
  if (!plain.ok) throw new Error(`plain fetch failed: HTTP ${plain.status}`);

  const disclosure = { response: { jsonPaths: target.reveal }, prove: predicates };
  const e2eStart = performance.now();
  const res = await zkFetch(target.url, {
    headers: target.headers,
    zkConfig: {
      notaryUrl: notary.url,
      expectedNotaryKey: notary.publicKey,
      predicates,
      backend,
      tlsVersion,
      mode,
      reveal: declareReveal ? disclosure : undefined,
    },
  });
  if (!res.ok) throw new Error(`zkFetch: HTTP ${res.status} ${await res.text()}`);

  t = performance.now();
  const presentation = res.zk.present(disclosure);
  const presentMs = performance.now() - t;

  t = performance.now();
  const verified = verify(presentation, {
    trustedNotaryKeys: notary.publicKey ? [notary.publicKey] : [],
    expectedPredicates: predicates,
  });
  const verifyMs = performance.now() - t;
  const e2eMs = performance.now() - e2eStart;

  if (jwt && (verified.sent.includes(jwt) || verified.recv.includes(jwt))) {
    throw new Error("BUG: auth token visible in presentation");
  }

  // Read the values from the *verified* transcript, not the raw response.
  const user = /"username":\s*"([^"]*)"/.exec(verified.recv)?.[1];
  const streakMatch = /"longestStreak":\s*\{[^}]*"length":\s*(\d+)/.exec(verified.recv)?.[1];
  const streak = streakMatch === undefined ? undefined : Number(streakMatch);
  if (!user) throw new Error("username not found in verified transcript");
  if (jwt && !minimum && streak === undefined) throw new Error("longest streak not found in verified transcript");
  const row: Row = {
    ...res.zk.timings,
    tlsVersion: verified.tlsVersion,
    baselineMs,
    presentMs,
    verifyMs,
    e2eMs,
    attestationBytes: Buffer.from(res.zk.attestation, "base64").length,
    presentationBytes: Buffer.from(presentation, "base64").length,
  };
  return { row, verified, user, streak };
}

try {
  const measurements: { backend: Backend; tlsVersion: TlsVersionPreference; runs: Row[] }[] = [];
  for (const version of tlsVersions) {
    console.log(`\n=== TLS ${version}: ${runs} runs each, alternating QuickSilver and Binius ===`);
    const results: Record<Backend, RunResult[]> = { quicksilver: [], binius: [] };
    for (let i = 0; i < runs; i++) {
      for (const backend of backends) {
        const result = await run(backend, version);
        results[backend].push(result);
        console.log(`${backendNames[backend]} run ${i + 1}/${runs}: e2e ${fmt(result.row.e2eMs)} · plain fetch ${fmt(result.row.baselineMs)} · TLS ${displayTlsVersion(result.verified.tlsVersion)} · verified`);
      }
    }
    for (const backend of backends) {
      report(backend, results[backend], version);
      measurements.push({ backend, tlsVersion: version, runs: results[backend].map(result => result.row) });
    }
  }
  if (process.env.PLAYGROUND_RESULTS) {
    writeFileSync(process.env.PLAYGROUND_RESULTS, JSON.stringify({
      measuredAt: new Date().toISOString(), notaryUrl: notary.url.split("?")[0],
      notaryPublicKey: notary.publicKey, predicates, measurements,
    }, null, 2) + "\n");
    console.log(`\nmeasurements saved to ${process.env.PLAYGROUND_RESULTS}`);
  }
} finally {
  notary.proc?.kill();
}
