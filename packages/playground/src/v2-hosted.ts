// Hosted check for experimental v2 (D1) attestations through the deployed
// notary: zkFetch -> presentV2 -> verifyV2, plus nonce and claim rejection.
//
//   bun packages/playground/src/v2-hosted.ts [url] [member] [minimum]
//
// Reads infra/aws/deployment.json and the git-ignored capability token in
// .zkf/notary-capability.token (or ZKF_NOTARY_CAPABILITY). Never prints it.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { newNonce, verifyV2, zkFetch } from "@omnid/zkfetch";

const root = join(import.meta.dir, "..", "..", "..");
const deployment = JSON.parse(readFileSync(join(root, "infra/aws/deployment.json"), "utf8"));
const token = (process.env.ZKF_NOTARY_CAPABILITY ?? readFileSync(join(root, ".zkf/notary-capability.token"), "utf8")).trim();
if (!/^[0-9a-f]{64}$/.test(token)) throw new Error("capability token must be 64 hex characters");

const url = process.argv[2] ?? "https://jsonplaceholder.typicode.com/todos/1";
const key = process.argv[3] ?? "userId";
const minimum = process.argv[4] ?? "1";
const notaryUrl = `${deployment.url}?capability=${token}`;

for (const round of ["cold", "warm"]) {
  const res = await zkFetch(url, {
    zkConfig: {
      notaryUrl,
      expectedNotaryKey: deployment.publicKey,
      mode: "proxy",
      tlsVersion: "1.3",
      attestationV2: true,
      context: "v2-hosted",
    },
  });
  const t = res.zk.timings;
  console.log(
    `${round}: status ${res.status}, v${res.zk.attestationVersion}, connect ${t.notaryConnectMs.toFixed(0)} ms, ` +
      `setup ${t.setupMs.toFixed(0)} ms, tls ${t.tlsMs.toFixed(0)} ms, prove ${t.proveMs.toFixed(0)} ms, ` +
      `attest ${t.attestMs.toFixed(0)} ms, total ${t.totalMs.toFixed(0)} ms, resumed ${t.voleResumed}`,
  );

  const nonce = newNonce();
  const predicate = { key, op: "ge", value: minimum } as const;
  let started = performance.now();
  const presentation = await res.zk.presentV2({ predicate, nonce });
  const proveMs = performance.now() - started;
  const opts = {
    trustedNotaryKeys: [deployment.publicKey],
    expectedServerName: new URL(url).hostname,
    predicate,
    nonce,
    expectedContext: "v2-hosted",
    maxAgeSecs: 600,
  };
  started = performance.now();
  const out = await verifyV2(presentation, opts);
  const verifyMs = performance.now() - started;
  console.log(
    `  presentV2 ${proveMs.toFixed(0)} ms, ${(presentation.length * 0.75 / 1024).toFixed(0)} KiB; ` +
      `verifyV2 ${verifyMs.toFixed(0)} ms: ${out.serverName} ${key} ${predicate.op} ${minimum} ✓`,
  );
  const rejected = await Promise.allSettled([
    verifyV2(presentation, { ...opts, nonce: newNonce() }),
    verifyV2(presentation, { ...opts, expectedServerName: "example.com" }),
  ]);
  if (rejected.some(r => r.status === "fulfilled")) throw new Error("a mutated policy verified");
  console.log("  other nonce and other server rejected ✓");
}
