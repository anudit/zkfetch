// Runs the browser build (wasm prover, no DOM) end to end under Bun:
// proxy mode against a local notary that dials the HTTPS fixture.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { init, verify, zkFetch } from "../src/browser";
import { startFixture, startNotary } from "../src/dev";

const fixture = await startFixture({ tlsVersion: process.argv[2] === "1.2" ? "1.2" : "1.3" });
const notary = await startNotary({ proxyResolve: { [fixture.serverName]: fixture.addr } });
try {
  await init(readFileSync(join(import.meta.dir, "../../wasm/pkg/zkf_bg.wasm")));
  const t = performance.now();
  const res = await zkFetch(`https://${fixture.serverName}/formats/json`, {
    headers: { Authorization: "Bearer browser-secret" },
    zkConfig: { notaryUrl: notary.url, mode: "proxy", tlsVersion: (process.argv[2] ?? "1.3") as "1.3", extraRootCerts: [fixture.caCert] },
  });
  const body = await res.json();
  const presentation = res.zk.present({ response: { jsonPaths: ["information.name"] } });
  const v = verify(presentation, { trustedNotaryKeys: [notary.publicKey], extraRootCerts: [fixture.caCert] });
  console.log(JSON.stringify({ ok: true, seconds: ((performance.now() - t) / 1000).toFixed(2), tls: v.tlsVersion, id: body.id, hidden: !v.sent.includes("browser-secret"), revealed: v.recv.includes('"name":"John Doe"') }));
} finally {
  notary.proc.kill();
  fixture.proc.kill();
}
