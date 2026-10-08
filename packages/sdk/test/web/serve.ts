// Serves a test page that runs the browser SDK in a Web Worker against a
// local notary (proxy mode) and the HTTPS fixture. Result lands in #result.
import { join } from "node:path";
import { startFixture, startNotary } from "../../src/dev";

const out = join(import.meta.dir, "../../../../.zkf/web");
const build = await Bun.build({ entrypoints: [join(import.meta.dir, "worker.ts")], outdir: out, target: "browser", conditions: ["browser"] });
if (!build.success) throw new AggregateError(build.logs, "bundle failed");

const fixture = await startFixture({ tlsVersion: "1.3" });
const notary = await startNotary({ proxyResolve: { [fixture.serverName]: fixture.addr } });
const job = { notaryUrl: notary.url, notaryKey: notary.publicKey, url: `https://${fixture.serverName}/formats/json`, caCert: fixture.caCert };
const page = `<!doctype html><title>zkfetch browser test</title><pre id="result">running…</pre><script>
const results = [];
const run = (tlsVersion) => new Promise((done) => { const w = new Worker("/worker.js", { type: "module" }); w.onmessage = (e) => { results.push({ tlsVersion, ...e.data }); w.terminate(); done(); }; w.postMessage({ ...${JSON.stringify(job)}, tlsVersion }); });
(async () => { await run("1.3"); await run("1.2"); document.getElementById("result").textContent = JSON.stringify(results); })();
</script>`;
const server = Bun.serve({
  port: Number(process.env.PORT ?? 8765),
  fetch(req) {
    const path = new URL(req.url).pathname;
    if (path === "/") return new Response(page, { headers: { "content-type": "text/html" } });
    if (path === "/worker.js") return new Response(Bun.file(join(out, "worker.js")), { headers: { "content-type": "text/javascript" } });
    if (path === "/zkf_bg.wasm") return new Response(Bun.file(join(import.meta.dir, "../../../wasm/pkg/zkf_bg.wasm")), { headers: { "content-type": "application/wasm" } });
    return new Response("not found", { status: 404 });
  },
});
console.log(`zkfetch browser test at http://localhost:${server.port}/`);
