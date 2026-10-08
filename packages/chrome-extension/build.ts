import { cpSync, existsSync, mkdirSync } from "node:fs";
import { basename, join } from "node:path";
import deployment from "../../infra/aws/deployment.json";

const root = import.meta.dir;
const dist = join(root, "dist");
const wasm = join(root, "../wasm/pkg/zkf_bg.wasm");
if (!existsSync(wasm)) {
  throw new Error("Build the WASM SDK first: bun run --cwd packages/wasm build (from the repository root).");
}
mkdirSync(dist, { recursive: true });
const result = await Bun.build({
  entrypoints: ["background", "sidepanel", "prover"].map(name => join(root, `src/${name}.ts`)),
  outdir: dist,
  target: "browser",
  conditions: ["browser"],
  format: "esm",
});
if (!result.success) throw new AggregateError(result.logs, "Extension bundle failed");
// The source manifest loads dist/ so the package directory can also be loaded
// unpacked. The standalone dist manifest uses paths relative to itself.
const manifest = await Bun.file(join(root, "manifest.json")).json();
// The notary host comes from infra/aws/deployment.json, which changes with the
// instance's IP; manifest.json holds the host from the last deployment.
const notaryHost = new URL(deployment.health).host;
manifest.host_permissions = ["https://*.duolingo.com/*", `https://${notaryHost}/*`];
manifest.content_security_policy.extension_pages = manifest.content_security_policy.extension_pages
  .replace(/connect-src [^;]*/, `connect-src 'self' https://*.duolingo.com https://${notaryHost} wss://${notaryHost}`);
manifest.background.service_worker = basename(manifest.background.service_worker);
manifest.side_panel.default_path = basename(manifest.side_panel.default_path);
await Bun.write(join(dist, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
for (const file of ["sidepanel.html", "sidepanel.css"]) {
  cpSync(join(root, file), join(dist, file));
}
cpSync(wasm, join(dist, "zkf_bg.wasm"));
// Multi-threaded prover, loaded by the cross-origin isolated panel's worker.
const threads = join(root, "../wasm/pkg-threads");
if (existsSync(join(threads, "zkf.js"))) {
  cpSync(threads, join(dist, "wasm-threads"), { recursive: true, filter: path => !path.endsWith(".gitignore") && !path.endsWith(".d.ts") });
} else {
  console.warn("No multi-threaded build (bun run --cwd packages/wasm build:threads); the prover will use one thread.");
}
console.log(`Load unpacked in chrome://extensions: ${dist}`);
