// Bundles the example into dist/ (load it with chrome://extensions → Load unpacked).
import { cpSync, mkdirSync } from "node:fs";
import { join } from "node:path";

const dist = join(import.meta.dir, "dist");
mkdirSync(dist, { recursive: true });
const build = await Bun.build({
  entrypoints: [join(import.meta.dir, "src/background.ts"), join(import.meta.dir, "src/popup.ts")],
  outdir: dist,
  target: "browser",
  conditions: ["browser"],
  format: "esm",
});
if (!build.success) throw new AggregateError(build.logs, "bundle failed");
for (const file of ["manifest.json", "popup.html"]) cpSync(join(import.meta.dir, file), join(dist, file));
cpSync(join(import.meta.dir, "../../packages/wasm/pkg/zkf_bg.wasm"), join(dist, "zkf_bg.wasm"));
console.log(`built ${dist}`);
