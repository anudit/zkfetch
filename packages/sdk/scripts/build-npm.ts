// Builds the publishable `zkfetch` package into packages/sdk/npm/.
//   bun packages/sdk/scripts/build-npm.ts
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const sdk = join(import.meta.dir, "..");
const root = join(sdk, "../..");
const out = join(sdk, "npm");
rmSync(out, { recursive: true, force: true });
mkdirSync(join(out, "dist"), { recursive: true });
mkdirSync(join(out, "native"), { recursive: true });

for (const [entry, target, conditions] of [
  ["node.ts", "node", []],
  ["browser.ts", "browser", ["browser"]],
] as const) {
  const build = await Bun.build({
    entrypoints: [join(sdk, "npm-src", entry)],
    outdir: join(out, "dist"),
    target,
    conditions: [...conditions],
    format: "esm",
  });
  if (!build.success) throw new AggregateError(build.logs, `bundling ${entry} failed`);
}
cpSync(join(root, "packages/wasm/pkg/zkf_bg.wasm"), join(out, "dist/zkf_bg.wasm"));
const addon = `zkf.${process.platform}-${process.arch}.node`;
cpSync(join(root, "packages/native/zkf.node"), join(out, "native", addon));

// Type declarations: emit, then point workspace imports at the bundled copies.
const tsc = Bun.spawnSync(["bunx", "tsc", "-p", join(sdk, "tsconfig.npm.json")], { stdout: "inherit", stderr: "inherit" });
if (tsc.exitCode !== 0) throw new Error("declaration build failed");
const types = join(out, "dist/types");
for (const file of ["sdk/src/core.d.ts", "sdk/src/browser.d.ts"]) {
  const path = join(types, file);
  writeFileSync(path, readFileSync(path, "utf8").replaceAll('"@zkfetch/native/types"', '"../../native/src/types"').replaceAll('"@zkfetch/wasm"', '"../../wasm/src/index"'));
}
const wasmTypes = join(types, "wasm/src/index.d.ts");
writeFileSync(wasmTypes, readFileSync(wasmTypes, "utf8").replaceAll('"@zkfetch/native/types"', '"../../native/src/types"').replaceAll('"../pkg/zkf.js"', '"./zkf"'));
cpSync(join(root, "packages/wasm/pkg/zkf.d.ts"), join(types, "wasm/src/zkf.d.ts"));
// Node16/NodeNext resolution needs explicit extensions on relative imports.
for (const file of new Bun.Glob("**/*.d.ts").scanSync(types)) {
  const path = join(types, file);
  writeFileSync(path, readFileSync(path, "utf8").replace(/(from\s+"\.{1,2}\/[^"]+?)(?<!\.js)"/g, '$1.js"'));
}
writeFileSync(join(out, "dist/node.d.ts"), `export * from "./types/sdk/src/core.js";\n/** "native" or "wasm": which prover this process uses. */\nexport declare const runtime: "native" | "wasm";\n/** No-op on Node.js/Bun; accepts the browser build's wasm source for shared code. */\nexport declare function init(source?: unknown): Promise<void>;\n`);
writeFileSync(join(out, "dist/browser.d.ts"), `export * from "./types/sdk/src/browser.js";\n`);

const version = JSON.parse(readFileSync(join(sdk, "package.json"), "utf8")).version;
writeFileSync(join(out, "package.json"), JSON.stringify({
  name: "@omnid/zkfetch",
  version,
  description: "fetch with a proof: notarized HTTPS with selective disclosure and zero-knowledge predicates, on TLSNotary.",
  type: "module",
  license: "MIT OR Apache-2.0",
  repository: { type: "git", url: "git+https://github.com/anudit/zkfetch.git" },
  homepage: "https://github.com/anudit/zkfetch#readme",
  keywords: ["tlsnotary", "zktls", "mpc-tls", "zero-knowledge", "attestation", "fetch", "tls"],
  engines: { node: ">=22" },
  exports: {
    ".": {
      types: { browser: "./dist/browser.d.ts", default: "./dist/node.d.ts" },
      browser: "./dist/browser.js",
      worker: "./dist/browser.js",
      default: "./dist/node.js",
    },
    "./zkf_bg.wasm": "./dist/zkf_bg.wasm",
  },
  types: "./dist/node.d.ts",
  files: ["dist", "native", "README.md"],
  sideEffects: true,
}, null, 2) + "\n");
// npm renders the README without the repo: make relative links absolute.
const repo = "https://github.com/anudit/zkfetch";
const readme = readFileSync(join(root, "README.md"), "utf8")
  .replace('src="zkfetch.svg"', `src="${repo}/raw/main/zkfetch.svg"`)
  .replace(/\]\((?!https?:|#)([^)]+)\)/g, (_, path) => `](${repo}/blob/main/${path})`);
writeFileSync(join(out, "README.md"), readme);
console.log(`built ${out}`);
