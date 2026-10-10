// Builds the multi-threaded prover into pkg-threads/. It needs a nightly
// toolchain with rust-src (std is rebuilt with atomics) and is used only in
// cross-origin isolated contexts; see `init({ threads })` in src/index.ts.
import { $ } from "bun";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dir, "../../..");
const out = join(import.meta.dir, "../pkg-threads");
const toolchain = process.env.ZKF_NIGHTLY ?? "nightly";
const rustflags = [
  '--cfg getrandom_backend="wasm_js"',
  "-C target-feature=+atomics,+bulk-memory,+mutable-globals,+simd128",
  // wasm-bindgen's thread support: shared, imported memory and TLS exports.
  ...["--shared-memory", "--import-memory", "--max-memory=4294967296",
    "--export=__wasm_init_tls", "--export=__tls_size", "--export=__tls_align", "--export=__tls_base"]
    .map(arg => `-C link-arg=${arg}`),
].join(" ");

await $`rustup run ${toolchain} wasm-pack build crates/zkf-wasm --release --target web --out-dir ${out} --out-name zkf --no-pack -- --locked --features threads -Z build-std=panic_abort,std`
  .cwd(root)
  .env({ ...process.env, RUSTFLAGS: rustflags, CARGO_TARGET_DIR: join(root, "target/wasm-threads") });

// wasm-bindgen-rayon's worker imports its parent module as `../../..`, which
// only bundlers resolve. Point it at the file so plain module workers work.
for (const dir of readdirSync(join(out, "snippets"))) {
  const helper = join(out, "snippets", dir, "src/workerHelpers.js");
  const source = readFileSync(helper, "utf8");
  if (!source.includes("import('../../..')")) throw new Error(`unexpected workerHelpers.js in ${dir}`);
  writeFileSync(helper, source.replace("import('../../..')", "import('../../../zkf.js')"));
}
console.log(`built ${out}`);
