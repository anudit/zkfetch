// Builds the zkf-napi addon and installs it next to the loader as `zkf.node`.
//
// macOS 27 (ld-27037) workaround: if the dylib's LINKEDIT string pool comes out
// 4-byte aligned (odd indirect-symbol count), dyld refuses to load it. We detect
// that and relink with `--cfg zkf_pad_indirect`, which adds one GOT entry.
import { $ } from "bun";
import { copyFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dir, "..", "..", "..");
const lib = { darwin: "libzkf_napi.dylib", linux: "libzkf_napi.so", win32: "zkf_napi.dll" }[
  process.platform as "darwin" | "linux" | "win32"
];
if (!lib) throw new Error(`unsupported platform ${process.platform}`);
const src = join(root, "target", "release", lib);

async function stringPoolAligned(): Promise<boolean> {
  const out = await $`otool -l ${src}`.text();
  const stroff = Number(/stroff (\d+)/.exec(out)?.[1]);
  if (!Number.isFinite(stroff)) throw new Error("could not read LC_SYMTAB from otool");
  return stroff % 8 === 0;
}

const cargo = (extra: string[] = []) =>
  $`cargo rustc --locked --release -p zkf-napi --lib --crate-type cdylib -- ${extra}`.cwd(root);

await cargo();
if (process.platform === "darwin" && !(await stringPoolAligned())) {
  console.log("relinking zkf-napi with zkf_pad_indirect (ld string-pool alignment workaround)");
  await cargo(["--cfg", "zkf_pad_indirect"]);
  if (!(await stringPoolAligned())) throw new Error("zkf-napi string pool still misaligned");
}

if (!existsSync(src)) throw new Error(`${src} not found`);
const dest = join(import.meta.dir, "..", "zkf.node");
copyFileSync(src, dest);
console.log(`installed ${dest}`);
