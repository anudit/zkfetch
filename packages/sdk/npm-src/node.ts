// Published Node.js / Bun entry. Uses the native addon when one ships for
// this platform, otherwise the wasm prover (also set ZKF_FORCE_WASM=1).
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { validatePredicates, type NotarizeParams, type RevealSpec, type VerifyOptions } from "@zkfetch/native/types";
import * as wasm from "../../wasm/pkg/zkf.js";
import { setBackend, type Backend } from "../src/core";

interface Addon {
  notarize(paramsJson: string): Promise<string>;
  present(attestation: string, secrets: string, specJson: string): string;
  verify(presentation: string, optionsJson: string): string;
}

function wrap(impl: Addon, ready: () => void = () => {}): Backend {
  return {
    async notarize(params: NotarizeParams) {
      validatePredicates(params.predicates);
      ready();
      return JSON.parse(await impl.notarize(JSON.stringify(params)));
    },
    present(attestation: string, secrets: string, spec: RevealSpec) {
      validatePredicates(spec.prove);
      ready();
      return impl.present(attestation, secrets, JSON.stringify(spec));
    },
    verify(presentation: string, options: VerifyOptions = {}) {
      validatePredicates(options.expectedPredicates);
      ready();
      return JSON.parse(impl.verify(presentation, JSON.stringify(options)));
    },
  };
}

function nativeBackend(): Backend | undefined {
  if (process.env.ZKF_FORCE_WASM === "1") return undefined;
  const file = fileURLToPath(new URL(`../native/zkf.${process.platform}-${process.arch}.node`, import.meta.url));
  if (!existsSync(file)) return undefined;
  return wrap(createRequire(import.meta.url)(file) as Addon);
}

let wasmLoaded = false;
function wasmBackend(): Backend {
  return wrap(wasm, () => {
    if (wasmLoaded) return;
    wasm.initSync({ module: readFileSync(fileURLToPath(new URL("./zkf_bg.wasm", import.meta.url))) });
    wasmLoaded = true;
  });
}

const backend = nativeBackend();
/** "native" or "wasm": which prover this process uses. */
export const runtime: "native" | "wasm" = backend ? "native" : "wasm";
setBackend(backend ?? wasmBackend());

export * from "../src/core";

/** No-op on Node.js/Bun (the prover loads at import); accepts the browser
 * build's optional wasm source so shared code can call `init(source)`. */
export async function init(_source?: unknown): Promise<void> {}
