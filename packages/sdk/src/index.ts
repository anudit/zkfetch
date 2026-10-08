// Node.js / Bun entry: the native prover addon.
import * as native from "@zkfetch/native";
import { setBackend } from "./core";

setBackend(native);

export * from "./core";
export * from "./dev";

/** No-op on Node.js/Bun (the prover loads at import); accepts the browser
 * build's optional wasm source so shared code can call `init(source)`. */
export async function init(_source?: unknown, _options?: unknown): Promise<void> {}

/** Worker threads of the wasm prover; always 0 here (the native prover manages its own). */
export function threads(): number {
  return 0;
}
