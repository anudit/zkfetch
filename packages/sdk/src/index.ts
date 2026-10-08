// Node.js / Bun entry: the native prover addon.
import * as native from "@zkfetch/native";
import { setBackend } from "./core";

setBackend(native);

export * from "./core";
export * from "./dev";

/** No-op on Node.js/Bun (the prover loads at import); accepts the browser
 * build's optional wasm source so shared code can call `init(source)`. */
export async function init(_source?: unknown): Promise<void> {}
