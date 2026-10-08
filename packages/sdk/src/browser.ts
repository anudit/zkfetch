// Browser, web worker and extension entry: the wasm prover.
// Call `await init()` before `present()`/`verify()`; `zkFetch` loads it itself.
import * as wasm from "@zkfetch/wasm";
import { setBackend } from "./core";

setBackend(wasm);

export * from "./core";
export { init, type WasmSource } from "@zkfetch/wasm";
