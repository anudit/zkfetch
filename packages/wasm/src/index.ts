// zkfetch prover/verifier compiled to wasm, for browsers, web workers and
// extension service workers. Same API as `@zkfetch/native`, plus `init()`.
import initWasm, * as wasm from "../pkg/zkf.js";
import type { InitInput } from "../pkg/zkf.js";
import {
  validatePredicates,
  type NotarizeOutput,
  type NotarizeParams,
  type RevealSpec,
  type VerifyOptions,
  type VerifyOutput,
} from "@zkfetch/native/types";

export * from "@zkfetch/native/types";

/** Where to load the module from: a URL, a `Response`, or the bytes. */
export type WasmSource = InitInput | Promise<InitInput>;

let loading: Promise<unknown> | undefined;
let loaded = false;

/**
 * Loads the wasm module once. Without an argument it is fetched next to this
 * package (`new URL("zkf_bg.wasm", import.meta.url)`), which bundlers resolve.
 * In a Chrome extension pass `chrome.runtime.getURL("zkf_bg.wasm")`.
 */
export function init(source?: WasmSource): Promise<void> {
  loading ??= initWasm(source === undefined ? undefined : { module_or_path: source }).then(() => {
    loaded = true;
  });
  return loading.then(() => undefined);
}

function ready() {
  if (!loaded) throw new Error("zkfetch: call `await init()` before using present() or verify()");
}

export async function notarize(params: NotarizeParams): Promise<NotarizeOutput> {
  validatePredicates(params.predicates);
  await init();
  return JSON.parse(await wasm.notarize(JSON.stringify(params)));
}

export function present(attestation: string, secrets: string, spec: RevealSpec): string {
  validatePredicates(spec.prove);
  ready();
  return wasm.present(attestation, secrets, JSON.stringify(spec));
}

export function verify(presentation: string, options: VerifyOptions = {}): VerifyOutput {
  validatePredicates(options.expectedPredicates);
  ready();
  return JSON.parse(wasm.verify(presentation, JSON.stringify(options)));
}
