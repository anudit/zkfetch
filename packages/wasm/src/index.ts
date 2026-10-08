// zkfetch prover/verifier compiled to wasm, for browsers, web workers and
// extension service workers. Same API as `@zkfetch/native`, plus `init()`.
import initWasm, * as single from "../pkg/zkf.js";
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

/** Multi-threaded prover, used only in a cross-origin isolated context. */
export interface ThreadsOptions {
  /** URL of the threaded build's `zkf.js` (shipped as `wasm-threads/zkf.js`). */
  module: string | URL;
  /** URL of the threaded `zkf_bg.wasm`. Defaults to next to `module`. */
  wasm?: string | URL;
  /** Worker threads. Defaults to `navigator.hardwareConcurrency`, capped at 8. */
  count?: number;
}

export interface InitOptions {
  threads?: ThreadsOptions;
}

type Module = typeof single & { initThreadPool?: (threads: number) => Promise<void> };
type PreparedSession = single.PreparedSession;

let wasm: Module = single;
let loading: Promise<unknown> | undefined;
let loaded = false;
let threadCount = 0;

/** Worker threads in use; 0 for the single-threaded build. */
export function threads(): number {
  return threadCount;
}

async function loadThreaded(options: ThreadsOptions): Promise<boolean> {
  const isolated = (globalThis as { crossOriginIsolated?: boolean }).crossOriginIsolated;
  if (!isolated || typeof SharedArrayBuffer === "undefined") return false;
  try {
    const url = new URL(options.module, (globalThis as { location?: { href: string } }).location?.href);
    const mod: Module = await import(/* @vite-ignore */ url.href);
    await mod.default({ module_or_path: new URL(options.wasm ?? "zkf_bg.wasm", url) });
    const cores = (globalThis as { navigator?: { hardwareConcurrency?: number } }).navigator?.hardwareConcurrency ?? 4;
    const count = Math.max(1, Math.floor(options.count ?? Math.min(cores, 8)));
    await mod.initThreadPool!(count);
    wasm = mod;
    threadCount = count;
    return true;
  } catch (cause) {
    console.warn("zkfetch: multi-threaded prover unavailable; using one thread.", cause);
    return false;
  }
}

/**
 * Loads the wasm module once. Without an argument it is fetched next to this
 * package (`new URL("zkf_bg.wasm", import.meta.url)`), which bundlers resolve.
 * In a Chrome extension pass `chrome.runtime.getURL("zkf_bg.wasm")`.
 *
 * With `options.threads` in a cross-origin isolated context (Web Worker
 * only), the multi-threaded build is used; otherwise the single-threaded one.
 */
export function init(source?: WasmSource, options: InitOptions = {}): Promise<void> {
  loading ??= (async () => {
    if (!(options.threads && await loadThreaded(options.threads))) {
      await initWasm(source === undefined ? undefined : { module_or_path: source });
    }
    loaded = true;
  })();
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

/** A notary session set up ahead of a request. Single use. */
export interface Prepared {
  notarize(params: NotarizeParams): Promise<NotarizeOutput>;
  /** Discards the session and closes it at the notary. */
  dispose(): void;
}

/** Connects to the notary and runs the request-independent preprocessing. */
export async function prepare(params: NotarizeParams): Promise<Prepared> {
  await init();
  let session: PreparedSession | undefined = await wasm.prepare(JSON.stringify(params));
  return {
    async notarize(request) {
      validatePredicates(request.predicates);
      if (!session) throw new Error("zkfetch: prepared session already used or disposed");
      const owned = session;
      session = undefined;
      return JSON.parse(await wasm.notarizePrepared(owned, JSON.stringify(request)));
    },
    dispose() {
      session?.free();
      session = undefined;
    },
  };
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
