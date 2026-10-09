// Runtime-independent SDK. Entry points (`index.ts` for Node/Bun, `browser.ts`
// for pages, workers and extensions) install the prover backend.
import type * as types from "@zkfetch/native/types";
import type { HttpResponseView, NotarizeMode, KeyView, NotarizeOutput, NotarizeParams, NotarizeTimings, PredicateSpec, TlsVersion, TlsVersionPreference, VerifyOptions, VerifyOutput } from "@zkfetch/native/types";

export type { NotarizeMode, PredicateSpec, VerifyOptions, VerifyOutput, HttpResponseView, KeyView, NotarizeTimings, TlsVersion, TlsVersionPreference } from "@zkfetch/native/types";
export type PredicateBackend = "quicksilver" | "binius";
/** Backend selection belongs to the fetched session, including after restoration. */
export type RevealSpec = Omit<types.RevealSpec, "backend">;

/** The prover/verifier implementation: the native addon or the wasm module. */
export interface Backend {
  notarize(params: NotarizeParams): Promise<NotarizeOutput>;
  present(attestation: string, secrets: string, spec: types.RevealSpec): string;
  verify(presentation: string, options?: VerifyOptions): VerifyOutput;
  /** Optional: request-independent setup ahead of a request (wasm builds). */
  prepare?(params: NotarizeParams): Promise<{
    notarize(params: NotarizeParams): Promise<NotarizeOutput>;
    dispose(): void;
  }>;
}

let active: Backend | undefined;

export function setBackend(backend: Backend) {
  active = backend;
}

function backendOrThrow(): Backend {
  if (!active) throw new Error("zkfetch: no prover backend; import from \"@omnid/zkfetch\" (not its core)");
  return active;
}

/** zkfetch-specific settings, passed as `init.zkConfig`. */
export interface ZkConfig {
  /** Defaults to auto (TLS 1.3). Choose 1.2 explicitly for compatibility; requests are never retried. */
  tlsVersion?: TlsVersionPreference;
  /** Notary WebSocket URL, e.g. `wss://notary.example`. */
  notaryUrl: string;
  /** Reuse single-use in-memory Ferret state in proxy mode (default true). */
  persistentVole?: boolean;
  /** FLOW2 batching and ORIGO TLS 1.3 schedule; false selects the conservative legacy flow. */
  protocolV2?: boolean;
  /** Signing key pin, compressed SEC1 hex; required for remote sessions. */
  expectedNotaryKey?: string;
  /** Bound into the attestation (`zkf.owner`). */
  owner?: string;
  /** Verifier-supplied challenge bound into the attestation (`zkf.context`). */
  context?: string;
  /** MPC preprocessing limits in bytes; smaller is faster. */
  maxSent?: number;
  maxRecv?: number;
  /** Testing: dial this host:port instead of the URL host (SNI still uses the URL host). */
  connectAddr?: string;
  /** Testing: extra trusted root CAs (base64 DER). */
  extraRootCerts?: string[];
  /** Predicates to prepare at fetch time. QuickSilver proves these to the notary;
   * Binius prepares commitments for later local proofs. */
  predicates?: PredicateSpec[];
  /** Defaults to QuickSilver. Automatically configures commitments and presentation proofs. */
  backend?: PredicateBackend;
  /** What `present()` will disclose, if known at fetch time. Commits only to
   * that (about half the proving work, smaller presentations); hidden values
   * are not committed at all. Later presentations can disclose this spec or
   * less (whole headers, fields, target or body), never more. With the
   * Binius backend, new predicates can still be proven later. */
  reveal?: RevealSpec;
  /** Defaults to "mpc". "proxy" needs far less traffic but trusts the
   * network path between the notary and the server. */
  mode?: NotarizeMode;
  /** Browser builds, MPC mode only: WebSocket-to-TCP relay used to reach the
   * server (browsers cannot open TCP). Proxy mode needs no relay. */
  relayUrl?: string;
  /** A session from `prepare()` for this request; falls back to a fresh
   * session if it expired or failed before the request was sent. */
  prepared?: ZkPrepared;
}

/** Notary sessions time out 120 s after connecting; leave room for the request. */
const PREPARED_LIFETIME_MS = 80_000;

type BackendPrepared = Awaited<ReturnType<NonNullable<Backend["prepare"]>>>;

/**
 * A notary session set up ahead of a `zkFetch` (connection and MPC
 * preprocessing, most of the latency). Pass it as `zkConfig.prepared`.
 * Single use; expires after 80 s. Call `dispose()` if it will not be used.
 */
export class ZkPrepared {
  /** Epoch milliseconds after which `zkFetch` ignores this session. */
  readonly expiresAt = Date.now() + PREPARED_LIFETIME_MS;
  #session: Promise<BackendPrepared | undefined>;
  #used = false;

  /** Use `prepare()`. */
  constructor(session: Promise<BackendPrepared>) {
    this.#session = session.catch(() => undefined);
  }

  /** Resolves once setup finished; `false` if it failed or is unsupported. */
  async ready(): Promise<boolean> {
    return (await this.#session) !== undefined;
  }

  /** True until used, disposed or expired. Setup may still be running. */
  get usable(): boolean {
    return !this.#used && Date.now() < this.expiresAt;
  }

  /** Hands the session to one request; `undefined` if it cannot be used. */
  async take(): Promise<BackendPrepared | undefined> {
    if (!this.usable) return undefined;
    this.#used = true;
    return this.#session;
  }

  /** Closes the session at the notary if it was not used. */
  dispose(): void {
    if (this.#used) return;
    this.#used = true;
    void this.#session.then(session => session?.dispose());
  }
}

/**
 * Starts the request-independent part of a `zkFetch` to `input` now, so the
 * later request only runs the TLS, proof and attestation phases. The session
 * is bound to the notary, mode, TLS version, MPC limits and (proxy mode) host.
 * On runtimes without support (native) it is a no-op.
 */
export function prepare(input: string | URL, zkConfig: Omit<ZkConfig, "prepared">): ZkPrepared {
  const backend = backendOrThrow();
  const session = backend.prepare
    ? backend.prepare(notarizeParams(input.toString(), {}, zkConfig))
    : Promise.reject(new Error("prepare is not supported by this backend"));
  return new ZkPrepared(session);
}

/** Standard `RequestInit` plus `zkConfig`. Only string bodies are supported. */
export interface ZkRequestInit extends Omit<RequestInit, "body"> {
  body?: string | null;
  zkConfig: ZkConfig;
}

/** Serialized session. Contains `secrets`; store it encrypted. */
export interface ZkSessionData {
  version: 1;
  url: string;
  attestation: string;
  secrets: string;
  response: HttpResponseView;
  notaryKey: KeyView;
  timings: NotarizeTimings;
  /** Actual negotiated version; absent in older serialized sessions. */
  tlsVersion?: TlsVersion;
  /** Absent in older sessions, which default to QuickSilver. */
  backend?: PredicateBackend;
}

/** The attested session behind a `zkFetch` response. */
export class ZkSession {
  constructor(readonly data: ZkSessionData) {}

  get attestation(): string {
    return this.data.attestation;
  }

  get notaryKey(): KeyView {
    return this.data.notaryKey;
  }

  get tlsVersion(): TlsVersion | undefined {
    return this.data.tlsVersion;
  }

  get backend(): PredicateBackend {
    return checkedBackend(this.data.backend);
  }

  /** Per-phase notarization latency for this session. */
  get timings(): NotarizeTimings {
    return this.data.timings;
  }

  /** Builds a base64 presentation disclosing only what `spec` selects. */
  present(spec: RevealSpec = {}): string {
    return backendOrThrow().present(this.data.attestation, this.data.secrets, { ...spec, backend: this.backend });
  }

  toJSON(): ZkSessionData {
    return this.data;
  }

  static fromJSON(data: ZkSessionData): ZkSession {
    if (data.version !== 1) throw new Error(`unsupported session version ${data.version}`);
    checkedBackend(data.backend);
    return new ZkSession(data);
  }
}

/** A standard `Response`, plus the attested session at `.zk`. */
export type ZkResponse = Response & { readonly zk: ZkSession };

/**
 * `fetch`, run as a 3-party (MPC-TLS) session with a notary.
 * Returns a normal `Response`; call `response.zk.present(spec)` to disclose parts of it.
 */
export async function zkFetch(input: string | URL, init: ZkRequestInit): Promise<ZkResponse> {
  const { zkConfig, method, headers, body } = init;
  if (!zkConfig?.notaryUrl) throw new TypeError("zkFetch: init.zkConfig.notaryUrl is required");
  if (body != null && typeof body !== "string") throw new TypeError("zkFetch: only string bodies are supported");
  const url = input.toString();
  const backend = checkedBackend(zkConfig.backend);
  const params = notarizeParams(url, { method, headers, body }, zkConfig);

  const out = await notarizeWith(params, zkConfig.prepared);
  const session = new ZkSession({ version: 1, url, ...out, backend });
  return toResponse(out.response, session);
}

/** Uses the prepared session if it is still good, else a fresh one. An attempted
 * prepared session is never retried because the request may already have been sent. */
async function notarizeWith(params: NotarizeParams, prepared: ZkPrepared | undefined): Promise<NotarizeOutput> {
  const session = await prepared?.take();
  if (!session) return backendOrThrow().notarize(params);
  return session.notarize(params);
}

function notarizeParams(
  url: string,
  request: { method?: string; headers?: HeadersInit; body?: string | null },
  zkConfig: Omit<ZkConfig, "prepared">,
): NotarizeParams {
  const backend = checkedBackend(zkConfig.backend);
  return {
    notaryUrl: zkConfig.notaryUrl,
    persistentVole: zkConfig.persistentVole,
    expectedNotaryKey: zkConfig.expectedNotaryKey,
    url,
    method: request.method,
    headers: [...new Headers(request.headers).entries()],
    body: request.body ?? undefined,
    connectAddr: zkConfig.connectAddr,
    extraRootCerts: zkConfig.extraRootCerts,
    maxSent: zkConfig.maxSent,
    maxRecv: zkConfig.maxRecv,
    owner: zkConfig.owner,
    context: zkConfig.context,
    predicates: backend === "quicksilver" ? zkConfig.predicates : undefined,
    binius: backend === "binius",
    reveal: zkConfig.reveal,
    tlsVersion: zkConfig.tlsVersion,
    protocolV2: zkConfig.protocolV2,
    mode: zkConfig.mode,
    relayUrl: zkConfig.relayUrl,
  };
}

function checkedBackend(backend: PredicateBackend | undefined): PredicateBackend {
  if (backend === undefined) return "quicksilver";
  if (backend !== "quicksilver" && backend !== "binius") {
    throw new TypeError('zkFetch: backend must be "quicksilver" or "binius"');
  }
  return backend;
}

/** Rebuilds a `ZkResponse` from a serialized session (e.g. to present later). */
export function restoreResponse(data: ZkSessionData): ZkResponse {
  const session = ZkSession.fromJSON(data);
  return toResponse(data.response, session);
}

function toResponse(view: HttpResponseView, session: ZkSession): ZkResponse {
  const nullBody = [101, 204, 205, 304].includes(view.status);
  const response = new Response(nullBody ? null : view.body, {
    status: view.status,
    headers: view.headers,
  });
  Object.defineProperty(response, "zk", { value: session, enumerable: false });
  return response as ZkResponse;
}

/** Verifies a presentation. Throws if invalid or if a policy option fails. */
export function verify(presentation: string, options: VerifyOptions = {}): VerifyOutput {
  return backendOrThrow().verify(presentation, options);
}
