// Shared zkfetch types; shapes mirror `crates/zkf-core/src/types.rs`.
// Runtime-free so browser builds can import it.

export type Header = [name: string, value: string];
export type TlsVersion = "1.2" | "1.3";
export type TlsVersionPreference = TlsVersion | "auto";
/** "mpc" (default): notary runs the TLS client with the prover in MPC.
 * "proxy": notary relays the TLS traffic and the prover proves the keys in ZK. */
export type NotarizeMode = "mpc" | "proxy";

export interface NotarizeParams {
  /** Defaults to auto (TLS 1.3); requests are never retried. */
  tlsVersion?: TlsVersionPreference;
  mode?: NotarizeMode;
  /** Browser builds, MPC mode: WebSocket-to-TCP relay for the prover's server
   * connection (`relayUrl?target=host:port`). Proxy mode needs no relay. */
  relayUrl?: string;
  notaryUrl: string;
  /** Signing key pin, compressed SEC1 hex; required for remote sessions. */
  expectedNotaryKey?: string;
  url: string;
  method?: string;
  headers?: Header[];
  body?: string;
  /** Dial this host:port instead of the URL host (SNI still uses the URL host). */
  connectAddr?: string;
  /** Extra trusted root CAs, base64 DER. */
  extraRootCerts?: string[];
  /** Request size limit in bytes (MPC mode; default 4096). */
  maxSent?: number;
  /** Response size limit in bytes. MPC mode preprocesses for it (default
   * 16384); proxy mode rejects larger responses (default 262144). */
  maxRecv?: number;
  owner?: string;
  context?: string;
  /** Numeric predicates proven to the notary with QuickSilver during the fetch
   * and signed into the attestation (default predicate backend). */
  predicates?: PredicateSpec[];
  /** Opt in to per-leaf SHA-256 commitments so predicates can be proven later,
   * offline, with Binius64. */
  binius?: boolean;
}

export interface KeyView {
  alg: string;
  key: string;
}

export interface HttpResponseView {
  status: number;
  headers: Header[];
  body: string;
}

/** Wall-clock milliseconds per notarization phase. */
export interface NotarizeTimings {
  /** WebSocket connect to the notary. */
  notaryConnectMs: number;
  /** MPC setup + preprocessing before touching the server. */
  setupMs: number;
  /** TCP connect, MPC-TLS handshake, request/response, decryption. */
  tlsMs: number;
  /** Transcript commitments proven to the notary. */
  proveMs: number;
  /** Attestation exchange + local validation. */
  attestMs: number;
  totalMs: number;
  /** Connect and setup ran ahead of the request (`prepare`); `totalMs` then excludes them. */
  prewarmed?: boolean;
}

export interface NotarizeOutput {
  /** Version actually used, rather than the requested preference. */
  tlsVersion: TlsVersion;
  /** base64 attestation (public). */
  attestation: string;
  /** base64 secrets (SENSITIVE: opens every commitment). */
  secrets: string;
  response: HttpResponseView;
  notaryKey: KeyView;
  timings: NotarizeTimings;
}

export interface RevealSpec {
  request?: { target?: boolean; headers?: string[]; body?: boolean };
  response?: { headers?: string[]; body?: boolean; jsonPaths?: string[]; byteOnly?: boolean };
  /** Prove comparisons over hidden unsigned JSON integers of at most 19 digits.
   * Reveals JSON keys, structure and scalar lengths; values remain hidden. */
  prove?: PredicateSpec[];
  /** `quicksilver` (default): disclose predicates the notary verified at fetch
   * time (`zkConfig.predicates`). `binius`: prove them now with Binius64
   * (the SDK configures this through `zkConfig.backend` at fetch time). */
  backend?: "quicksilver" | "binius";
}

export interface PredicateSpec {
  jsonPath: string;
  /** Use decimal strings for thresholds above Number.MAX_SAFE_INTEGER. */
  predicate: { gte: string | number; gt?: never } | { gt: string | number; gte?: never };
}

export interface VerifyOptions {
  /** Accepted notary keys (hex). Required unless `allowUntrustedNotary`. */
  trustedNotaryKeys?: string[];
  /** Inspection only: accept any notary and report `notaryTrusted`. */
  allowUntrustedNotary?: boolean;
  /** Accept only MPC-TLS sessions, not proxy ones. */
  rejectProxy?: boolean;
  extraRootCerts?: string[];
  expectedOwner?: string;
  expectedContext?: string;
  expectedPredicates?: PredicateSpec[];
  expectedServerName?: string;
  expectedMethod?: string;
  expectedTarget?: string;
  expectedStatus?: number;
  maxAgeSecs?: number;
  requireCompleteResponse?: boolean;
  requireJsonPaths?: boolean;
}

export interface VerifyOutput {
  serverName: string;
  time: number;
  tlsVersion: string;
  notaryKey: KeyView;
  notaryTrusted: boolean;
  /** Session mode signed by the notary. */
  mode: "mpc" | "proxy";
  /** Request bytes for display; undisclosed bytes are `X`. */
  sent: string;
  /** Response bytes for display; undisclosed bytes are `X`. A literal `X`
   * and a hidden byte look the same: use `recvAuthed` to decide. */
  recv: string;
  /** Authenticated byte ranges `[start, end)` (UTF-8 offsets). */
  sentAuthed: [number, number][];
  recvAuthed: [number, number][];
  /** Disclosed response JSON fields at proven paths (empty if the session
   * has no QuickSilver shape proofs or the skeleton was not disclosed). */
  json: { path: string; value: unknown }[];
  jsonPathsAuthenticated: boolean;
  owner: string | null;
  context: string | null;
  predicates: PredicateSpec[];
}

export function validatePredicates(predicates?: PredicateSpec[]) {
  for (const spec of predicates ?? []) {
    for (const threshold of Object.values(spec.predicate)) {
      if (typeof threshold === "number" && (!Number.isSafeInteger(threshold) || threshold < 0)) {
        throw new TypeError("predicate threshold must be a nonnegative safe integer; use a decimal string for larger values");
      }
    }
  }
}
