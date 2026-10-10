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
  /** Reuse single-use in-memory Ferret state in proxy mode (default true). */
  persistentVole?: boolean;
  /** Enable FLOW2 batching and the ORIGO TLS 1.3 schedule (default true). */
  protocolV2?: boolean;
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
  /** Commit only to what this spec discloses (about half the proving work).
   * Presentations can then disclose this spec, or less by whole headers,
   * fields, target or body, never more. Default: commit everything. */
  reveal?: RevealSpec;
  /** Experimental v2 (D1) attestation: proxy mode, TLS 1.3, AES-128-GCM only.
   * The notary signs ciphertext roots and commitments to the session keys
   * instead of plaintext commitments; claims are proven later, offline, with
   * `presentV2`. Not combinable with `predicates`, `reveal` or `binius`. */
  attestationV2?: boolean;
  /** Sign response framing during fetch; default false. Trades session work for smaller later proofs. */
  signedResponseHead?: boolean;
  /** Structural member claims known before fetching, signed by the notary. */
  sessionClaims?: MemberPredicate[];
  /** Independent verifier nonce (32 bytes, hex), required with sessionClaims. */
  sessionClaimNonce?: string;
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
  /** Setup resumed reserved Ferret correlations instead of running base OT. */
  voleResumed?: boolean;
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
  /** 2 for `attestationV2` sessions, whose `secrets` hold the session keys. */
  attestationVersion?: 1 | 2;
}

/** A comparison over the unsigned integer value of a JSON object member.
 * `key` names a member of the response root object: it is not a path and does
 * not assert uniqueness. Use decimal strings above Number.MAX_SAFE_INTEGER. */
export interface MemberPredicate {
  key: string;
  op: "eq" | "ne" | "lt" | "le" | "gt" | "ge";
  value: string | number;
}

export interface PresentV2Request {
  predicate: MemberPredicate;
  /** 32 bytes of hex chosen by the verifier; binds the presentation to it. */
  nonce: string;
  /** "fast" (default, larger proof) or "small" (more proving work). */
  parameters?: "fast" | "small";
  /** v2 presentations disclose every response header. Responses that set
   * cookies are refused unless this is true. */
  allowSetCookie?: boolean;
}

export interface VerifyV2Options {
  /** Accepted notary keys, compressed SEC1 hex. */
  trustedNotaryKeys: string[];
  expectedServerName: string;
  /** The claim the verifier requires. */
  predicate: MemberPredicate;
  /** The nonce this verifier issued for the presentation. */
  nonce: string;
  maxAgeSecs?: number;
  expectedOwner?: string;
  expectedContext?: string;
}

export interface VerifyV2Output {
  serverName: string;
  time: number;
  notaryKey: KeyView;
  mode: "proxy";
  /** Disclosed response head: status line and headers. */
  responseHeaders: string;
  predicate: MemberPredicate;
  owner: string | null;
  context: string | null;
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

export function validateMemberPredicate(predicate?: MemberPredicate) {
  const value = predicate?.value;
  if (typeof value === "number" && (!Number.isSafeInteger(value) || value < 0)) {
    throw new TypeError("predicate value must be a nonnegative safe integer; use a decimal string for larger values");
  }
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
