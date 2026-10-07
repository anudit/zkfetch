// Typed loader for the zkf-napi addon. Shapes mirror `crates/zkf-core/src/types.rs`.
import { createRequire } from "node:module";
import { join } from "node:path";

export type Header = [name: string, value: string];
export type TlsVersion = "1.2" | "1.3";
export type TlsVersionPreference = TlsVersion | "auto";
/** "mpc" (default): notary runs the TLS client with the prover in MPC.
 * "proxy": notary relays TLS 1.2 traffic and the prover proves the keys in ZK. */
export type NotarizeMode = "mpc" | "proxy";

export interface NotarizeParams {
  /** Defaults to auto: tries TLS 1.3, with TLS 1.2 retry for GET/HEAD/OPTIONS. */
  tlsVersion?: TlsVersionPreference;
  mode?: NotarizeMode;
  notaryUrl: string;
  url: string;
  method?: string;
  headers?: Header[];
  body?: string;
  /** Dial this host:port instead of the URL host (SNI still uses the URL host). */
  connectAddr?: string;
  /** Extra trusted root CAs, base64 DER. */
  extraRootCerts?: string[];
  maxSent?: number;
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
  response?: { headers?: string[]; body?: boolean; jsonPaths?: string[] };
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
  trustedNotaryKeys?: string[];
  extraRootCerts?: string[];
  expectedOwner?: string;
  expectedContext?: string;
  expectedPredicates?: PredicateSpec[];
}

export interface VerifyOutput {
  serverName: string;
  time: number;
  tlsVersion: string;
  notaryKey: KeyView;
  notaryTrusted: boolean;
  /** Request bytes; undisclosed bytes are `X`. */
  sent: string;
  /** Response bytes; undisclosed bytes are `X`. */
  recv: string;
  owner: string | null;
  context: string | null;
  predicates: PredicateSpec[];
}

interface Addon {
  notarize(paramsJson: string): Promise<string>;
  present(attestation: string, secrets: string, specJson: string): string;
  verify(presentation: string, optionsJson: string): string;
}

const addon = createRequire(import.meta.url)(join(import.meta.dir, "..", "zkf.node")) as Addon;

export async function notarize(params: NotarizeParams): Promise<NotarizeOutput> {
  validatePredicates(params.predicates);
  return JSON.parse(await addon.notarize(JSON.stringify(params)));
}

export function present(attestation: string, secrets: string, spec: RevealSpec): string {
  validatePredicates(spec.prove);
  return addon.present(attestation, secrets, JSON.stringify(spec));
}

export function verify(presentation: string, options: VerifyOptions = {}): VerifyOutput {
  validatePredicates(options.expectedPredicates);
  return JSON.parse(addon.verify(presentation, JSON.stringify(options)));
}

function validatePredicates(predicates?: PredicateSpec[]) {
  for (const spec of predicates ?? []) {
    for (const threshold of Object.values(spec.predicate)) {
      if (typeof threshold === "number" && (!Number.isSafeInteger(threshold) || threshold < 0)) {
        throw new TypeError("predicate threshold must be a nonnegative safe integer; use a decimal string for larger values");
      }
    }
  }
}
