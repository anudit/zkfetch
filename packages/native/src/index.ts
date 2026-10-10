// Typed loader for the zkf-napi addon (Node.js / Bun).
import { createRequire } from "node:module";
import { join } from "node:path";
import {
  validateMemberPredicate,
  validatePredicates,
  type NotarizeOutput,
  type NotarizeParams,
  type PresentV2Request,
  type RevealSpec,
  type VerifyOptions,
  type VerifyOutput,
  type VerifyV2Options,
  type VerifyV2Output,
} from "./types";

export * from "./types";

interface Addon {
  notarize(paramsJson: string): Promise<string>;
  present(attestation: string, secrets: string, specJson: string): string;
  verify(presentation: string, optionsJson: string): string;
  presentV2(attestation: string, secrets: string, requestJson: string): Promise<string>;
  verifyV2(presentation: string, optionsJson: string): Promise<string>;
}

const addon = createRequire(import.meta.url)(join(import.meta.dir, "..", "zkf.node")) as Addon;

export async function notarize(params: NotarizeParams): Promise<NotarizeOutput> {
  validatePredicates(params.predicates);
  validatePredicates(params.reveal?.prove);
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

/** Experimental: proves `request.predicate` about a v2 session offline. */
export async function presentV2(attestation: string, secrets: string, request: PresentV2Request): Promise<string> {
  validateMemberPredicate(request.predicate);
  return addon.presentV2(attestation, secrets, JSON.stringify(request));
}

/** Experimental: verifies a v2 presentation against the verifier's policy. */
export async function verifyV2(presentation: string, options: VerifyV2Options): Promise<VerifyV2Output> {
  validateMemberPredicate(options.predicate);
  return JSON.parse(await addon.verifyV2(presentation, JSON.stringify(options)));
}
