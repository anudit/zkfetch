// Typed loader for the zkf-napi addon (Node.js / Bun).
import { createRequire } from "node:module";
import { join } from "node:path";
import { validatePredicates, type NotarizeOutput, type NotarizeParams, type RevealSpec, type VerifyOptions, type VerifyOutput } from "./types";

export * from "./types";

interface Addon {
  notarize(paramsJson: string): Promise<string>;
  present(attestation: string, secrets: string, specJson: string): string;
  verify(presentation: string, optionsJson: string): string;
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
