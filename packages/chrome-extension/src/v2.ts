import type { MemberPredicate, VerifyV2Options } from "@omnid/zkfetch";

/** Issued by the panel before proving; never extracted from the presentation. */
export function verifierNonce(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)), byte => byte.toString(16).padStart(2, "0")).join("");
}

/** The current v2 query proves root-object members; Duolingo streaks are nested. */
export function streakMember(_body: string): MemberPredicate {
  throw new Error("V2 proves top-level JSON members only. Duolingo streaks require a nested-path proof; use v1 for this claim.");
}

export function v2VerificationPolicy(predicate: MemberPredicate, nonce: string, notaryKey: string): VerifyV2Options {
  if (!/^[0-9a-f]{64}$/.test(nonce)) throw new Error("V2 verification needs the panel's 32-byte challenge.");
  if (predicate.key !== "length" || predicate.op !== "eq" || !/^(0|[1-9]\d*)$/.test(String(predicate.value))) {
    throw new Error("Expected a v2 equality claim for the JSON member length.");
  }
  return {
    trustedNotaryKeys: [notaryKey], expectedServerName: "www.duolingo.com",
    predicate, nonce, maxAgeSecs: 600,
  };
}
