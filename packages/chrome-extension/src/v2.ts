import type { MemberPredicate, VerifyV2Options } from "@omnid/zkfetch";

/** Issued by the panel before proving; never extracted from the presentation. */
export function verifierNonce(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)), byte => byte.toString(16).padStart(2, "0")).join("");
}

export const STREAK_PATH = ["streakData", "longestStreak", "length"] as const;

/** Select the value to claim; the offline circuit authenticates the exact path. */
export function streakMember(body: string): MemberPredicate {
  const data = JSON.parse(body);
  const value = data?.streakData?.longestStreak?.length;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error("Duolingo streakData.longestStreak.length must be an unsigned safe integer.");
  }
  return { key: "length", path: [...STREAK_PATH], unique: true, op: "eq", value: String(value) };
}

export function v2VerificationPolicy(predicate: MemberPredicate, nonce: string, notaryKey: string): VerifyV2Options {
  if (!/^[0-9a-f]{64}$/.test(nonce)) throw new Error("V2 verification needs the panel's 32-byte challenge.");
  if (predicate.key !== "length" || predicate.op !== "eq"
    || JSON.stringify(predicate.path) !== JSON.stringify(STREAK_PATH) || predicate.unique !== true || !/^(0|[1-9]\d*)$/.test(String(predicate.value))) {
    throw new Error("Expected a unique v2 equality claim for streakData.longestStreak.length.");
  }
  return {
    trustedNotaryKeys: [notaryKey], expectedServerName: "www.duolingo.com",
    predicate, nonce, maxAgeSecs: 600,
  };
}

export const TOP_LEVEL_URL = "https://jsonplaceholder.typicode.com/todos/1";
export const TOP_LEVEL_PREDICATE: MemberPredicate = { key: "id", op: "eq", value: "1" };

/** A verifier-owned policy: never infer the expected origin or claim from a proof. */
export function topLevelVerificationPolicy(predicate: MemberPredicate, nonce: string, notaryKey: string): VerifyV2Options {
  if (!/^[0-9a-f]{64}$/.test(nonce)) throw new Error("V2 verification needs the panel's 32-byte challenge.");
  if (predicate.key !== "id" || predicate.op !== "eq" || String(predicate.value) !== "1"
    || (predicate.path?.length ?? 0) !== 0 || predicate.unique === true) {
    throw new Error("Expected the top-level id = 1 example claim.");
  }
  return { trustedNotaryKeys: [notaryKey], expectedServerName: "jsonplaceholder.typicode.com",
    predicate: { ...TOP_LEVEL_PREDICATE }, nonce, maxAgeSecs: 600 };
}
