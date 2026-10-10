import { expect, test } from "bun:test";
import { streakMember, verifierNonce, v2VerificationPolicy } from "../src/v2";

test("v2 rejects the nested Duolingo streak claim instead of proving another member", () => {
  for (const body of ['{"streakData":{"longestStreak":{"length":123}},"length":999}',
    '{"streakData":{"longestStreak":{"length":123}}}', '{"other":{"length":123}}']) {
    expect(() => streakMember(body)).toThrow("top-level JSON members only");
  }
});

test("v2 challenge is issued before proving and verification pins server and notary", () => {
  const nonce = verifierNonce();
  expect(nonce).toMatch(/^[0-9a-f]{64}$/);
  expect(verifierNonce()).not.toBe(nonce);
  const predicate = { key: "length", op: "eq", value: "123" } as const;
  expect(v2VerificationPolicy(predicate, nonce, "pinned-key")).toEqual({
    trustedNotaryKeys: ["pinned-key"], expectedServerName: "www.duolingo.com",
    predicate, nonce, maxAgeSecs: 600,
  });
  for (const invalid of ["", "00", "a".repeat(63), "z".repeat(64)]) {
    expect(() => v2VerificationPolicy(predicate, invalid, "key")).toThrow();
  }
  for (const invalid of [
    { ...predicate, key: "username" }, { ...predicate, op: "ge" },
    { ...predicate, value: "-1" }, { ...predicate, value: "123.5" },
  ] as const) expect(() => v2VerificationPolicy(invalid, nonce, "key")).toThrow();
});
