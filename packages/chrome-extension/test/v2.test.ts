import { expect, test } from "bun:test";
import { streakMember, verifierNonce, v2VerificationPolicy } from "../src/v2";

test("v2 selects the exact Duolingo path and requires uniqueness in the proof", () => {
  expect(streakMember('{"streakData":{"longestStreak":{"length":123}},"length":999}'))
    .toEqual({ key: "length", path: ["streakData", "longestStreak", "length"], unique: true, op: "eq", value: "123" });
  for (const body of ['{"other":{"length":123}}', '{"length":123}',
    '{"streakData":{"longestStreak":{"length":-1}}}',
    '{"streakData":{"longestStreak":{"length":1.5}}}']) expect(() => streakMember(body)).toThrow();
});

test("v2 challenge is issued before proving and verification pins server and notary", () => {
  const nonce = verifierNonce();
  expect(nonce).toMatch(/^[0-9a-f]{64}$/);
  expect(verifierNonce()).not.toBe(nonce);
  const predicate = { key: "length", path: ["streakData", "longestStreak", "length"], unique: true, op: "eq" as const, value: "123" };
  expect(v2VerificationPolicy(predicate, nonce, "pinned-key")).toEqual({
    trustedNotaryKeys: ["pinned-key"], expectedServerName: "www.duolingo.com",
    predicate, nonce, maxAgeSecs: 600,
  });
  for (const invalid of ["", "00", "a".repeat(63), "z".repeat(64)]) {
    expect(() => v2VerificationPolicy(predicate, invalid, "key")).toThrow();
  }
  for (const invalid of [
    { ...predicate, key: "username" }, { ...predicate, path: ["length"] }, { ...predicate, unique: false }, { ...predicate, op: "ge" },
    { ...predicate, value: "-1" }, { ...predicate, value: "123.5" },
  ] as const) expect(() => v2VerificationPolicy(invalid, nonce, "key")).toThrow();
});

test("public top-level example pins the claim, server, notary and challenge", async () => {
  const { TOP_LEVEL_PREDICATE, TOP_LEVEL_URL, topLevelVerificationPolicy } = await import("../src/v2");
  expect(TOP_LEVEL_URL).toBe("https://jsonplaceholder.typicode.com/todos/1");
  const nonce = verifierNonce();
  expect(topLevelVerificationPolicy(TOP_LEVEL_PREDICATE, nonce, "pin")).toEqual({
    trustedNotaryKeys: ["pin"], expectedServerName: "jsonplaceholder.typicode.com",
    predicate: { key: "id", op: "eq", value: "1" }, nonce, maxAgeSecs: 600,
  });
  for (const predicate of [
    { ...TOP_LEVEL_PREDICATE, key: "userId" }, { ...TOP_LEVEL_PREDICATE, value: "2" },
    { ...TOP_LEVEL_PREDICATE, op: "ge" as const }, { ...TOP_LEVEL_PREDICATE, path: ["history", "id"] },
    { ...TOP_LEVEL_PREDICATE, unique: true },
  ]) expect(() => topLevelVerificationPolicy(predicate, nonce, "pin")).toThrow();
  expect(() => topLevelVerificationPolicy(TOP_LEVEL_PREDICATE, "00", "pin")).toThrow();
});
