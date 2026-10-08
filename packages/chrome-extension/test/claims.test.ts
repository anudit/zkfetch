import { expect, test } from "bun:test";
import { readClaims } from "../src/claims";

test("reads claims from a selectively disclosed response with hidden bytes", () => {
  const transcript = 'HTTP/1.1 200 OK\r\nContent-Length: 120\r\n\r\n{"username":"anudit","hidden":XXXX,"streakData":{"longestStreak":{"length":123,"endDate":"2026-10-08"}}}';
  expect(readClaims(transcript)).toEqual({ username: "anudit", longestStreak: 123 });
});

test("rejects a response with missing streak instead of displaying a default", () => {
  expect(() => readClaims('{"username":"anudit","streakData":null}')).toThrow("missing");
});

test("handles JSON escapes in the disclosed username", () => {
  expect(readClaims('{"username":"a\\\"b","longestStreak":{"length":0}}')).toEqual({ username: 'a"b', longestStreak: 0 });
});
