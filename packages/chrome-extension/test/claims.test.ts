import { expect, test } from "bun:test";
import { claimsFromFields, readClaims } from "../src/claims";

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

const body = '{"username":"anudit","streakData":{"longestStreak":{"length":123,"endDate":"2026-10-08"}}}';
const response = `HTTP/1.1 200 OK\r\nX-Echo: "username":"evil"\r\n\r\n${body}`;
const allAuthed: [number, number][] = [[0, new TextEncoder().encode(response).length]];

test("ignores matches in headers and reads the body", () => {
  expect(readClaims(response, allAuthed)).toEqual({ username: "anudit", longestStreak: 123 });
});

test("rejects incomplete or non-integer numeric tokens", () => {
  for (const value of ["1e9", "123.45", "123XXX", "0123", "-5"]) {
    const transcript = `{"username":"a","longestStreak":{"length":${value}}}`;
    expect(() => readClaims(transcript)).toThrow();
  }
});

test("rejects duplicate claims", () => {
  expect(() => readClaims('{"username":"a","x":{"username":"b"},"longestStreak":{"length":1}}')).toThrow("more than one");
});

test("requires the matched claims to be authenticated", () => {
  const start = new TextEncoder().encode(response.slice(0, response.indexOf('"longestStreak"'))).length;
  // Everything authenticated except the streak.
  expect(() => readClaims(response, [[0, start]])).toThrow("not fully disclosed");
  // A literal-looking value that is in fact undisclosed.
  expect(() => readClaims(response, [])).toThrow("not fully disclosed");
});

test("reads claims only from exact verified paths", () => {
  const fields = [
    { path: "username", value: "anudit" },
    { path: "streakData.longestStreak.length", value: 123 },
    { path: "streakData.longestStreak.endDate", value: "2026-10-08" },
  ];
  expect(claimsFromFields(fields)).toEqual({ username: "anudit", longestStreak: 123 });
  expect(() => claimsFromFields([{ path: "other.username", value: "x" }, fields[1]!])).toThrow("verified path");
  expect(() => claimsFromFields([fields[0]!, { path: "streakData.longestStreak.length", value: 1.5 }])).toThrow("Invalid");
});
