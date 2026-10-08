// Reads the two disclosed claims from a Duolingo response transcript.
//
// Undisclosed bytes are X, so a selectively disclosed transcript is not valid
// JSON. The match is confined to the HTTP body, must be unique, must be a
// complete JSON token, and (for a verified transcript) every matched byte must
// lie in an authenticated range: a hidden byte and a literal X look the same.

const USERNAME = /"username"\s*:\s*("(?:[^"\\]|\\.)*")/g;
const LONGEST_STREAK = /"longestStreak"\s*:\s*\{[^{}]*?"length"\s*:\s*(0|[1-9]\d*)(?=\s*[,}])/g;

const encoder = new TextEncoder();
const byteOffset = (text: string, index: number) => encoder.encode(text.slice(0, index)).length;

function unique(pattern: RegExp, body: string, what: string): RegExpExecArray {
  const matches = [...body.matchAll(pattern)];
  if (matches.length === 0) throw new Error(`Duolingo ${what} is missing from the response.`);
  if (matches.length > 1) throw new Error(`The response contains more than one ${what}.`);
  return matches[0]!;
}

/**
 * @param transcript HTTP response (status line and headers optional).
 * @param authed Authenticated byte ranges `[start, end)` of `transcript`, from
 *   `verify()`. Omit only for a response read directly from the server.
 */
export function readClaims(
  transcript: string,
  authed?: [number, number][],
): { username: string; longestStreak: number } {
  const split = transcript.startsWith("HTTP/") ? transcript.indexOf("\r\n\r\n") : -1;
  if (transcript.startsWith("HTTP/") && split < 0) throw new Error("The response has no body.");
  const bodyStart = split < 0 ? 0 : split + 4;
  const body = transcript.slice(bodyStart);

  const requireAuthed = (match: RegExpExecArray, what: string) => {
    if (!authed) return;
    const start = byteOffset(transcript, bodyStart + match.index);
    const end = byteOffset(transcript, bodyStart + match.index + match[0].length);
    if (!authed.some(([from, to]) => from <= start && end <= to)) {
      throw new Error(`The ${what} in the proof is not fully disclosed.`);
    }
  };

  const username = unique(USERNAME, body, "username");
  const streak = unique(LONGEST_STREAK, body, "longest streak");
  requireAuthed(username, "username");
  requireAuthed(streak, "longest streak");
  const longestStreak = Number(streak[1]);
  if (!Number.isSafeInteger(longestStreak)) throw new Error("Invalid longest streak in the response.");
  return { username: JSON.parse(username[1]!) as string, longestStreak };
}

/**
 * Reads the claims from `verify()`'s path-authenticated JSON fields: exact
 * paths, so a value elsewhere in the response (or in a header) cannot stand in.
 */
export function claimsFromFields(fields: { path: string; value: unknown }[]): { username: string; longestStreak: number } {
  const field = (path: string) => {
    const matches = fields.filter(f => f.path === path);
    if (matches.length !== 1) throw new Error(`The proof does not disclose ${path} at a verified path.`);
    return matches[0]!.value;
  };
  const username = field("username");
  const longestStreak = field("streakData.longestStreak.length");
  if (typeof username !== "string") throw new Error("Invalid username in the proof.");
  if (typeof longestStreak !== "number" || !Number.isSafeInteger(longestStreak) || longestStreak < 0) {
    throw new Error("Invalid longest streak in the proof.");
  }
  return { username, longestStreak };
}
