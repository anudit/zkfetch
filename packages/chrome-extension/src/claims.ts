export function readClaims(transcript: string): { username: string; longestStreak: number } {
  // Undisclosed bytes are X, so the selectively disclosed transcript need not
  // be valid JSON. Match only the two fields selected by this extension.
  const username = /"username"\s*:\s*("(?:[^"\\]|\\.)*")/.exec(transcript)?.[1];
  const length = /"longestStreak"\s*:\s*\{[^}]*"length"\s*:\s*(\d+)/.exec(transcript)?.[1];
  if (!username || length === undefined) throw new Error("Duolingo username or longest streak is missing from the response.");
  const longestStreak = Number(length);
  if (!Number.isSafeInteger(longestStreak)) throw new Error("Invalid longest streak in the response.");
  return { username: JSON.parse(username) as string, longestStreak };
}
