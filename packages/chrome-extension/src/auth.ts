export interface Auth {
  token: string;
  source: "cookie" | "bearer";
  userId?: string;
}

export function tokenClaims(token: string): { sub?: unknown; exp?: unknown } {
  try {
    const part = token.split(".")[1];
    if (!part) return {};
    const value: unknown = JSON.parse(atob(part.replace(/-/g, "+").replace(/_/g, "/")));
    return value && typeof value === "object" ? value : {};
  } catch {
    return {};
  }
}

export function tokenUserId(token: string): string | undefined {
  const sub = tokenClaims(token).sub;
  if (typeof sub !== "string" && typeof sub !== "number") return undefined;
  return /^\d+$/.test(String(sub)) ? String(sub) : undefined;
}

export function tokenExpired(token: string): boolean {
  const exp = tokenClaims(token).exp;
  return typeof exp === "number" && exp * 1000 <= Date.now();
}
