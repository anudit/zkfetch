// Development helpers: spawn the local notary and HTTPS fixture binaries.
import { join } from "node:path";
import type { Subprocess } from "bun";
import type { TlsVersionPreference } from "@zkfetch/native";

const repoRoot = join(import.meta.dir, "..", "..", "..");
const bin = (name: string) => join(repoRoot, "target", "release", name);

export interface DevNotary {
  url: string;
  publicKey: string;
  proc: Subprocess;
}

export interface DevFixture {
  /** host:port to dial. */
  addr: string;
  /** SNI / certificate name, e.g. `test-server.io`. */
  serverName: string;
  /** Fixture CA, base64 DER. */
  caCert: string;
  proc: Subprocess;
}

async function waitForLine(proc: Subprocess<"ignore", "pipe", "inherit">, prefix: string): Promise<string[]> {
  const reader = proc.stdout.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  const timeout = setTimeout(() => proc.kill(), 30_000);
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) throw new Error(`process exited before printing ${prefix}`);
      buf += decoder.decode(value);
      const line = buf.split("\n").find((l) => l.startsWith(prefix));
      if (line) return line.trim().split(" ").slice(1);
    }
  } finally {
    clearTimeout(timeout);
    reader.releaseLock();
  }
}

/** Starts `zkf-notary` on a random port. `extraRoots` are DER file paths;
 * `proxyResolve` maps proxy-mode server names to `host:port` (fixtures). */
export async function startNotary(opts: { key?: string; extraRoots?: string[]; proxyResolve?: Record<string, string> } = {}): Promise<DevNotary> {
  const proc = Bun.spawn([bin("zkf-notary")], {
    env: {
      ...process.env,
      ZKF_NOTARY_ADDR: "127.0.0.1:0",
      ...(opts.key ? { ZKF_NOTARY_KEY: opts.key } : {}),
      ZKF_EXTRA_ROOTS: (opts.extraRoots ?? []).join(","),
      ZKF_PROXY_RESOLVE: Object.entries(opts.proxyResolve ?? {}).map(([name, addr]) => `${name}=${addr}`).join(","),
    },
    stdout: "pipe",
    stderr: "inherit",
  });
  const [addr, publicKey] = await waitForLine(proc, "ZKF_NOTARY_READY");
  return { url: `ws://${addr}`, publicKey: publicKey!, proc };
}

/** Starts the `zkf-fixture` HTTPS server on a random port. */
export async function startFixture(opts: { tlsVersion?: TlsVersionPreference } = {}): Promise<DevFixture> {
  const proc = Bun.spawn([bin("zkf-fixture")], {
    env: { ...process.env, ZKF_FIXTURE_ADDR: "127.0.0.1:0", ZKF_FIXTURE_TLS_VERSION: opts.tlsVersion ?? "auto" },
    stdout: "pipe",
    stderr: "inherit",
  });
  const [addr, serverName, caCert] = await waitForLine(proc, "ZKF_FIXTURE_READY");
  return { addr: addr!, serverName: serverName!, caCert: caCert!, proc };
}
