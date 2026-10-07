import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";

// Deploys the US, EU and SEA notaries with one shared signing key, waits for
// each container to report healthy, and writes a public manifest.
//
//   bun run deploy            all regions
//   bun run deploy eu sea     a subset

const root = join(import.meta.dir, "../../..");
const keyPath = join(root, ".zkf/hosted-notary.key");
const notaryBin = join(root, "target/release/zkf-notary");
const regions = process.argv.slice(2).length ? process.argv.slice(2) : ["us", "eu", "sea"];

if (!existsSync(keyPath)) {
  mkdirSync(join(root, ".zkf"), { recursive: true });
  writeFileSync(keyPath, randomBytes(32).toString("hex"), { mode: 0o600 });
  console.log(`generated hosted notary key at ${keyPath}`);
}
const key = readFileSync(keyPath, "utf8").trim();
const publicKey = await derivePublicKey(key);
console.log(`notary public key ${publicKey}`);

await run(["bun", "scripts/configure.ts"]);
const secretsDir = join(root, ".zkf/deploy");
mkdirSync(secretsDir, { recursive: true, mode: 0o700 });
const secretsFile = join(secretsDir, "secrets.json");
writeFileSync(secretsFile, JSON.stringify({ ZKF_NOTARY_KEY: key }), { mode: 0o600 });
chmodSync(secretsFile, 0o600);

const manifestPath = join(import.meta.dir, "../deployments.json");
const manifest: Record<string, unknown> = existsSync(manifestPath) ? JSON.parse(readFileSync(manifestPath, "utf8")) : {};
try {
  for (const region of regions) {
    console.log(`\n=== deploying ${region} ===`);
    const out = await run(["bunx", "wrangler", "deploy", "-c", `wrangler.${region}.jsonc`,
      "--secrets-file", secretsFile, "--containers-rollout", "immediate"]);
    const host = out.match(/https:\/\/([\w.-]+\.workers\.dev)/)?.[1];
    if (!host) throw new Error(`could not find workers.dev URL in ${region} deploy output`);
    const health = await waitHealthy(`https://${host}/health`);
    if (health.publicKey !== publicKey) throw new Error(`${region} serves key ${health.publicKey}, expected ${publicKey}`);
    manifest[region] = { url: `wss://${host}/notarize`, health: `https://${host}/health`, publicKey,
      location: health.location, deployedAt: new Date().toISOString() };
    console.log(`${region} healthy at wss://${host}/notarize (${health.location ?? "unknown location"})`);
  }
} finally {
  rmSync(secretsFile, { force: true });
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
}

async function run(cmd: string[]): Promise<string> {
  const proc = Bun.spawn(cmd, { cwd: join(import.meta.dir, ".."), stdout: "pipe", stderr: "inherit" });
  let out = "";
  for await (const chunk of proc.stdout.pipeThrough(new TextDecoderStream())) {
    process.stdout.write(chunk);
    out += chunk;
  }
  if ((await proc.exited) !== 0) throw new Error(`${cmd.join(" ")} failed`);
  return out;
}

async function derivePublicKey(hexKey: string): Promise<string> {
  if (!existsSync(notaryBin)) throw new Error("build the notary first: bun run build:bins");
  const { ZKF_HEALTH_ADDR: _, ...env } = process.env;
  const proc = Bun.spawn([notaryBin], { stdout: "pipe", stderr: "ignore",
    env: { ...env, ZKF_NOTARY_KEY: hexKey, ZKF_NOTARY_ADDR: "127.0.0.1:0" } });
  try {
    for await (const chunk of proc.stdout.pipeThrough(new TextDecoderStream())) {
      const match = chunk.match(/ZKF_NOTARY_READY \S+ ([0-9a-f]{66})/);
      if (match) return match[1];
    }
    throw new Error("notary exited before printing its public key");
  } finally {
    proc.kill();
  }
}

async function waitHealthy(url: string): Promise<{ publicKey: string; location?: string }> {
  const deadline = Date.now() + 5 * 60_000;
  let last = "";
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) return await res.json() as { publicKey: string; location?: string };
      last = `${res.status} ${await res.text()}`;
    } catch (err) {
      last = String(err);
    }
    await Bun.sleep(5_000);
  }
  throw new Error(`${url} not healthy after 5 minutes: ${last}`);
}
