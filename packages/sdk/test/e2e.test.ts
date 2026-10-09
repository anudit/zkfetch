// End-to-end through the Bun SDK -> napi addon -> MPC-TLS with a local notary.
// Requires `bun run build` (release binaries + zkf.node).
import { afterAll, beforeAll, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type DevFixture, type DevNotary, restoreResponse, startFixture, startNotary, verify, zkFetch } from "../src";

let fixture: DevFixture;
let fixture13: DevFixture;
let notary: DevNotary;

beforeAll(async () => {
  fixture = await startFixture({ tlsVersion: "1.2" });
  fixture13 = await startFixture({ tlsVersion: "1.3" });
  const caPath = join(mkdtempSync(join(tmpdir(), "zkf-")), "fixture-ca.der");
  writeFileSync(caPath, Buffer.from(fixture.caCert, "base64"));
  notary = await startNotary({ key: "07".repeat(32), extraRoots: [caPath] });
});

afterAll(() => {
  fixture?.proc.kill();
  fixture13?.proc.kill();
  notary?.proc.kill();
});

test("zkFetch -> present -> verify, with tamper and policy rejection", async () => {
  const res = await zkFetch(`https://${fixture.serverName}/formats/json`, {
    headers: { Authorization: "Bearer super-secret-token" },
    zkConfig: {
      notaryUrl: notary.url,
      owner: "0xowner",
      context: "challenge-42",
      connectAddr: fixture.addr,
      extraRootCerts: [fixture.caCert],
      tlsVersion: "1.2",
      // Proven to the notary with QuickSilver during the fetch (default backend).
      predicates: [{ jsonPath: "id", predicate: { gte: "1000000000" } }],
    },
  });

  // Behaves like a normal fetch Response.
  expect(res.status).toBe(200);
  expect(res.headers.get("content-type")).toBe("application/json");
  expect(((await res.json()) as { id: number }).id).toBe(1234567890);
  expect(res.zk.notaryKey.key).toBe(notary.publicKey);
  expect(res.zk.tlsVersion).toBe("1.2");

  // Session survives serialization (decide what to reveal later).
  const restored = restoreResponse(JSON.parse(JSON.stringify(res.zk)));
  const presentation = restored.zk.present({ response: { jsonPaths: ["id"] } });

  const opts = {
    trustedNotaryKeys: [notary.publicKey],
    extraRootCerts: [fixture.caCert],
    expectedOwner: "0xowner",
    expectedContext: "challenge-42",
  };
  const out = verify(presentation, opts);
  expect(out.serverName).toBe(fixture.serverName);
  expect(out.sent).toStartWith("GET /formats/json HTTP/1.1");
  expect(out.sent).not.toContain("super-secret-token");
  expect(out.recv).toStartWith("HTTP/1.1 200 OK");
  expect(out.recv).toContain('"id":1234567890');
  expect(out.recv).not.toContain("John Doe");

  const raw = Buffer.from(presentation, "base64");
  const pos = raw.indexOf("1234567890");
  expect(pos).toBeGreaterThan(-1);
  raw[pos] = raw[pos]! ^ 1;
  expect(() => verify(raw.toString("base64"), opts)).toThrow();

  expect(() => verify(presentation, { ...opts, trustedNotaryKeys: ["02".repeat(33)] })).toThrow();
  expect(() => verify(presentation, { ...opts, expectedContext: "other" })).toThrow();

  const predicate = { jsonPath: "id", predicate: { gte: "1000000000" } } as const;
  const hidden = restored.zk.present({ prove: [predicate] });
  const checked = verify(hidden, { ...opts, expectedPredicates: [predicate] });
  expect(checked.predicates).toEqual([predicate]);
  expect(checked.recv).toContain('"id":');
  expect(checked.recv).not.toContain("1234567890");
  expect(checked.recv).not.toContain("John Doe");
  expect(checked.sent).not.toContain("super-secret-token");
  // A plain disclosure also reveals the JSON skeleton (authenticated paths), so
  // the notary-signed predicate verifies there too; the value is simply visible.
  expect(verify(presentation, { ...opts, expectedPredicates: [predicate] }).predicates).toEqual([predicate]);
  expect(out.json).toEqual([{ path: "id", value: 1234567890 }]);
  expect(out.jsonPathsAuthenticated).toBe(true);
  expect(() => verify(presentation, { ...opts, expectedServerName: "attacker.invalid" })).toThrow();
  expect(() => verify(presentation, { ...opts, expectedTarget: "/wrong" })).toThrow();
  expect(() => verify(presentation, { ...opts, expectedStatus: 404 })).toThrow();
  verify(presentation, { ...opts, expectedServerName: fixture.serverName,
    expectedTarget: "/formats/json", expectedMethod: "GET", expectedStatus: 200,
    maxAgeSecs: 60, requireJsonPaths: true, requireCompleteResponse: true });

  expect(() => verify(hidden, { ...opts, expectedPredicates: [{ jsonPath: "id", predicate: { gt: "1234567890" } }] })).toThrow();
  expect(() => restored.zk.present({ prove: [{ jsonPath: "id", predicate: { gt: "1234567890" } }] })).toThrow();
  expect(() => restored.zk.present({ prove: [{ jsonPath: "id", predicate: { gte: Number.MAX_SAFE_INTEGER + 1 } }] })).toThrow();
  expect(() => restored.zk.present({ response: { jsonPaths: ["id"] }, prove: [predicate] })).toThrow();
  expect(restored.zk.backend).toBe("quicksilver");
  const damaged = Buffer.from(hidden, "base64");
  damaged[damaged.length - 1] = damaged[damaged.length - 1]! ^ 1;
  expect(() => verify(damaged.toString("base64"), opts)).toThrow();

  const dir = mkdtempSync(join(tmpdir(), "zkf-predicate-cli-"));
  const sessionPath = join(dir, "session.json");
  const proofPath = join(dir, "presentation.txt");
  writeFileSync(sessionPath, JSON.stringify(res.zk));
  const cli = join(import.meta.dir, "../../../apps/cli/src/index.ts");
  const presented = Bun.spawnSync([process.execPath, cli, "present", sessionPath, "--gte", "id=1000000000", "-o", proofPath]);
  expect(presented.exitCode).toBe(0);
  const verified = Bun.spawnSync([process.execPath, cli, "verify", proofPath, "--notary-key", notary.publicKey,
    "--ca", fixture.caCert, "--require-gte", "id=1000000000"]);
  expect(verified.exitCode).toBe(0);
  expect(verified.stdout.toString()).toContain('proven id: {"gte":"1000000000"}');
  expect(verified.stdout.toString()).not.toContain("1234567890");
  const stronger = Bun.spawnSync([process.execPath, cli, "verify", proofPath, "--notary-key", notary.publicKey,
    "--ca", fixture.caCert, "--require-gte", "id=1234567891"]);
  expect(stronger.exitCode).toBe(1);
}, 60_000);

test("auto does not retry a failed TLS 1.3 session against a TLS 1.2 fixture", async () => {
  await expect(zkFetch(`https://${fixture.serverName}/formats/json`, {
    zkConfig: { notaryUrl: notary.url, connectAddr: fixture.addr, extraRootCerts: [fixture.caCert] },
  })).rejects.toThrow();
}, 60_000);

test("TLS 1.3-only fixture -> restored session -> disclosure and QuickSilver predicate", async () => {
  const predicate = { jsonPath: "id", predicate: { gte: "1000" } } as const;
  const res = await zkFetch(`https://${fixture13.serverName}/formats/json`, {
    headers: { Authorization: "Bearer tls13-private" },
    zkConfig: {
      notaryUrl: notary.url,
      tlsVersion: "1.3",
      connectAddr: fixture13.addr,
      extraRootCerts: [fixture13.caCert],
      predicates: [predicate],
    },
  });
  expect(res.status).toBe(200);
  expect(res.zk.tlsVersion).toBe("1.3");
  const restored = restoreResponse(JSON.parse(JSON.stringify(res.zk)));
  expect(restored.zk.tlsVersion).toBe("1.3");
  const opts = { trustedNotaryKeys: [notary.publicKey], extraRootCerts: [fixture13.caCert] };
  const disclosed = verify(restored.zk.present({ response: { jsonPaths: ["information.name"] } }), opts);
  expect(disclosed.tlsVersion).toBe("V1_3");
  expect(disclosed.recv).toContain("John Doe");
  expect(disclosed.recv).not.toContain("1234567890");
  expect(disclosed.sent).not.toContain("tls13-private");
  const hidden = verify(restored.zk.present({ prove: [predicate] }), { ...opts, expectedPredicates: [predicate] });
  expect(hidden.predicates).toEqual([predicate]);
  expect(hidden.recv).not.toContain("1234567890");
  const cli = join(import.meta.dir, "../../../apps/cli/src/index.ts");
  const sessionPath = join(mkdtempSync(join(tmpdir(), "zkf-tls13-cli-")), "session.json");
  const fetched = Bun.spawnSync([process.execPath, cli, "fetch", `https://${fixture13.serverName}/formats/json`,
    "--notary", notary.url, "--connect", fixture13.addr, "--ca", fixture13.caCert,
    "--tls-version", "1.3", "--gte", "id=1000", "-o", sessionPath]);
  expect(fetched.exitCode).toBe(0);
  expect(fetched.stderr.toString()).toContain("TLS 1.3");
  expect(restoreResponse(JSON.parse(readFileSync(sessionPath, "utf8"))).zk.tlsVersion).toBe("1.3");
  const invalid = Bun.spawnSync([process.execPath, cli, "fetch", "https://example.com", "--tls-version", "1.4"]);
  expect(invalid.exitCode).toBe(1);
  expect(invalid.stderr.toString()).toContain("--tls-version must be");
}, 60_000);

// Real hosts through the local notary, without auto fallback. Opt-in: ZKF_LIVE=1.
for (const tlsVersion of ["1.2", "1.3"] as const) {
test(`TLS ${tlsVersion}: Binius backend is selected once and survives restoration`, async () => {
  const server = tlsVersion === "1.2" ? fixture : fixture13;
  const predicate = { jsonPath: "id", predicate: { gte: "1000" } } as const;
  const res = await zkFetch(`https://${server.serverName}/formats/json`, {
    zkConfig: {
      notaryUrl: notary.url,
      backend: "binius",
      predicates: [predicate],
      tlsVersion,
      connectAddr: server.addr,
      extraRootCerts: [server.caCert],
    },
  });
  const restored = restoreResponse(JSON.parse(JSON.stringify(res.zk)));
  expect(restored.zk.backend).toBe("binius");
  const opts = { trustedNotaryKeys: [notary.publicKey], extraRootCerts: [server.caCert], expectedPredicates: [predicate] };
  const presentation = restored.zk.present({ prove: [predicate] });
  const out = verify(presentation, opts);
  expect(out.predicates).toEqual([predicate]);
  expect(out.recv).not.toContain("1234567890");
  expect(() => restored.zk.present({ prove: [{ jsonPath: "id", predicate: { gt: "1234567890" } }] })).toThrow();
  expect(() => verify(presentation, { ...opts, expectedPredicates: [{ jsonPath: "id", predicate: { gte: "1234567891" } }] })).toThrow();
}, 120_000);
}

for (const tlsVersion of ["1.2", "1.3"] as const) {
test.skipIf(!process.env.ZKF_LIVE)(`live TLS ${tlsVersion}: public API notarize + selective reveal`, async () => {
  const res = await zkFetch("https://jsonplaceholder.typicode.com/todos/1", {
    zkConfig: { notaryUrl: notary.url, tlsVersion },
  });
  expect(res.status).toBe(200);
  expect(res.zk.tlsVersion).toBe(tlsVersion);
  const todo = (await res.json()) as { title: string };

  const out = verify(res.zk.present({ response: { jsonPaths: ["title"] } }), {
    trustedNotaryKeys: [notary.publicKey],
  });
  expect(out.serverName).toBe("jsonplaceholder.typicode.com");
  expect(out.recv).toContain(`"title": ${JSON.stringify(todo.title)}`);
  expect(out.recv).not.toContain('"userId"');
}, 120_000);
}
