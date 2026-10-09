#!/usr/bin/env bun
// zkfetch CLI: fetch -> (interactive) reveal -> present -> verify.
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { writePrivateFile } from "./output";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type ParseArgsOptionsConfig, parseArgs } from "node:util";
import {
  type RevealSpec,
  type PredicateSpec,
  type ZkSessionData,
  type TlsVersionPreference,
  type PredicateBackend,
  restoreResponse,
  startFixture,
  startNotary,
  verify,
  zkFetch,
} from "@omnid/zkfetch";

const USAGE = `zkfetch — fetch with a notarized MPC-TLS proof, then selectively disclose it.

  zkfetch fetch <url> [-X METHOD] [-H "Name: value"]... [-d BODY] [--notary URL] [--notary-key HEX]
                [--owner ID] [--context NONCE] [--connect host:port] [--ca base64-der]
                [--gte PATH=DECIMAL]... [--backend quicksilver|binius] [--tls-version 1.2|1.3|auto] [-o session.json] [--print-response]
                  --gte     prove PATH >= DECIMAL to the notary now (QuickSilver, default)
                  --backend select the predicate backend for fetch and presentation
  zkfetch reveal <session.json> [-o presentation.txt]        interactive picker
  zkfetch present <session.json> [--json PATH]... [--header NAME]... [--body]
                [--request-header NAME]... [--hide-target] [--gte PATH=DECIMAL]...
                [-o presentation.txt]
  zkfetch verify <presentation.txt> --notary-key HEX... [--owner ID] [--context NONCE]
                [--ca base64-der] [--require-gte PATH=DECIMAL]... [--reject-proxy]
                [--allow-untrusted]   inspect without a trusted notary key
  zkfetch dev                                                 start local notary + HTTPS fixture

Env: ZKF_NOTARY_KEY (required for remote sessions), ZKF_NOTARY_URL (default ws://127.0.0.1:7047), ZKF_EXTRA_CA (comma-separated base64 DER roots), ZKF_TLS_VERSION (default auto)
session.json holds secrets that open every commitment; keep it private.`;

const [cmd, ...rest] = process.argv.slice(2);

function args<const T extends ParseArgsOptionsConfig>(options: T) {
  return parseArgs({ args: rest, options, allowPositionals: true, strict: true });
}

const extraCa = (flag: string[] | undefined) =>
  flag ?? process.env.ZKF_EXTRA_CA?.split(",").filter(Boolean);

function readSession(path: string | undefined) {
  if (!path) throw new Error("missing session.json path");
  return restoreResponse(JSON.parse(readFileSync(path, "utf8")) as ZkSessionData);
}

function writeOut(path: string | undefined, data: string, what: string, secret = false) {
  if (path) {
    // Sessions open every commitment: readable by the owner only.
    if (secret) writePrivateFile(path, data);
    else writeFileSync(path, data);
    console.error(`${what} written to ${path}`);
  } else {
    console.log(data);
  }
}

async function cmdFetch() {
  const { values, positionals } = args({
    method: { type: "string", short: "X" },
    header: { type: "string", short: "H", multiple: true },
    data: { type: "string", short: "d" },
    notary: { type: "string" },
    "notary-key": { type: "string" },
    owner: { type: "string" },
    context: { type: "string" },
    connect: { type: "string" },
    ca: { type: "string", multiple: true },
    gte: { type: "string", multiple: true },
    binius: { type: "boolean" },
    backend: { type: "string" },
    "tls-version": { type: "string" },
    out: { type: "string", short: "o" },
    "print-response": { type: "boolean" },
  });
  const url = positionals[0];
  if (!url) throw new Error("missing url");
  const tlsVersion = values["tls-version"] ?? process.env.ZKF_TLS_VERSION ?? "auto";
  if (!["1.2", "1.3", "auto"].includes(tlsVersion)) throw new Error("--tls-version must be 1.2, 1.3 or auto");
  const backend = values.backend ?? (values.binius ? "binius" : "quicksilver");
  if (backend !== "quicksilver" && backend !== "binius") throw new Error("--backend must be quicksilver or binius");
  if (values.binius && backend !== "binius") throw new Error("--binius conflicts with --backend quicksilver");
  const headers = (values.header ?? []).map((h) => {
    const i = h.indexOf(":");
    if (i < 1) throw new Error(`bad header ${h}`);
    return [h.slice(0, i).trim(), h.slice(i + 1).trim()] as [string, string];
  });

  const started = performance.now();
  const res = await zkFetch(url, {
    method: values.method,
    headers,
    body: values.data,
    zkConfig: {
      expectedNotaryKey: values["notary-key"] ?? process.env.ZKF_NOTARY_KEY,
      notaryUrl: values.notary ?? process.env.ZKF_NOTARY_URL ?? "ws://127.0.0.1:7047",
      owner: values.owner,
      context: values.context,
      connectAddr: values.connect,
      extraRootCerts: extraCa(values.ca),
      predicates: parsePredicates(values.gte),
      backend: backend as PredicateBackend,
      tlsVersion: tlsVersion as TlsVersionPreference,
    },
  });
  console.error(`HTTP ${res.status} (TLS ${res.zk.tlsVersion}) — notarized in ${((performance.now() - started) / 1000).toFixed(2)}s`);
  console.error(`notary ${res.zk.notaryKey.alg} ${res.zk.notaryKey.key}`);
  if (values["print-response"]) console.error(await res.text());
  writeOut(values.out ?? "session.zkf.json", JSON.stringify(res.zk, null, 2), "session (contains secrets)", true);
}

function cmdPresent() {
  const { values, positionals } = args({
    json: { type: "string", multiple: true },
    header: { type: "string", multiple: true },
    body: { type: "boolean" },
    "request-header": { type: "string", multiple: true },
    "hide-target": { type: "boolean" },
    gte: { type: "string", multiple: true },
    out: { type: "string", short: "o" },
  });
  const spec: RevealSpec = {
    request: { target: !values["hide-target"], headers: values["request-header"] ?? [] },
    response: { headers: values.header ?? [], body: values.body ?? false, jsonPaths: values.json ?? [] },
    prove: parsePredicates(values.gte),
  };
  writeOut(values.out, readSession(positionals[0]).zk.present(spec), "presentation");
}

/** Dotted paths of every leaf in a JSON value (array indexes as numbers). */
function leafPaths(value: unknown, prefix = ""): string[] {
  if (value !== null && typeof value === "object") {
    return Object.entries(value).flatMap(([k, v]) => leafPaths(v, prefix ? `${prefix}.${k}` : k));
  }
  return prefix ? [prefix] : [];
}

async function cmdReveal() {
  const { values, positionals } = args({ out: { type: "string", short: "o" } });
  const res = readSession(positionals[0]);
  const choices: { label: string; apply: (s: Required<RevealSpec>) => void }[] = [];

  const alwaysShown = new Set(["content-length", "transfer-encoding", "content-type"]);
  for (const [name] of res.headers) {
    if (alwaysShown.has(name)) continue;
    choices.push({ label: `response header  ${name}`, apply: (s) => s.response.headers!.push(name) });
  }
  const text = await res.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {}
  if (parsed !== undefined) {
    for (const path of leafPaths(parsed)) {
      const preview = JSON.stringify(path.split(".").reduce<any>((o, k) => o?.[k], parsed));
      choices.push({
        label: `json  ${path} = ${preview.length > 40 ? `${preview.slice(0, 37)}...` : preview}`,
        apply: (s) => s.response.jsonPaths!.push(path),
      });
    }
  }
  choices.push({ label: "entire response body", apply: (s) => (s.response.body = true) });

  console.log("Always disclosed: request line structure, Host, header names, status line, framing headers.\n");
  choices.forEach((c, i) => console.log(`  [${i + 1}] ${c.label}`));
  const answer = prompt("\nReveal which? (comma-separated numbers, empty = nothing extra):") ?? "";

  const spec: Required<RevealSpec> = {
    request: { target: true, headers: [] },
    response: { headers: [], jsonPaths: [] },
    prove: [],
  };
  for (const n of answer.split(",").map((s) => Number(s.trim())).filter(Boolean)) {
    const choice = choices[n - 1];
    if (!choice) throw new Error(`no option ${n}`);
    choice.apply(spec);
  }
  writeOut(values.out ?? "presentation.txt", res.zk.present(spec), "presentation");
}

function cmdVerify() {
  const { values, positionals } = args({
    "notary-key": { type: "string", multiple: true },
    owner: { type: "string" },
    context: { type: "string" },
    ca: { type: "string", multiple: true },
    "require-gte": { type: "string", multiple: true },
    "reject-proxy": { type: "boolean" },
    "allow-untrusted": { type: "boolean" },
  });
  if (!positionals[0]) throw new Error("missing presentation path");
  const out = verify(readFileSync(positionals[0], "utf8").trim(), {
    trustedNotaryKeys: values["notary-key"] ?? [],
    allowUntrustedNotary: values["allow-untrusted"],
    rejectProxy: values["reject-proxy"],
    expectedOwner: values.owner,
    expectedContext: values.context,
    extraRootCerts: extraCa(values.ca),
    expectedPredicates: parsePredicates(values["require-gte"]),
  });
  console.log(`${out.notaryTrusted ? "✔ valid" : "⚠ UNTRUSTED (inspection only)"} presentation from ${out.serverName} at ${new Date(out.time * 1000).toISOString()} (${out.tlsVersion}, ${out.mode})`);
  console.log(
    `  notary ${out.notaryKey.alg} ${out.notaryKey.key}${out.notaryTrusted ? " (trusted)" : "  ⚠ not a trusted key: this proves nothing about the server"}`,
  );
  if (out.owner) console.log(`  owner ${out.owner}`);
  if (out.context) console.log(`  context ${out.context}`);
  for (const claim of out.predicates) console.log(`  proven ${claim.jsonPath}: ${JSON.stringify(claim.predicate)}`);
  console.log("\n--- sent (X = undisclosed) ---\n" + out.sent + "\n--- received ---\n" + out.recv);
}

function parsePredicates(values?: string[]): PredicateSpec[] {
  return (values ?? []).map((input) => {
    const i = input.lastIndexOf("=");
    if (i < 1 || !/^\d+$/.test(input.slice(i + 1))) throw new Error("expected PATH=DECIMAL for predicate");
    return { jsonPath: input.slice(0, i), predicate: { gte: input.slice(i + 1) } };
  });
}

async function cmdDev() {
  const fixture = await startFixture();
  const caPath = join(mkdtempSync(join(tmpdir(), "zkf-")), "fixture-ca.der");
  writeFileSync(caPath, Buffer.from(fixture.caCert, "base64"));
  const notary = await startNotary({ extraRoots: [caPath] });
  console.log(`notary   ${notary.url}  key ${notary.publicKey}`);
  console.log(`fixture  https://${fixture.serverName} at ${fixture.addr}\n`);
  console.log("in another shell:\n");
  console.log(`  export ZKF_NOTARY_URL=${notary.url}`);
  console.log(`  export ZKF_EXTRA_CA=${fixture.caCert}`);
  console.log(`  bun zkfetch fetch https://${fixture.serverName}/formats/json --connect ${fixture.addr} -H "Authorization: Bearer secret"`);
  console.log("  bun zkfetch reveal session.zkf.json");
  console.log(`  bun zkfetch verify presentation.txt --notary-key ${notary.publicKey}\n`);
  const stop = () => {
    fixture.proc.kill();
    notary.proc.kill();
    process.exit(0);
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
  await new Promise(() => {});
}

const commands: Record<string, () => unknown> = {
  fetch: cmdFetch,
  present: cmdPresent,
  reveal: cmdReveal,
  verify: cmdVerify,
  dev: cmdDev,
};

const run = cmd ? commands[cmd] : undefined;
if (!run) {
  console.log(USAGE);
  process.exit(cmd ? 1 : 0);
}
try {
  await run();
} catch (err) {
  console.error(`error: ${err instanceof Error ? err.message : err}`);
  process.exit(1);
}
