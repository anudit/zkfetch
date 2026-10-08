import { beforeEach, expect, test } from "bun:test";
import type { Auth } from "../src/auth";
import type { BackgroundReply, BackgroundRequest } from "../src/messages";

const listeners: Record<string, (...args: any[]) => any> = {};
let stored: { auth?: Auth } = {};
let cookie: { value: string } | null = null;
let tabs: { id: number; windowId: number }[] = [];
let created = 0;
let focused = 0;
let panelPath = "sidepanel.html";
const extensionUrl = () => `chrome-extension://test/${panelPath}`;

// Exercise the actual registered MV3 handlers; only Chrome's platform APIs
// are replaced. Tokens here are synthetic and never real credentials.
globalThis.chrome = {
  sidePanel: { setPanelBehavior: async () => {} },
  storage: { session: {
    set: async (value: { auth: Auth }) => { stored = { ...stored, ...value }; },
    get: async () => stored,
    remove: async () => { stored = {}; },
  } },
  cookies: { get: async () => cookie, onChanged: { addListener: (fn: any) => { listeners.cookie = fn; } } },
  webRequest: { onBeforeSendHeaders: { addListener: (fn: any) => { listeners.request = fn; } } },
  tabs: {
    query: async () => tabs,
    create: async () => { created++; const tab = { id: 7, windowId: 1 }; tabs.push(tab); return tab; },
    update: async () => { focused++; },
  },
  windows: { update: async () => {} },
  runtime: {
    id: "test",
    getURL: (path: string) => `chrome-extension://test/${path}`,
    getManifest: () => ({ side_panel: { default_path: panelPath } }),
    onMessage: { addListener: (fn: any) => { listeners.message = fn; } },
  },
} as unknown as typeof chrome;
await import("../src/background");

const jwt = (claims: object) => `header.${btoa(JSON.stringify(claims))}.signature`;
const send = (message: BackgroundRequest) => new Promise<BackgroundReply>(resolve => {
  listeners.message!(message, { id: "test", url: extensionUrl() }, resolve);
});

beforeEach(() => {
  stored = {};
  cookie = null;
  tabs = [];
  created = focused = 0;
  panelPath = "sidepanel.html";
});

test("loading the package directory allows its built panel to communicate", async () => {
  panelPath = "dist/sidepanel.html";
  const reply = await send({ type: "open-duolingo" });
  expect(reply.ok && reply.status.tabOpen).toBe(true);
});

test("opening the panel creates Duolingo once and reuses its tab", async () => {
  await send({ type: "open-duolingo" });
  await send({ type: "open-duolingo" });
  expect(created).toBe(1);
  expect(focused).toBe(0);
  await send({ type: "open-duolingo", focus: true });
  expect(focused).toBe(1);
});

test("status reports a cookie credential without sending its value", async () => {
  cookie = { value: jwt({ sub: "1234", exp: Date.now() / 1000 + 60 }) };
  const reply = await send({ type: "status" });
  expect(reply).toEqual({ ok: true, status: { tabOpen: false, hasToken: true, source: "cookie" } });
  expect(JSON.stringify(reply)).not.toContain(cookie.value);
  const authReply = await send({ type: "auth" });
  expect(authReply.ok && authReply.auth?.userId).toBe("1234");
});

test("expired cookie tokens cannot enable proof generation", async () => {
  cookie = { value: jwt({ sub: "1234", exp: 1 }) };
  const reply = await send({ type: "status" });
  expect(reply.ok && reply.status.hasToken).toBe(false);
  expect(stored.auth).toBeUndefined();
});

test("Bearer headers survive service-worker suspension in session storage", async () => {
  listeners.request!({ tabId: 4, url: "https://www.duolingo.com/2017-06-30/users/4567", requestHeaders: [{ name: "Authorization", value: "Bearer synthetic-opaque-token" }] });
  const reply = await send({ type: "auth" });
  expect(reply.ok && reply.auth).toEqual({ token: "synthetic-opaque-token", source: "bearer", userId: "4567" });
});

test("extension traffic cannot overwrite the detected tab token", async () => {
  listeners.request!({ tabId: -1, url: "https://www.duolingo.com/2017-06-30/users/999", requestHeaders: [{ name: "Authorization", value: "Bearer extension-token" }] });
  expect(stored.auth).toBeUndefined();
});

test("logout removes both cookie and captured Bearer credentials", async () => {
  stored.auth = { token: "captured-token", source: "bearer" };
  listeners.cookie!({ removed: true, cookie: { name: "jwt_token", domain: ".duolingo.com", value: "old-token" } });
  const reply = await send({ type: "status" });
  expect(reply.ok && reply.status.hasToken).toBe(false);
});

test("an expired observed token is cleared when reading status", async () => {
  stored.auth = { token: jwt({ exp: 1 }), source: "bearer" };
  const reply = await send({ type: "auth" });
  expect(reply.ok && reply.auth).toBeUndefined();
  expect(stored.auth).toBeUndefined();
});

test("unrelated cookie changes cannot replace the Duolingo token", () => {
  listeners.cookie!({ removed: false, cookie: { name: "jwt_token", domain: "otherduolingo.com", value: "unrelated-token" } });
  expect(stored.auth).toBeUndefined();
});

test("content scripts and external pages cannot request the token", () => {
  let replied = false;
  for (const sender of [
    { id: "test", url: "https://www.duolingo.com/learn" },
    { id: "another-extension", url: extensionUrl() },
  ]) {
    expect(listeners.message!({ type: "auth" }, sender, () => { replied = true; })).toBe(false);
  }
  expect(replied).toBe(false);
});
