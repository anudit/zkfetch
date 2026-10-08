// MV3 service worker: no DOM and no SharedArrayBuffer. The wasm prover runs
// single-threaded here. Proxy mode needs only the notary's WebSocket.
import { init, verify, zkFetch } from "@omnid/zkfetch";

declare const chrome: any;

const NOTARY_URL = "wss://zkfetch-notary-sea.anudit.workers.dev/notarize";
const NOTARY_KEY = "025429f34c4e03769db56d5f0be30278d5a55abc84ec3b140e6c0e6c051f963d14";

async function prove(url: string, jsonPaths: string[]) {
  await init(chrome.runtime.getURL("zkf_bg.wasm"));
  const started = performance.now();
  const res = await zkFetch(url, { zkConfig: { notaryUrl: NOTARY_URL, mode: "proxy", tlsVersion: "auto" } });
  const presentation = res.zk.present({ response: { jsonPaths } });
  const verified = verify(presentation, { trustedNotaryKeys: [NOTARY_KEY] });
  return {
    seconds: ((performance.now() - started) / 1000).toFixed(2),
    status: res.status,
    server: verified.serverName,
    tls: verified.tlsVersion,
    disclosed: verified.recv.split("\r\n\r\n").pop(),
    timings: res.zk.timings,
  };
}

chrome.runtime.onMessage.addListener((msg: any, _sender: unknown, reply: (r: unknown) => void) => {
  if (msg?.type !== "prove") return false;
  prove(msg.url, msg.jsonPaths).then(
    (result) => reply({ ok: true, result }),
    (error) => reply({ ok: false, error: String(error) }),
  );
  return true; // reply asynchronously
});
