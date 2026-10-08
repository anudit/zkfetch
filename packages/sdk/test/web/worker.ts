// Runs zkFetch inside a dedicated Web Worker (no DOM), like an extension
// service worker. Imports the package name so the "browser" export applies.
import { init, verify, zkFetch } from "@omnid/zkfetch";

self.onmessage = async (event: MessageEvent) => {
  const { notaryUrl, notaryKey, url, caCert, tlsVersion } = event.data;
  try {
    await init("/zkf_bg.wasm");
    const t = performance.now();
    const res = await zkFetch(url, {
      headers: { Authorization: "Bearer page-secret" },
      zkConfig: { notaryUrl, mode: "proxy", tlsVersion, extraRootCerts: caCert ? [caCert] : undefined },
    });
    await res.text();
    const presentation = res.zk.present({ response: { jsonPaths: ["information.name"] } });
    const v = verify(presentation, { trustedNotaryKeys: [notaryKey], extraRootCerts: caCert ? [caCert] : undefined });
    postMessage({ ok: true, seconds: ((performance.now() - t) / 1000).toFixed(2), tls: v.tlsVersion, hidden: !v.sent.includes("page-secret"), revealed: v.recv.includes('"name":"John Doe"') });
  } catch (e) {
    postMessage({ ok: false, error: String(e) });
  }
};
