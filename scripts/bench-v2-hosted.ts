// Native and real-Chrome 1/8-thread matrix, with independently verified outputs.
import { resolve } from 'node:path';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import * as native from '../packages/native/src/index.ts';
const casesFile = process.env.ZKF_EXTENSION_EXAMPLE ? 'scripts/hosted-extension-example.js' : process.env.ZKF_HOSTED_PATH_URL ? 'scripts/hosted-v2-path-cases.js' : 'scripts/hosted-v2-cases.js';
const { runCases } = await import('../' + casesFile);

const deployment = await Bun.file('infra/aws/deployment.json').json();
const capability = (await Bun.file('.zkf/notary-capability.token').text()).trim();
const url = new URL(deployment.url);
url.searchParams.set('capability', capability);
const config = { notaryUrl: url.toString(), publicKey: deployment.publicKey,
  pathUrl: process.env.ZKF_HOSTED_PATH_URL, pathSignedHead: process.env.ZKF_PATH_SIGNED_HEAD === '1', syntheticPaths: process.env.ZKF_HOSTED_SYNTHETIC_PATH === '1' };
const samples: any[] = [];
const onRow = (row: any) => { samples.push(row); console.log(JSON.stringify(row)); };
const out = process.env.ZKF_HOSTED_REPORT ?? 'docs/benchmarks/d1-d5-completion/hosted-matrix.json';
const startedAt = new Date().toISOString();
const server = Bun.serve({ hostname: '127.0.0.1', port: 0, fetch(req) {
  const path = new URL(req.url).pathname;
  const headers = { 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp',
    'Cache-Control': 'no-store' };
  if (path === '/config') return Response.json(config, { headers });
  if (path.startsWith('/extension/')) {
    if (path.includes('..')) return new Response('', { status: 400 });
    return new Response(Bun.file(resolve('packages/chrome-extension/dist', path.slice('/extension/'.length))), { headers: { ...headers,
      'Content-Type': path.endsWith('.wasm') ? 'application/wasm' : 'text/javascript' } });
  }
  if (path === '/cases.js') return new Response(Bun.file(casesFile), { headers: { ...headers, 'Content-Type': 'text/javascript' } });
  if (path.startsWith('/packages/wasm/pkg/') || path.startsWith('/packages/wasm/pkg-threads/')) {
    if (path.includes('..')) return new Response('', { status: 400 });
    return new Response(Bun.file(resolve('.' + path)), { headers: { ...headers,
      'Content-Type': path.endsWith('.wasm') ? 'application/wasm' : 'text/javascript' } });
  }
  if (path !== '/') return new Response('', { status: 404 });
  const threads = Number(new URL(req.url).searchParams.get('threads'));
  if (threads !== 1 && threads !== 8) return new Response('', { status: 400 });
  return new Response(`<!doctype html><script type="module">
  import init,* as w from '/packages/wasm/${threads === 8 ? 'pkg-threads' : 'pkg'}/zkf.js';
  import {runCases} from '/cases.js';
  window.result=(async()=>{
    await init();${threads === 8 ? 'await w.initThreadPool(8);' : ''}
    const backend={
      notarize:async p=>JSON.parse(await w.notarize(JSON.stringify(p))),
      prepare:async p=>{const s=await w.prepare(JSON.stringify(p));let consumed=false;
        return {notarize:async p=>{if(consumed)throw new Error('prepared session already consumed');consumed=true;return JSON.parse(await w.notarizePrepared(s,JSON.stringify(p)))},
        dispose:()=>{if(!consumed)s.free()}}},
      present:(a,s,p)=>w.present(a,s,JSON.stringify(p)),
      verify:(p,o)=>JSON.parse(w.verify(p,JSON.stringify(o))),
      presentV2:(a,s,p)=>w.presentV2(a,s,JSON.stringify(p)),
      verifyV2:(p,o)=>JSON.parse(w.verifyV2(p,JSON.stringify(o)))
    };
    return runCases(backend,await fetch('/config').then(r=>r.json()),'Chrome',${threads});
  })();</script>`, { headers: { ...headers, 'Content-Type': 'text/html' } });
} });

async function chromeCases(threads: number) {
  const pageUrl = `http://127.0.0.1:${server.port}/?threads=${threads}`;
  const probe = await fetch(pageUrl);
  if (probe.status !== 200 || !probe.headers.get('Content-Type')?.includes('text/html'))
    throw new Error(`Invalid benchmark page: ${probe.status} ${probe.headers.get('Content-Type')}`);
  console.log(JSON.stringify({ benchmarkPage: pageUrl, contentType: probe.headers.get('Content-Type') }));
  const dir = await mkdtemp(resolve(tmpdir(), 'zkf-hosted-chrome-'));
  const debugPort = 9250 + threads;
  const chrome = Bun.spawn([process.env.CHROME_BINARY ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '--headless=new', '--no-first-run', '--no-proxy-server', `--remote-debugging-port=${debugPort}`, `--user-data-dir=${dir}`, 'about:blank'],
    { stdout: 'ignore', stderr: 'ignore' });
  let socket: WebSocket | undefined;
  try {
    let tabs: any;
    for (let i = 0; i < 100; i++) {
      try { tabs = await fetch(`http://127.0.0.1:${debugPort}/json`).then(r => r.json()); break; }
      catch { await Bun.sleep(100); }
    }
    const tab = tabs?.find((tab: any) => tab.type === 'page' && tab.url === 'about:blank');
    if (!tab) throw new Error('Chrome benchmark page did not start');
    socket = new WebSocket(tab.webSocketDebuggerUrl);
    await new Promise((r, j) => { socket!.onopen = r; socket!.onerror = j; });
    let id = 0;
    const errors: any[] = [];
    const pending = new Map<number, { resolve: (v: any) => void; reject: (e: any) => void }>();
    socket.onmessage = e => { const data = JSON.parse(String(e.data));
      if (data.method === 'Runtime.exceptionThrown') errors.push(data.params.exceptionDetails);
      if (data.method === 'Log.entryAdded') errors.push(data.params.entry);
      if (data.method === 'Network.loadingFailed') errors.push(data.params);
      if (data.method === 'Network.responseReceived') errors.push({ url: data.params.response.url,
        status: data.params.response.status, mimeType: data.params.response.mimeType });
      const p = pending.get(data.id);
      if (p) { pending.delete(data.id); data.error ? p.reject(data.error) : p.resolve(data.result); } };
    const call = (method: string, params: any = {}) => new Promise<any>((resolve, reject) => {
      const next = ++id; pending.set(next, { resolve, reject }); socket!.send(JSON.stringify({ id: next, method, params }));
    });
    await call('Runtime.enable');
    await call('Page.enable');
    await call('Log.enable');
    await call('Network.enable');
    await call('Page.stopLoading');
    await Bun.sleep(500);
    const navigation = await call('Page.navigate', { url: pageUrl });
    if (navigation.errorText) {
      const page = await call('Runtime.evaluate', { expression: '({url:location.href,title:document.title,text:document.body?.innerText})', returnByValue: true });
      throw new Error(`Chrome navigation: ${navigation.errorText}; ${JSON.stringify({errors,page})}`);
    }
    let ready = false;
    for (let i = 0; i < 100; i++) {
      const check = await call('Runtime.evaluate', { expression: '!!window.result', returnByValue: true });
      if (check.result.value) { ready = true; break; }
      await Bun.sleep(100);
    }
    if (!ready) {
      const page = await call('Runtime.evaluate', { expression: '({url:location.href,title:document.title,text:document.body?.innerText})', returnByValue: true });
      throw new Error(`Chrome benchmark module did not initialize: ${JSON.stringify({ errors, page })}`);
    }
    const result = await call('Runtime.evaluate', { expression: 'window.result', awaitPromise: true, returnByValue: true, timeout: 240000 });
    if (result.exceptionDetails || !Array.isArray(result.result.value)) throw new Error(JSON.stringify(result));
    for (const row of result.result.value) onRow(row);
  } finally {
    socket?.close(); chrome.kill(); await chrome.exited; await rm(dir, { recursive: true, force: true });
  }
}
try {
  if (!process.env.ZKF_BROWSER_ONLY && !process.env.ZKF_EXTENSION_EXAMPLE) await runCases(native, { ...config, onRow }, 'native', 0);
  await chromeCases(1);
  await chromeCases(8);
  if (samples.length !== (process.env.ZKF_EXTENSION_EXAMPLE ? 2 : 12) || samples.some(row => !row.verified)) throw new Error('Incomplete hosted matrix');
} catch (e) {
  console.error(String(e).split(capability).join('[redacted]'));
  process.exitCode = 1;
} finally {
  server.stop(true);
  const provenance: Record<string, string> = {};
  for (const path of [casesFile, 'scripts/bench-v2-hosted.ts',
    '.zkf/aws/completion-artifacts/zkf-notary', 'packages/native/zkf.node',
    'packages/wasm/pkg/zkf_bg.wasm', 'packages/wasm/pkg-threads/zkf_bg.wasm']) {
    provenance[path] = createHash('sha256').update(new Uint8Array(await Bun.file(path).arrayBuffer())).digest('hex');
  }
  await Bun.write(out, JSON.stringify({ startedAt, completedAt: new Date().toISOString(),
    complete: samples.length === 12, host: deployment.url,
    scope: 'one observation per case; not medians', provenance, samples }, null, 2) + '\n');
}
