// Exercise the shipped extension worker, including SDK and verifier policy.
export async function runCases(_backend, _config, client, threads) {
  const worker = new Worker('/extension/prover.js', { type: 'module' });
  let resolve, reject;
  let timer;
  const exchange = message => new Promise((r, j) => {
    resolve = r; reject = j;
    timer = setTimeout(() => j(new Error('Extension worker operation timed out')), 180000);
    worker.postMessage(message);
  });
  worker.onerror = () => { clearTimeout(timer); reject?.(new Error('Extension worker failed')); };
  worker.onmessage = ({ data }) => {
    if (data.type === 'progress') return;
    clearTimeout(timer);
    resolve?.(data);
  };
  try {
    const loaded = await exchange({ type: 'init', wasmUrl: new URL('/extension/zkf_bg.wasm', location.href).href,
      ...(threads === 8 ? { threadsUrl: new URL('/extension/wasm-threads/zkf.js', location.href).href } : {}) });
    if (loaded.type !== 'loaded') throw new Error(loaded.error ?? 'Worker initialization failed');
    const nonce = Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');
    const result = await exchange({ type: 'prove-example', version: 2, nonce });
    if (result.type !== 'proof') throw new Error(result.error ?? 'Example proof failed');
    const proof = result.proof;
    if (proof.target !== 'top-level' || proof.nonce !== nonce || proof.predicate.key !== 'id') throw new Error('Wrong example target');
    const verification = { type: 'verify', version: 2, target: 'top-level', presentation: proof.presentation, predicate: proof.predicate, nonce };
    const good = await exchange(verification);
    if (good.type !== 'verified' || good.verified.serverName !== 'jsonplaceholder.typicode.com') throw new Error(good.error ?? 'Verification failed');
    const badNonce = await exchange({ ...verification, nonce: (nonce[0] === '0' ? '1' : '0') + nonce.slice(1) });
    const badPath = await exchange({ ...verification, predicate: { ...proof.predicate, path: ['history', 'id'] } });
    if (badNonce.type !== 'error' || badPath.type !== 'error') throw new Error('Verifier accepted a substituted policy');
    return [{ client, threads: loaded.threads, state: 'extension-public-top-level', verified: true,
      nonceRejected: true, nestedPathRejected: true, elapsedMs: proof.elapsedMs,
      presentMs: proof.presentMs, verifyMs: good.elapsedMs, timings: proof.timings }];
  } finally { clearTimeout(timer); worker.postMessage({ type: 'dispose' }); worker.terminate(); }
}
