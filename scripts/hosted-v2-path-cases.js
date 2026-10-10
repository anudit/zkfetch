// Public Duolingo path matrix. No account token, body, value or proof is exported.
// Shared native/Chrome workload. Never return attestations, secrets or capabilities.
export async function runCases(backend, config, client, threads) {
  const rows = [];
  let predicate;
  const params = {
    url: config.pathUrl, maxRecv: 8192,
    notaryUrl: config.notaryUrl,
    expectedNotaryKey: config.publicKey,
    mode: 'proxy', tlsVersion: '1.3', protocolV2: true,
    persistentVole: true, attestationV2: true, signedResponseHead: config.pathSignedHead,
    headers: [], extraRootCerts: [], predicates: [], binius: false,
  };
  for (const state of ['fresh', 'warm', 'prepared', 'v1-warm-baseline']) {
    const input = { ...params, attestationV2: state !== 'v1-warm-baseline',
      signedResponseHead: state !== 'v1-warm-baseline' && config.pathSignedHead,
      reveal: state === 'v1-warm-baseline' ? { response: { jsonPaths: ['streakData.longestStreak.length'] } } : undefined };
    const nonce = Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');
    let prepared, prepareMs;
    if (state === 'prepared') {
      const at = performance.now();
      prepared = await backend.prepare(input);
      prepareMs = performance.now() - at;
    }
    const at = performance.now();
    let output;
    try { output = prepared ? await prepared.notarize(input) : await backend.notarize(input); }
    finally { prepared?.dispose(); }
    const notarizeWallMs = performance.now() - at;
    let preparedReuseRejected = null;
    if (prepared) {
      preparedReuseRejected = false;
      try { await prepared.notarize(input); } catch { preparedReuseRejected = true; }
      if (!preparedReuseRejected) throw new Error('Prepared session was reusable');
    }
    if (output.response.status !== 200) throw new Error(`Duolingo HTTP ${output.response.status}`);
    const value = JSON.parse(output.response.body)?.streakData?.longestStreak?.length;
    if (!Number.isSafeInteger(value) || value < 0) throw new Error('Missing unsigned Duolingo streak');
    predicate = { key: 'length', path: ['streakData','longestStreak','length'], unique: true, op: 'eq', value: String(value) };
    let proof, verified, nonceRejected = null;
    const presentAt = performance.now();
    if (input.attestationV2) {
      proof = await backend.presentV2(output.attestation, output.secrets,
        { predicate, nonce, parameters: 'fast', allowSetCookie: true });
    } else {
      proof = await backend.present(output.attestation, output.secrets, {});
    }
    const presentMs = performance.now() - presentAt;
    const verifyAt = performance.now();
    const options = { trustedNotaryKeys: [config.publicKey], expectedServerName: new URL(config.pathUrl).hostname,
      predicate, nonce, maxAgeSecs: 600 };
    if (input.attestationV2) verified = await backend.verifyV2(proof, options);
    else verified = await backend.verify(proof, { trustedNotaryKeys: [config.publicKey] });
    const verifyMs = performance.now() - verifyAt;
    if (verified.serverName !== new URL(config.pathUrl).hostname) throw new Error('Wrong verified origin');
    if (input.attestationV2) {
      nonceRejected = false;
      try { await backend.verifyV2(proof, { ...options, nonce: (nonce[0] === 'f' ? '0' : 'f') + nonce.slice(1) }); }
      catch { nonceRejected = true; }
      if (!nonceRejected) throw new Error('Nonce substitution accepted');
      for (const wrong of [{ ...predicate, path: ['other','longestStreak','length'] },
        { ...predicate, path: [] }, { ...predicate, unique: false }]) {
        let rejected = false;
        try { await backend.verifyV2(proof, { ...options, predicate: wrong }); } catch { rejected = true; }
        if (!rejected) throw new Error('Path/uniqueness substitution accepted');
      }
      if (config.syntheticPaths && state === 'fresh') {
        for (const [path, value] of [[['rows', 1, 'length'], '777'],
          [['deep','a','b','c','d','e','f','g'], '456']]) {
          const claim = { key: path.at(-1), path, unique: true, op: 'eq', value };
          const nestedProof = await backend.presentV2(output.attestation, output.secrets,
            { predicate: claim, nonce, parameters: 'fast', allowSetCookie: false });
          await backend.verifyV2(nestedProof, { ...options, predicate: claim });
          const wrong = { ...claim, path: [...path] };
          if (typeof path[1] === 'number') wrong.path[1] = 0;
          else wrong.path[0] = 'other';
          let rejected = false;
          try { await backend.verifyV2(nestedProof, { ...options, predicate: wrong }); } catch { rejected = true; }
          if (!rejected) throw new Error('Additional path substitution accepted');
        }
      }
      if (state === 'fresh' && output.timings.voleResumed) throw new Error('Fresh case unexpectedly resumed');
      if (state !== 'fresh' && !output.timings.voleResumed) throw new Error('Warm case failed to resume');
      if (state === 'prepared' && !output.timings.prewarmed) throw new Error('Prepare did not run ahead');
    }
    const row = { client, threads, state, profile: input.attestationV2 ? (config.pathSignedHead ? 'signed-head-path-unique-fast' : 'ciphertext-only-path-unique-fast') : 'v1-path-reveal',
      exactPathVerified: input.attestationV2, additionalArrayAndDepth8Verified: config.syntheticPaths && state === 'fresh', pathSubstitutionRejected: input.attestationV2,
      verified: true, nonceRejected, preparedReuseRejected, prepareMs, notarizeWallMs, presentMs, verifyMs,
      proofBytes: Math.floor(proof.length * 3 / 4) - (proof.endsWith('==') ? 2 : proof.endsWith('=') ? 1 : 0),
      bodyBytes: new TextEncoder().encode(output.response.body).length, timings: output.timings };
    rows.push(row);
    config.onRow?.(row);
  }
  return rows;
}
