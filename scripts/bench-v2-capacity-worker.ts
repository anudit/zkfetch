import * as native from '../packages/native/src/index.ts';
import { existsSync } from 'node:fs';
const [directory, levelText, workerText] = process.argv.slice(2);
if (!directory || !levelText || !workerText) throw new Error('Missing capacity worker arguments');
const level = Number(levelText), worker = Number(workerText);
const deployment = await Bun.file('infra/aws/deployment.json').json();
const capability = (await Bun.file('.zkf/notary-capability.token').text()).trim();
const notaryUrl = new URL(deployment.url);
notaryUrl.searchParams.set('capability', capability);
const predicate = { key: 'id', op: 'eq' as const, value: '1' };
await Bun.write(`${directory}/${level}-${worker}.ready`, '');
const waves = Number(process.env.ZKF_CAPACITY_WAVES ?? '3');
if (!Number.isInteger(waves) || waves < 2 || waves > 100) throw new Error('Invalid wave count');
for (let round = 0; round < waves; round++) {
  while (!existsSync(`${directory}/start-${level}-${round}`)) await Bun.sleep(20);
  const start = Date.now();
  let result: any;
  try {
    const nonce = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('hex');
    const output = await native.notarize({ url: 'https://jsonplaceholder.typicode.com/todos/1',
      notaryUrl: notaryUrl.toString(), expectedNotaryKey: deployment.publicKey,
      mode: 'proxy', tlsVersion: '1.3', attestationV2: true, protocolV2: true,
      persistentVole: true, maxRecv: 8192,
      signedResponseHead: process.env.ZKF_CAPACITY_PROFILE === 'signed-head' });
    if (output.response.status !== 200) throw new Error(`HTTP ${output.response.status}`);
    const proof = await native.presentV2(output.attestation, output.secrets,
      { predicate, nonce, allowSetCookie: true });
    const verified = await native.verifyV2(proof, { trustedNotaryKeys: [deployment.publicKey],
      expectedServerName: 'jsonplaceholder.typicode.com', predicate, nonce, maxAgeSecs: 600 });
    if (verified.serverName !== 'jsonplaceholder.typicode.com') throw new Error('Wrong verified origin');
    result = { ok: true, timings: output.timings, proofBytes: Buffer.from(proof, 'base64').length };
  } catch (error) {
    result = { ok: false, error: String(error).split(capability).join('[redacted]') };
  }
  const record = { level, worker, round, start, end: Date.now(), ...result };
  await Bun.write(`${directory}/${level}-${worker}-${round}.done`, JSON.stringify(record));
}
