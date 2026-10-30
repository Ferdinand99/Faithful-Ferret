// Negative self-tests: xcheck must fail when it should. Run with `node src/selftest.mjs`.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { get, webcryptoVerify, spki } from './passkey.mjs';
import * as p256 from './p256.mjs';
import { unhex, hex } from './util.mjs';
import { encode } from './cbor.mjs';
import { parseBody } from './body.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(fs.readFileSync(path.join(here, '../../../vectors/internal/passkey.json'), 'utf8'));
const base = structuredClone(vectors.cases.find((c) => c.id === 'passkey/get/valid/001'));
let n = 0;
const ok = (name) => console.log(`ok ${++n} ${name}`);

async function rejects(fn, what, message) {
  let error = null;
  try {
    await fn();
  } catch (e) {
    error = e;
  }
  assert.ok(error, `${what}: expected a failure`);
  assert.match(error.message, message, `${what}: failed for the wrong reason`);
}
const flip = (h) => {
  const b = unhex(h);
  b[b.length - 1] ^= 1;
  return hex(b);
};

// 1. the untouched vector passes and reproduces the signature
{
  const r = await get(base.input, base.expect);
  assert.equal(r.expect.signature, base.expect.signature);
  ok('the untouched passkey.get vector passes');
}
// 2. a wrong signature (valid DER, one bit changed in s) makes the check fail
await rejects(() => get(base.input, { ...base.expect, signature: flip(base.expect.signature) }), 'wrong signature', /WebCrypto rejects the signature of the vector/);
ok('a signature with one bit changed is refused');
// 3. a wrong public key inside the stored PKCS#8 makes the check fail
{
  const input = structuredClone(base.input);
  input.record.priv_pkcs8 = flip(input.record.priv_pkcs8);
  await rejects(() => get(input, base.expect), 'wrong public key', /does not belong to its private key/);
  ok('a stored public key that does not belong to the private key is refused');
}
// 4. a wrong private scalar (public key kept) makes the check fail
{
  const input = structuredClone(base.input);
  const d = unhex(input.record.priv_pkcs8);
  d[36] ^= 1;
  input.record.priv_pkcs8 = hex(d);
  await rejects(() => get(input, base.expect), 'wrong scalar', /does not belong to its private key|disagree/);
  ok('a changed private scalar is refused');
}
// 5. webcryptoVerify itself: right key and data accept, wrong key, wrong data, bad DER refuse
{
  const scalar = unhex(base.input.record.priv_pkcs8).subarray(36, 68);
  const key = spki(p256.publicKey(scalar));
  const other = spki(p256.publicKey(Uint8Array.from(scalar, (b, i) => (i === 31 ? b ^ 1 : b))));
  const msg = new TextEncoder().encode('message');
  const sig = p256.sign(scalar, msg).der;
  assert.equal(await webcryptoVerify(key, msg, sig), true);
  assert.equal(await webcryptoVerify(other, msg, sig), false);
  assert.equal(await webcryptoVerify(key, new TextEncoder().encode('messagf'), sig), false);
  assert.equal(await webcryptoVerify(key, msg, sig.subarray(0, sig.length - 1)), false);
  ok('WebCrypto verification accepts only the right key, data and DER');
}
// 6. item bodies are written with the known keys in schema order first, then the unknown keys as read
{
  const t = (s) => ({ k: 'text', v: s });
  const body = {
    k: 'map',
    v: [
      ['zz_unknown', t('a')],
      ['favorite', { k: 'bool', v: false }],
      ['name', t('n')],
      ['modified', { k: 'int', v: 2n }],
      ['aa_unknown', { k: 'int', v: 1n }],
      ['schema', { k: 'int', v: 1n }],
      ['created', { k: 'int', v: 1n }],
      ['urls', { k: 'array', v: [{ k: 'map', v: [['x', t('u')], ['url', t('https://a')]] }] }],
      ['fields', { k: 'array', v: [] }],
      ['type', t('login')],
    ],
  };
  const out = parseBody(encode(body)).value;
  assert.deepEqual(out.v.map(([k]) => k), ['schema', 'type', 'name', 'fields', 'urls', 'created', 'modified', 'favorite', 'zz_unknown', 'aa_unknown']);
  assert.deepEqual(out.v.find(([k]) => k === 'urls')[1].v[0].v.map(([k]) => k), ['url', 'x']);
  ok('known keys come first in schema order, unknown keys follow as read');
}
// 7. an op without a handler (and not in NOT_COVERED) makes the runner exit non-zero
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'xcheck-'));
  const file = { format: 'ferret-vectors/1', group: 'bogus', suite: 1, spec: 's', generator: {}, cases: [{ id: 'bogus/1', title: 't', op: 'bogus.op', status: 'valid', tags: [], synthetic: true, rng: [], input: {}, expect: {}, expect_error: null }] };
  fs.writeFileSync(path.join(dir, 'bogus.json'), JSON.stringify(file));
  const r = spawnSync(process.execPath, [path.join(here, 'run.mjs')], { env: { ...process.env, XCHECK_VECTORS_DIR: dir }, encoding: 'utf8' });
  fs.rmSync(dir, { recursive: true, force: true });
  assert.notEqual(r.status, 0, 'a handler-less op must fail the run');
  assert.match(r.stdout, /NO HANDLER/);
  ok('an op without a handler fails the run');
}
console.log(`self-tests passed (${n})`);
