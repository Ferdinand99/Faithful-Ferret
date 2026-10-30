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
import { parseBody, parseManifest } from './body.mjs';

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
// 6. item bodies are written with the known keys in schema order first, then the unknown keys as read,
//    at every level: top level, fields[], urls[], totp and passkey
const t = (x) => ({ k: 'text', v: x });
const u = (x) => ({ k: 'int', v: BigInt(x) });
const bytes = (n) => ({ k: 'bytes', v: new Uint8Array(n) });
const map = (v) => ({ k: 'map', v });
const keysOf = (m) => m.v.map(([k]) => k);
const at = (m, key) => m.v.find(([k]) => k === key)[1];
const scrambled = (extra) =>
  map([
    ...extra('top'),
    ['favorite', { k: 'bool', v: false }],
    ['name', t('n')],
    ['modified', u(2)],
    ['passkey', map([...extra('passkey'), ['prf_seed_nouv', bytes(32)], ['created', u(1)], ['sign_count', u(0)], ['priv', bytes(8)], ['user_name', t('a')], ['user_handle', bytes(4)], ['rp_id', t('r')], ['cred_id', bytes(4)], ['prf_seed_uv', bytes(32)]])],
    ['schema', u(1)],
    ['created', u(1)],
    ['totp', map([...extra('totp'), ['uri', t('otpauth://totp/x?secret=ME')]])],
    ['urls', { k: 'array', v: [map([...extra('url'), ['match', t('host')], ['url', t('https://a')]])] }],
    ['fields', { k: 'array', v: [map([...extra('field'), ['value', t('v')], ['kind', t('text')], ['label', t('l')], ['id', t('i')]])] }],
    ['type', t('login')],
  ]);
{
  const out = parseBody(encode(scrambled((where) => [[`zz_${where}`, t('a')], [`aa_${where}`, u(1)]]))).value;
  assert.deepEqual(keysOf(out), ['schema', 'type', 'name', 'fields', 'urls', 'totp', 'passkey', 'created', 'modified', 'favorite', 'zz_top', 'aa_top']);
  assert.deepEqual(keysOf(at(out, 'fields').v[0]), ['id', 'label', 'kind', 'value', 'zz_field', 'aa_field']);
  assert.deepEqual(keysOf(at(out, 'urls').v[0]), ['url', 'match', 'zz_url', 'aa_url']);
  assert.deepEqual(keysOf(at(out, 'totp')), ['uri', 'zz_totp', 'aa_totp']);
  assert.deepEqual(keysOf(at(out, 'passkey')), ['cred_id', 'rp_id', 'user_handle', 'user_name', 'priv', 'sign_count', 'created', 'prf_seed_uv', 'prf_seed_nouv', 'zz_passkey', 'aa_passkey']);
  ok('known keys come first in schema order at every level, unknown keys follow as read');
}
// 6b. unknown keys named like members of Object.prototype are kept as any other unknown key, at every level
{
  const names = ['toString', 'valueOf', 'hasOwnProperty', 'constructor', '__proto__', 'isPrototypeOf'];
  const input = scrambled((where) => names.map((n, i) => [n, t(`${where}-${i}`)]));
  const out = parseBody(encode(input)).value;
  const sameTail = (m, where, known) => {
    assert.deepEqual(keysOf(m).slice(known), names);
    assert.deepEqual(m.v.slice(known).map(([, v]) => v.v), names.map((n, i) => `${where}-${i}`));
  };
  sameTail(out, 'top', 10);
  sameTail(at(out, 'fields').v[0], 'field', 4);
  sameTail(at(out, 'urls').v[0], 'url', 2);
  sameTail(at(out, 'totp'), 'totp', 1);
  sameTail(at(out, 'passkey'), 'passkey', 9);
  // and the bytes survive a round trip
  assert.equal(hex(encode(parseBody(encode(out)).value)), hex(encode(out)));
  ok('unknown keys named toString, valueOf, __proto__ ... round-trip unchanged at every level');
}
// 6c. manifests: known keys first in schema order (top level and method entries), then unknown keys as read
{
  const raw = (extra) =>
    map([
      ...extra('top'),
      ['methods', { k: 'array', v: [map([...extra('m'), ['g', u(1)], ['id', bytes(16)], ['t', u(1)]])] }],
      ['vk_epoch', u(1)],
      ['v', u(1)],
    ]);
  const out = parseManifest(encode(raw((w) => [[`zz_${w}`, u(1)], ['toString', t('x')], ['__proto__', t('y')]]))).value;
  assert.deepEqual(keysOf(out), ['v', 'vk_epoch', 'methods', 'zz_top', 'toString', '__proto__']);
  assert.deepEqual(keysOf(at(out, 'methods').v[0]), ['t', 'id', 'g', 'zz_m', 'toString', '__proto__']);
  ok('manifest keys follow the same rule as body keys');
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
