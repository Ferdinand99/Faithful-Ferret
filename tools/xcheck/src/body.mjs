// Item body and manifest shapes and the padding of Fase 1 section 5.2.
import { fail, concat } from './util.mjs';
import { decode, encode } from './cbor.mjs';

// ---- padding: padded = plain || 0x80 || 0x00 * n (ISO/IEC 7816-4) ----------------------------
export const MAX_PADDED = 61440;

export function paddedLength(plainLen) {
  const need = plainLen + 1;
  for (const c of [256, 512, 1024, 2048, 4096]) if (c >= need) return c;
  return Math.ceil(need / 4096) * 4096;
}

export function isPaddedClass(n) {
  return n === 256 || n === 512 || n === 1024 || n === 2048 || (n >= 4096 && n % 4096 === 0 && n <= MAX_PADDED);
}

export function pad(plain) {
  if (plain.length >= MAX_PADDED) fail('too_large');
  const n = paddedLength(plain.length);
  const out = new Uint8Array(n);
  out.set(plain, 0);
  out[plain.length] = 0x80;
  return out;
}

// Looks backwards for the last 0x80 with only zero bytes after it.
export function unpad(padded) {
  let i = padded.length - 1;
  while (i >= 0 && padded[i] === 0x00) i--;
  if (i < 0 || padded[i] !== 0x80) fail('decrypt');
  return padded.subarray(0, i);
}

// ---- shape checks -------------------------------------------------------------------------
const bad = (why) => fail('malformed_item_body', why);

const isMap = (v) => v && v.k === 'map';
const get = (m, key) => {
  const e = m.v.find(([k]) => k === key);
  return e ? e[1] : undefined;
};
const uint = (v) => v && v.k === 'int' && v.v >= 0n;

function need(m, key, test, what) {
  const v = get(m, key);
  if (v === undefined) bad(`missing ${key}`);
  if (!test(v)) bad(`${key} is not ${what}`);
  return v;
}
function opt(m, key, test, what) {
  const v = get(m, key);
  if (v !== undefined && !test(v)) bad(`${key} is not ${what}`);
  return v;
}
const isText = (v) => v.k === 'text';
const isBytes = (v) => v.k === 'bytes';

// Returns { readOnly }. `value` is the decoded CBOR value (unknown keys stay where they were read).
export function checkBody(value) {
  if (!isMap(value)) bad('body is not a map');
  const schema = get(value, 'schema');
  if (!uint(schema)) bad('schema missing or not an unsigned integer');
  if (schema.v > 1n) return { readOnly: true };
  if (schema.v !== 1n) bad('schema 0');
  need(value, 'type', isText, 'text');
  need(value, 'name', isText, 'text');
  const fields = need(value, 'fields', (v) => v.k === 'array', 'an array');
  for (const f of fields.v) {
    if (!isMap(f)) bad('field is not a map');
    for (const k of ['id', 'label', 'kind', 'value']) need(f, k, isText, 'text');
  }
  const urls = need(value, 'urls', (v) => v.k === 'array', 'an array');
  for (const u of urls.v) {
    if (!isMap(u)) bad('url entry is not a map');
    need(u, 'url', isText, 'text');
    opt(u, 'match', isText, 'text');
  }
  const totp = opt(value, 'totp', isMap, 'a map');
  if (totp) need(totp, 'uri', isText, 'text');
  const pk = opt(value, 'passkey', isMap, 'a map');
  if (pk) {
    need(pk, 'cred_id', isBytes, 'bytes');
    need(pk, 'rp_id', isText, 'text');
    need(pk, 'user_handle', isBytes, 'bytes');
    need(pk, 'user_name', isText, 'text');
    need(pk, 'priv', isBytes, 'bytes');
    need(pk, 'sign_count', uint, 'unsigned');
    need(pk, 'created', uint, 'unsigned');
    opt(pk, 'prf_seed_uv', isBytes, 'bytes');
    opt(pk, 'prf_seed_nouv', isBytes, 'bytes');
  }
  opt(value, 'notes', isText, 'text');
  need(value, 'created', uint, 'unsigned');
  need(value, 'modified', uint, 'unsigned');
  need(value, 'favorite', (v) => v.k === 'bool', 'a bool');
  opt(value, 'device', isText, 'text');
  return { readOnly: false };
}

// Written back as OPS.md says (export.plain.json): the known keys in schema order (item body schema), then the
// unknown keys in the order they were read. Done at the top level and in fields[], urls[], totp and passkey.
const SCHEMA_ORDER = {
  body: ['schema', 'type', 'name', 'fields', 'urls', 'totp', 'passkey', 'notes', 'created', 'modified', 'favorite', 'device'],
  field: ['id', 'label', 'kind', 'value'],
  url: ['url', 'match'],
  totp: ['uri'],
  passkey: ['cred_id', 'rp_id', 'user_handle', 'user_name', 'priv', 'sign_count', 'created', 'prf_seed_uv', 'prf_seed_nouv'],
};

// `nested` is a Map: an unknown key named like a member of Object.prototype (toString, __proto__, ...) must be
// treated as any other unknown key.
function inSchemaOrder(map, order, nested = new Map()) {
  const known = order.map((k) => map.v.find(([key]) => key === k)).filter(Boolean);
  const unknown = map.v.filter(([k]) => !order.includes(k));
  const fix = ([k, v]) => (nested.has(k) ? [k, nested.get(k)(v)] : [k, v]);
  return { k: 'map', v: [...known, ...unknown].map(fix) };
}

export function normalizeBody(value) {
  const listOf = (order) => (arr) => ({ k: 'array', v: arr.v.map((m) => inSchemaOrder(m, order)) });
  return inSchemaOrder(
    value,
    SCHEMA_ORDER.body,
    new Map([
      ['fields', listOf(SCHEMA_ORDER.field)],
      ['urls', listOf(SCHEMA_ORDER.url)],
      ['totp', (m) => inSchemaOrder(m, SCHEMA_ORDER.totp)],
      ['passkey', (m) => inSchemaOrder(m, SCHEMA_ORDER.passkey)],
    ]),
  );
}

// Manifests follow the same rule (see "Key order and newer schemas" in OPS.md): known keys first in schema order, at the top
// level and in each method entry, then unknown keys in the order read.
export function normalizeManifest(value) {
  return inSchemaOrder(
    value,
    ['v', 'vk_epoch', 'methods'],
    new Map([['methods', (arr) => ({ k: 'array', v: arr.v.map((m) => inSchemaOrder(m, ['t', 'id', 'g', 'c'])) })]]),
  );
}

export function parseBody(bytes) {
  const raw = decode(bytes);
  const { readOnly } = checkBody(raw);
  // a body of a newer schema is not understood and is written back as it was
  return { value: readOnly ? raw : normalizeBody(raw), readOnly };
}

// Manifest: { v: 1, vk_epoch: u64, methods: [ { t: u8, id: bytes(16), g: u64, c?: bytes } ] }
export function parseManifest(bytes) {
  const value = decode(bytes);
  if (!isMap(value)) bad('manifest is not a map');
  const v = need(value, 'v', uint, 'unsigned');
  if (v.v !== 1n) fail('unsupported');
  const epoch = need(value, 'vk_epoch', uint, 'unsigned');
  const methods = need(value, 'methods', (x) => x.k === 'array', 'an array');
  const list = [];
  for (const m of methods.v) {
    if (!isMap(m)) bad('method is not a map');
    const t = need(m, 't', uint, 'unsigned');
    const id = need(m, 'id', isBytes, 'bytes');
    const g = need(m, 'g', uint, 'unsigned');
    const c = opt(m, 'c', isBytes, 'bytes');
    // a type this version does not know is kept as it is (Fase 1 section 13), so the range is that of one byte
    if (t.v > 255n || t.v < 1n) bad('method type out of range');
    if (id.v.length !== 16) bad('method id is not 16 bytes');
    list.push({ t: Number(t.v), id: id.v, g: g.v, c: c ? c.v : undefined });
  }
  // A manifest of another version is not read at all (unsupported), before the rest is judged.
  return { value: normalizeManifest(value), version: v.v, epoch: epoch.v, methods: list };
}

export { decode, encode, concat };
