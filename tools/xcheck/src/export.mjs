// Encrypted export (Fase 1 section 6.4 as clarified 29.10) and the plain JSON / CSV exports.
import { aeadSeal, aeadOpen, hkdf, argon2id } from './crypto.mjs';
import { tlvs, label, fBytes, T } from './tlv.mjs';
import { concat, fail, ascii, utf8, hex, equal } from './util.mjs';
import { C, decode, encode, floatValue } from './cbor.mjs';
import { parseBody } from './body.mjs';
import { ZERO_ID } from './items.mjs';
import { checkKdfRange } from './keys.mjs';

export const MAX_ITEMS = 10000;
export const MAX_BODY = 128 * 1024 * 1024;

const get = (m, key) => {
  const e = m.v.find(([k]) => k === key);
  return e ? e[1] : undefined;
};

// items: [{ id: bytes(16), body: bytes (CBOR) }] -> [{ id, value }] after the body shape check
export function readItems(items) {
  if (items.length > MAX_ITEMS) fail('too_large');
  const seen = new Set();
  return items.map((it) => {
    if (equal(it.id, ZERO_ID)) fail('malformed_envelope');
    const k = hex(it.id);
    if (seen.has(k)) fail('malformed_entries');
    seen.add(k);
    const { value, readOnly } = parseBody(it.body);
    if (readOnly) fail('read_only_schema');
    return { id: it.id, value };
  });
}

export function headerBytes(salt, m, t, p, createdAt) {
  return encode(
    C.map([
      ['v', C.uint(1)],
      ['suite', C.uint(1)],
      ['kdf', C.map([['salt', C.bytes(salt)], ['m', C.uint(m)], ['t', C.uint(t)], ['p', C.uint(p)]])],
      ['created_at', C.uint(createdAt)],
    ]),
  );
}

export const kExp = (stretched) => hkdf(tlvs(label('ferret/v1/export')), stretched, ascii('ferret/v1/export/key'), 32);
const aadEk = (header) => tlvs(label('ferret/v1/export/ek'), fBytes(T.header, header));
const aadBody = (header) => tlvs(label('ferret/v1/export/body'), fBytes(T.header, header));

export function encryptExport({ password, kdf, createdAt, items, draw, unchecked }) {
  if (!unchecked) checkKdfRange(kdf.m_kib, kdf.t, kdf.p);
  const list = readItems(items);
  const salt = draw(16);
  const ek = draw(32);
  const nonceEk = draw(24);
  const nonceBody = draw(24);
  const header = headerBytes(salt, kdf.m_kib, kdf.t, kdf.p, createdAt);
  const key = kExp(argon2id(password, salt, kdf.m_kib, kdf.t, kdf.p, 32));
  const ekWrap = aeadSeal(key, nonceEk, ek, aadEk(header));
  const bodyCbor = encode(C.map([['v', C.uint(1)], ['items', C.array(list.map((i) => C.map([['id', C.bytes(i.id)], ['body', i.value]])))]]));
  const body = aeadSeal(ek, nonceBody, bodyCbor, aadBody(header));
  return { file: concat(header, ekWrap, body), header, kExp: key, aadEk: aadEk(header), aadBody: aadBody(header) };
}

const bad = () => fail('malformed_export_header');

// Reads the header from at most the first 256 bytes. Only the structure is checked here.
export function parseHeader(file) {
  let r;
  try {
    r = decode(file.subarray(0, 256), { prefix: true });
  } catch {
    bad();
  }
  const map = r.value;
  if (map.k !== 'map') bad();
  // the version and the suite are judged first, before the parameters
  const v = get(map, 'v');
  const suite = get(map, 'suite');
  if (!v || v.k !== 'int' || !suite || suite.k !== 'int') bad();
  if (v.v !== 1n || suite.v !== 1n) fail('unsupported');
  const keys = map.v.map(([k]) => k).sort().join(',');
  if (keys !== 'created_at,kdf,suite,v') bad();
  const kdf = get(map, 'kdf');
  const createdAt = get(map, 'created_at');
  if (kdf.k !== 'map' || createdAt.k !== 'int' || createdAt.v < 0n) bad();
  if (kdf.v.map(([k]) => k).sort().join(',') !== 'm,p,salt,t') bad();
  const salt = get(kdf, 'salt');
  if (salt.k !== 'bytes' || salt.v.length !== 16) bad();
  const num = {};
  for (const k of ['m', 't', 'p']) {
    const x = get(kdf, k);
    if (x.k !== 'int' || x.v < 0n) bad();
    num[k] = x.v;
  }
  return { headerLen: r.len, createdAt: createdAt.v, salt: salt.v, m: num.m, t: num.t, p: num.p };
}

export function decryptExport({ password, file, unchecked }) {
  const h = parseHeader(file);
  const max32 = 0xffffffffn;
  if (h.m > max32 || h.t > max32 || h.p > max32) fail('kdf_out_of_range');
  const m = Number(h.m);
  const t = Number(h.t);
  const p = Number(h.p);
  if (!unchecked) checkKdfRange(m, t, p);
  else if (!(m > 0 && t > 0 && p > 0)) fail('kdf_out_of_range');
  const rest = file.length - h.headerLen;
  if (rest < 72 + 40) bad();
  if (rest - 72 - 40 > MAX_BODY) fail('too_large');
  const header = file.subarray(0, h.headerLen);
  const ekWrap = file.subarray(h.headerLen, h.headerLen + 72);
  const body = file.subarray(h.headerLen + 72);
  const key = kExp(argon2id(password, h.salt, m, t, p, 32));
  const ek = aeadOpen(key, ekWrap, aadEk(header));
  const plain = aeadOpen(ek, body, aadBody(header));

  const v = decode(plain, { maxNodes: 1000000 });
  const shape = () => fail('malformed_item_body');
  if (v.k !== 'map') shape();
  const ver = get(v, 'v');
  if (!ver || ver.k !== 'int') shape();
  if (ver.v !== 1n) fail('unsupported');
  if (v.v.length !== 2 || !get(v, 'items') || get(v, 'items').k !== 'array') shape();
  const seen = new Set();
  const items = get(v, 'items').v.map((it) => {
    if (it.k !== 'map' || it.v.length !== 2) shape();
    const id = get(it, 'id');
    const bodyValue = get(it, 'body');
    if (!id || id.k !== 'bytes' || id.v.length !== 16 || !bodyValue) shape();
    if (equal(id.v, ZERO_ID)) shape();
    const k = hex(id.v);
    if (seen.has(k)) shape();
    seen.add(k);
    try {
      parseBodyValue(bodyValue);
    } catch (e) {
      if (e.code === 'malformed_item_body') shape();
      throw e;
    }
    return { id: id.v, value: bodyValue };
  });
  return { createdAt: h.createdAt, kdf: { m_kib: m, t, p }, items };
}

function parseBodyValue(value) {
  // reuse the byte-level parser: re-encode, then read again (no information is lost)
  return parseBody(encode(value));
}

// ---- plain exports ------------------------------------------------------------------------
const PASSKEY_SECRETS = new Set(['priv', 'prf_seed_uv', 'prf_seed_nouv']);

function jsonString(s) {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (c === 8) out += '\\b';
    else if (c === 12) out += '\\f';
    else if (c < 0x20) out += `\\u${c.toString(16).padStart(4, '0')}`;
    else out += ch;
  }
  return `${out}"`;
}

function jsonValue(val) {
  switch (val.k) {
    case 'int':
      return val.v.toString();
    case 'text':
      return jsonString(val.v);
    case 'bytes':
      return `"${hex(val.v)}"`;
    case 'bool':
      return val.v ? 'true' : 'false';
    case 'null':
      return 'null';
    case 'float': {
      const f = floatValue(val.raw);
      return Number.isFinite(f) ? String(f) : 'null';
    }
    case 'array':
      return `[${val.v.map(jsonValue).join(',')}]`;
    case 'map':
      return `{${val.v.map(([k, x]) => `${jsonString(k)}:${jsonValue(x)}`).join(',')}}`;
  }
  throw new Error('unknown value');
}

export function plainJson(items, includePasskeys) {
  const list = readItems(items);
  const body = (value) => {
    // the passkey secrets are dropped from the `passkey` map of the item
    const m = value.v.map(([k, x]) => [k, k === 'passkey' && !includePasskeys ? { k: 'map', v: x.v.filter(([kk]) => !PASSKEY_SECRETS.has(kk)) } : x]);
    return jsonValue({ k: 'map', v: m });
  };
  return `{"v":1,"items":[${list.map((i) => `{"id":"${hex(i.id)}","body":${body(i.value)}}`).join(',')}]}`;
}

function csvCell(text) {
  let s = text;
  // formula neutralisation: first character after any leading spaces
  const first = s.replace(/^ +/, '')[0];
  if (first !== undefined && ['=', '+', '-', '@', '\t', '\r'].includes(first)) s = `'${s}`;
  if (/[",\r\n]/.test(s)) s = `"${s.replace(/"/g, '""')}"`;
  return s;
}

export function plainCsv(items) {
  const list = readItems(items);
  const str = (m, key) => {
    const x = m && get(m, key);
    return x && x.k === 'text' ? x.v : '';
  };
  const rows = list.map((i) => {
    const v = i.value;
    const fields = get(v, 'fields').v;
    const urls = get(v, 'urls').v.map((u) => str(u, 'url')).join(' ');
    const totp = get(v, 'totp');
    const pk = get(v, 'passkey');
    const cells = [
      hex(i.id),
      str(v, 'type'),
      str(v, 'name'),
      urls,
      str(v, 'notes'),
      totp ? str(totp, 'uri') : '',
      get(v, 'favorite').v ? 'true' : 'false',
      get(v, 'created').v.toString(),
      get(v, 'modified').v.toString(),
      pk ? str(pk, 'rp_id') : '',
      pk ? str(pk, 'user_name') : '',
    ];
    const extra = [];
    for (const f of fields) extra.push(str(f, 'label'), str(f, 'kind'), str(f, 'value'));
    return { cells, extra, count: fields.length };
  });
  const widest = rows.reduce((n, r) => Math.max(n, r.count), 0);
  const head = ['id', 'type', 'name', 'url', 'notes', 'totp', 'favorite', 'created', 'modified', 'passkey_rp_id', 'passkey_user_name'];
  for (let n = 1; n <= widest; n++) head.push(`field_${n}_label`, `field_${n}_kind`, `field_${n}_value`);
  const lines = [head.join(',')];
  for (const r of rows) {
    const all = [...r.cells.map(csvCell), ...r.extra.map(csvCell)];
    while (all.length < head.length) all.push('');
    lines.push(all.join(','));
  }
  return lines.map((l) => `${l}\r\n`).join('');
}

export { utf8 };
