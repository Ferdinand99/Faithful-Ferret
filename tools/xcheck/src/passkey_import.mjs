// Import of a passkey from another program (Fase 1 section 9.1, 9.6): the op `passkey.import`.
// Written from the formats (RFC 5958, RFC 5915 and RFC 7518 section 6.2) and the rules of OPS.md, with its own
// small DER reader and JSON member scanner; nothing is taken from the core.
import { fail, hex, unhex, utf8, concat, equal } from './util.mjs';
import { canonicalHost } from './origin.mjs';
import { isPublicSuffix } from './psl.mjs';
import * as p256 from './p256.mjs';
import { pkcs8, spki } from './passkey.mjs';

const MAX_TEXT = 1024;
const MAX_CRED_ID = 1023;
const MAX_HANDLE = 64;
const MAX_PKCS8 = 1024;
const MAX_JWK = 4096;
const ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

const badKey = () => fail('malformed_item_body');

const noControls = (t) => t.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u061c\u200b\u200e\u200f\u202a-\u202e\u2066-\u2069\ufeff]/gu, '');
const storedText = (t) => (t === null || t === undefined || noControls(t) === '' ? null : noControls(t));

const scalarValue = (bytes) => BigInt(`0x${hex(bytes) || '0'}`);
const validScalar = (bytes) => bytes.length === 32 && scalarValue(bytes) > 0n && scalarValue(bytes) < ORDER;

// ---- DER (just enough for PKCS#8 of an EC key)

// One tag-length-value at `at`; returns { tag, body, end } or null when it does not fit.
function tlv(buf, at) {
  if (at + 2 > buf.length) return null;
  const tag = buf[at];
  let len = buf[at + 1];
  let start = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 2 || start + n > buf.length) return null;
    len = 0;
    for (let k = 0; k < n; k++) len = len * 256 + buf[start + k];
    start += n;
  }
  if (start + len > buf.length) return null;
  return { tag, body: buf.subarray(start, start + len), end: start + len };
}

const OID_EC = '2a8648ce3d0201'; // 1.2.840.10045.2.1
const OID_P256 = '2a8648ce3d030107'; // 1.2.840.10045.3.1.7

// PrivateKeyInfo ::= SEQUENCE { version, algorithm SEQUENCE { oid, params }, privateKey OCTET STRING, ... }
// Returns null when it is not that structure.
function privateKeyInfo(der) {
  const outer = tlv(der, 0);
  if (!outer || outer.tag !== 0x30 || outer.end !== der.length) return null;
  const version = tlv(outer.body, 0);
  if (!version || version.tag !== 0x02) return null;
  const alg = tlv(outer.body, version.end);
  if (!alg || alg.tag !== 0x30) return null;
  const key = tlv(outer.body, alg.end);
  if (!key || key.tag !== 0x04) return null;
  const oid = tlv(alg.body, 0);
  if (!oid || oid.tag !== 0x06) return null;
  const params = tlv(alg.body, oid.end);
  return { oid: hex(oid.body), params: params && params.tag === 0x06 ? hex(params.body) : null, key: key.body };
}

// ECPrivateKey ::= SEQUENCE { 1, OCTET STRING d, [0] params OPTIONAL, [1] BIT STRING public OPTIONAL }
function scalarOfPkcs8(der) {
  if (der.length > MAX_PKCS8) fail('too_large');
  const info = privateKeyInfo(der);
  if (!info) badKey();
  if (info.oid !== OID_EC || info.params !== OID_P256) fail('unsupported');
  const ec = tlv(info.key, 0);
  if (!ec || ec.tag !== 0x30 || ec.end !== info.key.length) badKey();
  const ver = tlv(ec.body, 0);
  if (!ver || ver.tag !== 0x02 || !equal(ver.body, Uint8Array.of(1))) badKey();
  const d = tlv(ec.body, ver.end);
  if (!d || d.tag !== 0x04 || !validScalar(d.body)) badKey();
  let at = d.end;
  let pub = null;
  while (at < ec.body.length) {
    const item = tlv(ec.body, at);
    if (!item) badKey();
    if (item.tag === 0xa0) {
      const curve = tlv(item.body, 0);
      if (!curve || curve.tag !== 0x06 || hex(curve.body) !== OID_P256) badKey();
    } else if (item.tag === 0xa1) {
      const bits = tlv(item.body, 0);
      if (!bits || bits.tag !== 0x03 || bits.body[0] !== 0 || bits.body[1] !== 4 || bits.body.length !== 66) badKey();
      pub = bits.body.subarray(2);
    } else {
      badKey();
    }
    at = item.end;
  }
  const scalar = Uint8Array.from(d.body);
  if (pub) {
    const real = p256.publicKey(scalar);
    if (!equal(pub, concat(real.x, real.y))) badKey();
  }
  return scalar;
}

// ---- JWK

// The members of the top-level object of `text`: [{ key, raw }] where `raw` is the text of a string value (the
// characters between the quotes) or null for any other kind of value. `text` is known to be valid JSON.
function members(text) {
  const out = [];
  let i = text.indexOf('{') + 1;
  const skipWs = () => {
    while (' \t\n\r'.includes(text[i])) i++;
  };
  const string = () => {
    const start = ++i;
    while (text[i] !== '"') i += text[i] === '\\' ? 2 : 1;
    i++;
    return text.slice(start, i - 1);
  };
  const skipValue = () => {
    let depth = 0;
    while (i < text.length) {
      const c = text[i];
      if (c === '"') {
        string();
        if (depth === 0) return;
        continue;
      }
      if (c === '{' || c === '[') depth++;
      else if (c === '}' || c === ']') {
        if (depth === 0) return;
        depth--;
        if (depth === 0) {
          i++;
          return;
        }
      } else if (depth === 0 && (c === ',')) return;
      i++;
    }
  };
  skipWs();
  while (text[i] !== '}') {
    skipWs();
    const key = string();
    skipWs();
    i++; // the colon
    skipWs();
    if (text[i] === '"') {
      out.push({ key, raw: string() });
    } else {
      const from = i;
      skipValue();
      out.push({ key, raw: null, from });
    }
    skipWs();
    if (text[i] === ',') i++;
    skipWs();
  }
  return out;
}

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

// 32 bytes from base64url text of 43 symbols (up to two `=` after them), spare bits zero.
function coordinate(text) {
  const t = text.replace(/={1,2}$/, '');
  if (t.length !== 43 || [...t].some((c) => !B64URL.includes(c))) badKey();
  const last = B64URL.indexOf(t[42]);
  if (last % 4 !== 0) badKey();
  return new Uint8Array(Buffer.from(t, 'base64url'));
}

function scalarOfJwk(text) {
  if (utf8(text).length > MAX_JWK) fail('too_large');
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return badKey();
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) badKey();
  const all = members(text);
  const known = ['kty', 'crv', 'alg', 'x', 'y', 'd'];
  const found = {};
  for (const m of all) {
    // no exporter escapes a member name; a reader that unescapes it would see another member
    if (m.key.includes('\\')) badKey();
    if (!known.includes(m.key)) continue;
    // a known member is one string without an escape, and appears once
    if (m.raw === null || m.raw.includes('\\') || m.key in found) badKey();
    found[m.key] = m.raw;
  }
  if (found.kty !== undefined && found.kty !== 'EC') fail('unsupported');
  if (found.crv === undefined) badKey();
  if (found.crv !== 'P-256') fail('unsupported');
  if (found.alg !== undefined && found.alg !== 'ES256') fail('unsupported');
  if (found.d === undefined) badKey();
  const scalar = coordinate(found.d);
  if (!validScalar(scalar)) badKey();
  if ((found.x === undefined) !== (found.y === undefined)) badKey();
  if (found.x !== undefined) {
    const real = p256.publicKey(scalar);
    if (!equal(coordinate(found.x), real.x) || !equal(coordinate(found.y), real.y)) badKey();
  }
  return scalar;
}

// ---- the op

function rpId(raw) {
  const host = canonicalHost(raw);
  if (host === null || isPublicSuffix(host)) fail('malformed_rp_id');
  return host;
}

export function importPasskey(input) {
  const credId = unhex(input.cred_id);
  if (credId.length === 0) fail('malformed_webauthn_options');
  if (credId.length > MAX_CRED_ID) fail('too_large');
  const handle = unhex(input.user_handle);
  if (handle.length === 0 || handle.length > MAX_HANDLE) fail('malformed_webauthn_options');
  const texts = [input.user_name, input.rp_name, input.user_display_name, input.rp_id].filter((t) => t !== null);
  if (texts.some((t) => utf8(t).length > MAX_TEXT)) fail('too_large');
  if (BigInt(input.created) > 2n ** 53n - 1n) fail('too_large');
  const rp = rpId(input.rp_id);
  const scalar = input.key.format === 'jwk' ? scalarOfJwk(input.key.text) : scalarOfPkcs8(unhex(input.key.hex));
  let seeds = null;
  if (input.prf) {
    seeds = { uv: unhex(input.prf.uv), nouv: unhex(input.prf.nouv) };
    if (seeds.uv.length !== 32 || seeds.nouv.length !== 32) badKey();
  }
  const pub = p256.publicKey(scalar);
  return {
    expect: {
      record: {
        cred_id: hex(credId),
        rp_id: rp,
        user_handle: hex(handle),
        user_name: noControls(input.user_name),
        rp_name: storedText(input.rp_name),
        user_display_name: storedText(input.user_display_name),
        created: input.created,
        priv_pkcs8: hex(pkcs8(scalar, pub)),
        public_key_spki: hex(spki(pub)),
        prf_seed_uv: seeds ? hex(seeds.uv) : null,
        prf_seed_nouv: seeds ? hex(seeds.nouv) : null,
      },
      notes: { register_again: input.counter > 0, counter: input.counter, prf: seeds !== null },
    },
  };
}
