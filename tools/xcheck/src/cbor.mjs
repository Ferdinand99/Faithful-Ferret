// A strict CBOR reader and shortest-form writer for the limits of Fase 1 section 5.2.
//
// Values: { k: 'int', v: bigint } | { k: 'bytes', v } | { k: 'text', v } | { k: 'array', v: [] }
//       | { k: 'map', v: [[key string, value], ...] } | { k: 'bool', v } | { k: 'null' }
//       | { k: 'float', raw: Uint8Array(2 | 4 | 8) }   (kept at the width it was read)
import { fail, concat } from './util.mjs';

export const LIMITS = { depth: 16, entries: 10000, bytes: 65536 };

const dec = new TextDecoder('utf-8', { fatal: true });
const enc = new TextEncoder();

export function decode(buf, { maxNodes = Infinity, prefix = false } = {}) {
  let pos = 0;
  let nodes = 0;
  const need = (n) => {
    if (buf.length - pos < n) fail('malformed_cbor', 'truncated');
  };
  const readUint = (info) => {
    if (info < 24) return BigInt(info);
    if (info === 24) {
      need(1);
      return BigInt(buf[pos++]);
    }
    if (info === 25) {
      need(2);
      const v = (buf[pos] << 8) | buf[pos + 1];
      pos += 2;
      return BigInt(v);
    }
    if (info === 26) {
      need(4);
      const v = new DataView(buf.buffer, buf.byteOffset + pos, 4).getUint32(0, false);
      pos += 4;
      return BigInt(v);
    }
    need(8);
    const v = new DataView(buf.buffer, buf.byteOffset + pos, 8).getBigUint64(0, false);
    pos += 8;
    return v;
  };

  function item(depth) {
    need(1);
    const ib = buf[pos++];
    const major = ib >> 5;
    const info = ib & 31;
    if (++nodes > maxNodes) fail('malformed_cbor_count', 'too many nodes');

    if (major === 6) fail('malformed_cbor_tag');
    if (major === 7) {
      if (info === 20) return { k: 'bool', v: false };
      if (info === 21) return { k: 'bool', v: true };
      if (info === 22) return { k: 'null' };
      if (info === 25 || info === 26 || info === 27) {
        const w = info === 25 ? 2 : info === 26 ? 4 : 8;
        need(w);
        const raw = buf.slice(pos, pos + w);
        pos += w;
        return { k: 'float', raw };
      }
      if (info === 31) fail('malformed_cbor', 'stray break');
      if (info >= 28) fail('malformed_cbor', 'reserved');
      fail('malformed_cbor_simple'); // undefined (23), simple 0..19, and 24 (one-byte simple)
    }
    if (info === 31) fail('malformed_cbor_indefinite');
    if (info >= 28) fail('malformed_cbor', 'reserved');
    const arg = readUint(info);
    switch (major) {
      case 0:
        return { k: 'int', v: arg };
      case 1: {
        const v = -1n - arg;
        if (v < -(2n ** 63n)) fail('malformed_cbor_int');
        return { k: 'int', v };
      }
      case 2:
      case 3: {
        if (arg > BigInt(LIMITS.bytes)) fail('malformed_cbor_size');
        const n = Number(arg);
        need(n);
        const bytes = buf.slice(pos, pos + n);
        pos += n;
        if (major === 2) return { k: 'bytes', v: bytes };
        try {
          return { k: 'text', v: dec.decode(bytes) };
        } catch {
          fail('malformed_cbor', 'bad UTF-8');
        }
        break;
      }
      case 4: {
        if (depth + 1 > LIMITS.depth) fail('malformed_cbor_depth');
        if (arg > BigInt(LIMITS.entries)) fail('malformed_cbor_count');
        const out = [];
        for (let i = 0; i < Number(arg); i++) out.push(item(depth + 1));
        return { k: 'array', v: out };
      }
      case 5: {
        if (depth + 1 > LIMITS.depth) fail('malformed_cbor_depth');
        if (arg > BigInt(LIMITS.entries)) fail('malformed_cbor_count');
        const out = [];
        const seen = new Set();
        for (let i = 0; i < Number(arg); i++) {
          const key = item(depth + 1);
          if (key.k !== 'text') fail('malformed_cbor_key_type');
          if (seen.has(key.v)) fail('malformed_cbor_duplicate_key');
          seen.add(key.v);
          out.push([key.v, item(depth + 1)]);
        }
        return { k: 'map', v: out };
      }
    }
    fail('malformed_cbor');
  }

  const v = item(0);
  if (prefix) return { value: v, len: pos }; // the first item of a longer buffer
  if (pos !== buf.length) fail('malformed_cbor_trailing');
  return v;
}

function head(major, n) {
  const m = major << 5;
  const b = BigInt(n);
  if (b < 24n) return Uint8Array.of(m | Number(b));
  if (b < 256n) return Uint8Array.of(m | 24, Number(b));
  if (b < 65536n) return Uint8Array.of(m | 25, Number(b >> 8n), Number(b & 255n));
  if (b < 4294967296n) {
    const o = new Uint8Array(5);
    o[0] = m | 26;
    new DataView(o.buffer).setUint32(1, Number(b), false);
    return o;
  }
  const o = new Uint8Array(9);
  o[0] = m | 27;
  new DataView(o.buffer).setBigUint64(1, b, false);
  return o;
}

export function encode(val) {
  switch (val.k) {
    case 'int':
      return val.v >= 0n ? head(0, val.v) : head(1, -1n - val.v);
    case 'bytes':
      return concat(head(2, val.v.length), val.v);
    case 'text': {
      const b = enc.encode(val.v);
      return concat(head(3, b.length), b);
    }
    case 'array':
      return concat(head(4, val.v.length), ...val.v.map(encode));
    case 'map':
      return concat(head(5, val.v.length), ...val.v.map(([k, v]) => concat(encode({ k: 'text', v: k }), encode(v))));
    case 'bool':
      return Uint8Array.of(val.v ? 0xf5 : 0xf4);
    case 'null':
      return Uint8Array.of(0xf6);
    case 'float':
      return concat(Uint8Array.of(val.raw.length === 2 ? 0xf9 : val.raw.length === 4 ? 0xfa : 0xfb), val.raw);
  }
  throw new Error('unknown CBOR value kind');
}

export const C = {
  uint: (n) => ({ k: 'int', v: BigInt(n) }),
  text: (s) => ({ k: 'text', v: s }),
  bytes: (b) => ({ k: 'bytes', v: b }),
  array: (a) => ({ k: 'array', v: a }),
  map: (m) => ({ k: 'map', v: m }),
  bool: (b) => ({ k: 'bool', v: b }),
};

export function floatValue(raw) {
  const dv = new DataView(raw.buffer, raw.byteOffset, raw.length);
  if (raw.length === 8) return dv.getFloat64(0, false);
  if (raw.length === 4) return dv.getFloat32(0, false);
  const h = dv.getUint16(0, false); // half precision
  const s = h & 0x8000 ? -1 : 1;
  const e = (h >> 10) & 31;
  const f = h & 1023;
  if (e === 0) return s * 2 ** -14 * (f / 1024);
  if (e === 31) return f ? NaN : s * Infinity;
  return s * 2 ** (e - 15) * (1 + f / 1024);
}
