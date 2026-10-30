// Small byte helpers. No dependencies.

export class XError extends Error {
  constructor(code, detail = '') {
    super(detail ? `${code}: ${detail}` : code);
    this.code = code;
  }
}

export const fail = (code, detail) => {
  throw new XError(code, detail);
};

export const hex = (u8) => Buffer.from(u8).toString('hex');

export function unhex(s) {
  if (typeof s !== 'string' || s.length % 2 !== 0 || !/^[0-9a-f]*$/.test(s)) {
    throw new Error(`bad hex: ${String(s).slice(0, 40)}`);
  }
  return new Uint8Array(Buffer.from(s, 'hex'));
}

export function concat(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export const ascii = (s) => new Uint8Array(Buffer.from(s, 'latin1'));
export const utf8 = (s) => new Uint8Array(Buffer.from(s, 'utf8'));

export function u8(n) {
  return Uint8Array.of(n & 0xff);
}
export function u16be(n) {
  return Uint8Array.of((n >> 8) & 0xff, n & 0xff);
}
export function u32be(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, false);
  return b;
}
// u64 from a BigInt or a decimal string.
export function u64be(v) {
  const n = typeof v === 'bigint' ? v : BigInt(v);
  if (n < 0n || n > 0xffffffffffffffffn) throw new Error('u64 out of range');
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, false);
  return b;
}

export function equal(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export function repeat(bytes, n) {
  const out = new Uint8Array(bytes.length * n);
  for (let i = 0; i < n; i++) out.set(bytes, i * bytes.length);
  return out;
}

// Byte segments of OPS.md: { "segments": [ { "hex", "repeat" } | { "keys": { count, value_hex } } ] }.
// The "keys" segment is `count` map entries without a map head: the five-digit counter as a CBOR
// text ("00000" ...), then the bytes value_hex.
export function segmentsToBytes(seg) {
  const parts = [];
  for (const s of Array.isArray(seg) ? seg : seg.segments) {
    if (s.keys) {
      const v = unhex(s.keys.value_hex);
      for (let i = 0; i < s.keys.count; i++) {
        parts.push(Uint8Array.of(0x65), ascii(String(i).padStart(5, '0')), v);
      }
    } else {
      parts.push(repeat(unhex(s.hex), s.repeat ?? 1));
    }
  }
  return concat(...parts);
}

// Text input of OPS.md: { utf8: hex } or { segments: [ { escapes: "U+0061 U+030A", repeat } ] }.
export function textInputToBytes(t) {
  if (t.utf8 !== undefined) return unhex(t.utf8);
  let s = '';
  for (const seg of t.segments) {
    const cps = seg.escapes.trim() === '' ? [] : seg.escapes.trim().split(/\s+/).map((x) => parseInt(x.replace(/^U\+/, ''), 16));
    const one = String.fromCodePoint(...cps);
    s += one.repeat(seg.repeat ?? 1);
  }
  return utf8(s);
}
