// P-256 (secp256r1) arithmetic with BigInt, and ECDSA with the deterministic nonce of RFC 6979.
// Written from the public curve parameters so the passkey signatures can be reproduced byte for byte;
// WebCrypto (in passkey.mjs) verifies them independently.
import nodeCrypto from 'node:crypto';
import { concat } from './util.mjs';

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
const GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;

const mod = (a, m = P) => ((a % m) + m) % m;
function inv(a, m = P) {
  let [r0, r1] = [mod(a, m), m];
  let [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  return mod(s0, m);
}

// affine points; null is the point at infinity
function add(p, q) {
  if (p === null) return q;
  if (q === null) return p;
  if (p.x === q.x) {
    if (mod(p.y + q.y) === 0n) return null;
    const l = mod((3n * p.x * p.x - 3n) * inv(2n * p.y));
    const x = mod(l * l - 2n * p.x);
    return { x, y: mod(l * (p.x - x) - p.y) };
  }
  const l = mod((q.y - p.y) * inv(q.x - p.x));
  const x = mod(l * l - p.x - q.x);
  return { x, y: mod(l * (p.x - x) - p.y) };
}

function mul(k, p) {
  let r = null;
  let a = p;
  for (let e = k; e > 0n; e >>= 1n) {
    if (e & 1n) r = add(r, a);
    a = add(a, a);
  }
  return r;
}

const G = { x: GX, y: GY };
const big = (b) => BigInt(`0x${Buffer.from(b).toString('hex') || '0'}`);
const bytes32 = (n) => Uint8Array.from(Buffer.from(n.toString(16).padStart(64, '0'), 'hex'));

export function publicKey(scalar) {
  const d = big(scalar);
  if (d <= 0n || d >= N) throw new Error('scalar out of range');
  const q = mul(d, G);
  if (mod(q.y * q.y) !== mod(q.x * q.x * q.x - 3n * q.x + B)) throw new Error('point not on the curve');
  return { x: bytes32(q.x), y: bytes32(q.y) };
}

const hmac = (key, ...parts) => new Uint8Array(nodeCrypto.createHmac('sha256', key).update(concat(...parts)).digest());

// RFC 6979 section 3.2 with SHA-256 and qlen = 256
function nonce(x, h1) {
  const h1n = mod(big(h1), N); // bits2octets
  const h1o = bytes32(h1n);
  const xo = bytes32(big(x));
  let V = new Uint8Array(32).fill(1);
  let K = new Uint8Array(32);
  K = hmac(K, V, Uint8Array.of(0), xo, h1o);
  V = hmac(K, V);
  K = hmac(K, V, Uint8Array.of(1), xo, h1o);
  V = hmac(K, V);
  for (;;) {
    V = hmac(K, V);
    const k = big(V);
    if (k >= 1n && k < N) return k;
    K = hmac(K, V, Uint8Array.of(0));
    V = hmac(K, V);
  }
}

const derInt = (n) => {
  let b = Buffer.from(n.toString(16).padStart(64, '0'), 'hex');
  while (b.length > 1 && b[0] === 0 && b[1] < 0x80) b = b.subarray(1);
  if (b[0] >= 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return Buffer.concat([Buffer.from([0x02, b.length]), b]);
};

// ECDSA over SHA-256(message); returns { der, p1363 }
export function sign(scalar, message) {
  const h = new Uint8Array(nodeCrypto.createHash('sha256').update(message).digest());
  const d = big(scalar);
  const z = big(h);
  const k = nonce(scalar, h);
  const r = mod(mul(k, G).x, N);
  const s = mod(inv(k, N) * (z + r * d), N);
  if (r === 0n || s === 0n) throw new Error('degenerate signature');
  const body = Buffer.concat([derInt(r), derInt(s)]);
  return { der: new Uint8Array(Buffer.concat([Buffer.from([0x30, body.length]), body])), p1363: concat(bytes32(r), bytes32(s)) };
}

// DER ECDSA signature -> r || s (IEEE P1363), the form WebCrypto verifies. Returns null when malformed.
export function derToP1363(der) {
  let i = 0;
  const b = Buffer.from(der);
  const rd = () => b[i++];
  if (rd() !== 0x30) return null;
  let len = rd();
  if (len & 0x80) return null; // signatures of P-256 are shorter than 128 bytes
  if (len !== b.length - 2) return null;
  const ints = [];
  for (let n = 0; n < 2; n++) {
    if (rd() !== 0x02) return null;
    const l = rd();
    let v = b.subarray(i, i + l);
    i += l;
    if (l === 0 || v[0] & 0x80) return null;
    if (v.length > 1 && v[0] === 0 && !(v[1] & 0x80)) return null; // not minimal
    while (v.length > 32 && v[0] === 0) v = v.subarray(1);
    if (v.length > 32) return null;
    ints.push(Buffer.concat([Buffer.alloc(32 - v.length), v]));
  }
  if (i !== b.length) return null;
  return new Uint8Array(Buffer.concat(ints));
}
