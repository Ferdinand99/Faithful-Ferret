// otpauth:// allow-list (Fase 1 section 5.2, F-31 and the rules in vectors/OPS.md) and RFC 6238 codes.
import nodeCrypto from 'node:crypto';
import { fail, u64be, utf8 } from './util.mjs';

const bad = (why) => fail('malformed_otpauth', why);
const strict = new TextDecoder('utf-8', { fatal: true });

const hexVal = (c) => '0123456789abcdefABCDEF'.indexOf(c);

// Percent-decodes to bytes; `plusIsSpace` for query values. Returns a string, rejecting bad UTF-8.
function pctDecode(s, plusIsSpace) {
  const bytes = [];
  const chars = Array.from(s);
  for (let i = 0; i < chars.length; i++) {
    const c = chars[i];
    if (c === '%') {
      const a = chars[i + 1];
      const b = chars[i + 2];
      if (a === undefined || b === undefined || hexVal(a) < 0 || hexVal(b) < 0) bad('bad percent escape');
      bytes.push(parseInt(a + b, 16));
      i += 2;
    } else if (c === '+' && plusIsSpace) bytes.push(0x20);
    else bytes.push(...utf8(c));
  }
  let out;
  try {
    out = strict.decode(Uint8Array.from(bytes));
  } catch {
    bad('not UTF-8');
  }
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(out)) bad('control character');
  return out;
}

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function decodeSecret(raw) {
  let s = raw.replace(/ /g, '');
  if (s === '') bad('empty secret');
  const eq = s.indexOf('=');
  let fill = 0;
  if (eq >= 0) {
    fill = s.length - eq;
    if (s.slice(eq) !== '='.repeat(fill)) bad('fill sign inside the secret');
    s = s.slice(0, eq);
    if (s === '') bad('fill only');
  }
  s = s.toUpperCase();
  const rem = s.length % 8;
  if (![0, 2, 4, 5, 7].includes(rem)) bad('impossible length');
  if (fill && fill !== (8 - rem) % 8) bad('wrong fill');
  let bits = '';
  for (const ch of s) {
    const v = B32.indexOf(ch);
    if (v < 0) bad('not base32');
    bits += v.toString(2).padStart(5, '0');
  }
  const n = Math.floor(bits.length / 8); // spare bits at the end are ignored
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  if (n > 128) fail('too_large');
  if (n < 1) bad('empty');
  return out;
}

function plainNumber(v, lo, hi) {
  if (!/^[1-9][0-9]*$/.test(v)) bad('not a plain number');
  const n = BigInt(v);
  if (n < BigInt(lo) || n > BigInt(hi)) bad('out of range');
  return Number(n);
}

export function parseOtpauth(uri) {
  if (utf8(uri).length > 2048) fail('too_large');
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(uri)) bad('control character');
  if (uri.includes('#')) bad('fragment');
  const prefix = 'otpauth://';
  if (!uri.startsWith(prefix)) bad('scheme');
  const rest = uri.slice(prefix.length);
  const slash = rest.indexOf('/');
  if (slash < 0 || rest.slice(0, slash) !== 'totp') bad('type');
  const afterType = rest.slice(slash + 1);
  const q = afterType.indexOf('?');
  if (q < 0) bad('no query');
  const labelRaw = afterType.slice(0, q);
  const query = afterType.slice(q + 1);

  const params = new Map();
  for (const pair of query.split('&')) {
    if (pair === '') bad('empty pair');
    const eq = pair.indexOf('=');
    if (eq < 0) bad('pair without =');
    const name = pctDecode(pair.slice(0, eq), false);
    if (!['secret', 'issuer', 'algorithm', 'digits', 'period'].includes(name)) bad('unknown parameter');
    if (params.has(name)) bad('repeated parameter');
    params.set(name, pctDecode(pair.slice(eq + 1), true));
  }
  if (!params.has('secret')) bad('no secret');

  const label = pctDecode(labelRaw, false); // a plus in the label is a plus
  let labelIssuer = null;
  let account = label;
  const colon = label.indexOf(':');
  if (colon >= 0) {
    labelIssuer = label.slice(0, colon);
    account = label.slice(colon + 1);
    if (account.startsWith(' ')) account = account.slice(1);
  }
  let issuer = params.get('issuer');
  if (issuer === undefined || issuer === '') issuer = labelIssuer === '' ? null : labelIssuer;
  if (utf8(label).length > 256 || (issuer !== null && utf8(issuer).length > 256)) fail('too_large');

  const algorithm = params.has('algorithm') ? params.get('algorithm') : 'SHA1';
  if (!['SHA1', 'SHA256', 'SHA512'].includes(algorithm)) bad('algorithm');
  const digits = params.has('digits') ? plainNumber(params.get('digits'), 6, 8) : 6;
  const period = params.has('period') ? plainNumber(params.get('period'), 1, 120) : 30;
  const secret = decodeSecret(params.get('secret'));
  return { secret, algorithm, digits, period, issuer, label: account };
}

export function totpCode(parsed, unixSeconds) {
  const t = BigInt(unixSeconds);
  const counter = t / BigInt(parsed.period);
  const mac = new Uint8Array(nodeCrypto.createHmac(parsed.algorithm.toLowerCase(), parsed.secret).update(u64be(counter)).digest());
  const o = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[o] & 0x7f) << 24) | (mac[o + 1] << 16) | (mac[o + 2] << 8) | mac[o + 3];
  const code = String(bin % 10 ** parsed.digits).padStart(parsed.digits, '0');
  const left = parsed.period - Number(t % BigInt(parsed.period));
  return { code, secondsLeft: left };
}
