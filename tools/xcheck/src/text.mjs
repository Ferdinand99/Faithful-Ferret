// Master password and export password text rules (Fase 1 section 3.1 and 4.1), and the
// recovery key and secret key codes (section 6.1 and 6.2).
import { fail, utf8, ascii, concat } from './util.mjs';
import { sha256 } from './crypto.mjs';
import { ASSIGNED_IN_17 } from './unicode17.mjs';

const strictUtf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

// "Not assigned in the locked table": the table is Unicode 16.0 (section 3.1).
const reAssigned = /^\p{Assigned}$/u;
function assignedIn16(cp) {
  if (!reAssigned.test(String.fromCodePoint(cp))) return false;
  if (process.versions.unicode >= '17') {
    // code points first assigned in 17.0 are outside the locked table
    for (const [a, b] of ASSIGNED_IN_17) if (cp >= a && cp <= b) return false;
  }
  return true;
}

const reControl = /^\p{Cc}$/u;
export function forbidden(cp) {
  const ch = String.fromCodePoint(cp);
  return reControl.test(ch) || !assignedIn16(cp);
}

const scalars = (s) => Array.from(s).length;

// Returns { nfkd: Uint8Array } for a text given as UTF-8 bytes.
// policy: { min } (min in scalars after NFC, 0 for none).
export function checkText(bytes, min) {
  let s;
  try {
    s = strictUtf8.decode(bytes);
  } catch {
    fail('input_not_utf8');
  }
  // forbidden characters win over the length rules
  for (const ch of s) if (forbidden(ch.codePointAt(0))) fail('input_forbidden_character');
  // more than 1 024 scalars is refused before NFKD is made
  if (scalars(s) > 1024) fail('input_too_long');
  const nfkd = s.normalize('NFKD');
  if (scalars(nfkd) > 1024) fail('input_too_long');
  if (bytes.length > 4096) fail('input_too_long');
  if (scalars(s.normalize('NFC')) < min) fail('input_too_short');
  return { nfkd: utf8(nfkd), text: nfkd };
}

export const MIN_WITH_SK = 12;
export const MIN_WITHOUT_SK = 15;
export const MIN_EXPORT = 12;

export function masterPassword(bytes, policy) {
  const min = policy === 'with_secret_key' ? MIN_WITH_SK : policy === 'without_secret_key' ? MIN_WITHOUT_SK : null;
  // `unlock` has no creation floor: it only has to be a valid text.
  return checkText(bytes, min ?? 1);
}

// ---- codes ---------------------------------------------------------------------------------
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford Base32

function bitsOf(bytes) {
  let b = '';
  for (const x of bytes) b += x.toString(2).padStart(8, '0');
  return b;
}
function toChars(bits) {
  let out = '';
  for (let i = 0; i < bits.length; i += 5) out += ALPHABET[parseInt(bits.slice(i, i + 5), 2)];
  return out;
}

const KINDS = {
  rk: { prefix: 'FFR1', keyLen: 32, spare: 4, dataChars: 52, groupSize: 4, checkLabel: 'ferret/v1/rk-check' },
  sk: { prefix: 'FFS1', keyLen: 16, spare: 2, dataChars: 26, groupSize: 5, checkLabel: 'ferret/v1/sk-check' },
};

function checkChars(kind, key) {
  const h = sha256(ascii(kind.checkLabel), key);
  return toChars(bitsOf(h).slice(0, 20));
}

export function encodeCode(which, key) {
  const k = KINDS[which];
  if (key.length !== k.keyLen) throw new Error('bad key length');
  const body = toChars(bitsOf(key) + '0'.repeat(k.spare)) + checkChars(k, key);
  const groups = body.match(new RegExp(`.{${k.groupSize}}`, 'g'));
  return `${k.prefix}-${groups.join('-')}`;
}

const SEPARATORS = new Set(['-', ' ', '\t', '\n', '\r', '\f', '\v', ' ', '–', '—']);

export function decodeCode(which, code) {
  const k = KINDS[which];
  let s = '';
  for (const ch of code) if (!SEPARATORS.has(ch)) s += ch;
  s = s.toUpperCase().replace(/O/g, '0').replace(/[IL]/g, '1');
  if (s.length < 4) fail('input_too_short');
  if (s.slice(0, 4) !== k.prefix) fail('malformed_code');
  const body = s.slice(4);
  const want = k.dataChars + 4;
  if (body.length < want) fail('input_too_short');
  if (body.length > want) fail('input_too_long');
  let bits = '';
  for (const ch of body) {
    const v = ALPHABET.indexOf(ch);
    if (v < 0) fail('malformed_code');
    bits += v.toString(2).padStart(5, '0');
  }
  const dataBits = bits.slice(0, k.dataChars * 5);
  const key = new Uint8Array(k.keyLen);
  for (let i = 0; i < k.keyLen; i++) key[i] = parseInt(dataBits.slice(i * 8, i * 8 + 8), 2);
  // the check comes first: a typo is a typo even if the spare bits are also wrong
  if (body.slice(k.dataChars) !== checkChars(k, key)) fail('checksum');
  if (/1/.test(dataBits.slice(k.keyLen * 8))) fail('non_canonical');
  return key;
}

export { concat };
