// Setup QR payload of the emergency sheet (vectors/OPS.md, sheet.qr.build and sheet.qr.parse).
import net from 'node:net';
import { fail, hex, unhex, ascii } from './util.mjs';
import { ksfParams } from './keys.mjs';

const bad = (why) => fail('malformed_setup_qr', why);
const UNRESERVED = /^[A-Za-z0-9\-._~]$/;

// Validates a server address. The address is kept as written.
export function checkServerAddress(url) {
  if (url.length > 512) fail('too_large'); // ASCII only below, so characters are bytes
  if (!/^[\x21-\x7e]*$/.test(url)) bad('not printable ASCII');
  let rest;
  let https;
  if (url.startsWith('https://')) {
    https = true;
    rest = url.slice(8);
  } else if (url.startsWith('http://')) {
    https = false;
    rest = url.slice(7);
  } else bad('scheme');
  const end = rest.search(/[/?#]/);
  const authority = end < 0 ? rest : rest.slice(0, end);
  if (authority === '' || !/^[A-Za-z0-9\-._~:[\]]*$/.test(authority)) bad('authority');

  let host;
  let port = null;
  if (authority.startsWith('[')) {
    const close = authority.indexOf(']');
    if (close < 0) bad('ipv6');
    host = authority.slice(0, close + 1);
    const after = authority.slice(close + 1);
    if (after !== '') {
      if (!after.startsWith(':')) bad('after ipv6');
      port = after.slice(1);
    }
    if (!net.isIPv6(host.slice(1, -1))) bad('ipv6 literal');
  } else {
    const colon = authority.indexOf(':');
    if (colon >= 0) {
      host = authority.slice(0, colon);
      port = authority.slice(colon + 1);
    } else host = authority;
    if (host === '' || /[[\]:]/.test(host)) bad('host');
  }
  if (port !== null) {
    if (!/^[0-9]{1,5}$/.test(port)) bad('port');
    const n = Number(port);
    if (n < 1 || n > 65535) bad('port');
  }

  let isIp = host.startsWith('[');
  if (!isIp) {
    // a host a browser would read as IPv4: last label all digits or starting with 0x
    const labels = host.endsWith('.') ? host.slice(0, -1).split('.') : host.split('.');
    const last = labels[labels.length - 1];
    if (/^[0-9]+$/.test(last) || /^0[xX]/.test(last)) {
      const canonical = !host.endsWith('.') && labels.length === 4 && labels.every((l) => /^(0|[1-9][0-9]{0,2})$/.test(l) && Number(l) <= 255);
      if (!canonical) bad('ipv4');
      isIp = true;
    }
  }
  if (!https && !(isIp || host.toLowerCase() === 'localhost')) bad('http needs a local address');
}

function pctEncode(s) {
  let out = '';
  for (const b of ascii(s)) {
    const ch = String.fromCharCode(b);
    out += UNRESERVED.test(ch) ? ch : `%${b.toString(16).toUpperCase().padStart(2, '0')}`;
  }
  return out;
}

export function buildPayload({ url, accountId, profile, skBit, serverKey }) {
  checkServerAddress(url);
  if (!ksfParams(profile)) fail('kdf_profile_unknown');
  return `ferret-setup:v1?u=${pctEncode(url)}&a=${hex(accountId)}&k=${profile}&s=${skBit ? 1 : 0}&o=${hex(serverKey)}`;
}

export function parsePayload(payload) {
  if (Buffer.byteLength(payload, 'utf8') > 1700) fail('too_large');
  const m = /^ferret-setup:v([^?]*)\?(.*)$/s.exec(payload);
  if (!m) bad('shape');
  if (!/^[0-9]+$/.test(m[1])) bad('version');
  if (m[1] !== '1') fail('unsupported');
  const pairs = m[2].split('&');
  const names = ['u', 'a', 'k', 's', 'o'];
  if (pairs.length !== 5) bad('parameters');
  const vals = {};
  pairs.forEach((p, i) => {
    const eq = p.indexOf('=');
    if (eq < 0 || p.slice(0, eq) !== names[i]) bad('parameter order');
    vals[names[i]] = p.slice(eq + 1);
  });
  // u: only unreserved characters raw; every other byte as %XX in upper case; never %XX for an unreserved one
  const raw = vals.u;
  let url = '';
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    if (c === '%') {
      const h = raw.slice(i + 1, i + 3);
      if (!/^[0-9A-F]{2}$/.test(h)) bad('percent escape');
      const ch = String.fromCharCode(parseInt(h, 16));
      if (UNRESERVED.test(ch)) bad('needless escape');
      url += ch;
      i += 2;
    } else if (UNRESERVED.test(c)) url += c;
    else bad('raw character');
  }
  checkServerAddress(url);
  if (!/^[0-9a-f]{32}$/.test(vals.a)) bad('account id');
  if (!/^(0|[1-9][0-9]*)$/.test(vals.k)) bad('profile');
  if (vals.s !== '0' && vals.s !== '1') bad('sk bit');
  if (!/^[0-9a-f]{64}$/.test(vals.o)) bad('server key');
  const profile = Number(vals.k);
  if (!ksfParams(profile)) fail('kdf_profile_unknown');
  return { url, accountId: unhex(vals.a), profile, skBit: vals.s === '1', serverKey: unhex(vals.o) };
}
