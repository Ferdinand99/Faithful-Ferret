// Page addresses: site matching, origin, same-site and the host to show (Fase 1 sections 10.4 and 10.5).
// The address is read by Node's WHATWG URL parser (ada), which is independent of the Rust `url` crate.
import { domainToUnicode } from 'node:url';
import { fail } from './util.mjs';
import { hasExplicitRule, registrableDomain } from './psl.mjs';

const MAX_URL_BYTES = 8 * 1024;
// Top-level domains under which names are never one site although the list has a rule: home networks and routers.
const LOCAL_TLDS = ['arpa', 'box'];

// A web address read, or null.
export function parseWeb(raw) {
  if (Buffer.byteLength(raw, 'utf8') > MAX_URL_BYTES) return null;
  let u;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  if (u.username !== '' || u.password !== '') return null;
  let host = u.hostname;
  const ip = host.startsWith('[') || /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(host);
  if (!ip) {
    if (host.endsWith('.')) host = host.slice(0, -1);
    if (host === '' || host.split('.').includes('')) return null;
  }
  const https = u.protocol === 'https:';
  const port = u.port === '' ? (https ? 443 : 80) : Number(u.port);
  if (port === 0) return null;
  const noFragment = u.href.split('#')[0];
  const q = noFragment.indexOf('?');
  return { https, host, ip, port, path: u.pathname, query: q < 0 ? null : noFragment.slice(q + 1) };
}

function registrable(p) {
  if (p.ip) return null;
  if (LOCAL_TLDS.includes(p.host.split('.').pop())) return null;
  if (!hasExplicitRule(p.host)) return null;
  return registrableDomain(p.host);
}

export function urlMatch(entryUrl, kind, pageUrl) {
  if (kind !== 'host' && kind !== 'domain' && kind !== 'exact') return 'none';
  const e = parseWeb(entryUrl);
  const p = parseWeb(pageUrl);
  if (!e || !p || e.https !== p.https || e.port !== p.port) return 'none';
  if (kind === 'exact') return e.host === p.host && e.path === p.path && e.query === p.query ? 'exact' : 'none';
  if (e.host === p.host) return 'host';
  // An address saved with http is never widened to other hosts.
  if (kind === 'domain' && e.https) {
    const a = registrable(e);
    const b = registrable(p);
    if (a !== null && a === b) return 'domain';
  }
  return 'none';
}

export function pageOrigin(pageUrl) {
  const p = parseWeb(pageUrl);
  if (!p) fail('malformed_origin');
  const scheme = p.https ? 'https' : 'http';
  const dflt = p.https ? 443 : 80;
  return { origin: `${scheme}://${p.host}${p.port === dflt ? '' : `:${p.port}`}`, scheme, host: p.host, port: p.port };
}

export function sameSite(a, b) {
  const x = parseWeb(a);
  const y = parseWeb(b);
  if (!x || !y || x.https !== y.https) return false;
  if (x.host === y.host) return true;
  const rx = registrable(x);
  return rx !== null && rx === registrable(y);
}

// The script of a letter, by the Unicode property; letters of other scripts by their block of 128 code points.
const SCRIPTS = ['Latin', 'Greek', 'Cyrillic', 'Armenian', 'Han', 'Hiragana', 'Katakana', 'Hangul', 'Bopomofo'];
const SCRIPT_RES = SCRIPTS.map((n) => [n, new RegExp(`^\\p{Script=${n}}$`, 'u')]);
const LETTER = /^\p{L}$/u;
function scriptOf(ch) {
  for (const [n, re] of SCRIPT_RES) if (re.test(ch)) return n;
  return `block${ch.codePointAt(0) >> 7}`;
}

// Letters of a label from more than one writing system. Digits, hyphens and marks do not count; Han with Hiragana and
// Katakana, with Hangul or with Bopomofo are one system each.
function mixesScripts(label) {
  const seen = new Set();
  for (const ch of label) if (LETTER.test(ch)) seen.add(scriptOf(ch));
  if (seen.size < 2) return false;
  const only = (allowed) => [...seen].every((x) => allowed.includes(x));
  return !(only(['Han', 'Hiragana', 'Katakana']) || only(['Han', 'Hangul']) || only(['Han', 'Bopomofo']));
}

function unicodeLabel(label) {
  if (!label.startsWith('xn--')) return label;
  const u = domainToUnicode(label);
  return u === '' || mixesScripts(u) ? label : u;
}

export function displayHost(pageUrl) {
  const p = parseWeb(pageUrl);
  if (!p) fail('malformed_origin');
  if (p.ip) return { a_label: p.host, unicode: p.host };
  return { a_label: p.host, unicode: p.host.split('.').map(unicodeLabel).join('.') };
}
