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
  if (kind === 'domain') {
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

export function displayHost(pageUrl) {
  const p = parseWeb(pageUrl);
  if (!p) fail('malformed_origin');
  if (p.ip) return { a_label: p.host, unicode: p.host };
  const u = domainToUnicode(p.host);
  return { a_label: p.host, unicode: u === '' ? p.host : u };
}
