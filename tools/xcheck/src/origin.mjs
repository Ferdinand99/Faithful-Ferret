// Canonical origin and RP ID rules (Fase 1 section 9.2).
import { domainToASCII } from 'node:url';
import { fail } from './util.mjs';
import { isPublicSuffix } from './psl.mjs';

const badOrigin = () => fail('malformed_origin');
const badRp = () => fail('malformed_rp_id');

const LABEL = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;

// Host as IDNA A-labels, lower case, without a trailing dot. Returns null when it is no usable name.
function canonicalHost(raw) {
  let h = raw;
  if (h.endsWith('.')) h = h.slice(0, -1); // one trailing dot only
  if (h === '' || h.includes('..') || h.startsWith('.')) return null;
  // the characters of a plain name; letters of other scripts are allowed here and converted below
  // eslint-disable-next-line no-control-regex
  if (/[\u0000- \u007f/\\?#@%:[\]*_!"'()+,;<>=^`{|}~]/.test(h)) return null;
  const a = domainToASCII(h);
  if (a === '') return null;
  const labels = a.split('.');
  if (!labels.every((l) => LABEL.test(l))) return null;
  // IPv4 as a browser reads it: the last label is all digits, or starts with 0x
  const last = labels[labels.length - 1];
  if (/^[0-9]+$/.test(last) || /^0x/.test(last)) return null;
  return a;
}

export function canonicalOrigin(raw) {
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#\\@%\s*]*)$/.exec(raw);
  if (!m) badOrigin();
  const scheme = m[1].toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') badOrigin();
  let hostPart = m[2];
  let port = null;
  if (hostPart.startsWith('[')) badOrigin(); // IP literal
  const colon = hostPart.lastIndexOf(':');
  if (colon >= 0) {
    const p = hostPart.slice(colon + 1);
    hostPart = hostPart.slice(0, colon);
    if (!/^[0-9]{1,5}$/.test(p)) badOrigin();
    port = Number(p);
    if (port < 1 || port > 65535) badOrigin();
  }
  const host = canonicalHost(hostPart);
  if (host === null) badOrigin();
  if (scheme === 'http' && host !== 'localhost') badOrigin();
  const defaultPort = scheme === 'https' ? 443 : 80;
  const origin = `${scheme}://${host}${port !== null && port !== defaultPort ? `:${port}` : ''}`;
  return { origin, host, scheme };
}

export function validateRpId(rpId, originHost) {
  if (rpId === '') badRp();
  const rp = canonicalHost(rpId);
  if (rp === null) badRp();
  if (rp !== originHost && !originHost.endsWith(`.${rp}`)) badRp();
  // `localhost` is usable only from localhost itself
  if (rp === 'localhost') {
    if (originHost !== 'localhost') badRp();
    return rp;
  }
  if (isPublicSuffix(rp)) badRp();
  return rp;
}
