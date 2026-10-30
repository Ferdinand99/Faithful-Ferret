// Public Suffix List lookup with the private domains included (Fase 1 section 9.2).
// Algorithm: https://github.com/publicsuffix/list/wiki/Format#algorithm
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { domainToASCII } from 'node:url';

const file = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../data/public_suffix_list.dat');

const rules = new Set();
const exceptions = new Set();
for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
  if (line === '' || line.startsWith('//')) continue;
  const exception = line.startsWith('!');
  const body = exception ? line.slice(1) : line;
  // rules are written in Unicode: compare in A-label form
  const ascii = body.split('.').map((l) => (l === '*' ? '*' : domainToASCII(l))).join('.');
  (exception ? exceptions : rules).add(ascii);
}

// domain: lower case A-label, no trailing dot. Returns the public suffix as a string.
export function publicSuffix(domain) {
  const labels = domain.split('.');
  let best = 1; // the default rule "*": the last label
  for (let n = 1; n <= labels.length; n++) {
    const suffix = labels.slice(labels.length - n).join('.');
    if (exceptions.has(suffix)) return labels.slice(labels.length - n + 1).join('.');
    const wildcard = ['*', ...labels.slice(labels.length - n + 1)].join('.');
    if (rules.has(suffix) || rules.has(wildcard)) best = Math.max(best, n);
  }
  return labels.slice(labels.length - best).join('.');
}

export const isPublicSuffix = (domain) => publicSuffix(domain) === domain;

// The domain one label to the left of the public suffix, or null.
export function registrableDomain(domain) {
  const labels = domain.split('.');
  const ps = publicSuffix(domain).split('.').length;
  if (labels.length <= ps) return null;
  return labels.slice(labels.length - ps - 1).join('.');
}
