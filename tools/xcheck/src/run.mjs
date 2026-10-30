// xcheck runner: opens every internal vector group it can, with no Rust involved.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { XError } from './util.mjs';
import { Rng } from './ops/context.mjs';
import { registry, NOT_COVERED } from './ops/index.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const vectorsDir = process.env.XCHECK_VECTORS_DIR ?? path.resolve(here, '../../../vectors/internal');

const args = process.argv.slice(2);
const only = args.filter((a) => !a.startsWith('--'));
const skipSlow = args.includes('--skip-slow');
const json = args.includes('--json');
const quiet = args.includes('--quiet');
// --mutate: the self-test. Every expected value is damaged, so every case must now be reported as a mismatch.
const mutate = args.includes('--mutate');

function damage(v) {
  if (typeof v === 'string') return v === '' ? 'x' : `${v.slice(0, -1)}${v.endsWith('0') ? '1' : '0'}`;
  if (typeof v === 'number') return v + 1;
  if (typeof v === 'boolean') return !v;
  if (Array.isArray(v)) return v.length ? [damage(v[0]), ...v.slice(1)] : ['x'];
  if (v && typeof v === 'object') {
    const k = Object.keys(v)[0];
    return { ...v, [k]: damage(v[k]) };
  }
  return 'x';
}

function same(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a);
  const kb = Object.keys(b);
  if (ka.length !== kb.length) return false;
  return ka.every((k) => same(a[k], b[k]));
}

const short = (x) => {
  const s = JSON.stringify(x);
  return s && s.length > 110 ? `${s.slice(0, 110)}...(${s.length})` : s;
};

// Compare the keys the vector states against the keys produced.
function diff(want, got, where) {
  if (same(want, got)) return null;
  if (want && got && typeof want === 'object' && typeof got === 'object' && !Array.isArray(want) && !Array.isArray(got)) {
    for (const k of Object.keys(want)) {
      const d = diff(want[k], got[k], `${where}.${k}`);
      if (d) return d;
    }
    for (const k of Object.keys(got)) if (!(k in want)) return `${where}.${k}: produced but not in the vector`;
    return null;
  }
  if (Array.isArray(want) && Array.isArray(got) && want.length === got.length) {
    for (let i = 0; i < want.length; i++) {
      const d = diff(want[i], got[i], `${where}[${i}]`);
      if (d) return d;
    }
  }
  return `${where}: expected ${short(want)}, got ${short(got)}`;
}

// Only the intermediate keys that a handler produces are compared.
function pick(want, got) {
  return Object.fromEntries(Object.keys(got).filter((k) => k in want).map((k) => [k, want[k]]));
}

const files = fs.readdirSync(vectorsDir).filter((f) => f.endsWith('.json')).sort();
const summary = [];

for (const f of files) {
  const group = f.replace(/\.json$/, '');
  if (only.length && !only.includes(group)) continue;
  const file = JSON.parse(fs.readFileSync(path.join(vectorsDir, f), 'utf8'));
  const row = { group, total: file.cases.length, matched: 0, mismatched: [], notCovered: [], unexpected: [], reasons: new Set(), codeDiffers: 0 };
  const t0 = Date.now();
  for (const c of file.cases) {
    if (mutate) {
      if (c.status === 'valid') c.expect = damage(c.expect);
      else c.expect_error = `${c.expect_error}_damaged`;
    }
    if (Object.hasOwn(NOT_COVERED, c.op)) {
      row.notCovered.push(c.id);
      row.reasons.add(`${c.op}: ${NOT_COVERED[c.op]}`);
      continue;
    }
    const fn = Object.hasOwn(registry, c.op) ? registry[c.op] : undefined;
    if (!fn) {
      row.notCovered.push(c.id);
      row.reasons.add(`${c.op}: NO HANDLER (not in the NOT_COVERED list)`);
      row.unexpected.push(c.id);
      continue;
    }
    if (skipSlow && c.tags.includes('slow')) {
      row.notCovered.push(c.id);
      row.reasons.add('skipped with --skip-slow');
      continue;
    }
    let result;
    let error;
    try {
      result = await fn({ input: c.input, rng: new Rng(c.rng), tags: c.tags, id: c.id, expected: c.expect });
    } catch (e) {
      error = e;
    }
    let problem = null;
    if (c.status === 'valid') {
      if (error) problem = `unexpected ${error instanceof XError ? error.code : 'crash'}: ${error.message}`;
      else {
        problem = diff(c.expect, result.expect, 'expect');
        if (!problem && c.intermediate && result.intermediate) problem = diff(pick(c.intermediate, result.intermediate), result.intermediate, 'intermediate');
      }
    } else if (!error) problem = `expected refusal ${c.expect_error}, but it succeeded`;
    else if (!(error instanceof XError)) problem = `expected refusal ${c.expect_error}, but crashed: ${error.stack}`;
    else if (error.code !== c.expect_error) {
      problem = `expected ${c.expect_error}, got ${error.code}`;
      row.codeDiffers++;
    }
    if (problem) {
      row.mismatched.push({ id: c.id, problem });
      if (!json && !quiet) console.log(`MISMATCH ${c.id}: ${problem}`);
    } else row.matched++;
  }
  row.ms = Date.now() - t0;
  summary.push(row);
  if (!json) {
    console.log(`${group.padEnd(12)} total ${String(row.total).padStart(3)}  matched ${String(row.matched).padStart(3)}  mismatched ${String(row.mismatched.length).padStart(3)}  not covered ${String(row.notCovered.length).padStart(3)}  (${row.ms} ms)`);
    for (const r of row.reasons) console.log(`    not covered: ${r}`);
  }
}

if (json) {
  console.log(JSON.stringify(summary.map((r) => ({ ...r, reasons: [...r.reasons] })), null, 2));
} else {
  const unexpected = summary.reduce((n, r) => n + r.unexpected.length, 0);
  if (unexpected) console.log(`\nFAIL: ${unexpected} case(s) have no handler and are not in the NOT_COVERED list`);
  const sum = (k) => summary.reduce((n, r) => n + (typeof r[k] === 'number' ? r[k] : r[k].length), 0);
  console.log(`\nTOTAL ${sum('total')} cases: matched ${sum('matched')}, mismatched ${sum('mismatched')}, not covered ${sum('notCovered')} (${sum('notCovered') - unexpected} listed in NOT_COVERED, ${unexpected} without a handler)`);
}
if (mutate) {
  const survived = summary.reduce((n, r) => n + r.matched, 0);
  console.log(survived === 0 ? 'self-test passed: every damaged expectation was detected' : `self-test FAILED: ${survived} damaged cases still matched`);
  process.exit(survived === 0 && !summary.some((r) => r.unexpected.length) ? 0 : 1);
}
process.exit(summary.some((r) => r.mismatched.length || r.unexpected.length) ? 1 : 0);
