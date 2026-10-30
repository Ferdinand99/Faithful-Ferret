#!/usr/bin/env node
// Writes the seed corpus of the fuzz targets from the test vectors:
//
//   node scripts/fuzz-seeds.mjs          write fuzz/corpus/<target>/<hash>
//   node scripts/fuzz-seeds.mjs --check  fail if a seed is missing or changed
//
// The files are named by the first 16 hex digits of their SHA-256, so the
// output is deterministic. Only the seeds are generated; libFuzzer adds its
// own finds to the same folders on a runner and they are never committed.
// Crashing inputs that were fixed live in fuzz/regression/<target>/ instead.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const vectors = join(root, 'vectors');
const corpus = join(root, 'fuzz', 'corpus');
const check = process.argv.includes('--check');

/**
 * Longest seed of a target: its -max_len in scripts/fuzz-run.sh. The targets
 * that take bodies of up to 61 440 bytes, envelopes of up to 65 536 bytes and
 * byte strings over 64 KiB are run with a larger -max_len; the others keep
 * libFuzzer's default of 4096.
 */
const BIG = 70000;
const MAX_LEN_OF = {
  fuzz_envelope: BIG,
  fuzz_item_body: BIG,
  fuzz_cbor_value: BIG,
  fuzz_export_file: BIG,
};
const DEFAULT_MAX_LEN = 4096;
/** The most any seed may be, for reading vector values. */
const MAX_LEN = BIG;
/** Most seeds per target (the shortest are kept, spread over the length range). */
const MAX_SEEDS = 160;

const load = (file) => JSON.parse(readFileSync(join(vectors, 'internal', file), 'utf8')).cases;
const cases = (file, ...ops) => load(file).filter((c) => ops.includes(c.op));
const hex = (s) => Buffer.from(s, 'hex');
const text = (s) => Buffer.from(s, 'utf8');

/** A vector value that is hex, or {segments: [{hex, repeat}]}; null if too long. */
function bytesOf(v) {
  if (typeof v === 'string') return hex(v);
  if (v && Array.isArray(v.segments)) {
    const parts = [];
    let total = 0;
    for (const s of v.segments) {
      if (typeof s.hex !== 'string') return null;
      total += (s.hex.length / 2) * s.repeat;
      if (total > MAX_LEN) return null;
      for (let i = 0; i < s.repeat; i++) parts.push(hex(s.hex));
    }
    return Buffer.concat(parts);
  }
  return null;
}

const seeds = {};
const add = (target, buf) => {
  if (buf && buf.length <= (MAX_LEN_OF[target] ?? DEFAULT_MAX_LEN)) (seeds[target] ??= []).push(buf);
};
const withMode = (mode, body) => (body ? Buffer.concat([Buffer.from([mode]), body]) : null);

// CBOR: the limit cases, item bodies and manifests.
for (const c of cases('cbor-limits.json', 'cbor.decode')) {
  const b = bytesOf(c.input);
  add('fuzz_cbor_value', b);
  add('fuzz_item_body', b);
}
for (const file of ['item.json', 'rekey.json', 'proofs.json']) {
  for (const c of load(file)) {
    const body = c.input?.body ? bytesOf(c.input.body) : null;
    add('fuzz_cbor_value', body);
    add('fuzz_item_body', body);
    // Keyed envelope harness: mode byte (item, plaintext) then the body.
    if (file === 'item.json') add('fuzz_envelope', withMode(0x00, body));
  }
}
for (const c of cases('item.json', 'item.manifest.seal')) {
  const m = hex(c.input.manifest);
  add('fuzz_cbor_value', m);
  add('fuzz_item_body', m);
  add('fuzz_envelope', withMode(0x01, m));
}
for (const c of cases('padding.json', 'pad.apply')) {
  const p = bytesOf(c.input.plain);
  add('fuzz_envelope', withMode(0x00, p));
  add('fuzz_envelope', withMode(0x03, p));
}
for (const c of cases('padding.json', 'pad.remove')) {
  add('fuzz_envelope', withMode(0x02, bytesOf(c.input.padded)));
}

// Envelopes (unkeyed half of the envelope target): every envelope in the vectors.
for (const file of ['item.json', 'tomb-tag.json', 'rekey.json']) {
  for (const c of load(file)) {
    if (typeof c.input?.envelope === 'string') add('fuzz_envelope', hex(c.input.envelope));
  }
}

// Export files: the whole file, and the header alone.
for (const c of cases('export.json', 'export.decrypt', 'export.header')) {
  add('fuzz_export_file', bytesOf(c.input.file));
}

// Checkpoint: seq (8) | top_seq (8) | n (1) | entries | rows (57 each).
for (const c of cases('checkpoint.json', 'checkpoint.verify')) {
  const cp = c.input.checkpoint;
  if (typeof cp.entries !== 'string' || !Array.isArray(c.input.rows)) continue; // generated case
  const entries = hex(cp.entries);
  const rows = Buffer.concat(
    c.input.rows.map((r) => {
      const row = Buffer.alloc(57);
      hex(r.item_id).copy(row, 0);
      row.writeBigUInt64BE(BigInt(r.rev), 16);
      row[24] = r.state === 'live' ? 1 : 0;
      if (r.hash) hex(r.hash).copy(row, 25);
      return row;
    }),
  );
  const head = Buffer.alloc(17);
  head.writeBigUInt64BE(BigInt(cp.seq ?? 0), 0);
  head.writeBigUInt64BE(BigInt(c.input.top_seq), 8);
  head[16] = entries.length / 56;
  add('fuzz_checkpoint', Buffer.concat([head, entries, rows]));
  add('fuzz_checkpoint', entries);
}

// Codes.
for (const c of cases('codes.json', 'code.rk.decode', 'code.sk.decode')) add('fuzz_codes', text(c.input.code));
for (const c of cases('account.json', 'account.verify_recovery', 'account.verify_secret_key')) {
  if (typeof c.input.entered === 'string') add('fuzz_codes', text(c.input.entered));
}

// Passwords and PINs.
for (const c of cases('unicode.json', 'text.mp', 'text.nfkd', 'text.export_password', 'text.opaque_input')) {
  if (typeof c.input.text === 'string') add('fuzz_mp_input', text(c.input.text));
}
for (const c of cases('kdf.json', 'kdf.kek.pin_extension', 'kdf.kek.pin_mobile')) {
  if (typeof c.input.pin === 'string') add('fuzz_mp_input', text(c.input.pin));
}

// otpauth addresses.
for (const c of cases('totp.json', 'totp.parse', 'totp.code')) add('fuzz_otpauth', text(c.input.uri));

// Origins and RP IDs: origin NUL rp_id.
for (const c of cases('origin.json', 'origin.canonical')) {
  add('fuzz_origin_psl', Buffer.concat([hex(c.input.raw_utf8), Buffer.from([0])]));
}
for (const c of cases('origin.json', 'origin.rp_id')) {
  add('fuzz_origin_psl', Buffer.concat([hex(c.input.origin_utf8), Buffer.from([0]), hex(c.input.rp_id_utf8)]));
}
const psl = join(vectors, 'external', 'publicsuffix-test_psl.txt');
if (existsSync(psl)) {
  for (const m of readFileSync(psl, 'utf8').matchAll(/checkPublicSuffix\('([^']+)'/g)) {
    add('fuzz_origin_psl', text(`https://${m[1]}\0${m[1].replace(/^[^.]*\./, '')}`));
  }
}

// WebAuthn requests: the request fields run together (the target reads an
// `Arbitrary` structure, so these are starting points only).
for (const c of cases('passkey.json', 'passkey.create')) {
  const r = c.input.request;
  add(
    'fuzz_webauthn_options',
    Buffer.concat([hex(r.challenge), text(r.rp_name), hex(r.user_id), text(r.user_name), text(r.user_display_name)]),
  );
}

// OPAQUE: the server's messages.
for (const c of cases('opaque.json', 'opaque.login')) add('fuzz_opaque_messages', hex(c.input.ke2));
for (const c of cases('opaque.json', 'opaque.register')) add('fuzz_opaque_messages', hex(c.input.response));

// Setup QR payloads.
for (const c of cases('sheet.json', 'sheet.qr.parse')) add('fuzz_sheet', text(c.input.payload));

// ---------------------------------------------------------------- output

const out = new Map();
let total = 0;
for (const [target, list] of Object.entries(seeds).sort()) {
  const unique = new Map();
  for (const b of list) unique.set(createHash('sha256').update(b).digest('hex').slice(0, 16), b);
  let entries = [...unique].sort((a, b) => a[1].length - b[1].length || (a[0] < b[0] ? -1 : 1));
  if (entries.length > MAX_SEEDS) {
    entries = Array.from({ length: MAX_SEEDS }, (_, i) => entries[Math.floor((i * entries.length) / MAX_SEEDS)]);
  }
  out.set(target, entries);
  total += entries.length;
}

let stale = 0;
for (const [target, entries] of out) {
  const dir = join(corpus, target);
  const want = new Map(entries);
  const have = existsSync(dir) ? readdirSync(dir) : [];
  if (check) {
    // Files libFuzzer added are not seeds; only missing or changed seeds count.
    for (const [name, buf] of want) {
      if (!have.includes(name) || !readFileSync(join(dir, name)).equals(buf)) stale++;
    }
    continue;
  }
  mkdirSync(dir, { recursive: true });
  for (const f of have) if (!want.has(f)) rmSync(join(dir, f));
  for (const [name, buf] of want) writeFileSync(join(dir, name), buf);
  console.log(`${target}: ${entries.length} seeds`);
}
if (check) {
  if (stale) {
    console.error(`fuzz-seeds: ${stale} seed file(s) are missing or changed; run node scripts/fuzz-seeds.mjs`);
    process.exit(1);
  }
  console.log(`fuzz-seeds: ${total} seeds are up to date`);
}
