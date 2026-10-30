// Signed checkpoints (Fase 1 section 8.6).
import { sha256, hmac256, ctEqual } from './crypto.mjs';
import { tlvs, label, fU64, fBytes, T } from './tlv.mjs';
import { concat, u32be, u64be, fail, equal, ascii } from './util.mjs';

const ZERO_HASH = new Uint8Array(32);
const isZero = (h) => equal(h, ZERO_HASH);

const cmp = (a, b) => {
  for (let i = 0; i < 16; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
};

// rows: [{ itemId, rev (bigint), hash (32 bytes) | null for a tombstone }]
export function buildEntries(rows) {
  const list = rows.map((r) => {
    if (r.hash && isZero(r.hash)) fail('malformed_entries'); // cannot be told from a tombstone
    return { itemId: r.itemId, rev: r.rev, h: r.hash ?? ZERO_HASH };
  });
  list.sort((a, b) => cmp(a.itemId, b.itemId));
  for (let i = 1; i < list.length; i++) if (cmp(list[i - 1].itemId, list[i].itemId) === 0) fail('malformed_entries');
  return concat(...list.map((r) => concat(r.itemId, u64be(r.rev), r.h)));
}

export function checkpointMessage(seq, digest) {
  return tlvs(label('ferret/v1/checkpoint'), fU64(T.seq, seq), fBytes(T.hash, digest));
}

export function makeCheckpoint(kHead, seq, rows) {
  const entries = buildEntries(rows);
  const digest = sha256(entries);
  const message = checkpointMessage(seq, digest);
  return { entries, digest, message, mac: hmac256(kHead, message) };
}

// Rows 0 <= i < n of the generated vectors (OPS.md).
export function generatedRows(n) {
  const rows = [];
  for (let i = 0; i < n; i++) {
    const idx = u32be(i);
    const itemId = sha256(ascii('ferret/checkpoint-vector/id'), idx).subarray(0, 16);
    const h = sha256(ascii('ferret/checkpoint-vector/hash'), idx);
    rows.push({ itemId, rev: BigInt(1 + (i % 7)), hash: i % 5 === 0 ? null : h });
  }
  return rows;
}

// Parses the entries list: 56 bytes per row, sorted ascending and without repeats.
export function parseEntries(entries) {
  if (entries.length % 56 !== 0) fail('malformed_entries');
  const out = [];
  for (let o = 0; o < entries.length; o += 56) {
    const itemId = entries.subarray(o, o + 16);
    const rev = new DataView(entries.buffer, entries.byteOffset + o + 16, 8).getBigUint64(0, false);
    const h = entries.subarray(o + 24, o + 56);
    if (out.length && cmp(out[out.length - 1].itemId, itemId) >= 0) fail('malformed_entries'); // unsorted or repeated
    out.push({ itemId, rev, h, tomb: isZero(h) });
  }
  return out;
}

const key = (id) => Buffer.from(id).toString('hex');

// serverRows: [{ itemId, rev (bigint), live (bool), hash }]
export function verifyCheckpoint(kHead, topSeq, cp, serverRows) {
  const message = checkpointMessage(cp.seq, cp.digest);
  if (cp.mac.length !== 32 || !ctEqual(cp.mac, hmac256(kHead, message))) fail('checkpoint_bad_mac');
  if (!ctEqual(cp.digest, sha256(cp.entries))) fail('checkpoint_bad_digest');
  const entries = parseEntries(cp.entries);
  if (cp.seq > topSeq) fail('checkpoint_seq_above_top');

  const rows = new Map();
  for (const r of serverRows) {
    if (r.live && isZero(r.hash)) fail('malformed_entries');
    const k = key(r.itemId);
    if (rows.has(k)) fail('malformed_entries');
    rows.set(k, r);
  }
  const atTop = topSeq === cp.seq;

  for (const e of entries) {
    const r = rows.get(key(e.itemId));
    if (!r) {
      if (!e.tomb && !atTop) fail('checkpoint_hidden_or_rolled_back');
      continue; // at the top the exact comparison below decides
    }
    if (!e.tomb) {
      if (r.rev < e.rev) fail('checkpoint_lower_rev');
      if (r.rev === e.rev && !(r.live && equal(r.hash, e.h))) fail('checkpoint_same_rev_different_hash');
    } else if (r.live) {
      if (r.rev < e.rev) fail('checkpoint_live_behind_tombstone');
      if (r.rev === e.rev) fail('checkpoint_same_rev_different_hash');
    } else if (r.rev < e.rev) fail('checkpoint_lower_rev');
  }

  if (atTop) {
    // The rows must be exactly the entries; a tombstone entry may have no row.
    const byId = new Map(entries.map((e) => [key(e.itemId), e]));
    for (const [k, r] of rows) {
      const e = byId.get(k);
      if (!e || e.rev !== r.rev) fail('checkpoint_top_digest_mismatch');
    }
    for (const e of entries) if (!e.tomb && !rows.has(key(e.itemId))) fail('checkpoint_top_digest_mismatch');
  }
}
