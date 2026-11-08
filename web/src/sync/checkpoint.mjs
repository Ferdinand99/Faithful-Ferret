// Checkpoints and the full listing, from the client's side: the entries of a
// checkpoint, the warning each failure of the core stands for, and the checks of
// a listing from a server that may lie.
//
// A checkpoint is the vault key's signature over what a device has seen: for
// every item the revision and the SHA-256 of its envelope (a tombstone has no
// hash). The server stores it without checking the MAC; every device that has the
// key checks it against the rows the server shows, and a server that hides or
// rolls back rows is caught by the first device that compares the two.
//
// Spec: Fase 1 section 8.6 ("Sjekkpunkt", "Lokalt minne"), section 8.4 (full
// reconciliation after a 410).
import { b64u, hex16 } from "../b64.mjs";
import { encodeWire } from "../wire.mjs";
import { SyncError } from "./errors.mjs";

/**
 * @typedef {import("../store/cache.mjs").CachedRow} CachedRow
 * @typedef {{ seq: number, digest: Uint8Array, mac: Uint8Array, entries: Uint8Array }} Checkpoint
 */

/** A verification older than this is made again. */
export const VERIFY_AFTER_MS = 24 * 3_600_000;
/** The least time between two uploads of a checkpoint from one device. */
export const UPLOAD_EVERY_MS = 10 * 60_000;
/** The least time between two automatic tries to verify while the last one did not succeed. */
export const VERIFY_RETRY_MS = 5 * 60_000;

/** The most rows the client asks for in one page of the feed or the listing (the server's maximum). */
export const MAX_PAGE = 500;

/** The bytes of one entry: 16 for the id, 8 for the revision, 32 for the hash. */
const ENTRY_LEN = 16 + 8 + 32;

/**
 * Every warning and stop the sync engine can show, and what each does. The one
 * table the engine, the banner and the tests read.
 *   `state`   a warning about what the server shows; stands until a later check
 *             succeeds, and is kept across a reload
 *   `warning` a warning that does not stop anything
 *   `stop`    nothing is pulled or sent until the user acts
 * `suspendsUpload`: no checkpoint is uploaded while it stands.
 * @type {Readonly<Record<string, { kind: "state" | "warning" | "stop", suspendsUpload: boolean }>>}
 */
export const WARNING_TABLE = Object.freeze({
  server_shows_older_state: { kind: "state", suspendsUpload: true },
  checkpoint_rolled_back: { kind: "state", suspendsUpload: true },
  checkpoint_forged: { kind: "warning", suspendsUpload: false },
  bad_feed: { kind: "warning", suspendsUpload: false },
  server_hid_item: { kind: "warning", suspendsUpload: false },
  verify_deferred: { kind: "warning", suspendsUpload: true },
  rollback_suspected: { kind: "stop", suspendsUpload: true },
  server_restored: { kind: "stop", suspendsUpload: true },
  restore_epoch_lowered: { kind: "stop", suspendsUpload: true },
  sync_memory_full: { kind: "stop", suspendsUpload: true },
  unsupported: { kind: "stop", suspendsUpload: true },
});

/** The codes that stop the engine. */
export const STOP_CODES = Object.freeze(Object.keys(WARNING_TABLE).filter((code) => WARNING_TABLE[code].kind === "stop"));

/** The warnings a verification can raise or clear (the other warnings have other causes). */
export const VERIFY_WARNINGS = Object.freeze(
  ["server_shows_older_state", "checkpoint_rolled_back", "checkpoint_forged", "bad_feed", "verify_deferred"],
);

/** How serious a warning of a verification is: 1 is information, 2 is a pause, 3 is a state warning. */
const RANK = Object.freeze({ checkpoint_forged: 1, bad_feed: 1, server_hid_item: 1, verify_deferred: 2 });

/**
 * The rank of a stored warning (0 for none). A code nobody named ranks as a state warning.
 * @param {string | null | undefined} code
 */
export function warningRank(code) {
  if (code === null || code === undefined) return 0;
  return Object.hasOwn(RANK, code) ? RANK[/** @type {keyof typeof RANK} */ (code)] : 3;
}

/**
 * What is kept in the state after a failed verification: a failure may raise the warning that is stored, or replace one of
 * the same rank, but never lower it. A forged checkpoint or a bad feed does not wipe a state warning; a pause does not wipe
 * one either. Only a verification that succeeds clears.
 * @param {string | null} stored @param {string} incoming
 */
export function escalate(stored, incoming) {
  return warningRank(incoming) >= warningRank(stored) ? incoming : /** @type {string} */ (stored);
}

/** @param {string | null | undefined} code */
export const suspendsUpload = (code) => typeof code === "string" && Object.hasOwn(WARNING_TABLE, code) && WARNING_TABLE[code].suspendsUpload;

/** The failures of the core that the table names; a code that is not here is not known. @type {Readonly<Record<string, string>>} */
const FROM_CORE = Object.freeze({
  checkpoint_hidden_or_rolled_back: "server_shows_older_state",
  checkpoint_lower_rev: "server_shows_older_state",
  checkpoint_same_rev_different_hash: "server_shows_older_state",
  checkpoint_live_behind_tombstone: "server_shows_older_state",
  checkpoint_top_digest_mismatch: "server_shows_older_state",
  checkpoint_seq_below_remembered: "checkpoint_rolled_back",
  checkpoint_rev_below_remembered: "checkpoint_rolled_back",
  checkpoint_bad_mac: "checkpoint_forged",
  checkpoint_bad_digest: "checkpoint_forged",
  malformed_entries: "checkpoint_forged",
  checkpoint_seq_above_top: "bad_feed",
  checkpoint_top_seq_below_remembered: "rollback_suspected",
  too_large: "sync_memory_full",
});

/**
 * The failures that a mark of an item that was uploaded again can explain: that
 * copy is below the floor the item had, so rows and entries disagree about it.
 *
 * Deviation from the design: the design does not know that this device uploads an
 * item again under its old id. When the server hides an item at revision 1 and the
 * device uploads it again, the copy is a new envelope at revision 1, and the
 * checkpoint of another device, which lists the old hash for that revision, shows
 * "same revision, different hash" (`checkpoint_same_rev_different_hash`). Without
 * it in this list an honest server would give a hard warning for something this
 * device did itself. It counts only when every entry the checkpoint disagrees on
 * belongs to a marked item.
 */
const DEFERRABLE = new Set([
  "checkpoint_lower_rev",
  "checkpoint_hidden_or_rolled_back",
  "checkpoint_top_digest_mismatch",
  "checkpoint_rev_below_remembered",
  "checkpoint_same_rev_different_hash",
]);

/**
 * The warning (or stop) for a failure of `verify_checkpoint`. A code that is not in
 * the table is `server_shows_older_state`: a check that fails for a reason nobody
 * has named is not a check that passed. With `deferred` (every failing entry
 * belongs to an item that was uploaded again) the failures a mark can explain
 * give `verify_deferred`.
 * @param {string} code
 * @param {{ deferred?: boolean }} [options]
 * @returns {string}
 */
export function hardWarningOf(code, { deferred = false } = {}) {
  if (deferred && DEFERRABLE.has(code)) return "verify_deferred";
  return Object.hasOwn(FROM_CORE, code) ? FROM_CORE[code] : "server_shows_older_state";
}

/** @param {Uint8Array} bytes */
async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", /** @type {BufferSource} */ (bytes)));
}

/**
 * The entries of a checkpoint for these rows: `{ item_id, rev, hash }` sorted by
 * the bytes of the id, `hash` the SHA-256 of the envelope of a live row and `null`
 * for a tombstone. The rows must be what this device holds after a drained pass
 * (the manifest row included); one id twice, or a row that is neither a live row
 * nor a tombstone, is refused: a list that cannot be right is not signed.
 * @param {Iterable<CachedRow>} rows
 * @returns {Promise<Array<{ item_id: Uint8Array, rev: number, hash: Uint8Array | null }>>}
 */
export async function entriesOf(rows) {
  /** @type {Map<string, CachedRow>} */
  const byId = new Map();
  for (const row of rows) {
    if (!hex16.is(row.itemId) || byId.has(row.itemId)) throw new TypeError("a checkpoint lists each item once");
    if (!Number.isSafeInteger(row.rev) || row.rev < 1) throw new TypeError("a revision starts at 1");
    if (row.deleted ? row.envelope !== null : row.envelope === null) throw new TypeError("a row is a live row or a tombstone");
    byId.set(row.itemId, row);
  }
  // Lower-case hex of one length sorts like the bytes.
  const ids = [...byId.keys()].sort();
  return Promise.all(
    ids.map(async (id) => {
      const row = /** @type {CachedRow} */ (byId.get(id));
      const hash = row.deleted ? null : await sha256(/** @type {Uint8Array} */ (row.envelope));
      // A live row with the hash of a tombstone cannot be told from one (it cannot happen with SHA-256 of anything real).
      if (hash !== null && hash.every((n) => n === 0)) throw new TypeError("a live row cannot have the hash of a tombstone");
      return { item_id: hex16.decode(id), rev: row.rev, hash };
    }),
  );
}

/**
 * The checkpoint the server holds.
 * @param {import("../api.mjs").Api} api
 * @returns {Promise<Checkpoint>}
 */
export async function fetchCheckpoint(api) {
  const raw = await api.get("/api/sync/checkpoint", { shape: "checkpoint" });
  return { seq: raw.seq, digest: b64u.decode(raw.digest), mac: b64u.decode(raw.mac), entries: b64u.decode(raw.entries) };
}

/**
 * The exact text of the body of `PUT /api/sync/checkpoint`. `restoreEpoch` is the restore epoch this device has accepted: the
 * server refuses the upload (`409 restore_epoch_changed`) when its own is another. Left out (null): no condition.
 * @param {Checkpoint} checkpoint
 * @param {number | null} [restoreEpoch]
 */
export function checkpointBody(checkpoint, restoreEpoch = null) {
  return encodeWire("checkpoint_put_req", {
    seq: checkpoint.seq,
    digest: b64u.encode(checkpoint.digest),
    mac: b64u.encode(checkpoint.mac),
    entries: b64u.encode(checkpoint.entries),
    ...(restoreEpoch === null ? {} : { restore_epoch: restoreEpoch }),
  });
}

/**
 * The ids a checkpoint does not agree with, read from its entries against the rows
 * of this device, with the core's rules for an entry and a row (no new crypto: the
 * MAC and the digest have been accepted by the core before this is asked, and the
 * hashes are plain SHA-256 of what is held). A live entry needs a row at its
 * revision or above, with the same hash at the same revision; a tombstone entry may
 * have no row, and a live row at its revision or below is wrong. At the top (the
 * checkpoint is as new as the feed) every row must be an entry as well, with the
 * same revision and hash. Returns null when the entries cannot be read.
 * @param {Uint8Array} entries
 * @param {Map<string, CachedRow>} rows
 * @param {boolean} atTop
 * @returns {Promise<Set<string> | null>}
 */
export async function failingIds(entries, rows, atTop) {
  if (entries.length % ENTRY_LEN !== 0) return null;
  /** @type {Map<string, { rev: number, hash: Uint8Array | null }>} */
  const listed = new Map();
  const view = new DataView(entries.buffer, entries.byteOffset, entries.byteLength);
  for (let at = 0; at < entries.length; at += ENTRY_LEN) {
    const id = hex16.encode(entries.subarray(at, at + 16));
    const rev = Number(view.getBigUint64(at + 16));
    const hash = entries.subarray(at + 24, at + ENTRY_LEN);
    listed.set(id, { rev, hash: hash.every((n) => n === 0) ? null : hash });
  }
  /** @param {CachedRow} row */
  const hashOf = async (row) => (row.deleted ? null : await sha256(/** @type {Uint8Array} */ (row.envelope)));
  /** @param {Uint8Array | null} a @param {Uint8Array | null} b */
  const same = (a, b) => (a === null || b === null ? a === b : a.length === b.length && a.every((n, i) => n === b[i]));
  /** @type {Set<string>} */
  const failing = new Set();
  for (const [id, entry] of listed) {
    const row = rows.get(id);
    if (row === undefined) {
      if (entry.hash !== null) failing.add(id);
    } else if (row.rev < entry.rev) {
      failing.add(id);
    } else if (row.rev === entry.rev && !same(await hashOf(row), entry.hash)) {
      failing.add(id);
    }
  }
  if (atTop) {
    for (const [id, row] of rows) {
      const entry = listed.get(id);
      if (entry === undefined || entry.rev !== row.rev || !same(await hashOf(row), entry.hash)) failing.add(id);
    }
  }
  return failing;
}

/**
 * Checks a page of the full listing against the one before it. A server that
 * lists in a way no honest one does (ids that do not rise, a position that does
 * not move forward, epochs that change in the middle, a page that claims more
 * rows and has none) is `SyncError("bad_feed")`.
 *
 * `as_of_seq` holds for its own page: it is at least the highest `seq` on the page
 * and it never falls from one page to the next. It is not compared with the `seq`
 * of rows on other pages: an honest server takes writes while a listing goes on.
 *
 * A page holds at most `limit` rows (the number the client asked for): more is a server that ignores the request, and is
 * refused before any row is looked at.
 * @param {{ items: Array<{ id: string, seq: number }>, as_of_seq: number, vk_epoch: number, restore_epoch: number, restore_seq?: number, next_after?: string | null, has_more: boolean }} page
 * @param {typeof page | null} [previous] the page before this one, or null for the first
 * @param {number} [limit] the most rows a page may hold
 */
export function checkListingPage(page, previous = null, limit = MAX_PAGE) {
  const bad = () => new SyncError("bad_feed", "The server's listing cannot be right.");
  if (page.items.length > limit) throw bad();
  if (previous !== null) {
    if (!previous.has_more) throw bad(); // a page after the last one
    if (page.vk_epoch !== previous.vk_epoch || page.restore_epoch !== previous.restore_epoch) throw bad();
    if (page.restore_seq !== previous.restore_seq) throw bad();
    if (page.as_of_seq < previous.as_of_seq) throw bad();
  }
  // This page starts after the position the last one named.
  let last = previous?.next_after ?? null;
  let highest = 0;
  for (const item of page.items) {
    if (last !== null && item.id <= last) throw bad();
    last = item.id;
    highest = Math.max(highest, item.seq);
  }
  if (page.as_of_seq < highest) throw bad();
  if (page.has_more) {
    // The next page starts after the last row of this one; anything else repeats rows or skips some.
    if (page.items.length === 0 || last === null || page.next_after !== last) throw bad();
  } else if (page.next_after !== undefined && page.next_after !== null) {
    throw bad();
  }
}

/**
 * Checks a page of the frozen restore rows (`GET /api/sync/restore-rows`) against the one before it and against the listing
 * it goes with. The list is only information for the honest case, but a list that cannot be right is not used: ids that do not
 * strictly rise, a revision below 1, a row written after the restore it was frozen at (its `seq` above `restore_seq`), a restore
 * epoch or `restore_seq` that differs from the listing's or changes in the middle, a `restore_seq` above the top of the
 * listing, a position that does not move forward, or a page that claims more rows and has none is `SyncError("bad_feed")`.
 * @param {{ rows: Array<{ id: string, rev: number, seq: number }>, restore_epoch: number, restore_seq: number, next_after?: string | null, has_more: boolean }} page
 * @param {typeof page | null} previous the page before this one, or null for the first
 * @param {{ restoreEpoch: number, restoreSeq: number, asOfSeq: number }} listed what the listing showed
 * @param {number} [limit] the most rows a page may hold
 */
export function checkRestoreRowsPage(page, previous, listed, limit = MAX_PAGE) {
  const bad = () => new SyncError("bad_feed", "The server's list of rows at the restore cannot be right.");
  if (page.rows.length > limit) throw bad();
  if (page.restore_epoch !== listed.restoreEpoch || page.restore_seq !== listed.restoreSeq) throw bad();
  if (page.restore_seq > listed.asOfSeq) throw bad();
  if (previous !== null) {
    if (!previous.has_more) throw bad(); // a page after the last one
    if (page.restore_epoch !== previous.restore_epoch || page.restore_seq !== previous.restore_seq) throw bad();
  }
  let last = previous?.next_after ?? null;
  for (const row of page.rows) {
    if (last !== null && row.id <= last) throw bad();
    last = row.id;
    if (row.rev < 1 || row.seq > page.restore_seq) throw bad();
  }
  if (page.has_more) {
    if (page.rows.length === 0 || last === null || page.next_after !== last) throw bad();
  } else if (page.next_after !== undefined && page.next_after !== null) {
    throw bad();
  }
}
