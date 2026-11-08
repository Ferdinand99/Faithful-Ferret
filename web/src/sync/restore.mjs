// What to do with the local versions of items when the user accepts the older state of a server that was restored
// from a backup: which of them the server lacks (and is sent again, built on what the server has now), and which of
// them must not be sent because the server holds something this device has not seen.
//
// This file only decides. It reads rows, entries and revision numbers; it opens nothing and writes nothing. The engine
// does the sealing, the queueing and the replacing of rows (see engine.mjs, `acceptOlderState`).
//
// A local version is "newer" than the server's row when it has a higher revision. Only an item the server has no row for
// is sent by itself (revision 0, nothing can be overwritten). A local version over a row the server does have is never
// sent by itself: it is kept as a draft that is not sent and the user chooses (a conflict). This is on purpose and
// conservative: the server may hold a write that another device made after the restore, a checkpoint that device uploaded
// covers that write (so the row looks as the checkpoint says), and a client alone cannot tell it from the restored state.
// A version byte for byte the server's, or a deletion on both sides, needs nothing; a version that differs from the
// server's row is kept as a draft even when its revision is lower (revisions no longer form one line after a restore).
//
// Spec: Fase 1 section 8.6 ("Legitimate rollbacks": accept older state, and the local changes the server is missing
// are uploaded), section 8.3 (a write over a row that has changed is a conflict).

/**
 * @typedef {import("../store/cache.mjs").CachedRow} CachedRow
 * @typedef {import("../store/outbox.mjs").OutboxEntry} OutboxEntry
 * @typedef {"reseal" | "resurrect" | "tombstone" | "new"} Kind
 *   `reseal` the item is live on both sides, the write is the local version numbered `server rev + 1`;
 *   `resurrect` the server holds a tombstone and the local version is live: it comes back (`base_rev` is the tombstone's);
 *   `tombstone` the local version is a deletion of an item the server still has;
 *   `new` the server has no row for the item: the write is built on revision 0.
 *   Only `new` is sent by itself; the other three are kept as drafts (conflicts), see above
 * @typedef {{ id: string, baseRev: number, kind: Kind }} Plan
 *
 * @typedef {object} Decision what to do with one item
 * @property {string} id
 * @property {Kind | "skip"} kind `skip`: nothing to send (the server has the same or a newer version, or both are deleted)
 * @property {number} baseRev the revision the write builds on (the server's, or 0)
 * @property {boolean} conflict the write is kept as a draft that is not sent (every kind but `new` and `skip`)
 * @property {"row" | "outbox"} source where the newest local version is: the row this device holds, or the last write
 *   that was waiting in the outbox (it exists only here)
 * @property {number} localRev the revision of that version
 */

/** The all-zero id of the unlock-method manifest: a row, never an item, never sent from here. */
const MANIFEST = "0".repeat(32);

/** @param {Uint8Array | null} a @param {Uint8Array | null} b */
const sameBytes = (a, b) => (a === null || b === null ? a === b : a.length === b.length && a.every((n, i) => n === b[i]));

/**
 * Decides, for every item this device holds a version of, what happens to it. The manifest is left out: it changes only
 * with the unlock methods, never as an item.
 *
 * The newest local version of an item is its last write in the outbox when there is one (it was never on the server,
 * so it is newer than any row), else the row this device holds. The exception is an item that was uploaded again after
 * the server lost it: the write in the outbox with `base_rev` 0 is a renumbered copy of the row, so the row is the version
 * (at the revision it had before it was lost, which the mark keeps).
 * @param {{
 *   listing: Iterable<CachedRow>,
 *   checkpoint?: { seq: number, entries: Uint8Array },
 *   rows: Iterable<CachedRow>,
 *   outbox: Iterable<OutboxEntry>,
 *   blocked?: ReadonlySet<string> | Iterable<string>,
 *   marks?: ReadonlyMap<string, { kind: string, rev: number }>,
 * }} input
 *   `listing` is what the server shows now, `checkpoint` the restored one (not used for the decision: see the head of this
 *   file), `rows` what this device holds, `outbox` what
 *   it has queued, `blocked` the items whose earlier write was refused (they stay conflicts), `marks` the marks of items
 *   that were uploaded again.
 * @returns {Promise<Decision[]>} in the order of the item ids
 */
export async function restoreItems({ listing, rows, outbox, blocked = new Set(), marks = new Map() }) {
  const served = new Map([...listing].map((row) => [row.itemId, row]));
  const held = new Map([...rows].map((row) => [row.itemId, row]));
  /** @type {Map<string, OutboxEntry[]>} */
  const queued = new Map();
  for (const entry of outbox) queued.set(entry.itemId, [...(queued.get(entry.itemId) ?? []), entry]);
  const blockedIds = new Set(blocked);
  const ids = [...new Set([...held.keys(), ...queued.keys()])].filter((id) => id !== MANIFEST).sort();

  /** @type {Decision[]} */
  const out = [];
  for (const id of ids) {
    const row = held.get(id);
    const last = queued.get(id)?.at(-1);
    const mark = marks.get(id);
    const again = mark !== undefined && (mark.kind === "missing_on_server" || mark.kind === "reuploaded");
    /** @type {{ from: "row" | "outbox", rev: number, deleted: boolean }} */
    let local;
    if (last !== undefined && !(again && last.baseRev === 0 && row !== undefined)) {
      local = { from: "outbox", rev: last.baseRev + 1, deleted: "tomb" in last.body };
    } else if (row !== undefined) {
      local = { from: "row", rev: again ? Math.max(mark.rev, row.rev) : row.rev, deleted: row.deleted };
    } else {
      continue;
    }
    const server = served.get(id);
    /** @param {Kind | "skip"} kind @param {boolean} conflict */
    const decide = (kind, conflict) => out.push({ id, kind, baseRev: server?.rev ?? 0, conflict, source: local.from, localRev: local.rev });

    if (server === undefined) {
      // The restored server has no row for it: the item is sent again (a deletion of something the server lacks is nothing to send).
      decide(local.deleted ? "skip" : "new", false);
      continue;
    }
    if (local.deleted && server.deleted) {
      decide("skip", false); // deleted on both sides
      continue;
    }
    /** @type {Kind} */
    const kind = local.deleted ? "tombstone" : server.deleted ? "resurrect" : "reseal";
    // Only a version byte for byte the server's is nothing to do. After a restore the revisions no longer form one line: a
    // lower revision here than on the server can be a version this device wrote and uploaded before the restore (which the
    // restore lost) against a row another device wrote after it, and nothing on this device says which. So a version that
    // differs from the server's row is kept as a draft whatever its revision, never skipped and never dropped.
    const identical = local.from === "row" && !blockedIds.has(id) && !local.deleted && row !== undefined && !server.deleted &&
      sameBytes(row.envelope, server.envelope) && sameBytes(row.tag, server.tag);
    decide(identical ? "skip" : kind, !identical);
  }
  return out;
}

/**
 * What accepting the older state would send and keep back, for the preview and the tests.
 * `upload` lists the writes built on what the server has now; `conflicts` the items that are kept as drafts and not sent;
 * `unchanged` the items with nothing to send.
 * @param {Parameters<typeof restoreItems>[0]} input
 * @returns {Promise<{ upload: Plan[], conflicts: string[], unchanged: number }>}
 */
export async function planRestore(input) {
  const items = await restoreItems(input);
  /** @type {Plan[]} */
  const upload = [];
  /** @type {string[]} */
  const conflicts = [];
  let unchanged = 0;
  for (const item of items) {
    if (item.kind === "skip") unchanged += 1;
    else if (item.conflict) conflicts.push(item.id);
    else upload.push({ id: item.id, baseRev: item.baseRev, kind: item.kind });
  }
  return { upload, conflicts, unchanged };
}
