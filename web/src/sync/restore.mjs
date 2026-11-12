// What to do with the local versions of items when the user accepts the older state of a server that was restored
// from a backup: which of them the server lacks (and is sent again, built on what the server has now), which of them
// must not be sent because the server holds something this device has not seen, and which of them the server has
// already moved past.
//
// This file only decides. It reads rows, frozen rows and revision numbers; it opens nothing and writes nothing. The
// engine does the sealing, the queueing and the replacing of rows (see engine.mjs, `acceptOlderState`).
//
// Two things are known about the server. `restore_seq` is the `seq` the vault had when the restore was recorded, and the
// frozen rows are what the vault held for each item at that moment (`GET /api/sync/restore-rows`). A row of the server with a
// `seq` at or below `restore_seq` has not been written since the restore; a row above it was written after. Neither the
// number nor the list is signed, so this protects the honest case only (a server that lies about them can turn a conflict
// into an overwrite of another device's later write: the same class as the writes since the last checkpoint, which no
// check on the client closes).
//
// First, a deletion on both sides needs nothing, an item that was blocked as a conflict stays one (it is never settled by
// itself), and a version that is byte for byte the server's row needs nothing (honest case only). Then, for the server's row now
// (S), the frozen row at the restore (F) and the local version (L):
//
//   S has `seq` <= restore_seq (untouched)       a row version: higher than S: made again over S (`base_rev` is S's revision);
//                                                lower than S: skipped; the same revision with other bytes: a conflict
//                                                (another line of history)
//                                                a write waiting in the outbox: made again over S only when it was built on S or on
//                                                a later revision the restore lost (`base_rev` >= S's revision); built on an older
//                                                one it is a conflict, as it would have been a 409 without the restore. A write
//                                                that is byte for byte S at `base_rev` + 1 = S's revision is this device's own
//                                                and counts as done
//   S has `seq` > restore_seq (written after)    a row version with a revision below F's, or equal to it with F's bytes: skipped
//                                                (older on the same line); anything else, and every write in the outbox: a conflict
//   S exists and F does not                      a conflict
//   S does not exist                             the item is new (`base_rev` 0); a deletion of nothing is skipped
//
// A write that waits in the outbox is a change made on this device and never sent: it is never dropped. Without frozen rows
// (an older server, `restore_seq` 0) the interim rules apply: only an item the server has no row for is sent by itself; a
// version that differs from the server's row is kept as a draft that is not sent, whatever its revision.
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
 *   `new` the server has no row for the item: the write is built on revision 0
 * @typedef {{ id: string, baseRev: number, kind: Kind }} Plan
 * @typedef {{ restoreSeq: number, frozen: ReadonlyMap<string, { rev: number, seq: number, hash: string | null }> }} Restore
 *   what the server froze when it was restored: its `seq` then, and a row per item
 *
 * @typedef {object} Decision what to do with one item
 * @property {string} id
 * @property {Kind | "skip"} kind `skip`: nothing to send (the server has the same or a newer version, or both are deleted)
 * @property {number} baseRev the revision the write builds on (the server's, or 0)
 * @property {boolean} conflict the write is kept as a draft that is not sent
 * @property {"row" | "outbox"} source where the newest local version is: the row this device holds, or the last write
 *   that was waiting in the outbox (it exists only here)
 * @property {number} localRev the revision of that version
 */

import { b64u } from "../b64.mjs";

/** The all-zero id of the unlock-method manifest: a row, never an item, never sent from here. */
const MANIFEST = "0".repeat(32);

/**
 * The hash a frozen row has for a row: the SHA-256 of the envelope of a live row, base64url, and null for a tombstone.
 * @param {CachedRow} row
 * @returns {Promise<string | null>}
 */
export async function rowHash(row) {
  if (row.deleted || row.envelope === null) return null;
  return b64u.encode(new Uint8Array(await crypto.subtle.digest("SHA-256", /** @type {BufferSource} */ (row.envelope))));
}

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
 *   restore?: Restore | null,
 *   rows: Iterable<CachedRow>,
 *   outbox: Iterable<OutboxEntry>,
 *   blocked?: ReadonlySet<string> | Iterable<string>,
 *   marks?: ReadonlyMap<string, { kind: string, rev: number }>,
 * }} input
 *   `listing` is what the server shows now, `restore` what it froze (null: it did not, the interim rules apply), `rows` what
 *   this device holds, `outbox` what it has queued, `blocked` the items whose earlier write was refused (they stay
 *   conflicts), `marks` the marks of items that were uploaded again.
 * @returns {Promise<Decision[]>} in the order of the item ids
 */
export async function restoreItems({ listing, restore = null, rows, outbox, blocked = new Set(), marks = new Map() }) {
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
    if (blockedIds.has(id)) {
      decide(kind, true); // blocked as a conflict: it stays one until the user chooses
      continue;
    }
    // A version byte for byte the server's row is nothing to do (the honest case: the server has what this device has).
    const identical = local.from === "row" && !local.deleted && row !== undefined && !server.deleted &&
      sameBytes(row.envelope, server.envelope) && sameBytes(row.tag, server.tag);
    // The writes of the item that wait in the outbox, oldest first: a chain, each built on the one before. A leading write that is the
    // very row the server holds, one revision above its base, is this device's own write, which got there (the answer was lost): it
    // counts as done, and the rest of the chain (if any) is judged against the server's row.
    const chain = local.from === "outbox" ? (queued.get(id) ?? []) : [];
    const first = chain[0];
    const leadsWithOwn = first !== undefined && first.baseRev + 1 === server.rev && (
      "tomb" in first.body
        ? server.deleted && sameBytes(first.body.tomb, server.tomb)
        : !server.deleted && sameBytes(first.body.blob, server.envelope) && sameBytes(first.body.tag, server.tag)
    );
    const rest = leadsWithOwn ? chain.slice(1) : chain;
    if (identical || (local.from === "outbox" && rest.length === 0)) {
      decide("skip", false);
      continue;
    }
    if (restore === null) {
      // No frozen rows. After a restore the revisions no longer form one line: a lower revision here than on the server can be a
      // version this device wrote before the restore against a row another device wrote after it, and nothing on this device
      // says which. So a version that differs is kept as a draft whatever its revision, never skipped and never dropped.
      decide(kind, true);
      continue;
    }
    const frozen = restore.frozen.get(id);
    if (frozen === undefined) {
      decide(kind, true); // the server shows a row that did not exist at the restore: someone wrote it since
    } else if (server.seq <= restore.restoreSeq) {
      // Not written since the restore: what is here is the restored row.
      if (local.from === "outbox") {
        // A change made here and never sent. Over the restored row only when it was built on that row or on a later revision the
        // restore lost; built on an older one the server would have refused it, and so does the restore. Of a chain of writes the
        // first one decides: the later ones are built on this device's own unsent revisions, and the first one names the server
        // revision the whole chain was built on.
        decide(kind, rest[0].baseRev < server.rev);
      } else if (local.rev > server.rev) {
        decide(kind, false); // a version the restore lost
      } else {
        decide(local.rev === server.rev ? kind : "skip", local.rev === server.rev); // the same revision with other bytes: another line
      }
    } else if (local.from === "row" && (local.rev < frozen.rev || (local.rev === frozen.rev && (await rowHash(/** @type {CachedRow} */ (row))) === frozen.hash))) {
      decide("skip", false); // written after the restore, and this device's version is older on the same line
    } else {
      decide(kind, true); // written after the restore, and this device has a change the server has not seen
    }
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
