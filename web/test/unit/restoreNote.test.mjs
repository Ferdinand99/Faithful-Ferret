// The local note about an accepted restore: kept across a reload, gone after 30 days, never a secret,
// and the two ends of it (written at the accept, found again at a refusal).
import assert from "node:assert/strict";
import { test } from "node:test";
import { recordAcceptedRestore, restoreNoteFinder } from "../../src/flows/restoreNote.mjs";
import { StoreError } from "../../src/store/idb.mjs";
import { loadPinned, savePinned } from "../../src/store/pinned.mjs";
import { loadRestoreNote, RESTORE_NOTE_TTL_MS, restoreNoteKey, saveRestoreNote } from "../../src/store/restoreNote.mjs";
import { setSetting } from "../../src/store/settings.mjs";
import { loadSyncState, saveSyncState } from "../../src/store/syncState.mjs";
import { ACCOUNT, SERVER, freshStore, pinnedRecord } from "./idbHelpers.mjs";

const DAY = 24 * 60 * 60 * 1000;
const T0 = Date.UTC(2026, 10, 8, 12);
const note = (over = {}) => ({ acceptedAt: T0, restoreEpoch: 3, manifestOlder: true, ...over });
const state = (restoreEpoch) => ({ memory: new Uint8Array(8), restoreEpoch, verifiedAt: 1, verifiedSeq: 1, uploadedAt: 1, uploadedSeq: 1, hardWarning: null, restore: null });

/** The slice of the store service the flows use, over one open database. */
function serviceOver(store) {
  return {
    open: async () => store,
    loadSyncState,
    pinHintForEmail: loadPinned,
    restoreNote: { save: saveRestoreNote, load: loadRestoreNote },
  };
}

test("restore_note_survives_reload_and_expires_after_30_days", async () => {
  const db = await freshStore();
  assert.equal(await loadRestoreNote(db.store, SERVER, ACCOUNT, T0), null, "no note at first");
  await saveRestoreNote(db.store, SERVER, ACCOUNT, note());
  assert.equal(restoreNoteKey(SERVER, ACCOUNT), `restore.note.${SERVER}.${ACCOUNT}`);

  // A reload: the database is closed and opened again.
  const reopened = await db.reopen();
  assert.deepEqual(await loadRestoreNote(reopened, SERVER, ACCOUNT, T0 + DAY), note());
  assert.deepEqual(await loadRestoreNote(reopened, `${SERVER}/other/path`, ACCOUNT, T0 + DAY), note(), "the server is its origin");
  assert.equal(RESTORE_NOTE_TTL_MS, 30 * DAY);
  assert.deepEqual(await loadRestoreNote(reopened, SERVER, ACCOUNT, T0 + 30 * DAY), note(), "the 30th day still counts");
  assert.equal(await loadRestoreNote(reopened, SERVER, ACCOUNT, T0 + 30 * DAY + 1), null, "after 30 days it is gone");
  assert.equal(await loadRestoreNote(reopened, SERVER, ACCOUNT, T0 + 400 * DAY), null);
  // A clock that went back by days does not make a note from the future valid.
  assert.equal(await loadRestoreNote(reopened, SERVER, ACCOUNT, T0 - 3 * DAY), null);
});

test("a_note_is_per_server_and_account_and_the_newest_replaces_the_older", async () => {
  const { store } = await freshStore();
  const other = "ffeeddccbbaa99887766554433221100";
  await saveRestoreNote(store, SERVER, ACCOUNT, note());
  assert.equal(await loadRestoreNote(store, "https://other.example", ACCOUNT, T0), null);
  assert.equal(await loadRestoreNote(store, SERVER, other, T0), null);
  await saveRestoreNote(store, SERVER, ACCOUNT, note({ acceptedAt: T0 + DAY, restoreEpoch: 4 }));
  assert.deepEqual(await loadRestoreNote(store, SERVER, ACCOUNT, T0 + DAY), note({ acceptedAt: T0 + DAY, restoreEpoch: 4 }));
});

test("a_note_holds_the_three_fields_and_nothing_else", async () => {
  const { store } = await freshStore();
  for (const bad of [
    null, "x", [], {}, note({ extra: "name" }), note({ acceptedAt: 0 }), note({ acceptedAt: 1.5 }), note({ acceptedAt: "1" }),
    note({ restoreEpoch: -1 }), note({ restoreEpoch: null }), note({ manifestOlder: "yes" }), { acceptedAt: T0, restoreEpoch: 1 },
  ]) {
    await assert.rejects(() => saveRestoreNote(store, SERVER, ACCOUNT, bad), TypeError, JSON.stringify(bad));
  }
  await assert.rejects(() => saveRestoreNote(store, SERVER, "nope", note()), TypeError);
  await assert.rejects(() => loadRestoreNote(store, SERVER, ACCOUNT, "now"), TypeError);
  // A stored value that is not a note (edited by hand, another version) reads as no note.
  for (const bad of ["text", { acceptedAt: T0 }, note({ manifestOlder: 1 }), note({ extra: 1 })]) {
    await setSetting(store, restoreNoteKey(SERVER, ACCOUNT), bad);
    assert.equal(await loadRestoreNote(store, SERVER, ACCOUNT, T0), null, JSON.stringify(bad));
  }
});

test("a_successful_accept_with_manifest_older_saves_the_note_with_the_restore_epoch_the_engine_stored", async () => {
  const { store } = await freshStore();
  await saveSyncState(store, SERVER, ACCOUNT, state(7));
  const service = serviceOver(store);
  const kept = await recordAcceptedRestore({ store: service, serverUrl: SERVER, accountId: ACCOUNT, result: { reuploaded: 1, conflicts: 0, manifestOlder: true }, now: () => T0 });
  assert.equal(kept, true);
  assert.deepEqual(await loadRestoreNote(store, SERVER, ACCOUNT, T0), { acceptedAt: T0, restoreEpoch: 7, manifestOlder: true });

  // Without manifestOlder there is nothing to say at an unlock, and an earlier note is left as it is.
  assert.equal(await recordAcceptedRestore({ store: service, serverUrl: SERVER, accountId: ACCOUNT, result: { manifestOlder: false }, now: () => T0 + DAY }), false);
  assert.equal(await recordAcceptedRestore({ store: service, serverUrl: SERVER, accountId: ACCOUNT, result: {}, now: () => T0 + DAY }), false);
  assert.equal((await loadRestoreNote(store, SERVER, ACCOUNT, T0)).acceptedAt, T0);
});

test("a_note_that_cannot_be_kept_or_read_never_throws_and_is_no_note", async () => {
  const broken = { open: async () => { throw new StoreError("disk_error", "no"); } };
  assert.equal(await recordAcceptedRestore({ store: broken, serverUrl: SERVER, accountId: ACCOUNT, result: { manifestOlder: true } }), false);
  const { store } = await freshStore();
  assert.equal(await recordAcceptedRestore({ store: serviceOver(store), serverUrl: SERVER, accountId: undefined, result: { manifestOlder: true } }), false);
  assert.equal(await restoreNoteFinder({ store: broken, serverUrl: SERVER })({ accountId: ACCOUNT }), null);
});

test("the_finder_reads_the_note_by_account_id_or_by_the_e_mail_the_device_has_pinned", async () => {
  const { store } = await freshStore();
  const service = serviceOver(store);
  await savePinned(store, SERVER, ACCOUNT, "ada@example.org", pinnedRecord({ accountId: ACCOUNT, server: SERVER }));
  await saveRestoreNote(store, SERVER, ACCOUNT, note());
  const find = restoreNoteFinder({ store: service, serverUrl: SERVER, now: () => T0 + 2 * DAY });
  assert.deepEqual(await find({ accountId: ACCOUNT }), note());
  assert.deepEqual(await find({ email: "ada@example.org" }), note(), "the typed address finds the record the device pinned");
  assert.equal(await find({ email: "nobody@example.org" }), null, "an address this device does not know has no note");
  assert.equal(await find({}), null);
  const later = restoreNoteFinder({ store: service, serverUrl: SERVER, now: () => T0 + 31 * DAY });
  assert.equal(await later({ accountId: ACCOUNT }), null);
  assert.ok(await loadPinned(store, SERVER, "ada@example.org"), "the finder changed nothing");
});
