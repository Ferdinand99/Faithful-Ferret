// The local trash: a verified tombstone moves the last live row of an item here for 30 days, and only a verified one; the
// user can bring the item back (a resurrection at the tombstone's revision + 1) or throw the copy away. Ciphertext only.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { b64u, hex16 } from "../../src/b64.mjs";
import { cache } from "../../src/store/cache.mjs";
import { outbox } from "../../src/store/outbox.mjs";
import { trash as trashStore, TRASH_FIELDS } from "../../src/store/trash.mjs";
import { TRASH_MS } from "../../src/sync/conflict.mjs";
import { scope } from "./idbHelpers.mjs";
import { createFakeClient, currentRev, Model, settle, syncDevice, until } from "./syncHelpers.mjs";

const ID_A = "11".repeat(16);
const ID_B = "22".repeat(16);
const T0 = 1_700_000_000_000;
const DAY = 86_400_000;
const MARKER = "Secret Bank Login";

const setRow = (model, client, id, rev, name, extra = {}) => model.set(id, { rev, ...client.wireRow(id, rev, { item_type: "login", name, fields: [{ id: "password", label: "Password", kind: "password", value: "hunter2" }] }), ...extra });
const setTomb = (model, client, id, rev, extra = {}) => model.set(id, { rev, deleted: true, tomb: client.wireTomb(id, rev), ...extra });
const trashed = (d) => trashStore.all(d.store.database.store, scope());
const rowsOf = (d) => cache.getRows(d.store.database.store, scope());
const itemOf = (d, id = ID_A) => d.engine.list().find((entry) => entry.id === id);
const reload = (d) => syncDevice({ model: d.model, client: d.client, db: d.store.database, locks: d.locks });

/** One device with A at revision 2; another device then deletes A (a good tombstone at revision 3) and this device reads it. */
async function deletedElsewhere({ name = MARKER } = {}) {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 2, name);
  const d = await syncDevice({ model, client });
  await d.engine.start();
  const live = (await rowsOf(d)).find((row) => row.itemId === ID_A);
  setTomb(model, client, ID_A, 3);
  await d.engine.syncNow();
  return { d, model, client, live };
}

test("a_verified_tombstone_moves_the_last_live_row_to_the_trash", async () => {
  const { d, live } = await deletedElsewhere();
  assert.equal(itemOf(d), undefined, "the item is gone from the list");
  const [entry, ...rest] = await trashed(d);
  assert.equal(rest.length, 0);
  assert.deepEqual([entry.itemId, entry.rev, entry.tombRev], [ID_A, 2, 3]);
  assert.deepEqual([...entry.envelope], [...live.envelope], "the last live row, as it was");
  assert.deepEqual([...entry.tag], [...live.tag]);
  assert.equal(entry.deletedAt, T0 + d.timers.time, "stamped when the deletion was verified");
  // The cache now holds the tombstone (the live row is only in the trash).
  const row = (await rowsOf(d)).find((r) => r.itemId === ID_A);
  assert.deepEqual([row.deleted, row.rev], [true, 3]);
  // The trash lists the name, read out of the sealed item now.
  assert.deepEqual(await d.engine.trash(), [{ id: ID_A, name: MARKER, deletedAt: entry.deletedAt }]);
  d.engine.stop();
});

test("the_trash_is_written_before_the_cache_is_written_over_the_live_row", async () => {
  const { d } = await deletedElsewhere();
  const log = d.store.spy.log;
  const put = log.indexOf("trash.put");
  assert.ok(put >= 0);
  assert.ok(put < log.lastIndexOf("cache.putRows"), "the live row is in the trash before the tombstone replaces it");
  d.engine.stop();
});

test("a_trash_that_cannot_be_written_keeps_the_live_row_and_the_next_pass_tries_again", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 2, MARKER);
  const d = await syncDevice({ model, client });
  await d.engine.start();
  setTomb(model, client, ID_A, 3);
  d.store.failTrashPut = 1;
  await d.engine.syncNow();
  const row = (await rowsOf(d)).find((r) => r.itemId === ID_A);
  assert.deepEqual([row.deleted, row.rev], [false, 2], "nothing was replaced");
  assert.equal(itemOf(d).name, MARKER);
  assert.deepEqual(await trashed(d), []);
  await d.engine.syncNow();
  assert.equal(itemOf(d), undefined);
  assert.equal((await trashed(d)).length, 1);
  d.engine.stop();
});

test("an_unverified_tombstone_does_not_touch_the_trash", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 2, MARKER);
  const d = await syncDevice({ model, client });
  await d.engine.start();
  model.set(ID_A, { rev: 3, deleted: true, tomb: b64u.encode(new Uint8Array(40).fill(1)) });
  await d.engine.syncNow();
  assert.deepEqual(await trashed(d), [], "nothing is trashed on the server's word alone");
  assert.equal(itemOf(d).quarantined, true);
  const row = (await rowsOf(d)).find((r) => r.itemId === ID_A);
  assert.deepEqual([row.deleted, row.rev], [false, 2], "the live row is still the cached one");
  assert.deepEqual(await d.engine.trash(), []);
  d.engine.stop();
});

test("a_tombstone_for_an_item_this_device_never_held_trashes_nothing", async () => {
  const model = new Model();
  const client = createFakeClient();
  const d = await syncDevice({ model, client });
  await d.engine.start();
  setTomb(model, client, ID_B, 4);
  await d.engine.syncNow();
  assert.deepEqual(await trashed(d), []);
  d.engine.stop();
});

test("an_own_delete_goes_to_the_trash_when_its_tombstone_comes_back", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, MARKER);
  const d = await syncDevice({ model, client });
  await d.engine.start();
  await d.engine.remove(ID_A);
  await until(() => d.model.items.get(ID_A).deleted === true, "the deletion is on the server");
  await until(async () => (await trashed(d)).length === 1, "and its tombstone has come back");
  assert.deepEqual((await d.engine.trash()).map((entry) => [entry.id, entry.name]), [[ID_A, MARKER]]);
  d.engine.stop();
});

test("restore_from_trash_resurrects_at_tomb_rev_plus_1", async () => {
  const { d, model } = await deletedElsewhere();
  await d.engine.restoreFromTrash(ID_A);
  await until(() => model.items.get(ID_A).deleted === false, "the item is back on the server");
  const sent = JSON.parse(model.writes.at(-1).body);
  assert.deepEqual([sent.base_rev, sent.resurrect], [3, true], "on the tombstone's revision, with the flag");
  const row = model.items.get(ID_A);
  assert.equal(row.rev, 4);
  const handle = await d.client.vault.open_item(hex16.decode(ID_A), 4, b64u.decode(row.blob), b64u.decode(row.tag));
  assert.equal((await d.client.vault.item_view(handle)).name, MARKER);
  await d.client.vault.close_item(handle);
  assert.deepEqual(await trashed(d), [], "it has left the trash");
  await until(() => itemOf(d)?.rev === 4 && itemOf(d).pending === false, "the live row comes back");
  assert.equal(itemOf(d).name, MARKER);
  assert.deepEqual(await outbox.all(d.store.database.store, scope()), []);
  d.engine.stop();
});

test("restore_from_trash_shows_the_item_at_once_and_survives_a_restart_before_it_is_sent", async () => {
  const { d } = await deletedElsewhere();
  d.api.faults.push({ kind: "network" });
  await d.engine.restoreFromTrash(ID_A);
  assert.deepEqual([itemOf(d).name, itemOf(d).rev, itemOf(d).pending], [MARKER, 4, true]);
  d.engine.stop();
  const back = await reload(d);
  await back.engine.start();
  await until(() => d.model.items.get(ID_A).deleted === false, "the stored write goes out after the restart");
  assert.equal(JSON.parse(d.model.writes.at(-1).body).resurrect, true);
  back.engine.stop();
});

test("restore_from_trash_refuses_what_the_server_no_longer_shows_as_deleted_there", async () => {
  const { d, model, client } = await deletedElsewhere();
  await assert.rejects(() => d.engine.restoreFromTrash(ID_B), { code: "not_found" });
  await assert.rejects(() => d.engine.restoreFromTrash("nothex"), { code: "not_found" });
  // Another device has brought the item back already.
  setRow(model, client, ID_A, 4, "Back elsewhere");
  await d.engine.syncNow();
  await assert.rejects(() => d.engine.restoreFromTrash(ID_A), { code: "invalid_state" });
  assert.equal(model.writes.length, 0);
  // The trash lists nothing for an item that is alive again, and the stale entry is dropped.
  assert.deepEqual(await d.engine.trash(), []);
  assert.deepEqual(await trashed(d), []);
  d.engine.stop();
});

test("remove_from_trash_drops_the_entry_and_the_item_stays_deleted", async () => {
  const { d, model } = await deletedElsewhere();
  await d.engine.removeFromTrash(ID_A);
  assert.deepEqual(await trashed(d), []);
  assert.deepEqual(await d.engine.trash(), []);
  await d.engine.removeFromTrash(ID_A); // nothing there: no harm
  await assert.rejects(() => d.engine.restoreFromTrash(ID_A), { code: "not_found" });
  assert.equal(model.items.get(ID_A).deleted, true);
  assert.equal(model.writes.length, 0);
  d.engine.stop();
});

test("trash_older_than_30_days_is_purged_at_start", async () => {
  const { d } = await deletedElsewhere();
  const [entry] = await trashed(d);
  // A second entry that is newer. Its bytes are not an item; only its age matters for the purge.
  const store = d.store.database.store;
  await trashStore.put(store, scope(), { itemId: ID_B, rev: 1, envelope: new Uint8Array(40).fill(3), tag: new Uint8Array(32).fill(4), tombRev: 2, deletedAt: entry.deletedAt + 10 * DAY });
  d.engine.stop();

  // 29 days later nothing has gone; 31 days later the first has, and the newer one has not.
  const early = await reload(d);
  early.timers.advance(29 * DAY);
  await early.engine.start();
  assert.equal((await trashed(early)).length, 2);
  early.engine.stop();
  const late = await reload(d);
  late.timers.advance(31 * DAY);
  await late.engine.start();
  assert.deepEqual((await trashed(late)).map((e) => e.itemId), [ID_B], "30 days after the deletion it is gone");
  late.engine.stop();
  assert.equal(TRASH_MS, 30 * DAY);
});

test("the_trash_listing_purges_what_has_grown_old_and_names_what_cannot_be_opened_with_nothing", async () => {
  const { d } = await deletedElsewhere();
  const [entry] = await trashed(d);
  await trashStore.put(d.store.database.store, scope(), { itemId: ID_B, rev: 1, envelope: new Uint8Array(40).fill(3), tag: new Uint8Array(32).fill(4), tombRev: 2, deletedAt: entry.deletedAt + 5 * DAY });
  d.timers.time += 31 * DAY; // the clock of this device moves on
  const listed = await d.engine.trash();
  assert.deepEqual(listed, [{ id: ID_B, name: "", deletedAt: entry.deletedAt + 5 * DAY }], "the old one is purged, the one that cannot be opened has no name");
  d.engine.stop();
});

test("trash_holds_only_ciphertext", async () => {
  const { d } = await deletedElsewhere();
  const [entry] = await trashed(d);
  assert.deepEqual(Object.keys(entry).sort(), [...TRASH_FIELDS].sort(), "only the allowed fields");
  const all = Buffer.concat([Buffer.from(entry.envelope), Buffer.from(entry.tag), Buffer.from(JSON.stringify(entry, (key, value) => (value instanceof Uint8Array ? "bytes" : value)))]);
  assert.equal(all.includes(Buffer.from(MARKER)), false, "the name is nowhere in the stored entry");
  assert.equal(all.includes(Buffer.from("hunter2")), false, "nor is a secret");
  // The store refuses a field that is not ciphertext.
  await assert.rejects(() => trashStore.put(d.store.database.store, scope(), { ...entry, name: MARKER }), { code: "trash_field" });
  // The names of the list come from opening the sealed item, and are not kept: a second look finds the store unchanged.
  await d.engine.trash();
  assert.deepEqual(await trashed(d), [entry]);
  d.engine.stop();
});

test("a_newer_tombstone_in_an_accepted_older_state_puts_the_live_row_in_the_trash", async () => {
  // This device holds A live at revision 1. The server is restored to a state where A is deleted at revision 2.
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, MARKER, { seq: 5 });
  const d = await syncDevice({ model, client });
  await d.engine.start();
  model.items.clear();
  setTomb(model, client, ID_A, 2, { seq: 1 });
  model.restoreEpoch = 1;
  await d.engine.syncNow();
  assert.equal(d.engine.health().halted, "server_restored");
  assert.deepEqual(await trashed(d), [], "nothing is trashed before the user accepts");
  assert.deepEqual(await d.engine.acceptOlderState(), { reuploaded: 0, conflicts: 1, manifestOlder: false });
  const [entry] = await trashed(d);
  assert.deepEqual([entry.itemId, entry.rev, entry.tombRev], [ID_A, 1, 2]);
  // The local version is also a draft: a conflict with a deleted server, for the user to choose in.
  assert.equal(itemOf(d).conflict, true);
  await settle(20);
  d.engine.stop();
});

test("clearing_the_cache_of_the_account_empties_the_trash", async () => {
  const { d } = await deletedElsewhere();
  assert.equal((await trashed(d)).length, 1);
  d.engine.stop();
  await cache.clearAccount(d.store.database.store, scope().accountId);
  assert.deepEqual(await trashed(d), []);
});

test("a_pending_edit_when_the_tombstone_arrives_is_not_lost_and_the_trash_has_the_server_row", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, MARKER);
  const d = await syncDevice({ model, client });
  await d.engine.start();
  setTomb(model, client, ID_A, 2);
  await d.engine.update(ID_A, { name: "Edit after the deletion" }, currentRev(d.engine, ID_A));
  await until(async () => itemOf(d)?.conflict === true && (await trashed(d)).length === 1, "the edit is refused and the tombstone arrives");
  await settle(10);
  const [entry] = await trashed(d);
  assert.deepEqual([entry.rev, entry.tombRev], [1, 2], "the last server version is in the trash");
  assert.equal(itemOf(d).name, "Edit after the deletion", "and the edit is still on screen, as the draft");
  d.engine.stop();
});

// ------------------------------------------------------------------ fix round 1

test("a_resurrection_that_is_refused_and_then_discarded_keeps_the_version_in_the_trash", async () => {
  const { d, model } = await deletedElsewhere();
  d.api.faults.push({ kind: "status", status: 413, code: "too_large" });
  await d.engine.restoreFromTrash(ID_A);
  await until(() => itemOf(d)?.blockedReason === "too_large", "the write is refused for good");
  assert.deepEqual(await trashed(d), [], "the entry left the trash when the write was stored");
  await d.engine.discard(ID_A);
  const [entry] = await trashed(d);
  assert.deepEqual([entry.itemId, entry.tombRev], [ID_A, 3], "the draft is in the trash again");
  assert.ok(entry.rev < entry.tombRev);
  assert.deepEqual((await d.engine.trash()).map((e) => e.name), [MARKER]);
  await d.engine.restoreFromTrash(ID_A);
  await until(() => model.items.get(ID_A).deleted === false, "and it can be restored");
  d.engine.stop();
});

test("restore_from_trash_goes_on_top_of_a_newer_tombstone_and_the_entry_is_kept", async () => {
  const { d, model, client } = await deletedElsewhere();
  // Brought back and deleted again elsewhere: the server's tombstone is at revision 5 now, above the entry's 3.
  setRow(model, client, ID_A, 4, "Back elsewhere");
  setTomb(model, client, ID_A, 5);
  await d.engine.syncNow();
  assert.equal((await d.engine.trash()).length, 1, "the entry is not dropped: the row is not live above its tombstone");
  await d.engine.restoreFromTrash(ID_A);
  await until(() => model.items.get(ID_A).deleted === false, "restored");
  const sent = JSON.parse(model.writes.at(-1).body);
  assert.deepEqual([sent.base_rev, sent.resurrect], [5, true]);
  assert.equal(model.items.get(ID_A).rev, 6);
  d.engine.stop();
});

test("the_trash_listing_goes_by_the_stored_rows_and_not_by_this_tabs_memory", async () => {
  const { d, model, client } = await deletedElsewhere();
  // Another tab brought the item back (live at revision 4) and stored it; this tab has not read it yet.
  const other = await syncDevice({ model, client, db: d.store.database, locks: d.locks, seed: 9 });
  setRow(model, client, ID_A, 4, "Back");
  await other.engine.start();
  await until(() => itemOf(other)?.rev === 4, "the other tab has the live row");
  assert.equal(itemOf(d), undefined, "this tab still has the tombstone in memory");
  assert.deepEqual(await d.engine.trash(), [], "the stale entry is dropped by what is stored");
  other.engine.stop();
  d.engine.stop();
});

test("an_own_delete_of_a_reuploaded_item_below_the_floor_keeps_a_trash_copy", async () => {
  // B was held at revision 3 and the server lost it; this device uploaded it again and deleted it (revision 2, below the
  // floor of 3). The cached old copy is the last live row, and it is above the tombstone: it is sealed again below it.
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_B, 3, MARKER);
  const first = await syncDevice({ model, client });
  await first.engine.start();
  first.engine.stop();
  const tomb = client.wireTomb(ID_B, 2);
  const digest = createHash("sha256").update(Buffer.concat([Buffer.from([2]), Buffer.from(b64u.decode(tomb))])).digest("base64url");
  const key = `sync.flags.${scope().accountId}.${scope().vaultId}.${scope().vkEpoch}`;
  await first.store.setSetting(first.store.database.store, key, { v: 1, marks: { [ID_B]: { kind: "missing_on_server", rev: 3, sent: [`2:t:${digest}`] } }, blocked: {} });
  model.set(ID_B, { rev: 2, deleted: true, tomb });
  const d = await reload(first);
  await d.engine.start();
  await until(async () => (await trashed(d)).length === 1, "the copy is in the trash");
  const [entry] = await trashed(d);
  assert.deepEqual([entry.itemId, entry.rev, entry.tombRev], [ID_B, 1, 2]);
  assert.deepEqual((await d.engine.trash()).map((e) => e.name), [MARKER]);
  d.engine.stop();
});
