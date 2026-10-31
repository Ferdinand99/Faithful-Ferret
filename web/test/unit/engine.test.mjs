// The sync engine against a model of the server: rows in, items out, and what
// happens to rows that are wrong.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { ApiError } from "../../src/api.mjs";
import { b64u, hex16 } from "../../src/b64.mjs";
import { cache } from "../../src/store/cache.mjs";
import { createSyncEngine, MANIFEST_ID, SyncError } from "../../src/sync/engine.mjs";
import { freshStore, scope } from "./idbHelpers.mjs";
import {
  counterRand, createFakeApi, createFakeClient, createFakeStore, currentRev, FakeTimers, Model, settle, until,
} from "./syncHelpers.mjs";

const MARKER = "Secret Bank Login";
const DRAFT = { item_type: "login", name: MARKER, urls: ["https://bank.example"] };
const ID_A = "11".repeat(16);
const ID_B = "22".repeat(16);

/** One device: an engine over its own fake browser storage and a fake clock. */
async function device({ model, client = createFakeClient(), seed = 1, pollMs = 5_000, db = null, win = null } = {}) {
  const order = [];
  const store = await createFakeStore({ order, db });
  const api = createFakeApi(model, { order });
  const timers = new FakeTimers();
  const events = { changed: [], error: [], state: [] };
  const engine = createSyncEngine({
    api, client: { vault: client.vault }, store, scope: scope(), timers, rand: counterRand(seed), pollMs, win,
    now: () => 1_700_000_000_000 + timers.time,
  });
  for (const name of Object.keys(events)) engine.on(name, (payload) => events[name].push(payload));
  return { model, client, store, api, timers, engine, events, order };
}

const rowsOf = (d) => cache.getRows(d.store.database.store, scope());
const warnings = (d) => d.events.state.filter((s) => s.kind === "warning");

test("create_update_delete_roundtrip_against_the_model", async () => {
  const d = await device({ model: new Model() });
  await d.engine.start();
  const id = await d.engine.create(DRAFT);
  assert.match(id, /^[0-9a-f]{32}$/);
  await until(() => d.model.items.get(id)?.rev === 1, "the server has rev 1");
  await until(async () => (await rowsOf(d)).some((r) => r.itemId === id && r.rev === 1), "rev 1 in the cache");
  let [item] = d.engine.list();
  assert.equal(item.id, id);
  assert.equal(item.name, MARKER);
  assert.equal(item.type, "login");
  assert.deepEqual(item.urls, ["https://bank.example"]);
  assert.equal(item.rev, 1);
  await until(() => d.engine.list()[0].pending === false, "no longer pending");

  await d.engine.update(id, { name: "Renamed" }, currentRev(d.engine, id));
  await until(() => d.model.items.get(id)?.rev === 2, "the server has rev 2");
  await until(async () => (await rowsOf(d)).some((r) => r.rev === 2), "rev 2 in the cache");
  [item] = d.engine.list();
  assert.equal(item.name, "Renamed");
  assert.deepEqual(item.urls, ["https://bank.example"], "the edit keeps what the draft does not mention");
  assert.equal(item.rev, 2);

  const open = await d.engine.open(id);
  assert.equal(typeof open.handle, "number");
  assert.equal(open.view.name, "Renamed");
  assert.equal(d.client.vault.handles.size, 1);
  await open.close();
  await open.close(); // closing twice is harmless
  assert.equal(d.client.vault.handles.size, 0);

  await d.engine.remove(id);
  await until(() => d.model.items.get(id)?.deleted === true, "the server has the tombstone");
  assert.equal(d.model.items.get(id).rev, 3);
  assert.equal(d.engine.list().length, 0);
  await until(async () => (await rowsOf(d)).some((r) => r.deleted && r.rev === 3), "the tombstone in the cache");
  await assert.rejects(d.engine.open(id), (e) => e instanceof SyncError && e.code === "not_found");
  assert.ok(d.events.changed.length > 0);
});

test("second_engine_sees_the_change_within_one_poll", async () => {
  const model = new Model();
  const client = createFakeClient();
  const a = await device({ model, client: createFakeClient(), seed: 1 });
  const b = await device({ model, client, seed: 2 });
  await a.engine.start();
  await b.engine.start();
  assert.equal(b.engine.list().length, 0);

  const id = await a.engine.create(DRAFT);
  await until(() => model.items.has(id), "the write reaches the server");
  assert.equal(b.engine.list().length, 0, "nothing until B polls");

  b.timers.advance(4_999);
  await settle();
  assert.equal(b.engine.list().length, 0, "not before the poll time");
  b.timers.advance(1);
  await until(() => b.engine.list().length === 1, "B sees the item");
  assert.equal(b.engine.list()[0].name, MARKER);

  await a.engine.update(id, { name: "Changed on A" }, currentRev(a.engine, id));
  await until(() => model.items.get(id).rev === 2);
  b.timers.advance(5_000);
  await until(() => b.engine.list()[0].name === "Changed on A", "B sees the edit");

  await a.engine.remove(id);
  await until(() => model.items.get(id).deleted);
  b.timers.advance(5_000);
  await until(() => b.engine.list().length === 0, "B sees the deletion");
  a.engine.stop();
  b.engine.stop();
});

test("a_focus_event_syncs_at_once", async () => {
  const model = new Model();
  const win = new EventTarget();
  const d = await device({ model, win });
  await d.engine.start();
  const before = d.api.gets.length;
  win.dispatchEvent(new Event("focus"));
  await until(() => d.api.gets.length > before, "a sync after the focus");
  d.engine.stop();
  const after = d.api.gets.length;
  win.dispatchEvent(new Event("focus"));
  await settle();
  assert.equal(d.api.gets.length, after, "no listener is left after stop");
});

test("row_with_invalid_tag_is_not_accepted_and_marks_damaged", async () => {
  const model = new Model();
  const client = createFakeClient();
  const bad = client.wireRow(ID_A, 1, { item_type: "login", name: "Broken" });
  const tag = b64u.decode(bad.tag);
  tag[0] ^= 1;
  model.set(ID_A, { rev: 1, blob: bad.blob, tag: b64u.encode(tag) });
  const good = client.wireRow(ID_B, 1, { item_type: "login", name: "Fine" });
  model.set(ID_B, { rev: 1, ...good });

  const d = await device({ model, client });
  await d.engine.start();
  const list = d.engine.list();
  assert.deepEqual(list.map((i) => [i.id, i.damaged]), [[ID_A, true], [ID_B, false]]);
  assert.equal(list[0].name, "", "nothing good to show");
  assert.deepEqual((await rowsOf(d)).map((r) => r.itemId), [ID_B], "the bad row is not cached");
  assert.ok(warnings(d).some((w) => w.code === "row_damaged" && w.id === ID_A));
  await assert.rejects(d.engine.open(ID_A), (e) => e.code === "damaged");
  await assert.rejects(d.engine.update(ID_A, { name: "x" }, currentRev(d.engine, ID_A)), (e) => e.code === "damaged");

  // A good version first, then a bad newer row: the good one stays.
  model.set(ID_B, { rev: 2, ...client.wireRow(ID_B, 2, { item_type: "login", name: "Newer" }), tag: b64u.encode(new Uint8Array(32)) });
  await d.engine.syncNow();
  const b = d.engine.list().find((i) => i.id === ID_B);
  assert.equal(b.name, "Fine");
  assert.equal(b.damaged, true);
  assert.equal(b.rev, 1);
  assert.equal((await rowsOf(d)).find((r) => r.itemId === ID_B).rev, 1);
  assert.equal((await d.engine.open(ID_B)).view.name, "Fine");

  // A later good row clears the mark.
  model.set(ID_B, { rev: 3, ...client.wireRow(ID_B, 3, { item_type: "login", name: "Mended" }) });
  await d.engine.syncNow();
  const mended = d.engine.list().find((i) => i.id === ID_B);
  assert.equal(mended.name, "Mended");
  assert.equal(mended.damaged, false);
  d.engine.stop();
});

test("a_damaged_mark_survives_a_restart", async () => {
  const model = new Model();
  const client = createFakeClient();
  model.set(ID_A, { rev: 1, ...client.wireRow(ID_A, 1, { item_type: "login", name: "First" }) });
  const db = await freshStore();
  const one = await device({ model, client, db });
  await one.engine.start();
  model.set(ID_A, { rev: 2, ...client.wireRow(ID_A, 2, { item_type: "login", name: "Second" }), tag: b64u.encode(new Uint8Array(32)) });
  model.set(ID_B, { rev: 1, ...client.wireRow(ID_B, 1, { item_type: "login", name: "Later" }) });
  await one.engine.syncNow();
  assert.equal(one.engine.list().find((i) => i.id === ID_A).damaged, true);
  one.engine.stop();

  await db.reopen();
  const two = await device({ model, client, db });
  await two.engine.start();
  // The cache cursor is past the bad row, so the row is not read again: the mark has to come from storage.
  assert.equal(two.api.gets[0].includes("since=3"), true);
  const a = two.engine.list().find((i) => i.id === ID_A);
  assert.equal(a.damaged, true);
  assert.equal(a.name, "First");
  two.engine.stop();
});

test("tombstone_without_valid_tag_is_quarantined_and_the_local_copy_is_kept", async () => {
  const model = new Model();
  const client = createFakeClient();
  model.set(ID_A, { rev: 1, ...client.wireRow(ID_A, 1, { item_type: "login", name: "Keep me" }) });
  const d = await device({ model, client });
  await d.engine.start();
  assert.equal(d.engine.list()[0].quarantined, false);

  // The server says deleted, with a tombstone that is not the right one.
  model.set(ID_A, { rev: 2, deleted: true, tomb: b64u.encode(new Uint8Array(40).fill(9)) });
  await d.engine.syncNow();
  const [item] = d.engine.list();
  assert.equal(item.id, ID_A);
  assert.equal(item.quarantined, true);
  assert.equal(item.name, "Keep me");
  assert.equal(item.rev, 1);
  assert.ok(warnings(d).some((w) => w.code === "tombstone_unverified" && w.id === ID_A));
  const rows = await rowsOf(d);
  assert.deepEqual(rows.map((r) => [r.rev, r.deleted]), [[1, false]], "the cache still has the live row");
  assert.equal((await d.engine.open(ID_A)).view.name, "Keep me");
  await assert.rejects(d.engine.update(ID_A, { name: "x" }, currentRev(d.engine, ID_A)), (e) => e.code === "quarantined");
  await assert.rejects(d.engine.remove(ID_A), (e) => e.code === "quarantined");
  d.engine.stop();

  // A wrong tombstone for the right item at another revision is wrong too.
  const model2 = new Model();
  model2.set(ID_B, { rev: 1, ...client.wireRow(ID_B, 1, { item_type: "login", name: "B" }) });
  const e = await device({ model: model2, client });
  await e.engine.start();
  model2.set(ID_B, { rev: 2, deleted: true, tomb: client.wireTomb(ID_B, 5) });
  await e.engine.syncNow();
  assert.equal(e.engine.list()[0].quarantined, true);
  // A valid tombstone later removes the item.
  model2.set(ID_B, { rev: 3, deleted: true, tomb: client.wireTomb(ID_B, 3) });
  await e.engine.syncNow();
  assert.equal(e.engine.list().length, 0);
  e.engine.stop();
});

test("lower_rev_than_local_is_rejected_with_a_warning", async () => {
  const model = new Model();
  const client = createFakeClient();
  model.set(ID_A, { rev: 2, ...client.wireRow(ID_A, 2, { item_type: "login", name: "Two" }) });
  const d = await device({ model, client });
  await d.engine.start();
  assert.equal(d.engine.list()[0].rev, 2);

  model.set(ID_A, { rev: 1, ...client.wireRow(ID_A, 1, { item_type: "login", name: "One" }) });
  await d.engine.syncNow();
  assert.equal(d.engine.list()[0].name, "Two");
  assert.equal(d.engine.list()[0].rev, 2);
  assert.ok(warnings(d).some((w) => w.code === "rev_lower_than_local" && w.rev === 1 && w.localRev === 2));
  assert.equal((await rowsOf(d))[0].rev, 2, "the cache keeps rev 2");

  // The same revision with other bytes is refused too.
  model.set(ID_A, { rev: 2, ...client.wireRow(ID_A, 2, { item_type: "login", name: "Other two" }) });
  await d.engine.syncNow();
  assert.equal(d.engine.list()[0].name, "Two");
  assert.ok(warnings(d).some((w) => w.code === "rev_same_row_changed"));

  // A tombstone below the local revision does not delete either.
  model.set(ID_A, { rev: 1, deleted: true, tomb: client.wireTomb(ID_A, 1) });
  await d.engine.syncNow();
  assert.equal(d.engine.list().length, 1);
  d.engine.stop();
});

test("manifest_row_is_skipped_in_list_but_kept_in_cache", async () => {
  const model = new Model();
  const client = createFakeClient();
  // Not a valid item row: the engine must not try to open it as one.
  model.set(MANIFEST_ID, { rev: 1, blob: b64u.encode(new Uint8Array(64).fill(3)), tag: b64u.encode(new Uint8Array(32).fill(4)) });
  model.set(ID_A, { rev: 1, ...client.wireRow(ID_A, 1, { item_type: "login", name: "Item" }) });
  const d = await device({ model, client });
  await d.engine.start();
  assert.deepEqual(d.engine.list().map((i) => i.id), [ID_A]);
  const rows = await rowsOf(d);
  assert.ok(rows.some((r) => r.itemId === MANIFEST_ID && r.rev === 1), "kept in the cache");
  assert.equal(d.client.vault.calls.some((c) => c[1] === MANIFEST_ID), false, "never opened as an item");
  await assert.rejects(d.engine.open(MANIFEST_ID), (e) => e.code === "not_found");
  await assert.rejects(d.engine.update(MANIFEST_ID, { name: "x" }, currentRev(d.engine, MANIFEST_ID)), (e) => e.code === "not_found");
  d.engine.stop();
});

test("cache_never_receives_plaintext", async () => {
  const model = new Model();
  const d = await device({ model });
  await d.engine.start();
  const id = await d.engine.create(DRAFT);
  await until(() => model.items.has(id));
  await d.engine.update(id, { name: `${MARKER} 2`, notes: "TopSecretNotes" }, currentRev(d.engine, id));
  await until(() => model.items.get(id).rev === 2);
  await d.engine.syncNow();
  await until(async () => (await rowsOf(d)).some((r) => r.rev === 2));
  await d.engine.remove(id);
  await until(() => model.items.get(id).deleted);
  await d.engine.syncNow();

  const leaks = (value) => {
    const needles = [MARKER, "bank.example", "TopSecretNotes", "Renamed"].map((s) => Buffer.from(s));
    const bytes = [];
    const walk = (v) => {
      if (v instanceof Uint8Array) bytes.push(Buffer.from(v));
      else if (typeof v === "string") bytes.push(Buffer.from(v));
      else if (v && typeof v === "object") Object.values(v).forEach(walk);
    };
    walk(value);
    return bytes.some((b) => needles.some((n) => b.includes(n)));
  };
  const { spy } = d.store;
  assert.ok(spy.putRows.length > 0);
  assert.equal(spy.enqueued.length, 3);
  assert.equal(leaks(spy.putRows), false, "rows");
  assert.equal(leaks(spy.enqueued), false, "outbox entries");
  assert.equal(leaks(spy.settings), false, "settings");
  assert.equal(leaks(await rowsOf(d)), false, "stored rows");
  // The same check finds a plaintext view, so a silent check would not pass.
  const open = await (async () => {
    const other = await device({ model: new Model() });
    await other.engine.start();
    const made = await other.engine.create(DRAFT);
    const handle = await other.engine.open(made);
    other.engine.stop();
    return handle.view;
  })();
  assert.equal(leaks(open), true, "control: a decrypted view holds the marker");
  d.engine.stop();
});

test("writes_to_different_items_do_not_block_each_other", async () => {
  const model = new Model();
  const d = await device({ model });
  await d.engine.start();
  const a = await d.engine.create({ item_type: "login", name: "A" });
  await until(async () => model.items.has(a) && (await d.store.outbox.all(d.store.database.store, scope())).length === 0, "A is stored on the server");
  // From now on writes of item A fail three times; B must go through regardless.
  d.api.faults.push(...Array.from({ length: 3 }, () => ({ kind: "network", only: a })));
  await d.engine.update(a, { name: "A2" }, currentRev(d.engine, a));
  await until(() => d.timers.pending >= 1, "A waits for its retry");
  const b = await d.engine.create({ item_type: "login", name: "B" });
  await until(() => model.items.has(b), "B reaches the server while A waits");
  assert.equal(model.items.get(a).rev, 1, "A has not gone through yet");
  assert.equal(d.engine.list().find((i) => i.id === a).pending, true);
  for (const wait of [1_000, 2_000, 4_000]) {
    await until(() => d.timers.waiting.some((t) => t.at - d.timers.time === wait), `a wait of ${wait} ms`);
    d.timers.advance(wait);
  }
  await until(() => model.items.get(a)?.rev === 2, "A gets through after its retries");
  d.engine.stop();
});

test("restart_resumes_from_cached_max_seq_and_outbox", async () => {
  const model = new Model();
  const client = createFakeClient();
  for (const [n, id] of ["11", "22", "33"].entries()) {
    model.set(id.repeat(16), { rev: 1, ...client.wireRow(id.repeat(16), 1, { item_type: "login", name: `Item ${n}` }) });
  }
  const db = await freshStore();
  const one = await device({ model, client, db });
  await one.engine.start();
  assert.equal(one.engine.list().length, 3);
  assert.match(one.api.gets[0], /since=0&/);

  // Offline: the write is queued and stays in the outbox.
  one.api.faults.push(...Array.from({ length: 50 }, () => ({ kind: "network" })));
  const id = await one.engine.create({ item_type: "login", name: "Queued" });
  await settle();
  assert.equal(model.items.has(id), false);
  one.engine.stop();

  await db.reopen();
  const two = await device({ model, client, db, seed: 9 });
  await two.engine.start();
  assert.match(two.api.gets[0], /since=3&/, "resumes after the highest cached seq");
  const queued = two.engine.list().find((i) => i.id === id);
  assert.equal(queued.name, "Queued", "the draft shows after the restart");
  await until(() => model.items.has(id), "the queued write is sent after the restart");
  await until(() => two.engine.list().find((i) => i.id === id).pending === false);
  assert.equal(model.writes.filter((w) => w.id === id).length, 1);
  two.engine.stop();
});

test("stop_drops_the_summary_index_and_closes_handles", async () => {
  const model = new Model();
  const client = createFakeClient();
  model.set(ID_A, { rev: 1, ...client.wireRow(ID_A, 1, { item_type: "login", name: MARKER }) });
  const d = await device({ model, client });
  await d.engine.start();
  assert.equal(d.engine.list().length, 1);
  const open = await d.engine.open(ID_A);
  assert.equal(d.client.vault.handles.size, 1);
  const seen = [];
  d.engine.on("changed", (e) => seen.push(e));

  d.engine.stop();
  await settle();
  assert.equal(d.client.vault.handles.size, 0, "the handle was closed");
  assert.deepEqual(d.engine.list(), []);
  assert.equal(d.timers.pending, 0, "no poll timer is left");
  await assert.rejects(d.engine.open(ID_A), (e) => e.code === "stopped");
  await assert.rejects(d.engine.create(DRAFT), (e) => e.code === "stopped");
  await open.close(); // after stop: no error
  const gets = d.api.gets.length;
  await d.engine.syncNow();
  assert.equal(d.api.gets.length, gets, "no request after stop");
  d.engine.stop(); // twice is fine
});

test("after_stop_no_decrypted_field_is_reachable_from_the_engine", async () => {
  const model = new Model();
  const client = createFakeClient();
  model.set(ID_A, { rev: 1, ...client.wireRow(ID_A, 1, { item_type: "login", name: MARKER, urls: ["https://bank.example"] }) });
  const d = await device({ model, client });
  await d.engine.start();
  assert.ok(JSON.stringify(d.engine.list()).includes(MARKER), "control: the index holds it while running");
  await d.engine.open(ID_A);
  d.engine.stop();
  await settle();

  // Everything a caller can reach: the engine's members and what they return.
  const reachable = [];
  const walk = (value, depth = 0) => {
    if (depth > 6 || value === null) return;
    if (typeof value === "string") reachable.push(value);
    else if (typeof value === "function") return;
    else if (typeof value === "object") {
      for (const key of Reflect.ownKeys(value)) walk(Object.getOwnPropertyDescriptor(value, key).value, depth + 1);
    }
  };
  walk(d.engine);
  walk(d.engine.list());
  assert.ok(Object.values(d.engine).every((member) => typeof member === "function"));
  assert.ok(Object.isFrozen(d.engine));
  assert.equal(reachable.some((s) => s.includes(MARKER) || s.includes("bank.example")), false);
  assert.equal(JSON.stringify(d.engine.list()), "[]");
  // Events carry nothing after stop, and a listener added after stop is ignored.
  const heard = [];
  d.engine.on("changed", (e) => heard.push(e));
  d.api.gets.length = 0;
  await d.engine.syncNow();
  assert.deepEqual(heard, []);
});

test("the_feed_is_read_from_the_last_row_not_from_latest_seq", async () => {
  const model = new Model();
  const client = createFakeClient();
  for (const n of [1, 2, 3, 4, 5]) {
    const id = String(n).repeat(32);
    model.set(id, { rev: 1, ...client.wireRow(id, 1, { item_type: "login", name: `N${n}` }) });
  }
  model.pageSize = 2;
  model.latestSeqLie = 1_000_000;
  const d = await device({ model, client });
  await d.engine.start();
  assert.equal(d.engine.list().length, 5);
  const sinces = d.api.gets.map((p) => /since=(\d+)/.exec(p)[1]);
  assert.deepEqual(sinces, ["0", "2", "4"], "each page starts at the last row of the one before");

  // A row written after the lie is still seen: the cursor is the last row, not latest_seq.
  const late = "6".repeat(32);
  model.set(late, { rev: 1, ...client.wireRow(late, 1, { item_type: "login", name: "Late" }) });
  await d.engine.syncNow();
  assert.equal(d.engine.list().length, 6);
  d.engine.stop();
});

test("a_410_is_answered_with_one_full_listing_from_zero_and_nothing_is_deleted", async () => {
  const model = new Model();
  const client = createFakeClient();
  const ID_C = "33".repeat(16);
  model.set(ID_A, { rev: 1, ...client.wireRow(ID_A, 1, { item_type: "login", name: "Stays" }) });
  model.set(ID_B, { rev: 3, ...client.wireRow(ID_B, 3, { item_type: "login", name: "Hidden, rev 3" }) });
  model.set(ID_C, { rev: 1, ...client.wireRow(ID_C, 1, { item_type: "login", name: "Hidden, rev 1" }) });
  const d = await device({ model, client });
  await d.engine.start();
  assert.equal(d.engine.list().length, 3);

  // The floor moves up, and the listing no longer shows B and C.
  model.items.delete(ID_B);
  model.items.delete(ID_C);
  model.seq += 5;
  model.set(ID_A, { rev: 2, ...client.wireRow(ID_A, 2, { item_type: "login", name: "Stays 2" }) });
  model.minValidSince = model.seq;
  d.api.gets.length = 0;
  d.api.faults.push({ kind: "network", only: ID_B }, { kind: "network", only: ID_C }); // the uploads wait for a retry
  await d.engine.syncNow();
  assert.match(d.api.gets[0], /since=3&/);
  assert.match(d.api.gets[1], /since=0&/, "restarts from 0");
  assert.equal(d.api.gets.filter((p) => p.includes("since=0")).length, 1, "once");
  const byId = Object.fromEntries(d.engine.list().map((i) => [i.id, i]));
  assert.equal(byId[ID_A].name, "Stays 2");
  assert.equal(byId[ID_A].missingOnServer, false);
  assert.deepEqual([byId[ID_B].missingOnServer, byId[ID_B].name, byId[ID_B].rev], [true, "Hidden, rev 3", 3], "kept and marked");
  assert.deepEqual([byId[ID_C].missingOnServer, byId[ID_C].name], [true, "Hidden, rev 1"]);
  assert.deepEqual((await rowsOf(d)).map((r) => r.itemId).sort(), [ID_A, ID_B, ID_C], "the cache keeps every row");
  assert.ok(warnings(d).some((w) => w.code === "missing_on_server" && w.count === 2));
  assert.equal(d.events.error.length, 0);

  // They are uploaded again (a new write against nothing); the copy that comes back is recognised as ours.
  await until(() => d.timers.pending >= 2, "both uploads wait for a retry");
  d.timers.advance(1_000);
  await until(() => model.items.has(ID_B) && model.items.has(ID_C), "both are uploaded again");
  assert.deepEqual(model.writes.filter((w) => w.id === ID_B).map((w) => JSON.parse(w.body).base_rev), [0]);
  await until(() => d.engine.list().every((i) => !i.missingOnServer), "the marks clear when the copies come back");
  const after = Object.fromEntries(d.engine.list().map((i) => [i.id, i]));
  assert.deepEqual([after[ID_B].rev, after[ID_B].name], [1, "Hidden, rev 3"], "the uploaded copy has the local content at revision 1");
  assert.equal(after[ID_C].rev, 1);
  d.engine.stop();
});

test("an_older_row_after_a_listing_still_triggers_rev_lower_than_local", async () => {
  const model = new Model();
  const client = createFakeClient();
  model.set(ID_A, { rev: 5, ...client.wireRow(ID_A, 5, { item_type: "login", name: "Five" }) });
  model.set(ID_B, { rev: 1, ...client.wireRow(ID_B, 1, { item_type: "login", name: "Other" }) });
  const d = await device({ model, client });
  await d.engine.start();
  // The upload of A is refused, so it stays marked; the listing hides it.
  d.api.faults.push({ kind: "status", status: 413, code: "quota_exceeded", only: ID_A });
  model.items.delete(ID_A);
  model.seq += 3;
  model.minValidSince = model.seq;
  model.set(ID_B, { rev: 2, ...client.wireRow(ID_B, 2, { item_type: "login", name: "Other 2" }) });
  await d.engine.syncNow();
  await until(() => d.engine.list().find((i) => i.id === ID_A)?.blocked === true, "the upload is refused");
  assert.equal(d.engine.list().find((i) => i.id === ID_A).missingOnServer, true);

  // Later the server shows an old, valid row of A. The floor from before the listing is still there.
  model.set(ID_A, { rev: 2, ...client.wireRow(ID_A, 2, { item_type: "login", name: "Old two" }) });
  await d.engine.syncNow();
  assert.ok(warnings(d).some((w) => w.code === "rev_lower_than_local" && w.id === ID_A && w.rev === 2 && w.localRev === 5));
  const a = d.engine.list().find((i) => i.id === ID_A);
  assert.deepEqual([a.name, a.rev], ["Five", 5]);
  d.engine.stop();
});

test("discardMissing_removes_the_item_with_its_row_and_its_upload", async () => {
  const model = new Model();
  const client = createFakeClient();
  model.set(ID_A, { rev: 4, ...client.wireRow(ID_A, 4, { item_type: "login", name: "Gone from the server" }) });
  model.set(ID_B, { rev: 1, ...client.wireRow(ID_B, 1, { item_type: "login", name: "Normal" }) });
  const d = await device({ model, client });
  await d.engine.start();
  d.api.faults.push({ kind: "status", status: 413, code: "quota_exceeded", only: ID_A });
  model.items.delete(ID_A);
  model.seq += 3;
  model.minValidSince = model.seq;
  await d.engine.syncNow();
  await until(() => d.engine.list().find((i) => i.id === ID_A)?.blocked === true);
  await assert.rejects(d.engine.update(ID_A, { name: "x" }, currentRev(d.engine, ID_A)), (e) => e.code === "blocked");
  await assert.rejects(d.engine.discardMissing(ID_B), (e) => e.code === "not_found");

  await d.engine.discardMissing(ID_A);
  assert.deepEqual(d.engine.list().map((i) => i.id), [ID_B]);
  assert.deepEqual((await rowsOf(d)).map((r) => r.itemId), [ID_B]);
  assert.equal((await d.store.outbox.all(d.store.database.store, scope())).length, 0);
  d.engine.stop();
});

test("a_malformed_row_marks_the_item_damaged_and_the_pass_goes_on", async () => {
  const model = new Model();
  const client = createFakeClient();
  model.set(ID_A, { rev: 1, blob: null, tag: null, deleted: false }); // a live row with nothing in it
  model.set(ID_B, { rev: 1, ...client.wireRow(ID_B, 1, { item_type: "login", name: "Fine" }) });
  const d = await device({ model, client });
  await d.engine.start();
  assert.deepEqual(d.engine.list().map((i) => [i.id, i.damaged]), [[ID_A, true], [ID_B, false]]);
  assert.equal(d.events.error.length, 0);
  assert.ok(d.events.state.some((s) => s.kind === "idle"));
  d.engine.stop();
});

test("a_2xx_answer_that_is_not_a_changes_page_is_a_failure_not_offline", async () => {
  const d = await device({ model: new Model() });
  d.api.failFeed = new ApiError(200, "bad_response");
  d.api.failFeedTimes = 1;
  await d.engine.start();
  assert.ok(d.events.state.some((s) => s.kind === "failed" && s.code === "bad_response"));
  assert.ok(!d.events.state.some((s) => s.kind === "offline"));
  d.engine.stop();
});

test("a_changed_restore_epoch_and_an_unexpected_revision_are_warnings", async () => {
  const model = new Model();
  const d = await device({ model });
  await d.engine.start();
  model.restoreEpoch = 1;
  await d.engine.syncNow();
  assert.ok(warnings(d).some((w) => w.code === "server_restored" && w.from === 0 && w.to === 1));

  const real = d.api.put;
  d.api.put = async (path, body) => ({ ...(await real(path, body)), rev: 9 });
  const id = await d.engine.create(DRAFT);
  await until(() => warnings(d).some((w) => w.code === "unexpected_rev" && w.id === id && w.rev === 9 && w.expected === 1));
  d.engine.stop();
});

test("idle_is_reported_on_every_pass_with_the_time", async () => {
  const d = await device({ model: new Model() });
  await d.engine.start();
  d.timers.advance(5_000);
  await until(() => d.events.state.filter((s) => s.kind === "idle").length === 2);
  const [first, second] = d.events.state.filter((s) => s.kind === "idle");
  assert.ok(second.at >= first.at + 5_000);
  d.engine.stop();
});

test("a_410_on_a_later_page_restarts_once_and_then_surfaces_an_error", async () => {
  const model = new Model();
  const client = createFakeClient();
  for (const n of [1, 2, 3]) {
    const id = String(n).repeat(32);
    model.set(id, { rev: 1, ...client.wireRow(id, 1, { item_type: "login", name: `N${n}` }) });
  }
  model.pageSize = 2;
  const d = await device({ model, client });
  // The floor rises while page 2 of the first listing is being read; the second answer is a 410 as well.
  const real = d.api.get;
  let calls = 0;
  d.api.get = async (path) => {
    calls += 1;
    if (calls === 2 || calls === 4) throw new ApiError(410, "gone", null, { error: "gone", min_valid_since: 9 });
    return real(path);
  };
  await d.engine.start();
  assert.equal(calls, 4, "page 1, 410, restart from 0, 410 again: no third try in the same pass");
  assert.deepEqual(d.events.error, [{ code: "gone" }]);
  assert.ok(d.events.state.some((s) => s.kind === "failed" && s.code === "gone"));
  // The next pass can recover.
  calls = 100;
  await d.engine.syncNow();
  assert.equal(d.engine.list().length, 3);
  d.engine.stop();
});

test("a_feed_that_cannot_be_right_changes_nothing", async () => {
  const model = new Model();
  const client = createFakeClient();
  model.set(ID_A, { rev: 1, ...client.wireRow(ID_A, 1, { item_type: "login", name: "A" }) });
  const d = await device({ model, client });
  model.vkEpoch = 2;
  await d.engine.start();
  assert.equal(d.engine.list().length, 0);
  assert.deepEqual(d.events.error, [{ code: "epoch_mismatch" }]);
  assert.equal((await rowsOf(d)).length, 0);
  d.engine.stop();

  const bad = new Model();
  bad.set(ID_A, { rev: 1, ...client.wireRow(ID_A, 1, { item_type: "login", name: "A" }) });
  const e = await device({ model: bad, client });
  const real = e.api.get;
  e.api.get = async (path) => ({ ...(await real(path)), has_more: true, changes: [] });
  await e.engine.start();
  assert.deepEqual(e.events.error, [{ code: "bad_feed" }]);
  e.engine.stop();
});

test("a_server_behind_the_device_is_a_warning_once_and_nothing_is_lowered", async () => {
  const model = new Model();
  const client = createFakeClient();
  model.set(ID_A, { rev: 1, ...client.wireRow(ID_A, 1, { item_type: "login", name: "A" }) });
  model.set(ID_B, { rev: 1, ...client.wireRow(ID_B, 1, { item_type: "login", name: "B" }) });
  const d = await device({ model, client });
  await d.engine.start();
  model.items.delete(ID_B);
  model.seq = 1; // a restore: the server counts from an older point
  model.latestSeqLie = 1;
  await d.engine.syncNow();
  await d.engine.syncNow();
  assert.equal(warnings(d).filter((w) => w.code === "server_behind").length, 1);
  assert.equal(d.engine.list().length, 2, "the device keeps what it has");
  d.engine.stop();
});

test("a_409_on_a_deleted_item_is_checked_through_the_feed", async () => {
  const model = new Model();
  const client = createFakeClient();
  model.set(ID_A, { rev: 1, ...client.wireRow(ID_A, 1, { item_type: "login", name: "A" }) });
  const d = await device({ model, client });
  await d.engine.start();
  // Another device deletes it (a good tombstone) before this one writes.
  model.set(ID_A, { rev: 2, deleted: true, tomb: client.wireTomb(ID_A, 2) });
  await d.engine.update(ID_A, { name: "Late edit" }, currentRev(d.engine, ID_A));
  await until(() => d.events.error.some((e) => e.code === "conflict"), "the conflict");
  const conflict = d.events.error.find((e) => e.code === "conflict");
  assert.deepEqual([conflict.id, conflict.currentRev, conflict.deleted], [ID_A, 2, true]);
  await until(() => d.engine.list().length === 0, "the deletion arrives through /changes and is verified");
  assert.ok(d.client.vault.calls.some((c) => c[0] === "verify_tombstone" && c[2] === 2));
  d.engine.stop();

  // The same with a tombstone that does not verify: the item is quarantined, not removed.
  const model2 = new Model();
  model2.set(ID_B, { rev: 1, ...client.wireRow(ID_B, 1, { item_type: "login", name: "B" }) });
  const e = await device({ model: model2, client });
  await e.engine.start();
  model2.set(ID_B, { rev: 2, deleted: true, tomb: b64u.encode(new Uint8Array(40).fill(1)) });
  await e.engine.update(ID_B, { name: "Late edit" }, currentRev(e.engine, ID_B));
  await until(() => e.events.error.some((x) => x.code === "conflict"));
  await until(() => e.engine.list()[0]?.quarantined === true, "quarantined");
  e.engine.stop();
});

test("the_engine_is_not_given_a_wrong_id_or_a_second_start", async () => {
  const d = await device({ model: new Model() });
  await d.engine.start();
  await assert.rejects(d.engine.start(), (e) => e.code === "invalid_state");
  await assert.rejects(d.engine.update("nothex", { name: "x" }, currentRev(d.engine, "nothex")), (e) => e.code === "not_found");
  await assert.rejects(d.engine.remove(ID_A), (e) => e.code === "not_found");
  assert.throws(() => d.engine.on("nothing", () => {}), TypeError);
  const off = d.engine.on("changed", () => assert.fail("removed listeners are not called"));
  off();
  await d.engine.create(DRAFT);
  assert.equal(hex16.is(d.engine.list()[0].id), true);
  d.engine.stop();
});

/** Two items, B at revision 3; the server then hides B and moves its floor up, and one pass lists the vault again. */
async function hideItemB({ uploadWaits = false, db = null, model = new Model(), client = createFakeClient(), floor = 3 } = {}) {
  const rowB = client.wireRow(ID_B, floor, { item_type: "login", name: "Hidden B" });
  model.set(ID_A, { rev: 1, ...client.wireRow(ID_A, 1, { item_type: "login", name: "A" }) });
  model.set(ID_B, { rev: floor, ...rowB });
  const d = await device({ model, client, db });
  await d.engine.start();
  if (uploadWaits) d.api.faults.push({ kind: "network", only: ID_B }, { kind: "network", only: ID_B });
  model.items.delete(ID_B);
  model.seq += 4;
  model.minValidSince = model.seq;
  model.set(ID_A, { rev: 2, ...client.wireRow(ID_A, 2, { item_type: "login", name: "A2" }) });
  await d.engine.syncNow();
  return { ...d, rowB, client };
}

const itemB = (d) => d.engine.list().find((i) => i.id === ID_B);

test("a_reuploaded_item_keeps_its_old_floor_and_an_old_genuine_row_is_refused", async () => {
  const d = await hideItemB();
  await until(() => model_has(d, ID_B) && itemB(d)?.missingOnServer === false, "the copy is back");
  assert.equal(itemB(d).rev, 1);
  assert.equal(itemB(d).name, "Hidden B");
  // The server now serves the genuine old revision 2 of B: valid for the id, above the new revision 1, below the old floor 3.
  d.model.set(ID_B, { rev: 2, ...d.client.wireRow(ID_B, 2, { item_type: "login", name: "Old two" }) });
  await d.engine.syncNow();
  assert.ok(warnings(d).some((w) => w.code === "rev_lower_than_local" && w.id === ID_B && w.rev === 2 && w.localRev === 3));
  assert.equal(itemB(d).name, "Hidden B", "the content stays");
  assert.equal(itemB(d).rev, 1);
  d.engine.stop();
});

const model_has = (d, id) => d.model.items.has(id);

test("a_reuploaded_item_accepts_its_own_writes_below_the_floor_and_drops_the_mark_above_it", async () => {
  const d = await hideItemB();
  await until(() => itemB(d)?.missingOnServer === false && d.model.items.has(ID_B), "the copy is back");
  const key = `sync.flags.${scope().accountId}.${scope().vaultId}.${scope().vkEpoch}`;
  const marks = async () => (await d.store.getSetting(d.store.database.store, key))?.marks ?? {};
  await until(async () => (await marks())[ID_B]?.kind === "reuploaded", "the mark is saved as reuploaded");
  assert.equal((await marks())[ID_B].rev, 3, "the old floor is saved");
  for (const rev of [2, 3, 4]) {
    await d.engine.update(ID_B, { name: `Mine ${rev}` }, currentRev(d.engine, ID_B));
    await until(() => d.model.items.get(ID_B).rev === rev && itemB(d).rev === rev && !itemB(d).pending, `rev ${rev}`);
    assert.equal(itemB(d).name, `Mine ${rev}`);
  }
  assert.equal(warnings(d).filter((w) => w.code === "rev_lower_than_local").length, 0, "its own writes are never refused");
  await until(async () => !(ID_B in (await marks())), "above the floor the mark is gone");
  d.engine.stop();
});

test("the_same_row_shown_again_clears_missing_and_no_upload_is_sent", async () => {
  const d = await hideItemB({ uploadWaits: true });
  await until(() => itemB(d)?.missingOnServer === true && d.timers.pending >= 1, "marked, the upload waits");
  assert.equal((await d.store.outbox.all(d.store.database.store, scope())).length, 1);
  const sent = d.api.puts.length;
  // The server shows B again with the very row this device has.
  d.model.set(ID_B, { rev: 3, ...d.rowB });
  await d.engine.syncNow();
  assert.equal(itemB(d).missingOnServer, false);
  assert.equal(itemB(d).blocked, false);
  assert.equal((await d.store.outbox.all(d.store.database.store, scope())).length, 0, "the unsent upload is dropped");
  d.timers.advance(120_000);
  await settle(20);
  assert.equal(d.api.puts.length, sent, "nothing more is sent");
  assert.equal(d.model.writes.filter((w) => w.id === ID_B).length, 0);
  d.engine.stop();
});

test("rows_at_or_below_the_floor_never_overwrite_other_marks", async () => {
  const d = await hideItemB({ uploadWaits: true });
  await until(() => itemB(d)?.missingOnServer === true);
  // A malformed row, a valid row with a bad tag and a good old row, all at or below the floor of 3.
  d.model.set(ID_B, { rev: 2, blob: null, tag: null, deleted: false });
  await d.engine.syncNow();
  d.model.set(ID_B, { rev: 3, ...d.client.wireRow(ID_B, 3, { item_type: "login", name: "Other three" }) });
  await d.engine.syncNow();
  d.model.set(ID_B, { rev: 1, ...d.client.wireRow(ID_B, 1, { item_type: "login", name: "Old one" }) });
  await d.engine.syncNow();
  const b = itemB(d);
  assert.deepEqual([b.missingOnServer, b.damaged, b.name, b.rev], [true, false, "Hidden B", 3]);
  assert.ok(warnings(d).some((w) => w.code === "rev_lower_than_local" && w.rev === 2));
  assert.ok(warnings(d).some((w) => w.code === "rev_same_row_changed" && w.rev === 3));
  await d.engine.discardMissing(ID_B); // the mark still allows the user's discard
  assert.equal(itemB(d), undefined);
  d.engine.stop();
});

test("a_lock_during_a_mark_save_never_wipes_the_saved_marks", async () => {
  const model = new Model();
  const client = createFakeClient();
  model.set(ID_A, { rev: 1, ...client.wireRow(ID_A, 1, { item_type: "login", name: "Quarantined later" }) });
  const db = await freshStore();
  const d = await device({ model, client, db });
  await d.engine.start();
  model.set(ID_A, { rev: 2, deleted: true, tomb: b64u.encode(new Uint8Array(40).fill(1)) });
  await d.engine.syncNow();
  assert.equal(d.engine.list()[0].quarantined, true);
  const key = `sync.flags.${scope().accountId}.${scope().vaultId}.${scope().vkEpoch}`;
  assert.ok((await d.store.getSetting(db.store, key)).marks[ID_A], "the quarantine is saved");

  // Another item is refused by the server.
  const id = await d.engine.create({ item_type: "login", name: "C" });
  await until(() => model.items.get(id)?.rev === 1 && d.engine.list().find((i) => i.id === id)?.pending === false);
  model.set(id, { rev: 2, ...client.wireRow(id, 2, { item_type: "login", name: "From elsewhere" }) });
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const itemView = client.vault.item_view;
  let slow = false;
  client.vault.item_view = async (handle) => {
    if (slow) await gate;
    return itemView(handle);
  };
  await d.engine.update(id, { name: "Late edit" }, currentRev(d.engine, id));
  await until(() => d.engine.list().find((i) => i.id === id)?.blocked === true, "the refusal");
  // The user discards the refused draft; the worker is slow to describe the item, and the lock lands in that wait.
  slow = true;
  const discarding = d.engine.discard(id).catch(() => {});
  await until(() => d.engine.list().find((i) => i.id === id)?.blocked === false, "the block is lifted in memory");
  d.engine.stop();
  release();
  await discarding;
  await settle(40);
  const saved = await d.store.getSetting(db.store, key);
  assert.ok(saved, "the saved marks are still there");
  assert.ok(saved.marks[ID_A], "the quarantine is not wiped");

  await db.reopen();
  const back = await device({ model, client, db, seed: 9 });
  await back.engine.start();
  assert.equal(back.engine.list().find((i) => i.id === ID_A).quarantined, true);
  back.engine.stop();
});

test("a_failed_pass_at_start_does_not_upload_an_item_again", async () => {
  const model = new Model();
  const client = createFakeClient();
  const db = await freshStore();
  const one = await hideItemB({ uploadWaits: true, db, model, client });
  await until(() => itemB(one)?.missingOnServer === true);
  one.engine.stop();
  // The upload went through before the restart, as far as this device knows: its entry is gone, the mark and its digest stay.
  const entries = await one.store.outbox.all(db.store, scope());
  assert.equal(entries.length, 1);
  await one.store.outbox.remove(db.store, scope(), entries[0].idem);

  await db.reopen();
  const two = await device({ model, client, db, seed: 4 });
  two.api.failFeed = new ApiError(0, "network");
  two.api.failFeedTimes = 1;
  await two.engine.start();
  await settle(30);
  assert.equal(two.api.puts.length, 0, "no upload after a pass that failed");
  assert.equal(itemB(two).missingOnServer, true);
  // The next pass reads the whole feed, and B is still not in it: now it is uploaded, once.
  await two.engine.syncNow();
  await until(() => model.items.has(ID_B), "uploaded after a good pass");
  assert.equal(model.writes.filter((w) => w.id === ID_B).length, 1);
  two.engine.stop();
});

test("discardMissing_while_the_upload_is_under_way_wins", async () => {
  const model = new Model();
  const client = createFakeClient();
  const rowB = client.wireRow(ID_B, 3, { item_type: "login", name: "Hidden B" });
  model.set(ID_B, { rev: 3, ...rowB });
  const d = await device({ model, client });
  await d.engine.start();
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const put = d.api.put;
  let started = 0;
  d.api.put = async (path, body) => {
    started += 1;
    await gate;
    return put(path, body);
  };
  model.items.delete(ID_B);
  model.seq += 4;
  model.minValidSince = model.seq;
  await d.engine.syncNow();
  await until(() => started === 1, "the upload is under way");
  const discarded = d.engine.discardMissing(ID_B);
  release();
  await discarded;
  await settle(40);
  await d.engine.syncNow();
  assert.equal(itemB(d), undefined, "the item does not come back");
  assert.deepEqual(d.events.error, []);
  assert.deepEqual((await rowsOf(d)).filter((r) => r.itemId === ID_B), []);
  d.engine.stop();
});

const copyIsBack = (d) => until(() => itemB(d)?.missingOnServer === false && d.model.items.has(ID_B), "the copy is back");
const marksOf = async (d) => {
  const key = `sync.flags.${scope().accountId}.${scope().vaultId}.${scope().vkEpoch}`;
  return (await d.store.getSetting(d.store.database.store, key))?.marks ?? {};
};
const editB = async (d, name, rev) => {
  await d.engine.update(ID_B, { name }, currentRev(d.engine, ID_B));
  await until(() => d.model.items.get(ID_B).rev === rev && itemB(d)?.rev === rev && !itemB(d).pending, `rev ${rev}`);
  await until(async () => (await rowsOf(d)).find((r) => r.itemId === ID_B)?.rev === rev, `rev ${rev} cached`);
};

test("a_replay_of_an_own_earlier_version_does_not_roll_the_item_back_or_bring_it_back", async () => {
  const d = await hideItemB({ floor: 5 });
  await copyIsBack(d);
  await editB(d, "Mine 2", 2);
  const rev2 = { ...d.model.items.get(ID_B) };
  await editB(d, "Mine 3", 3);
  const rev3 = { ...d.model.items.get(ID_B) };

  // The server serves the bytes of the device's own rev 2 again.
  d.model.set(ID_B, { rev: 2, blob: rev2.blob, tag: rev2.tag });
  await d.engine.syncNow();
  assert.ok(warnings(d).some((w) => w.code === "rev_lower_than_local" && w.id === ID_B && w.rev === 2 && w.localRev === 3));
  assert.deepEqual([itemB(d).name, itemB(d).rev], ["Mine 3", 3]);
  d.model.set(ID_B, { rev: 3, blob: rev3.blob, tag: rev3.tag }); // an honest server again
  await d.engine.syncNow();

  // The user deletes the item (an own tombstone below the old floor); a replay of an own live version must not revive it.
  await d.engine.remove(ID_B);
  await until(() => d.model.items.get(ID_B).deleted && itemB(d) === undefined, "deleted");
  await until(async () => (await rowsOf(d)).find((r) => r.itemId === ID_B)?.rev === 4, "the tombstone is cached");
  d.model.set(ID_B, { rev: 2, blob: rev2.blob, tag: rev2.tag });
  await d.engine.syncNow();
  assert.equal(itemB(d), undefined, "still deleted");
  assert.ok(warnings(d).some((w) => w.code === "rev_lower_than_local" && w.localRev === 4));
  d.engine.stop();
});

test("a_foreign_row_at_exactly_the_old_floor_is_refused_after_the_device_has_edited_the_copy", async () => {
  const d = await hideItemB({ floor: 3 });
  await copyIsBack(d);
  await editB(d, "Mine 2", 2);
  d.model.set(ID_B, { rev: 3, ...d.client.wireRow(ID_B, 3, { item_type: "login", name: "Old three" }) });
  await d.engine.syncNow();
  assert.ok(warnings(d).some((w) => w.code === "rev_same_row_changed" && w.id === ID_B && w.rev === 3));
  assert.deepEqual([itemB(d).name, itemB(d).rev], ["Mine 2", 2]);
  d.engine.stop();
});

test("a_forged_tombstone_above_the_floor_does_not_drop_the_floor", async () => {
  const d = await hideItemB({ floor: 3 });
  await copyIsBack(d);
  await until(async () => (await marksOf(d))[ID_B]?.kind === "reuploaded", "the mark is saved");
  d.model.set(ID_B, { rev: 4, deleted: true, tomb: b64u.encode(new Uint8Array(40).fill(7)) });
  await d.engine.syncNow();
  assert.ok(warnings(d).some((w) => w.code === "tombstone_unverified" && w.id === ID_B));
  assert.equal(itemB(d).quarantined, false, "the floor mark is not replaced");
  // The genuine old row at revision 2 is still below the floor.
  d.model.set(ID_B, { rev: 2, ...d.client.wireRow(ID_B, 2, { item_type: "login", name: "Old two" }) });
  await d.engine.syncNow();
  assert.ok(warnings(d).some((w) => w.code === "rev_lower_than_local" && w.rev === 2 && w.localRev === 3));
  assert.equal(itemB(d).name, "Hidden B");
  assert.equal((await marksOf(d))[ID_B].rev, 3, "the floor is still saved");
  d.engine.stop();
});

test("a_failed_save_of_the_digest_list_stops_the_write", async () => {
  const d = await hideItemB({ floor: 5 });
  await copyIsBack(d);
  await until(async () => (await marksOf(d))[ID_B]?.kind === "reuploaded", "the mark is saved");
  const sent = d.api.puts.length;
  d.store.failSet = 1;
  await assert.rejects(d.engine.update(ID_B, { name: "Not queued" }, currentRev(d.engine, ID_B)), /disk is full/);
  assert.equal((await d.store.outbox.all(d.store.database.store, scope())).length, 0);
  assert.equal(d.api.puts.length, sent, "nothing was sent");
  assert.equal(itemB(d).name, "Hidden B");
  await editB(d, "Queued now", 2); // the next try works, and its row is recognised
  assert.equal(warnings(d).filter((w) => w.code === "rev_lower_than_local").length, 0);
  d.engine.stop();
});

test("the_answer_to_a_dropped_upload_is_ignored", async () => {
  const model = new Model();
  const client = createFakeClient();
  const rowB = client.wireRow(ID_B, 3, { item_type: "login", name: "Hidden B" });
  model.set(ID_B, { rev: 3, ...rowB });
  const d = await device({ model, client });
  await d.engine.start();
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const put = d.api.put;
  let started = 0;
  d.api.put = async (path, body) => {
    started += 1;
    await gate;
    return put(path, body);
  };
  model.items.delete(ID_B);
  model.seq += 4;
  model.minValidSince = model.seq;
  await d.engine.syncNow();
  await until(() => started === 1, "the upload is under way");
  // The server shows the item again with the same row: the upload nobody asked for is dropped ...
  model.set(ID_B, { rev: 3, ...rowB });
  await d.engine.syncNow();
  assert.equal(itemB(d).missingOnServer, false);
  // ... and when its (conflicting) answer arrives, nothing happens.
  release();
  await settle(40);
  assert.deepEqual(d.events.error, []);
  assert.equal(itemB(d).blocked, false);
  d.engine.stop();
});

test("a_mark_that_was_not_saved_after_the_copy_was_cached_is_finished_at_the_next_start_without_a_second_upload", async () => {
  const db = await freshStore();
  const d = await hideItemB({ floor: 3, db });
  await copyIsBack(d);
  await until(async () => (await marksOf(d))[ID_B]?.kind === "reuploaded");
  d.engine.stop();
  // A crash between caching the row and saving the mark: the mark is still "missing" in storage.
  const key = `sync.flags.${scope().accountId}.${scope().vaultId}.${scope().vkEpoch}`;
  const saved = await d.store.getSetting(db.store, key);
  saved.marks[ID_B].kind = "missing_on_server";
  await d.store.setSetting(db.store, key, saved);

  await db.reopen();
  const back = await device({ model: d.model, client: d.client, db, seed: 8 });
  await back.engine.start();
  await settle(30);
  assert.equal(back.api.puts.length, 0, "no second upload");
  await until(async () => (await marksOf(back))[ID_B]?.kind === "reuploaded", "the mark is finished");
  assert.equal(itemB(back).blocked, false);
  back.engine.stop();
});

const settingsKey = () => `sync.flags.${scope().accountId}.${scope().vaultId}.${scope().vkEpoch}`;

test("a_saved_mark_behind_the_cache_does_not_let_an_own_replay_roll_the_item_back", async () => {
  const db = await freshStore();
  const d = await hideItemB({ floor: 3, db });
  await copyIsBack(d);
  await editB(d, "Mine 2", 2);
  const rev2 = { ...d.model.items.get(ID_B) };
  await until(async () => ((await marksOf(d))[ID_B]?.sent ?? []).length >= 2, "the keys of rev 1 and rev 2 are saved");
  const older = (await marksOf(d))[ID_B];
  await editB(d, "Mine 3", 3);
  await until(async () => !(ID_B in (await marksOf(d))), "the mark ended");
  d.engine.stop();
  // A lock or a crash left the older mark in storage while the cache holds rev 3 (the old floor itself).
  const saved = (await d.store.getSetting(db.store, settingsKey())) ?? { v: 1, marks: {}, blocked: {} };
  saved.marks[ID_B] = older;
  await d.store.setSetting(db.store, settingsKey(), saved);

  await db.reopen();
  const back = await device({ model: d.model, client: d.client, db, seed: 8 });
  await back.engine.start();
  d.model.set(ID_B, { rev: 2, blob: rev2.blob, tag: rev2.tag });
  await back.engine.syncNow();
  assert.ok(warnings(back).some((w) => w.code === "rev_lower_than_local" && w.rev === 2 && w.localRev === 3));
  assert.deepEqual([itemB(back).name, itemB(back).rev], ["Mine 3", 3]);
  back.engine.stop();
});

test("a_mark_ends_only_after_the_row_that_ends_it_is_in_the_cache", async () => {
  const d = await hideItemB({ floor: 3 });
  await copyIsBack(d);
  await editB(d, "Mine 2", 2);
  d.store.failPutRows = 1;
  await d.engine.update(ID_B, { name: "Mine 3" }, currentRev(d.engine, ID_B)); // its row reaches the old floor and would end the mark
  await until(() => d.events.state.some((s) => s.kind === "failed"), "the cache write fails");
  // Another flag save follows (an unrelated item is refused); it must still carry the mark of B.
  d.api.faults.push({ kind: "status", status: 413, code: "too_large" });
  const other = await d.engine.create({ item_type: "login", name: "Other" });
  await until(() => d.engine.list().find((i) => i.id === other)?.blocked === true, "the other item is blocked");
  await until(async () => ((await d.store.getSetting(d.store.database.store, settingsKey()))?.blocked ?? {})[other] === "too_large");
  assert.equal((await marksOf(d))[ID_B]?.kind, "reuploaded", "the saved mark is still there");
  await d.engine.syncNow(); // the cache works again: the same row is processed again and ends the mark
  await until(async () => !(ID_B in (await marksOf(d))), "the mark ends once the row is cached");
  assert.equal((await rowsOf(d)).find((r) => r.itemId === ID_B).rev, 3);
  assert.equal(itemB(d).name, "Mine 3");
  d.engine.stop();
});

test("an_own_delete_below_the_floor_shows_nothing_after_a_restart", async () => {
  const db = await freshStore();
  const d = await hideItemB({ floor: 5, db });
  await copyIsBack(d);
  await editB(d, "Mine 2", 2);
  await d.engine.remove(ID_B);
  await until(async () => (await rowsOf(d)).find((r) => r.itemId === ID_B)?.deleted === true && itemB(d) === undefined, "deleted and cached");
  await until(async () => (await marksOf(d))[ID_B]?.kind === "reuploaded");
  d.engine.stop();

  await db.reopen();
  const back = await device({ model: d.model, client: d.client, db, seed: 8 });
  await back.engine.start();
  assert.equal(itemB(back), undefined, "no blank item");
  await assert.rejects(back.engine.open(ID_B), (e) => e.code === "not_found");
  assert.equal((await marksOf(back))[ID_B]?.kind, "reuploaded", "the floor mark is kept");
  back.engine.stop();
});

test("the_heal_also_finishes_an_item_that_was_never_edited", async () => {
  const db = await freshStore();
  const d = await hideItemB({ floor: 1, db });
  await copyIsBack(d);
  await until(async () => !(ID_B in (await marksOf(d))) && (await rowsOf(d)).find((r) => r.itemId === ID_B)?.rev === 1, "the copy is cached and the mark ended");
  const row = (await rowsOf(d)).find((r) => r.itemId === ID_B);
  d.engine.stop();
  // A crash between caching the copy and saving the mark: the mark is still "missing" in storage.
  const digest = createHash("sha256").update(Buffer.concat([Buffer.from([1]), row.envelope, row.tag])).digest("base64url");
  const saved = (await d.store.getSetting(db.store, settingsKey())) ?? { v: 1, marks: {}, blocked: {} };
  saved.marks[ID_B] = { kind: "missing_on_server", rev: 1, sent: [`1:r:${digest}`] };
  await d.store.setSetting(db.store, settingsKey(), saved);

  await db.reopen();
  const back = await device({ model: d.model, client: d.client, db, seed: 8 });
  await back.engine.start();
  await settle(30);
  assert.equal(back.api.puts.length, 0, "no second upload");
  assert.deepEqual([itemB(back).missingOnServer, itemB(back).blocked], [false, false]);
  await until(async () => !(ID_B in (await marksOf(back))), "the mark is gone");
  back.engine.stop();
});

test("a_write_waits_for_the_save_of_its_digest_that_another_save_has_taken_over", async () => {
  const d = await hideItemB({ floor: 5 });
  await copyIsBack(d);
  await until(async () => (await marksOf(d))[ID_B]?.kind === "reuploaded", "the mark is saved");
  let releaseOpen;
  let releaseSet;
  d.store.holdOpen = new Promise((resolve) => { releaseOpen = resolve; });
  const update = d.engine.update(ID_B, { name: "Mine 2" }, currentRev(d.engine, ID_B)); // stops in `queue`, after it has noted its digest
  await settle(10);
  d.store.holdSet = new Promise((resolve) => { releaseSet = resolve; });
  const pass = d.engine.syncNow(); // its save takes the changed marks and is slow
  await settle(10);
  const sent = d.api.puts.length;
  releaseOpen();
  await settle(30);
  assert.equal(d.api.puts.length, sent, "the write is not sent before its digest is stored");
  releaseSet();
  await update;
  await pass;
  await until(() => d.model.items.get(ID_B).rev === 2, "the write is sent");
  await until(async () => ((await marksOf(d))[ID_B]?.sent ?? []).some((k) => k.startsWith("2:r:")), "the digest of rev 2 is stored");
  assert.equal(warnings(d).filter((w) => w.code === "rev_lower_than_local").length, 0);
  d.engine.stop();
});

test("an_edit_made_from_an_older_revision_is_refused_and_nothing_is_written", async () => {
  const d = await device({ model: new Model() });
  await d.engine.start();
  const id = await d.engine.create(DRAFT);
  await until(() => d.model.items.get(id)?.rev === 1, "the server has rev 1");
  await d.engine.update(id, { name: "Second" }, currentRev(d.engine, id));
  await until(() => d.model.items.get(id)?.rev === 2, "the server has rev 2");
  await assert.rejects(() => d.engine.update(id, { name: "From a stale form" }, 1), { code: "item_changed" });
  await settle();
  assert.equal(d.model.items.get(id).rev, 2, "no write went out");
  assert.equal(d.engine.list()[0].name, "Second");
  await d.engine.update(id, { name: "Third" }, 2);
  await until(() => d.model.items.get(id)?.rev === 3, "the matching revision is accepted");
  d.engine.stop();
});

test("an_edit_without_the_revision_it_was_made_from_is_refused_and_writes_nothing", async () => {
  const d = await device({ model: new Model() });
  await d.engine.start();
  const id = await d.engine.create(DRAFT);
  await until(() => d.model.items.get(id)?.rev === 1, "the server has rev 1");
  for (const rev of [undefined, null, "1", 1.5, Number.NaN]) {
    await assert.rejects(() => d.engine.update(id, { name: "No base" }, rev), TypeError, String(rev));
  }
  await assert.rejects(() => d.engine.update(id, { name: "No base" }), TypeError);
  await settle();
  assert.equal(d.model.items.get(id).rev, 1, "no write went out");
  assert.equal(d.engine.list()[0].name, MARKER);
  d.engine.stop();
});
