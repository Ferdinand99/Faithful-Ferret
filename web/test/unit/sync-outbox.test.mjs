// The outbox sender: what is stored before a request, what is sent again and
// when, and which answers end a write for good.
import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError } from "../../src/api.mjs";
import { b64u } from "../../src/b64.mjs";
import { outbox } from "../../src/store/outbox.mjs";
import { encodeWireBytes } from "../../src/wire.mjs";
import { backoffMs, classify, createOutboxRunner, itemPath, MAX_BACKOFF_MS } from "../../src/sync/outbox.mjs";
import { createSyncEngine } from "../../src/sync/engine.mjs";
import { freshStore, scope } from "./idbHelpers.mjs";
import {
  counterRand, createFakeApi, createFakeClient, createFakeStore, currentRev, FakeTimers, Model, settle, until,
} from "./syncHelpers.mjs";

const hex = (n) => n.toString(16).padStart(32, "0");
const ID_NONE = "ee".repeat(16);

/** A queued live write for item `n` as the engine would build it. */
function entryFor(n, { baseRev = 0, idem = 5000 + n, fill = n } = {}) {
  const blob = new Uint8Array(48).fill(fill);
  const tag = new Uint8Array(32).fill(fill + 100);
  const bytes = encodeWireBytes("put_item_req", { base_rev: baseRev, blob: b64u.encode(blob), tag: b64u.encode(tag), idem: hex(idem) });
  return { idem: hex(idem), itemId: hex(n), baseRev, body: { blob, tag }, bytes };
}

async function runner({ hooks = {}, model = new Model() } = {}) {
  const order = [];
  const store = await createFakeStore({ order });
  const api = createFakeApi(model, { order });
  const timers = new FakeTimers();
  const log = { done: [], blocked: [], retry: [] };
  const run = createOutboxRunner({
    api, store, scope: scope(), timers,
    hooks: {
      onDone: (entry, answer) => log.done.push([entry.itemId, answer]),
      onBlocked: (entry, error, kind) => log.blocked.push([entry.itemId, error.code, kind]),
      onRetry: (entry, ms) => log.retry.push([entry.itemId, ms]),
      ...hooks,
    },
  });
  const stored = () => outbox.all(store.database.store, scope());
  return { run, api, model, store, timers, log, order, stored };
}

test("backoff_is_1_2_4_up_to_60_seconds_and_retry_after_can_only_lengthen_it", () => {
  assert.deepEqual([0, 1, 2, 3, 4, 5, 6, 7, 20].map((n) => backoffMs(n)), [1000, 2000, 4000, 8000, 16000, 32000, 60000, 60000, 60000]);
  assert.equal(backoffMs(0, 10), 10_000);
  assert.equal(backoffMs(3, 2), 8000);
  assert.equal(backoffMs(0, 3600), MAX_BACKOFF_MS);
});

test("answers_are_classified_by_what_retrying_can_do", () => {
  const kind = (status, code) => classify(new ApiError(status, code));
  for (const [status, code] of [[0, "network"], [500, "internal"], [502, "bad_response"], [503, "internal"], [408, "bad_response"], [429, "throttled"], [200, "bad_response"]]) {
    assert.equal(kind(status, code), "retry", `${status} ${code}`);
  }
  for (const [status, code] of [[400, "bad_request"], [403, "manifest_not_writable"], [413, "too_large"], [413, "quota_exceeded"], [422, "unsupported_envelope"], [422, "tombstone_invalid"], [422, "idem_reuse"]]) {
    assert.equal(kind(status, code), "terminal", `${status} ${code}`);
  }
  assert.equal(kind(409, "conflict"), "conflict");
  assert.equal(kind(401, "unauthorized"), "unauthorized");
  // 401 and 404 are not terminal for the client, but a 404 is not sent again either.
  assert.equal(new ApiError(401, "unauthorized").terminal, false);
  assert.equal(new ApiError(404, "not_found").terminal, false);
  assert.equal(kind(404, "not_found"), "other");
  assert.equal(kind(410, "gone"), "other");
});

test("outbox_is_written_before_the_request_and_resends_identical_bytes", async () => {
  const t = await runner();
  const entry = entryFor(1);
  t.api.faults.push({ kind: "network" }, { kind: "network" });
  await t.run.enqueue(entry);
  await until(() => t.api.puts.length === 1);
  assert.deepEqual(t.order, ["outbox.enqueue", "put"], "stored first");
  assert.equal((await t.stored()).length, 1, "stored while the request is out");
  t.timers.advance(1_000);
  await until(() => t.api.puts.length === 2);
  t.timers.advance(2_000);
  await until(() => t.model.items.has(entry.itemId));
  const sent = t.api.puts.map((p) => p.text);
  assert.equal(sent.length, 3);
  assert.deepEqual(new Set(sent).size, 1, "the same text each time");
  assert.deepEqual(t.api.puts.map((p) => Buffer.from(p.bytes).toString("hex")), Array(3).fill(Buffer.from(entry.bytes).toString("hex")));
  assert.equal(sent[0], new TextDecoder().decode(entry.bytes));
  await until(async () => (await t.stored()).length === 0, "removed after the 200");
});

test("a_stored_entry_keeps_its_own_byte_layout", async () => {
  // Not what JSON.stringify makes: another key order and spacing. The server hashes these bytes.
  const t = await runner();
  const base = entryFor(2);
  const wire = JSON.parse(new TextDecoder().decode(base.bytes));
  const text = `{ "idem":"${wire.idem}",\n"tag":"${wire.tag}", "blob":"${wire.blob}",\n "base_rev":0 }\n`;
  const entry = { ...base, bytes: new TextEncoder().encode(text) };
  t.api.faults.push({ kind: "lost" });
  await t.run.enqueue(entry);
  await until(() => t.api.puts.length === 1);
  t.timers.advance(1_000);
  await until(() => t.log.done.length === 1);
  assert.deepEqual(t.api.puts.map((p) => p.text), [text, text]);
});

test("network_failure_retries_with_backoff_and_same_idem", async () => {
  const t = await runner();
  const entry = entryFor(3);
  for (let i = 0; i < 8; i += 1) t.api.faults.push({ kind: "network" });
  await t.run.enqueue(entry);
  await until(() => t.api.puts.length === 1);
  const waits = [1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000];
  for (const [i, wait] of waits.entries()) {
    await until(() => t.timers.pending === 1, `a wait after try ${i + 1}`);
    assert.equal(t.timers.delays[i], wait);
    t.timers.advance(wait - 1);
    await settle(5);
    assert.equal(t.api.puts.length, i + 1, "not sent before the wait is over");
    t.timers.advance(1);
    await until(() => t.api.puts.length === i + 2);
  }
  await until(() => t.log.done.length === 1);
  assert.deepEqual(t.log.retry.map(([, ms]) => ms), waits);
  const idems = t.api.puts.map((p) => JSON.parse(p.text).idem);
  assert.equal(new Set(idems).size, 1);
  assert.equal(idems[0], entry.idem);
  assert.equal(t.model.writes.length, 1);
});

test("a_5xx_and_a_429_are_retried_and_retry_after_is_kept_within_60_seconds", async () => {
  const t = await runner();
  const entry = entryFor(4);
  t.api.faults.push({ kind: "status", status: 503, code: "internal" }, { kind: "status", status: 429, code: "throttled", retryAfter: 7 }, { kind: "status", status: 429, code: "throttled", retryAfter: 900 });
  await t.run.enqueue(entry);
  await until(() => t.timers.delays.length === 1);
  t.timers.advance(1_000);
  await until(() => t.timers.delays.length === 2);
  t.timers.advance(7_000);
  await until(() => t.timers.delays.length === 3);
  t.timers.advance(60_000);
  await until(() => t.log.done.length === 1);
  assert.deepEqual(t.timers.delays, [1_000, 7_000, 60_000]);
});

test("a_200_after_a_lost_response_is_replayed_true_and_counts_as_done", async () => {
  const t = await runner();
  const entry = entryFor(5);
  t.api.faults.push({ kind: "lost" }); // the server wrote, the answer never came
  await t.run.enqueue(entry);
  await until(() => t.model.writes.length === 1 && t.timers.pending === 1);
  assert.equal(t.log.done.length, 0);
  t.timers.advance(1_000);
  await until(() => t.log.done.length === 1);
  assert.equal(t.log.done[0][1].replayed, true);
  assert.equal(t.model.writes.length, 1, "written once");
  assert.equal(t.model.items.get(entry.itemId).rev, 1);
  await until(async () => (await t.stored()).length === 0, "the entry is removed");
  assert.equal(t.run.entriesOf(entry.itemId).length, 0);
});

test("terminal_answers_are_not_sent_again_and_the_draft_stays", async () => {
  for (const [status, code] of [[400, "bad_request"], [403, "manifest_not_writable"], [413, "too_large"], [413, "quota_exceeded"], [422, "unsupported_envelope"], [422, "tombstone_invalid"], [422, "idem_reuse"], [404, "not_found"]]) {
    const t = await runner();
    const entry = entryFor(6);
    t.api.faults.push({ kind: "status", status, code });
    await t.run.enqueue(entry);
    await until(() => t.log.blocked.length === 1, `${status} ${code}`);
    t.timers.advance(120_000);
    await settle(10);
    assert.equal(t.api.puts.length, 1, `${code}: sent once`);
    assert.equal(t.timers.pending, 0, `${code}: no retry wait`);
    assert.equal(t.log.blocked[0][1], code, "the server's code is passed on");
    assert.equal((await t.stored()).length, 1, `${code}: the draft stays`);
    assert.equal(t.run.entriesOf(entry.itemId).length, 1);
    t.run.stop();
  }
});

test("a_401_stops_the_sender_until_it_is_resumed", async () => {
  const t = await runner();
  const first = entryFor(7);
  t.api.faults.push({ kind: "status", status: 401, code: "unauthorized" });
  await t.run.enqueue(first);
  await until(() => t.log.blocked.length === 1);
  assert.equal(t.log.blocked[0][2], "unauthorized");
  t.timers.advance(120_000);
  await settle(10);
  assert.equal(t.api.puts.length, 1);
  t.run.resume();
  await until(() => t.log.done.length === 1);
  assert.equal(t.api.puts.length, 2);
  assert.equal(t.api.puts[0].text, t.api.puts[1].text);
});

test("409_keeps_the_draft_and_does_not_overwrite", async () => {
  const model = new Model();
  const client = createFakeClient();
  const make = async (seed) => {
    const store = await createFakeStore({ order: [] });
    const api = createFakeApi(model);
    const timers = new FakeTimers();
    const events = { error: [] };
    const engine = createSyncEngine({
      api, client: { vault: client.vault }, store, scope: scope(), timers, rand: counterRand(seed), win: null,
    });
    engine.on("error", (e) => events.error.push(e));
    return { store, api, timers, engine, events };
  };
  const a = await make(1);
  const b = await make(2);
  await a.engine.start();
  await b.engine.start();
  const id = await a.engine.create({ item_type: "login", name: "Original" });
  await until(() => model.items.get(id)?.rev === 1);
  b.timers.advance(5_000);
  await until(() => b.engine.list().length === 1);

  // B edits and the server takes it; A, which has not polled, edits from rev 1.
  await b.engine.update(id, { name: "From B" }, currentRev(b.engine, id));
  await until(() => model.items.get(id).rev === 2);
  const serverRow = { ...model.items.get(id) };
  await a.engine.update(id, { name: "From A" }, currentRev(a.engine, id));
  await until(() => a.events.error.length === 1, "the conflict event");
  assert.equal(a.events.error[0].code, "conflict");
  assert.equal(a.events.error[0].id, id);
  assert.equal(a.events.error[0].currentRev, 2);
  assert.deepEqual(model.items.get(id), serverRow, "the server row is not overwritten");
  assert.equal(model.writes.filter((w) => w.id === id).length, 2, "A's write never landed");
  const draft = await outbox.all(a.store.database.store, scope());
  assert.equal(draft.length, 1, "the draft stays in A's outbox");
  assert.equal(draft[0].baseRev, 1);
  const puts = a.api.puts.filter((p) => p.id === id).length;
  a.timers.advance(120_000);
  await settle(20);
  assert.equal(a.api.puts.filter((p) => p.id === id).length, puts, "no automatic retry");
  // After A has read the feed, B's version is on screen and the draft is still stored.
  await until(() => a.engine.list()[0].rev >= 2, "A reads the server row");
  assert.equal((await outbox.all(a.store.database.store, scope())).length, 1);
  a.engine.stop();
  b.engine.stop();
});

test("a_401_on_the_feed_pauses_the_poll_until_syncNow_succeeds", async () => {
  const model = new Model();
  const timers = new FakeTimers();
  const store = await createFakeStore();
  const api = createFakeApi(model);
  const states = [];
  const engine = createSyncEngine({ api, client: { vault: createFakeClient().vault }, store, scope: scope(), timers, win: null, rand: counterRand(1) });
  engine.on("state", (s) => states.push(s.kind));
  api.failFeed = new ApiError(401, "unauthorized");
  api.failFeedTimes = 1;
  await engine.start();
  assert.ok(states.includes("unauthorized"));
  assert.equal(timers.pending, 0, "no poll while signed out");
  await engine.syncNow();
  assert.equal(states.at(-1), "idle");
  assert.equal(timers.pending, 1, "polling is back");
  engine.stop();
});

test("a_network_failure_on_the_feed_looks_offline_and_the_poll_goes_on", async () => {
  const model = new Model();
  const timers = new FakeTimers();
  const store = await createFakeStore();
  const api = createFakeApi(model);
  const states = [];
  const engine = createSyncEngine({ api, client: { vault: createFakeClient().vault }, store, scope: scope(), timers, win: null, rand: counterRand(1) });
  engine.on("state", (s) => states.push(s.kind));
  api.failFeed = new ApiError(0, "network");
  api.failFeedTimes = 2;
  await engine.start();
  assert.deepEqual(states, ["syncing", "offline"]);
  assert.equal(timers.pending, 1);
  timers.advance(5_000);
  await until(() => api.gets.length === 2);
  timers.advance(5_000);
  await until(() => states.at(-1) === "idle", "back online");
  engine.stop();
});

test("itemPath_is_under_the_sync_items_route", () => {
  assert.equal(itemPath("ab".repeat(16)), `/api/sync/items/${"ab".repeat(16)}`);
});

/** An engine over its own storage (or the one given) and fake clock. */
async function engineOn(model, client, { db = null, seed = 1 } = {}) {
  const store = await createFakeStore({ db });
  const api = createFakeApi(model);
  const timers = new FakeTimers();
  const events = { error: [], state: [] };
  const engine = createSyncEngine({
    api, client: { vault: client.vault }, store, scope: scope(), timers, rand: counterRand(seed), win: null,
  });
  engine.on("error", (e) => events.error.push(e));
  engine.on("state", (s) => events.state.push(s));
  return { store, api, timers, engine, events };
}

const stored = (t) => outbox.all(t.store.database.store, scope());

test("an_edit_after_a_409_is_refused_and_the_block_survives_a_restart_and_discard_unblocks", async () => {
  const model = new Model();
  const client = createFakeClient();
  const adb = await freshStore();
  const a = await engineOn(model, client, { db: adb, seed: 1 });
  const b = await engineOn(model, client, { seed: 2 });
  await a.engine.start();
  await b.engine.start();
  const id = await a.engine.create({ item_type: "login", name: "Original" });
  await until(() => model.items.get(id)?.rev === 1);
  b.timers.advance(5_000);
  await until(() => b.engine.list().length === 1);
  await b.engine.update(id, { name: "From B" }, currentRev(b.engine, id));
  await until(() => model.items.get(id).rev === 2);

  await a.engine.update(id, { name: "From A" }, currentRev(a.engine, id));
  await until(() => a.events.error.some((e) => e.code === "conflict"), "the conflict");
  // The server's version is what is on screen, with the block shown; the draft stays in the outbox.
  await until(() => a.engine.list()[0].name === "From B" && a.engine.list()[0].rev === 2, "the server's version is shown");
  const [item] = a.engine.list();
  assert.deepEqual([item.blocked, item.blockedReason], [true, "conflict"]);
  assert.equal((await stored(a)).length, 1);

  // A new edit is refused with a clear error, not queued behind the refused write.
  await assert.rejects(a.engine.update(id, { name: "Again" }, currentRev(a.engine, id)), (e) => e.code === "blocked" && e.reason === "conflict");
  await assert.rejects(a.engine.remove(id), (e) => e.code === "blocked");
  assert.equal((await stored(a)).length, 1);
  a.engine.stop();

  // After a restart the block is still there and the server's version is still on screen; nothing is sent.
  await adb.reopen();
  const again = await engineOn(model, client, { db: adb, seed: 5 });
  await again.engine.start();
  again.timers.advance(120_000);
  await settle(20);
  const [back] = again.engine.list();
  assert.deepEqual([back.blocked, back.blockedReason, back.name, back.rev], [true, "conflict", "From B", 2]);
  assert.equal(again.api.puts.length, 0, "a refused write is not sent again");
  await assert.rejects(again.engine.update(id, { name: "Again" }, currentRev(again.engine, id)), (e) => e.code === "blocked");
  await assert.rejects(again.engine.discard(ID_NONE), (e) => e.code === "not_found");

  // discard drops the draft and the block; the item can be edited again, from the server's version.
  await again.engine.discard(id);
  assert.equal((await stored(again)).length, 0);
  const [free] = again.engine.list();
  assert.deepEqual([free.blocked, free.blockedReason, free.pending, free.name], [false, null, false, "From B"]);
  await again.engine.update(id, { name: "After discard" }, currentRev(again.engine, id));
  await until(() => model.items.get(id).rev === 3, "the new edit is sent");
  assert.equal(JSON.parse(model.writes.at(-1).body).base_rev, 2);
  again.engine.stop();
  b.engine.stop();
});

test("a_delete_refused_with_413_leaves_the_item_visible_live_and_marked", async () => {
  const model = new Model();
  const client = createFakeClient();
  const db = await freshStore();
  const t = await engineOn(model, client, { db });
  await t.engine.start();
  const id = await t.engine.create({ item_type: "login", name: "Cannot delete me" });
  await until(async () => model.items.has(id) && (await stored(t)).length === 0);
  await until(() => t.engine.list()[0]?.pending === false);
  t.api.faults.push({ kind: "status", status: 413, code: "quota_exceeded" });
  await t.engine.remove(id);
  await until(() => t.events.error.some((e) => e.code === "quota_exceeded" && e.id === id), "the refusal");
  await until(() => t.engine.list().length === 1 && t.engine.list()[0].blocked, "the item is back, marked");
  const [item] = t.engine.list();
  assert.deepEqual([item.name, item.blockedReason, item.rev], ["Cannot delete me", "quota_exceeded", 1]);
  assert.equal(model.items.get(id).deleted, false);
  assert.equal((await t.engine.open(id)).view.name, "Cannot delete me");
  t.engine.stop();

  await db.reopen();
  const back = await engineOn(model, client, { db, seed: 7 });
  await back.engine.start();
  assert.deepEqual(back.engine.list().map((i) => [i.name, i.blockedReason]), [["Cannot delete me", "quota_exceeded"]], "still visible after a restart");
  await back.engine.discard(id);
  await back.engine.remove(id);
  await until(() => model.items.get(id).deleted === true, "after discard the delete goes through");
  back.engine.stop();
});

test("a_create_refused_for_good_keeps_its_draft_on_screen_until_it_is_discarded", async () => {
  const model = new Model();
  const client = createFakeClient();
  const db = await freshStore();
  const t = await engineOn(model, client, { db });
  await t.engine.start();
  t.api.faults.push({ kind: "status", status: 413, code: "too_large" });
  const id = await t.engine.create({ item_type: "login", name: "Never accepted" });
  await until(() => t.engine.list()[0]?.blocked === true, "blocked");
  assert.equal(t.engine.list()[0].name, "Never accepted");
  assert.equal(model.items.has(id), false);
  t.engine.stop();

  await db.reopen();
  const back = await engineOn(model, client, { db, seed: 9 });
  await back.engine.start();
  assert.deepEqual(back.engine.list().map((i) => [i.name, i.blocked]), [["Never accepted", true]]);
  assert.equal(back.api.puts.length, 0);
  await back.engine.discard(id);
  assert.deepEqual(back.engine.list(), []);
  assert.equal((await stored(back)).length, 0);
  back.engine.stop();
});

test("a_failed_store_during_discard_leaves_the_item_blocked_and_nothing_is_sent_after_a_restart", async () => {
  const model = new Model();
  const client = createFakeClient();
  const db = await freshStore();
  const a = await engineOn(model, client, { db, seed: 1 });
  const b = await engineOn(model, client, { seed: 2 });
  await a.engine.start();
  await b.engine.start();
  const id = await a.engine.create({ item_type: "login", name: "Original" });
  await until(() => model.items.get(id)?.rev === 1);
  b.timers.advance(5_000);
  await until(() => b.engine.list().length === 1);
  await b.engine.update(id, { name: "From B" }, currentRev(b.engine, id));
  await until(() => model.items.get(id).rev === 2);
  await a.engine.update(id, { name: "From A" }, currentRev(a.engine, id));
  await until(() => a.engine.list()[0]?.blocked === true && a.engine.list()[0].name === "From B");

  a.store.failRemove = 1;
  await assert.rejects(a.engine.discard(id), /disk is full/);
  assert.equal(a.engine.list()[0].blocked, true, "the block is held");
  await assert.rejects(a.engine.update(id, { name: "Again" }, currentRev(a.engine, id)), (e) => e.code === "blocked");
  assert.equal((await stored(a)).length, 1, "the entry is still stored");
  a.engine.stop();

  // After a restart the entry is loaded blocked; nothing is sent.
  await db.reopen();
  const again = await engineOn(model, client, { db, seed: 5 });
  await again.engine.start();
  again.timers.advance(120_000);
  await settle(20);
  assert.equal(again.api.puts.length, 0);
  assert.equal(again.engine.list()[0].blocked, true);

  // A second discard in the same session works the same way and now succeeds, with the store first.
  again.store.failRemove = 1;
  await assert.rejects(again.engine.discard(id), /disk is full/);
  await again.engine.discard(id);
  assert.equal((await stored(again)).length, 0);
  again.engine.stop();
  await db.reopen();
  const last = await engineOn(model, client, { db, seed: 6 });
  await last.engine.start();
  last.timers.advance(120_000);
  await settle(20);
  assert.equal(last.api.puts.length, 0, "a discarded write is never sent");
  assert.equal(last.engine.list()[0].blocked, false);
  last.engine.stop();
  b.engine.stop();
});
