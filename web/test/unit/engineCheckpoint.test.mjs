// The sync engine and the checkpoints: when the checkpoint of the server is verified, what each failure shows, when this
// device uploads one of its own, and what a mark of an item that was uploaded again does to all of that.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { ApiError } from "../../src/api.mjs";
import { b64u } from "../../src/b64.mjs";
import { outbox } from "../../src/store/outbox.mjs";
import { loadSyncState } from "../../src/store/syncState.mjs";
import { suspendsUpload } from "../../src/sync/checkpoint.mjs";
import { ACCOUNT, freshStore, scope, SERVER } from "./idbHelpers.mjs";
import {
  createFakeClient, FakeFerretError, FakeLocks, memoryOf, Model, settle, syncDevice, until,
} from "./syncHelpers.mjs";

const T0 = 1_700_000_000_000;
const DAY = 86_400_000;
const ID_A = "11".repeat(16);
const ID_B = "22".repeat(16);
const ID_C = "33".repeat(16);
const ID_D = "44".repeat(16);
const DRAFT = { item_type: "login", name: "Written here" };

const setRow = (model, client, id, rev, name, extra = {}) => model.set(id, { rev, ...client.wireRow(id, rev, { item_type: "login", name }), ...extra });
const stateOf = (d) => loadSyncState(d.store.database.store, SERVER, ACCOUNT);
const warningEvents = (d, code) => d.events.state.filter((s) => s.kind === "warning" && (code === undefined || s.code === code));
const standing = (d) => d.engine.health().warnings;
/** Stores a field of the sync state, as an earlier session would have left it. */
const seed = (d, patch) => d.memory.withLock(async (state) => ({ ...state, ...patch }));
const failWith = (d, code) => {
  d.client.vault.verify_checkpoint = async () => {
    throw new FakeFerretError(code);
  };
};
const sha = (bytes) => new Uint8Array(createHash("sha256").update(bytes).digest());
/** A checkpoint nobody with the key made: a digest that fits and a mac that does not. */
const junk = (seq = 1) => ({ seq, digest: sha(new Uint8Array(0)), mac: new Uint8Array(32), entries: new Uint8Array(0) });

/** A and B on the server and a checkpoint of that moment (seq 2), then C: the server's head is 2 and its top 3. */
function withNewerRow() {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A");
  setRow(model, client, ID_B, 2, "B");
  model.pinCheckpoint();
  setRow(model, client, ID_C, 1, "C");
  return { model, client };
}

// ------------------------------------------------------------------ when it is verified

test("first_start_verifies_after_the_first_drained_pass_and_saves_verified_at", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A");
  setRow(model, client, ID_B, 2, "B");
  const d = await syncDevice({ model, client });
  assert.equal(await stateOf(d), null, "nothing is stored before the first start");
  await d.engine.start();
  assert.equal(d.api.checkpointGets.length, 1, "the checkpoint is read once, after the feed is drained");
  const state = await stateOf(d);
  assert.equal(state.verifiedAt, T0 + d.timers.time);
  assert.equal(state.verifiedSeq, 2, "and the seq of the checkpoint it verified");
  assert.equal(state.hardWarning, null);
  assert.equal(memoryOf(state.memory).checkpointSeq, 2, "the memory knows the checkpoint it has verified");
  assert.deepEqual(d.engine.health(), { halted: null, warnings: [] });
  assert.equal(d.client.vault.calls.filter((c) => c[0] === "verify_checkpoint").length, 1);
  // Later passes in the same day do not ask again.
  await d.engine.syncNow();
  await d.engine.syncNow();
  assert.equal(d.api.checkpointGets.length, 1);
  d.engine.stop();
});

test("verify_uses_latest_seq_of_the_drained_page_even_when_the_last_row_was_purged", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A");
  model.seq = 7; // a tombstone above A was purged: no row has seq 7, but the vault is at 7
  const d = await syncDevice({ model, client });
  await d.engine.start();
  const [, checkpointSeq, topSeq] = d.client.vault.calls.find((c) => c[0] === "verify_checkpoint");
  assert.equal(topSeq, 7, "the top is the latest_seq of the drained page, not the seq of its last row");
  assert.equal(checkpointSeq, 7);
  assert.deepEqual(d.engine.health(), { halted: null, warnings: [] }, "an honest checkpoint at the top passes");
  assert.notEqual((await stateOf(d)).verifiedAt, null);
  d.engine.stop();
});

test("unlock_after_24_hours_verifies_again_and_before_does_not", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A");
  const d = await syncDevice({ model, client });
  await d.engine.start();
  const first = (await stateOf(d)).verifiedAt;
  assert.equal(d.api.checkpointGets.length, 1);

  await until(() => d.timers.pending > 0);
  d.timers.advance(DAY - 1_000);
  await settle(60);
  assert.equal(d.api.checkpointGets.length, 1, "a pass 23 hours and 59 minutes later does not verify");
  assert.equal((await stateOf(d)).verifiedAt, first);

  await until(() => d.timers.pending > 0);
  d.timers.advance(6_000);
  await until(() => d.api.checkpointGets.length === 2, "a pass after a day verifies again");
  await until(async () => (await stateOf(d)).verifiedAt > first, "and stores the time");
  d.engine.stop();
});

test("verifyNow_checks_at_once_whatever_the_time", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A");
  const d = await syncDevice({ model, client });
  await d.engine.start();
  assert.equal(await d.engine.verifyNow(), "ok");
  assert.equal(d.api.checkpointGets.length, 2);
  d.api.checkpointFaults.push({ kind: "network" });
  assert.equal(await d.engine.verifyNow(), "not_checked", "a server that cannot be reached is not a verdict");
  assert.equal(standing(d).length, 0);
  failWith(d, "checkpoint_lower_rev");
  assert.equal(await d.engine.verifyNow(), "server_shows_older_state");
  d.engine.stop();
  await assert.rejects(d.engine.verifyNow(), (e) => e.code === "stopped");
});

// ------------------------------------------------------------------ what each failure shows

const FAILURES = [
  ["checkpoint_hidden_or_rolled_back", "server_shows_older_state"],
  ["checkpoint_lower_rev", "server_shows_older_state"],
  ["checkpoint_same_rev_different_hash", "server_shows_older_state"],
  ["checkpoint_live_behind_tombstone", "server_shows_older_state"],
  ["checkpoint_top_digest_mismatch", "server_shows_older_state"],
  ["checkpoint_seq_below_remembered", "checkpoint_rolled_back"],
  ["checkpoint_rev_below_remembered", "checkpoint_rolled_back"],
  ["checkpoint_bad_mac", "checkpoint_forged"],
  ["checkpoint_bad_digest", "checkpoint_forged"],
  ["malformed_entries", "checkpoint_forged"],
  ["checkpoint_seq_above_top", "bad_feed"],
];

test("each_core_failure_code_maps_to_its_warning", async () => {
  for (const [code, warning] of FAILURES) {
    const model = new Model();
    const client = createFakeClient();
    setRow(model, client, ID_A, 1, "A");
    const d = await syncDevice({ model, client });
    failWith(d, code);
    await d.engine.start();
    assert.deepEqual(standing(d), [warning], code);
    assert.deepEqual(warningEvents(d).map((w) => w.code), [warning], code);
    assert.equal((await stateOf(d)).hardWarning, warning, `${code}: kept in the state`);
    assert.equal((await stateOf(d)).verifiedAt, null, `${code}: nothing was verified`);
    assert.equal(d.engine.health().halted, null, code);
    d.engine.stop();
  }
  // The two that are not warnings: the top below what this device has seen stops the engine, a full memory too.
  for (const [code, stop] of [["checkpoint_top_seq_below_remembered", "rollback_suspected"], ["too_large", "sync_memory_full"]]) {
    const model = new Model();
    const client = createFakeClient();
    setRow(model, client, ID_A, 1, "A");
    const d = await syncDevice({ model, client });
    failWith(d, code);
    await d.engine.start();
    assert.equal(d.engine.health().halted, stop, code);
    assert.equal((await stateOf(d)).hardWarning, null, `${code}: a stop is not kept as a warning`);
    d.engine.stop();
  }
});

test("an_unknown_failure_code_is_server_shows_older_state", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A");
  const d = await syncDevice({ model, client });
  failWith(d, "a_code_from_a_newer_core");
  await d.engine.start();
  assert.deepEqual(standing(d), ["server_shows_older_state"], "a check that fails for no known reason did not pass");
  assert.equal(d.engine.health().halted, null);
  d.engine.stop();
});

test("a_checkpoint_that_is_not_there_is_a_bad_feed_and_one_that_cannot_be_reached_is_nothing", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A");
  model.checkpoint = null;
  const d = await syncDevice({ model, client });
  await d.engine.start();
  assert.deepEqual(standing(d), ["bad_feed"], "every vault has one from its registration");
  d.engine.stop();

  const later = new Model();
  setRow(later, client, ID_A, 1, "A");
  const e = await syncDevice({ model: later, client });
  e.api.checkpointFaults.push({ kind: "status", status: 503, code: "busy" });
  await e.engine.start();
  assert.deepEqual(standing(e), [], "a 503 says nothing about the checkpoint");
  assert.equal((await stateOf(e)).verifiedAt, null);
  e.engine.stop();
});

test("state_warnings_suspend_uploads_and_survive_a_reload", async () => {
  const { model, client } = withNewerRow();
  const db = await freshStore();
  const locks = new FakeLocks();
  const first = await syncDevice({ model, client, db, locks });
  await seed(first, { verifiedAt: T0 - 2 * DAY });
  failWith(first, "checkpoint_lower_rev");
  await first.engine.start();
  assert.deepEqual(standing(first), ["server_shows_older_state"]);
  assert.equal(model.checkpointPuts.length, 0, "the top is above the head, and still nothing is uploaded");
  assert.equal(first.api.checkpointPuts.length, 0);
  assert.equal((await stateOf(first)).hardWarning, "server_shows_older_state");
  first.engine.stop();

  // A reload, and the feed cannot be reached: the warning is still there, from the state.
  const second = await syncDevice({ model, client: createFakeClient(), db, locks, seed: 2 });
  second.api.failFeed = new ApiError(0, "network");
  second.api.failFeedTimes = 1;
  await second.engine.start();
  assert.deepEqual(standing(second), ["server_shows_older_state"]);
  assert.equal(second.api.checkpointGets.length, 0, "no pass has been drained, so nothing was checked");
  assert.equal(model.checkpointPuts.length, 0);

  // The server is back and still shows the older state: it is looked at again, and still nothing is uploaded.
  failWith(second, "checkpoint_lower_rev");
  await until(() => second.timers.pending > 0);
  second.timers.advance(5_000);
  await until(() => second.api.checkpointGets.length === 1, "a warning in the state is looked at again");
  await settle(60);
  assert.deepEqual(standing(second), ["server_shows_older_state"]);
  assert.equal(warningEvents(second, "server_shows_older_state").length, 1, "said once");
  assert.equal(model.checkpointPuts.length, 0);
  second.engine.stop();
});

test("a_later_successful_verify_clears_the_warning_with_warning_cleared", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A");
  const d = await syncDevice({ model, client });
  const real = d.client.vault.verify_checkpoint;
  failWith(d, "checkpoint_lower_rev");
  await d.engine.start();
  assert.deepEqual(standing(d), ["server_shows_older_state"]);
  d.client.vault.verify_checkpoint = real;
  assert.equal(await d.engine.verifyNow(), "ok");
  assert.deepEqual(d.events.state.filter((s) => s.kind === "warning_cleared"), [{ kind: "warning_cleared", code: "server_shows_older_state" }]);
  assert.deepEqual(standing(d), []);
  const state = await stateOf(d);
  assert.equal(state.hardWarning, null);
  assert.notEqual(state.verifiedAt, null);
  d.engine.stop();
});

/**
 * A device that has verified before, a newer row on the server than its head, and a state warning that a failed
 * verification left in the state: what the next failures may and may not do to it.
 */
async function withStoredOlderState() {
  const { model, client } = withNewerRow();
  const d = await syncDevice({ model, client });
  await seed(d, { verifiedAt: T0 - 2 * DAY });
  const real = d.client.vault.verify_checkpoint;
  failWith(d, "checkpoint_lower_rev");
  await d.engine.start();
  assert.deepEqual(standing(d), ["server_shows_older_state"]);
  assert.equal((await stateOf(d)).hardWarning, "server_shows_older_state");
  d.client.vault.verify_checkpoint = real;
  d.events.state.length = 0;
  return { d, model, client };
}

const cleared = (d) => d.events.state.filter((s) => s.kind === "warning_cleared");

test("a_junk_checkpoint_does_not_wipe_a_stored_state_warning_or_unlock_uploads", async () => {
  const { d, model } = await withStoredOlderState();
  model.checkpoint = junk(1); // the server now shows a checkpoint nobody with the key made
  assert.equal(await d.engine.verifyNow(), "server_shows_older_state", "the most serious warning still stands");
  assert.deepEqual(standing(d).sort(), ["checkpoint_forged", "server_shows_older_state"], "the junk is shown next to it");
  assert.equal((await stateOf(d)).hardWarning, "server_shows_older_state", "and is not stored over it");
  assert.deepEqual(cleared(d), [], "nothing was cleared");
  assert.equal(d.api.checkpointPuts.length, 0, "a device with a state warning signs nothing, whatever else the server shows");
  assert.deepEqual(model.checkpoint, junk(1));
  // It stays so after a reload of the engine (the state is what is kept).
  d.engine.stop();
});

test("a_checkpoint_that_is_not_there_does_not_wipe_a_stored_state_warning_or_unlock_uploads", async () => {
  const { d, model } = await withStoredOlderState();
  model.checkpoint = null; // a 404 on the checkpoint
  assert.equal(await d.engine.verifyNow(), "server_shows_older_state");
  assert.deepEqual(standing(d).sort(), ["bad_feed", "server_shows_older_state"]);
  assert.equal((await stateOf(d)).hardWarning, "server_shows_older_state");
  assert.deepEqual(cleared(d), []);
  assert.equal(d.api.checkpointPuts.length, 0);
  d.engine.stop();
});

test("a_pause_does_not_lower_a_stored_state_warning", async () => {
  const d = await hiddenB();
  assert.deepEqual(standing(d), []);
  await seed(d, { hardWarning: "server_shows_older_state" }); // what another failed check left
  assert.equal(await d.engine.verifyNow(), "server_shows_older_state", "the check would only be a pause, and does not lower the warning");
  assert.deepEqual(standing(d), ["server_shows_older_state"]);
  assert.equal((await stateOf(d)).hardWarning, "server_shows_older_state");
  assert.deepEqual(cleared(d), []);
  d.engine.stop();
});

test("a_later_successful_verify_clears_what_a_failure_could_not", async () => {
  const { d, model } = await withStoredOlderState();
  model.checkpoint = junk(1);
  await d.engine.verifyNow();
  assert.equal(standing(d).length, 2);
  model.checkpoint = "auto";
  assert.equal(await d.engine.verifyNow(), "ok");
  assert.deepEqual(standing(d), []);
  assert.deepEqual(cleared(d).map((e) => e.code).sort(), ["checkpoint_forged", "server_shows_older_state"]);
  assert.equal((await stateOf(d)).hardWarning, null);
  d.engine.stop();
});

test("a_forged_checkpoint_replaces_nothing_but_information", async () => {
  // Information (forged, bad feed) is replaced by the other information, and a state warning replaces it.
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A");
  const d = await syncDevice({ model, client });
  failWith(d, "checkpoint_bad_mac");
  await d.engine.start();
  failWith(d, "checkpoint_seq_above_top");
  assert.equal(await d.engine.verifyNow(), "bad_feed");
  assert.deepEqual(standing(d), ["bad_feed"]);
  failWith(d, "checkpoint_lower_rev");
  assert.equal(await d.engine.verifyNow(), "server_shows_older_state");
  assert.deepEqual(standing(d), ["server_shows_older_state"]);
  assert.equal((await stateOf(d)).hardWarning, "server_shows_older_state");
  d.engine.stop();
});

test("a_403_on_the_checkpoint_is_the_session_and_not_a_bad_feed", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A");
  const d = await syncDevice({ model, client });
  await d.engine.start();
  d.api.checkpointFaults.push({ kind: "status", status: 403, code: "forbidden" });
  assert.equal(await d.engine.verifyNow(), "not_checked");
  assert.deepEqual(standing(d), [], "no warning about the server");
  assert.equal((await stateOf(d)).hardWarning, null);
  assert.ok(d.events.state.some((s) => s.kind === "unauthorized"), "the pass stops like it does for a refused session");
  d.engine.stop();
});

// ------------------------------------------------------------------ uploads

test("no_upload_before_a_successful_verify", async () => {
  // A new device whose checkpoint could not be read: it has verified nothing, so it signs nothing.
  const { model, client } = withNewerRow();
  const fresh = await syncDevice({ model, client });
  fresh.api.checkpointFaults.push({ kind: "network" });
  await fresh.engine.start();
  assert.equal(fresh.api.checkpointPuts.length, 0);
  assert.equal(fresh.api.checkpointGets.length, 1);
  // Once a verification has succeeded the same state is uploaded.
  assert.equal(await fresh.engine.verifyNow(), "ok");
  assert.equal(model.checkpointPuts.length, 1, "after the verification, and only then");
  assert.equal(model.checkpointPuts[0].seq, 3);
  fresh.engine.stop();

  // A reload within 24 hours: it verified yesterday, so it does not verify now, and a session with no verification does not upload.
  const other = withNewerRow();
  const reloaded = await syncDevice({ model: other.model, client: other.client });
  await seed(reloaded, { verifiedAt: T0 - 3_600_000 });
  await reloaded.engine.start();
  await reloaded.engine.syncNow();
  assert.equal(reloaded.api.checkpointGets.length, 0, "not due");
  assert.equal(other.model.checkpointPuts.length, 0, "no verification in this session, no upload");
  reloaded.engine.stop();
});

test("upload_happens_only_when_drained_with_an_empty_outbox_and_no_marks", async () => {
  // Not drained: the feed breaks after the first page.
  {
    const { model, client } = withNewerRow();
    model.pageSize = 1;
    const d = await syncDevice({ model, client });
    await seed(d, { verifiedAt: T0 - 2 * DAY });
    const real = d.api.get;
    let pages = 0;
    d.api.get = async (path) => {
      if (path.includes("/changes") && (pages += 1) === 2) throw new ApiError(0, "network");
      return real(path);
    };
    await d.engine.start();
    assert.equal(d.api.checkpointGets.length, 0, "a pass that did not reach the end verifies nothing");
    assert.equal(model.checkpointPuts.length, 0);
    d.api.get = real;
    await d.engine.syncNow();
    assert.equal(model.checkpointPuts.length, 1, "drained: verified and uploaded");
    d.engine.stop();
  }
  // The outbox is not empty.
  {
    const model = new Model();
    const client = createFakeClient();
    setRow(model, client, ID_A, 1, "A");
    setRow(model, client, ID_B, 2, "B");
    model.pinCheckpoint();
    const d = await syncDevice({ model, client });
    await d.engine.start();
    assert.equal(model.checkpointPuts.length, 0, "the server's head is at the top");
    d.api.faults.push({ kind: "network" });
    await d.engine.create(DRAFT);
    setRow(model, client, ID_C, 1, "C"); // another device wrote
    await d.engine.syncNow();
    assert.equal(d.api.checkpointGets.length, 1);
    assert.equal(model.checkpointPuts.length, 0, "a write is waiting in the outbox");
    d.timers.advance(1_000); // the write is sent again and answered
    await until(() => model.checkpointPuts.length === 1, "when the outbox is empty");
    assert.equal(model.checkpointPuts[0].seq, 4, "with the write in it");
    assert.equal((await outbox.all(d.store.database.store, scope())).length, 0);
    d.engine.stop();
  }
  // A mark: a row that cannot be opened.
  {
    const { model, client } = withNewerRow();
    model.set(ID_D, { rev: 1, blob: null, tag: null, deleted: false });
    const d = await syncDevice({ model, client });
    await seed(d, { verifiedAt: T0 - 2 * DAY });
    await d.engine.start();
    assert.equal(d.engine.list().find((i) => i.id === ID_D)?.damaged, true);
    assert.equal(d.api.checkpointGets.length, 1);
    assert.deepEqual(standing(d), [], "the verification itself passed");
    assert.equal(model.checkpointPuts.length, 0, "the list of entries would be missing an item");
    d.engine.stop();
  }
});

test("upload_at_most_every_ten_minutes_and_only_when_something_changed", async () => {
  const { model, client } = withNewerRow();
  const d = await syncDevice({ model, client });
  await seed(d, { verifiedAt: T0 - 2 * DAY });
  await d.engine.start();
  assert.equal(model.checkpointPuts.length, 1);
  assert.equal(model.checkpointPuts[0].seq, 3);
  const state = await stateOf(d);
  assert.deepEqual([state.uploadedSeq, state.uploadedAt], [3, T0]);

  setRow(model, client, ID_D, 1, "D"); // something changed
  await until(() => d.timers.pending > 0);
  d.timers.advance(60_000);
  await until(() => d.engine.list().length === 4, "the pass has read the new row");
  await settle(60);
  assert.equal(model.checkpointPuts.length, 1, "not within ten minutes of the last upload");

  await until(() => d.timers.pending > 0);
  d.timers.advance(540_000);
  await until(() => model.checkpointPuts.length === 2, "ten minutes after the first upload");
  assert.equal(model.checkpointPuts[1].seq, 4);
  await until(async () => (await stateOf(d)).uploadedSeq === 4, "the upload is stored");
  assert.equal((await stateOf(d)).uploadedAt, T0 + 600_000);

  await until(() => d.timers.pending > 0);
  d.timers.advance(600_000);
  await settle(60);
  await d.engine.syncNow();
  assert.equal(model.checkpointPuts.length, 2, "nothing has changed since the last one");
  d.engine.stop();
});

test("409_stale_counts_as_uploaded_and_429_waits", async () => {
  // 409: the server holds one at least as new. It counts: it is not sent again for the same state.
  {
    const { model, client } = withNewerRow();
    const d = await syncDevice({ model, client });
    await seed(d, { verifiedAt: T0 - 2 * DAY });
    d.api.checkpointPutFaults.push({ kind: "status", status: 409, code: "checkpoint_stale", body: { error: "checkpoint_stale", stored_seq: 3 } });
    await d.engine.start();
    assert.equal(d.api.checkpointPuts.length, 1);
    const state = await stateOf(d);
    assert.deepEqual([state.uploadedSeq, state.uploadedAt], [3, T0], "stored under the lock, as an upload");
    await until(() => d.timers.pending > 0);
    d.timers.advance(660_000);
    await settle(60);
    await d.engine.syncNow();
    assert.equal(d.api.checkpointPuts.length, 1, "not sent again");
    d.engine.stop();
  }
  // 429: nothing is stored, and the next try waits for what the server asked.
  {
    const { model, client } = withNewerRow();
    const d = await syncDevice({ model, client });
    await seed(d, { verifiedAt: T0 - 2 * DAY });
    d.api.checkpointPutFaults.push({ kind: "status", status: 429, code: "throttled", retryAfter: 120 });
    await d.engine.start();
    assert.equal(d.api.checkpointPuts.length, 1);
    assert.equal((await stateOf(d)).uploadedAt, null, "a refused upload is not an upload");
    await until(() => d.timers.pending > 0);
    d.timers.advance(60_000);
    await settle(60);
    await d.engine.syncNow();
    assert.equal(d.api.checkpointPuts.length, 1, "after 60 seconds it is still waiting");
    await until(() => d.timers.pending > 0);
    d.timers.advance(61_000);
    await until(() => model.checkpointPuts.length === 1, "after the 120 seconds it tries again");
    assert.equal(d.api.checkpointPuts.length, 2);
    await until(async () => (await stateOf(d)).uploadedAt === T0 + 121_000, "stored as an upload at the time it went through");
    d.engine.stop();
  }
});

test("an_upload_that_fails_for_another_reason_is_reported_and_tried_again_later", async () => {
  const { model, client } = withNewerRow();
  const d = await syncDevice({ model, client });
  await seed(d, { verifiedAt: T0 - 2 * DAY });
  d.api.checkpointPutFaults.push({ kind: "status", status: 422, code: "checkpoint_invalid" });
  await d.engine.start();
  assert.deepEqual(d.events.error, [{ code: "checkpoint_upload_failed", reason: "checkpoint_invalid" }]);
  assert.equal((await stateOf(d)).uploadedAt, null);
  assert.equal(d.engine.health().halted, null);
  await until(() => d.timers.pending > 0);
  d.timers.advance(310_000);
  await until(() => model.checkpointPuts.length === 1, "tried again after a wait");
  d.engine.stop();
});

test("forged_checkpoint_and_bad_feed_do_not_suspend_uploads", async () => {
  for (const [code, warning] of [["checkpoint_bad_mac", "checkpoint_forged"], ["checkpoint_seq_above_top", "bad_feed"]]) {
    const { model, client } = withNewerRow();
    const d = await syncDevice({ model, client });
    await seed(d, { verifiedAt: T0 - 2 * DAY }); // it has verified before
    failWith(d, code);
    await d.engine.start();
    assert.deepEqual(standing(d), [warning], code);
    assert.equal(model.checkpointPuts.length, 1, `${code}: the warning does not stop the checkpoints of this device`);
    assert.equal(model.checkpointPuts[0].seq, 3);
    assert.equal(d.engine.health().halted, null);
    assert.equal((await stateOf(d)).uploadedSeq, 3);
    d.engine.stop();
  }
});

test("a_higher_upload_replaces_a_junk_checkpoint", async () => {
  const { model, client } = withNewerRow();
  model.checkpoint = junk(1); // whoever signed this did not have the key
  const d = await syncDevice({ model, client });
  await seed(d, { verifiedAt: T0 - 2 * DAY }); // the device has verified before
  await d.engine.start();
  assert.deepEqual(standing(d), ["checkpoint_forged"], "the junk is reported");
  assert.equal(model.checkpointPuts.length, 1, "and replaced by a checkpoint at a higher seq");
  assert.equal(model.checkpoint.seq, 3);
  assert.equal(await d.engine.verifyNow(), "ok", "the one that replaced it verifies");
  assert.deepEqual(standing(d), []);
  d.engine.stop();
});

test("a_fresh_device_never_uploads_over_a_junk_checkpoint", async () => {
  const { model, client } = withNewerRow();
  model.checkpoint = junk(1);
  const d = await syncDevice({ model, client });
  await d.engine.start();
  assert.deepEqual(standing(d), ["checkpoint_forged"]);
  assert.equal(model.checkpointPuts.length, 0, "it has verified nothing before: it signs nothing now");
  await until(() => d.timers.pending > 0);
  d.timers.advance(660_000);
  await settle(60);
  await d.engine.syncNow();
  assert.equal(model.checkpointPuts.length, 0);
  assert.deepEqual(model.checkpoint, junk(1));
  d.engine.stop();
});

// ------------------------------------------------------------------ marks of items that were uploaded again

/**
 * B at revision 3 and A, a checkpoint of that moment from another device, then the server hides B (and moves its floor up) and
 * one pass lists the vault again: B is marked and uploaded again as revision 1. With `rolledBackC`, the checkpoint also lists C at
 * revision 2, which this device has only ever seen at revision 1.
 */
async function hiddenB({ rolledBackC = false, oldB = false } = {}) {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A");
  setRow(model, client, ID_B, oldB ? 1 : 3, "Hidden B");
  const rowC = client.wireRow(ID_C, 1, { item_type: "login", name: "C" });
  if (rolledBackC) model.set(ID_C, { rev: 1, ...rowC });
  const d = await syncDevice({ model, client });
  await d.engine.start();
  if (oldB) {
    // The checkpoint was made when B was at revision 1; B has been changed twice since, and this device has seen that.
    model.pinCheckpoint();
    setRow(model, client, ID_B, 3, "Hidden B");
    await d.engine.syncNow();
  }
  if (rolledBackC) setRow(model, client, ID_C, 2, "C two");
  if (!oldB) model.pinCheckpoint(); // B at 3 (and C at 2)
  if (rolledBackC) model.set(ID_C, { rev: 1, ...rowC }); // the server shows the old C again
  model.items.delete(ID_B);
  model.seq += 4;
  model.minValidSince = model.seq;
  setRow(model, client, ID_A, 2, "A two");
  await d.engine.syncNow();
  await until(() => model.items.has(ID_B) && d.engine.list().find((i) => i.id === ID_B)?.missingOnServer === false, "B is back as a copy");
  return d;
}

test("verify_with_k4_marks_is_deferred_not_rolled_back", async () => {
  const d = await hiddenB();
  assert.deepEqual(standing(d), [], "the pass that listed the vault still held the old copy of B, which agrees with the checkpoint");
  // The copy that was uploaded again is revision 1, below the 3 the checkpoint records and the old floor of the memory.
  assert.equal(await d.engine.verifyNow(), "verify_deferred");
  assert.deepEqual(standing(d), ["verify_deferred"], "a pause in the checking of checkpoints, not a rollback");
  assert.equal((await stateOf(d)).hardWarning, "verify_deferred");
  assert.equal(d.engine.health().halted, null);
  assert.equal(d.model.checkpointPuts.length, 0, "and nothing is signed while it lasts");
  d.engine.stop();
});

test("a_rollback_of_an_unmarked_item_is_hard_even_while_marks_exist", async () => {
  const d = await hiddenB({ rolledBackC: true });
  // The pass that listed the vault already found that C is behind the checkpoint.
  assert.deepEqual(standing(d), ["server_shows_older_state"]);
  assert.equal(await d.engine.verifyNow(), "server_shows_older_state", "B explains its own disagreement, not C's");
  assert.deepEqual(standing(d), ["server_shows_older_state"]);
  assert.equal((await stateOf(d)).hardWarning, "server_shows_older_state");
  d.engine.stop();
});

test("a_checkpoint_that_lists_the_old_hash_of_a_hidden_item_at_its_old_revision_is_deferred", async () => {
  const d = await hiddenB({ oldB: true });
  assert.deepEqual(standing(d), [], "the listing pass still held the old copy of B");
  // The copy that was uploaded again is revision 1 with a new envelope; the checkpoint has revision 1 with the hash of the old one.
  assert.equal(await d.engine.verifyNow(), "verify_deferred");
  assert.deepEqual(standing(d), ["verify_deferred"]);
  d.engine.stop();
});

test("a_hidden_item_whose_floor_is_revision_1_keeps_its_mark_and_the_old_hash_is_a_pause", async () => {
  // B was at revision 1 when the checkpoint was made. The server hides it; this device uploads its copy again, and the server
  // numbers it from 1: the copy is revision 1 with a new envelope, and the checkpoint lists revision 1 with the old hash.
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A");
  setRow(model, client, ID_B, 1, "Hidden B");
  const d = await syncDevice({ model, client });
  await d.engine.start();
  model.pinCheckpoint();
  model.items.delete(ID_B);
  model.seq += 4;
  model.minValidSince = model.seq;
  setRow(model, client, ID_A, 2, "A two");
  await d.engine.syncNow();
  await until(() => model.items.has(ID_B) && d.engine.list().find((i) => i.id === ID_B)?.missingOnServer === false, "B is back as a copy");
  const marks = async () => (await d.store.getSetting(d.store.database.store, `sync.flags.${scope().accountId}.${scope().vaultId}.${scope().vkEpoch}`))?.marks ?? {};
  await until(async () => (await marks())[ID_B]?.kind === "reuploaded", "the mark stays: the copy is at the old floor itself");
  assert.equal((await marks())[ID_B].rev, 1);
  assert.equal(await d.engine.verifyNow(), "verify_deferred", "a pause, not a hard warning");
  assert.deepEqual(standing(d), ["verify_deferred"]);
  assert.equal(d.model.checkpointPuts.length, 0, "nothing is signed while it lasts");

  // An edit that passes the old floor ends the mark.
  await d.engine.update(ID_B, { name: "B two" }, 1);
  await until(async () => model.items.get(ID_B).rev === 2 && !(ID_B in (await marks())), "the mark ends above the floor");
  d.engine.stop();
});

test("a_row_below_its_floor_with_an_unrelated_mark_is_hard_and_not_deferred", async () => {
  // B was uploaded again (marked); the checkpoint of this moment lists the copy, so only the memory objects to B's old floor.
  const marked = await hiddenB();
  marked.model.pinCheckpoint();
  assert.equal(await marked.engine.verifyNow(), "verify_deferred", "the copy of the marked item alone is a pause");
  marked.engine.stop();

  // The same, and A, which has no mark, is below the floor the memory holds for it: no mark can explain that.
  const d = await hiddenB();
  d.model.pinCheckpoint();
  await d.memory.withLock(async (state) => {
    const floors = memoryOf(state.memory);
    floors.revs[ID_A] = 9;
    return { ...state, memory: new TextEncoder().encode(JSON.stringify(floors)) };
  });
  assert.equal(await d.engine.verifyNow(), "checkpoint_rolled_back");
  assert.deepEqual(standing(d), ["checkpoint_rolled_back"]);
  assert.equal(d.engine.health().halted, null);
  d.engine.stop();
});

test("an_old_checkpoint_does_not_give_a_pause_when_an_unmarked_row_is_below_its_floor", async () => {
  // The checkpoint lists B at revision 3, and the copy of B that was uploaded again is revision 1: that alone is a pause.
  // The core names it first and checks the memory last, so a row of A that is below its floor would never be seen.
  const d = await hiddenB();
  await d.memory.withLock(async (state) => {
    const floors = memoryOf(state.memory);
    floors.revs[ID_A] = 9; // A is held at revision 2
    return { ...state, memory: new TextEncoder().encode(JSON.stringify(floors)) };
  });
  assert.equal(await d.engine.verifyNow(), "server_shows_older_state");
  assert.deepEqual(standing(d), ["server_shows_older_state"]);
  d.engine.stop();
});

test("a_replayed_checkpoint_below_the_highest_verified_one_is_hard_and_not_a_pause", async () => {
  const d = await hiddenB();
  assert.equal((await stateOf(d)).verifiedSeq, 2, "the listing pass verified the checkpoint at seq 2");
  // The same checkpoint is a pause while nothing newer has been verified ...
  assert.equal(await d.engine.verifyNow(), "verify_deferred");
  // ... and hard once a newer one has verified: the server shows an old checkpoint again.
  await seed(d, { verifiedSeq: 50, hardWarning: null });
  assert.equal(await d.engine.verifyNow(), "server_shows_older_state");
  assert.deepEqual(standing(d), ["server_shows_older_state"]);
  d.engine.stop();
});

test("a_stored_warning_nobody_named_blocks_uploads", async () => {
  const { model, client } = withNewerRow();
  const d = await syncDevice({ model, client });
  await seed(d, { verifiedAt: T0 - 2 * DAY });
  await d.engine.start();
  assert.equal(model.checkpointPuts.length, 1, "verified and uploaded");
  // Another tab stores a code this engine has never seen, and the checkpoint cannot be read.
  await seed(d, { hardWarning: "a_code_nobody_named" });
  d.api.checkpointFaults.push({ kind: "network" });
  setRow(model, client, ID_D, 1, "D");
  await until(() => d.timers.pending > 0);
  d.timers.advance(660_000);
  await until(() => d.api.checkpointGets.length === 2, "the engine looks again");
  await d.engine.syncNow();
  assert.equal(model.checkpointPuts.length, 1, "an unknown warning is read as a serious one");
  d.engine.stop();
});

test("a_pause_is_not_tried_again_when_the_feed_shows_no_head", async () => {
  const d = await hiddenB();
  await settle(80); // the pass that brings the copy back may still be running
  const real = d.api.get;
  d.api.get = async (path) => {
    const answer = await real(path);
    if (!path.includes("/changes")) return answer;
    const { checkpoint: _head, ...rest } = answer;
    return rest;
  };
  assert.equal(await d.engine.verifyNow(), "verify_deferred");
  const asked = d.api.checkpointGets.length;
  await until(() => d.timers.pending > 0);
  d.timers.advance(400_000);
  await settle(60);
  await d.engine.syncNow();
  assert.equal(d.api.checkpointGets.length, asked, "nothing has moved, with or without a head in the feed");
  d.engine.stop();
});

test("a_pause_is_not_tried_again_until_the_feed_has_moved_or_a_day_has_passed", async () => {
  const d = await hiddenB();
  assert.equal(await d.engine.verifyNow(), "verify_deferred");
  const asked = d.api.checkpointGets.length;
  await until(() => d.timers.pending > 0);
  d.timers.advance(400_000);
  await settle(60);
  await d.engine.syncNow();
  assert.equal(d.api.checkpointGets.length, asked, "nothing has moved: the checkpoint is not asked for again");
  // The server's top moves (another device wrote): it is looked at again.
  setRow(d.model, d.client, ID_D, 1, "D");
  await until(() => d.timers.pending > 0);
  d.timers.advance(400_000);
  await until(() => d.api.checkpointGets.length === asked + 1, "a change in the feed makes it try again");
  await settle(60);
  const again = d.api.checkpointGets.length;
  // And after a day without a change.
  await until(() => d.timers.pending > 0);
  d.timers.advance(DAY + 10_000);
  await until(() => d.api.checkpointGets.length === again + 1, "a day later it tries again");
  assert.deepEqual(standing(d), ["verify_deferred"]);
  d.engine.stop();
});

test("a_409_on_a_reupload_with_the_cached_row_is_server_hid_item", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A");
  setRow(model, client, ID_B, 3, "B held by the server");
  const d = await syncDevice({ model, client });
  await d.engine.start();
  // The listing leaves B out; the server still has it (the upload answers with exactly the row this device holds).
  model.hidden.add(ID_B);
  model.seq += 4;
  model.minValidSince = model.seq;
  await d.engine.syncNow();
  await until(() => warningEvents(d, "server_hid_item").length === 1, "the server showed B when it was uploaded again");
  assert.deepEqual(warningEvents(d, "server_hid_item")[0], { kind: "warning", code: "server_hid_item", id: ID_B });
  const b = d.engine.list().find((i) => i.id === ID_B);
  assert.deepEqual([b.missingOnServer, b.blocked, b.pending], [false, false, false], "the mark is gone, nothing blocks the item");
  assert.deepEqual(standing(d).includes("server_hid_item"), true);
  assert.equal((await outbox.all(d.store.database.store, scope())).length, 0, "the upload that was queued is dropped");
  assert.equal(d.events.error.length, 0);
  assert.equal(d.model.writes.length, 0, "nothing was written");
  // It is only a warning: checkpoints are not held back by it.
  assert.equal(suspendsUpload("server_hid_item"), false);
  d.engine.stop();
});

test("a_409_with_another_row_is_still_refused_and_not_a_hidden_item", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A");
  setRow(model, client, ID_B, 3, "B");
  const d = await syncDevice({ model, client });
  await d.engine.start();
  model.hidden.add(ID_B);
  model.seq += 4;
  setRow(model, client, ID_B, 4, "B edited elsewhere"); // another row than the one this device holds
  model.minValidSince = model.seq;
  await d.engine.syncNow();
  // Nobody changed anything: the refusal of the automatic upload does not speak of a change (it is not a conflict to choose in).
  await until(() => d.events.error.some((e) => e.code === "reupload_refused" && e.id === ID_B), "the upload is refused");
  assert.equal(d.events.error.some((e) => e.code === "conflict"), false);
  assert.equal(warningEvents(d, "server_hid_item").length, 0);
  const refused = d.engine.list().find((i) => i.id === ID_B);
  assert.deepEqual([refused.blocked, refused.blockedReason, refused.conflict], [true, "reupload_refused", false], "refused, and not a conflict to choose in");
  d.engine.stop();
});

// ------------------------------------------------------------------ another tab, and a checkpoint that is newer than the feed

test("a_checkpoint_newer_than_the_feed_is_read_again_before_it_is_called_a_lie", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A");
  setRow(model, client, ID_B, 2, "B");
  const d = await syncDevice({ model, client });
  // Another device writes and uploads a checkpoint after this device has read the feed, before it asks for the checkpoint.
  const real = d.api.get;
  let once = true;
  d.api.get = async (path) => {
    if (path === "/api/sync/checkpoint" && once) {
      once = false;
      setRow(model, client, ID_A, 2, "A two");
      model.pinCheckpoint();
    }
    return real(path);
  };
  await d.engine.start();
  assert.equal(d.api.checkpointGets.length, 2, "the feed was read again and the checkpoint with it");
  assert.deepEqual(standing(d), [], "no bad feed");
  assert.equal(d.engine.list().find((i) => i.id === ID_A).name, "A two");
  assert.equal(memoryOf((await stateOf(d)).memory).checkpointSeq, 3);
  d.engine.stop();

  // A server that always shows a checkpoint above its own top is lying: after the second look it is a bad feed.
  const lying = new Model();
  setRow(lying, client, ID_A, 1, "A");
  lying.checkpoint = lying.autoCheckpoint(99);
  const e = await syncDevice({ model: lying, client });
  await e.engine.start();
  assert.equal(e.api.checkpointGets.length, 2);
  assert.deepEqual(standing(e), ["bad_feed"]);
  e.engine.stop();
});

test("a_floor_raised_by_another_tab_makes_the_verification_read_the_feed_again_once", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A");
  const d = await syncDevice({ model, client });
  // Between this tab's feed and its verification, the other tab saves a higher floor for A.
  const real = d.api.get;
  let once = true;
  d.api.get = async (path) => {
    if (path === "/api/sync/checkpoint" && once) {
      once = false;
      await d.memory.withLock(async (state) => {
        const memory = memoryOf(state.memory);
        memory.revs[ID_A] = 2;
        return { ...state, memory: new TextEncoder().encode(JSON.stringify(memory)) };
      });
    }
    return real(path);
  };
  await d.engine.start();
  // The first answer was held back (no warning was made), the feed was read again, and the second look is final.
  assert.equal(d.api.checkpointGets.length, 2);
  assert.deepEqual(warningEvents(d, "checkpoint_rolled_back").length, 1, "said once, after the second look");
  assert.deepEqual(standing(d), ["checkpoint_rolled_back"]);
  assert.equal(d.engine.health().halted, null);
  d.engine.stop();
});

test("the_uploaded_checkpoint_lists_every_row_it_was_made_from", async () => {
  const { model, client } = withNewerRow();
  const d = await syncDevice({ model, client });
  await seed(d, { verifiedAt: T0 - 2 * DAY });
  await d.engine.start();
  const stored = model.checkpoint;
  assert.equal(stored.seq, 3);
  const entries = stored.entries;
  assert.equal(entries.length, 3 * 56, "A, B and C");
  assert.equal(b64u.encode(stored.digest), model.checkpointPuts[0].digest);
  d.engine.stop();
});
