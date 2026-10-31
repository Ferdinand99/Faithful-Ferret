// Locking: the idle timer and the absolute lock time, and what a lock leaves
// behind (nothing: no worker, no open item, no decrypted index, no secret on
// the page, and the unlock screen where the vault was).
import assert from "node:assert/strict";
import { test } from "node:test";
import { autoLockFor, createAutoLock, DEFAULT_IDLE_MS, lockVault } from "../../src/lock.mjs";
import { createSyncEngine } from "../../src/sync/engine.mjs";
import { createWipeScope } from "../../src/views/common.mjs";
import { itemView } from "../../src/views/item.mjs";
import { shellView } from "../../src/views/shell.mjs";
import { unlockScreen } from "../../src/views/unlock.mjs";
import { freshStore, scope as syncScope } from "./idbHelpers.mjs";
import { counterRand, createFakeApi, createFakeClient, createFakeStore, FakeTimers, Model, until } from "./syncHelpers.mjs";
import { click, fakeClient, fakeClock, fakeEngine, fakePage, fakeSession, find, settle, t, textOf, withDom } from "./vaultHelpers.mjs";

/** An idle lock over a fake clock, a fake page and a counting session. */
function lockRig({ idleMs = 60_000 } = {}) {
  const clock = fakeClock();
  const page = fakePage();
  const rig = { clock, page, locks: 0, onLock: 0 };
  rig.session = { lock: async () => void (rig.locks += 1) };
  rig.lock = createAutoLock({ session: rig.session, now: clock.now, timers: clock, idleMs, doc: page, onLock: () => void (rig.onLock += 1) });
  return rig;
}

test("auto_lock_fires_after_idle_and_on_hidden_tab_timeout", async () => {
  // After the idle time, by the timer.
  let rig = lockRig();
  rig.lock.start();
  assert.equal(rig.lock.lockAt(), rig.clock.time + 60_000);
  rig.clock.advance(59_999);
  assert.equal(rig.locks, 0);
  rig.clock.advance(1);
  await settle();
  assert.equal(rig.locks, 1);
  assert.equal(rig.onLock, 1);
  assert.equal(rig.clock.pending, 0, "no timer is left");
  assert.equal(rig.page.listening, 0, "the page listener is removed");
  assert.equal(rig.lock.running(), false);

  // Activity moves the time on; the timer that was set earlier waits again.
  rig = lockRig();
  rig.lock.start();
  rig.clock.advance(30_000);
  assert.equal(rig.lock.touch(), true);
  rig.clock.advance(59_000);
  assert.equal(rig.locks, 0, "30 s + 59 s is inside the moved idle time");
  rig.clock.advance(1_000);
  await settle();
  assert.equal(rig.locks, 1, "and 60 s after the last touch it locks");

  // A hidden tab keeps its timer: the tab locks when the time is up.
  rig = lockRig();
  rig.lock.start();
  rig.page.change("hidden");
  rig.clock.advance(60_000);
  await settle();
  assert.equal(rig.locks, 1);

  // A hidden tab whose timers are slowed down or stopped (a background tab, a sleeping
  // laptop) locks the moment it is shown again, from the absolute time.
  rig = lockRig();
  rig.lock.start();
  rig.page.change("hidden");
  rig.clock.jump(61_000); // no timer ran
  assert.equal(rig.locks, 0);
  rig.page.change("visible");
  await settle();
  assert.equal(rig.locks, 1, "locked before anything could be used");
});

test("lock_at_is_checked_before_every_action", async () => {
  const rig = lockRig();
  rig.lock.start();
  rig.clock.jump(60_000); // the timer was late
  assert.equal(rig.lock.touch(), false, "the action is refused");
  await settle();
  assert.equal(rig.locks, 1);
  assert.equal(rig.lock.touch(), false, "and so is the next one: the vault is locked");
  assert.equal(rig.locks, 1, "the lock is made once");

  // Within the time, an action is allowed and moves the time on.
  const again = lockRig();
  again.lock.start();
  again.clock.jump(59_999);
  assert.equal(again.lock.touch(), true);
  assert.equal(again.lock.lockAt(), again.clock.time + 60_000);

  // A new start after an unlock opens it again.
  rig.lock.start();
  assert.equal(rig.lock.touch(), true);
});

test("the_idle_time_can_change_and_must_be_a_positive_whole_number", async () => {
  const rig = lockRig();
  assert.equal(DEFAULT_IDLE_MS, 15 * 60_000);
  rig.lock.start();
  rig.lock.setIdle(120_000);
  assert.equal(rig.lock.lockAt(), rig.clock.time + 120_000);
  rig.clock.advance(119_999);
  assert.equal(rig.locks, 0);
  rig.clock.advance(1);
  await settle();
  assert.equal(rig.locks, 1);
  for (const bad of [0, -1, 1.5, Number.NaN, Infinity, "60000", null]) {
    assert.throws(() => rig.lock.setIdle(bad), TypeError, String(bad));
    assert.throws(() => createAutoLock({ session: rig.session, idleMs: bad }), TypeError, String(bad));
  }
});

test("locking_twice_ends_the_worker_once_and_a_failing_session_still_wipes_the_screen", async () => {
  const rig = lockRig();
  rig.lock.start();
  await Promise.all([rig.lock.lock(), rig.lock.lock()]);
  assert.equal(rig.locks, 1);
  assert.equal(rig.onLock, 1);

  const failing = createAutoLock({
    session: { lock: async () => { throw new Error("the worker is gone"); } },
    now: rig.clock.now, timers: rig.clock, doc: rig.page, onLock: () => void (rig.onLock += 1),
  });
  failing.start();
  await failing.lock();
  assert.equal(rig.onLock, 2, "the screen is wiped even when the session cannot say it locked");
});

test("lock_ends_the_worker_and_clears_view_state", async () => {
  await withDom(async () => {
    const engine = fakeEngine({
      items: [{ id: "11".repeat(16), name: "Bank", type: "login", favorite: false, urls: [], username: "", rev: 1, pending: false, damaged: false, quarantined: false, missingOnServer: false, blocked: false, blockedReason: null, readOnly: false }],
      views: { ["11".repeat(16)]: { item_type: "login", name: "Bank", fields: [{ id: "password", label: "Password", kind: "password", value: null }], urls: [], has_notes: false, read_only: false } },
      secrets: { ["11".repeat(16)]: ["pw-SECRET-1"] },
    });
    const client = fakeClient(engine);
    client.locked = 0;
    const session = fakeSession({ client });
    const clock = fakeClock();
    const autoLock = autoLockFor(session, engine, { now: clock.now, timers: clock, doc: fakePage() });
    autoLock.start();

    const scope = createWipeScope();
    const id = "11".repeat(16);
    const content = await itemView({ engine, sync: engine, client, id, t, scope, touch: () => autoLock.touch() });
    const shell = shellView({
      t, engine, session, content, scope,
      lock: () => autoLock.lock(), touch: () => autoLock.touch(),
      onLocked: () => unlockScreen({ session, t, go() {}, onUnlocked() {} }),
    });
    await click(find(shell, "reveal", "f0"));
    assert.ok(textOf(shell).includes("pw-SECRET-1"), "the secret is on the page before the lock");

    await click(find(shell, "lock"));
    await settle();

    assert.equal(session.locked, 1, "the session ended the worker");
    assert.equal(client.locked, 1);
    assert.equal(engine.stopped, true, "the sync engine was stopped");
    assert.equal(engine.handles.size, 0, "no item is open");
    assert.deepEqual(engine.list(), [], "no decrypted summary is left");
    assert.ok(!textOf(shell).includes("pw-SECRET-1"), "no secret is in the page");
    assert.equal(find(shell, "reveal", "f0"), null);
    assert.equal(find(shell, "item"), null, "the item screen is gone");
    assert.equal(find(shell, "lock"), null, "so is the frame around it");
    assert.ok(find(shell, "unlock"), "the view is the unlock screen");
    assert.ok(find(shell, "password"), "which asks for the master password");
    assert.equal(autoLock.running(), false, "the idle timer is stopped");
  });
});

test("an_idle_lock_wipes_the_screen_the_same_way", async () => {
  await withDom(async () => {
    const engine = fakeEngine({ items: [] });
    const session = fakeSession({ client: { locked: 0 } });
    const clock = fakeClock();
    const autoLock = autoLockFor(session, engine, { now: clock.now, timers: clock, doc: fakePage(), idleMs: 60_000 });
    autoLock.start();
    const scope = createWipeScope();
    const content = document.createElement("section");
    const shell = shellView({
      t, engine, session, content, scope, lock: () => autoLock.lock(), touch: () => autoLock.touch(),
      onLocked: () => unlockScreen({ session, t, go() {}, onUnlocked() {} }),
    });
    clock.advance(60_000);
    await settle();
    assert.equal(session.locked, 1);
    assert.equal(engine.stopped, true);
    assert.ok(find(shell, "unlock"));
  });
});

test("lock_drops_the_decrypted_item_summary_index_and_open_handles", async () => {
  // The real sync engine over fakes (Spec: Fase 1 section 7.1: a lock deletes decrypted objects).
  const model = new Model();
  const client = createFakeClient();
  const store = await createFakeStore({ db: await freshStore() });
  const engine = createSyncEngine({
    api: createFakeApi(model), client: { vault: client.vault }, store, scope: syncScope(), timers: new FakeTimers(), rand: counterRand(3),
  });
  await engine.start();
  const id = await engine.create({ item_type: "login", name: "Bank" });
  await until(() => model.items.get(id)?.rev === 1, "the item is on the server");
  const opened = await engine.open(id);
  assert.equal(engine.list().length, 1, "the index holds a summary");
  assert.ok(client.vault.handles.has(opened.handle), "an item is open in the worker");

  // The sync service wraps the engine; `stop` is what the lock calls.
  const sync = { stop: () => engine.stop() };
  let ended = 0;
  const session = { lock: async () => void (ended += 1) };
  await lockVault({ session, sync });

  assert.deepEqual(engine.list(), [], "the index is dropped");
  assert.equal(client.vault.handles.size, 0, "every open item is closed");
  assert.equal(ended, 1, "and the worker is ended");
  await assert.rejects(() => engine.open(id), { code: "stopped" });

  // Locking again, or with no engine, is harmless.
  await lockVault({ session, sync });
  await lockVault({ session, sync: null });
  assert.equal(ended, 3);
});

test("an_engine_that_will_not_stop_does_not_keep_the_worker_alive", async () => {
  let ended = 0;
  await lockVault({
    session: { lock: async () => void (ended += 1) },
    sync: { stop() { throw new Error("already gone"); } },
  });
  assert.equal(ended, 1);
});

test("a_lock_wipes_every_frame_that_was_built_not_only_the_last", async () => {
  await withDom(async () => {
    const id = "11".repeat(16);
    const engine = fakeEngine({
      items: [{ id, name: "Bank", type: "login", favorite: false, urls: [], username: "", rev: 1, pending: false, damaged: false, quarantined: false, missingOnServer: false, blocked: false, blockedReason: null, readOnly: false }],
      views: { [id]: { item_type: "login", name: "Bank", fields: [{ id: "password", label: "Password", kind: "password", value: null }], urls: [], has_notes: false, read_only: false } },
      secrets: { [id]: ["pw-SECRET-1"] },
    });
    const client = fakeClient(engine);
    const session = fakeSession({ client });
    const clock = fakeClock();
    const autoLock = autoLockFor(session, engine, { now: clock.now, timers: clock, doc: fakePage() });
    autoLock.start();
    const frame = async (content, scope) => shellView({
      t, engine, session, content, scope, lock: () => autoLock.lock(), touch: () => autoLock.touch(),
      onLocked: () => unlockScreen({ session, t, go() {}, onUnlocked() {} }),
    });

    // The item frame is the one on the page; a route that finished later built the list frame, which is detached.
    const scopeA = createWipeScope();
    const first = await frame(await itemView({ engine, sync: engine, client, id, t, scope: scopeA }), scopeA);
    first.isConnected = true;
    await click(find(first, "reveal", "f0"));
    assert.ok(textOf(first).includes("pw-SECRET-1"));
    const scopeB = createWipeScope();
    const second = await frame(document.createElement("section"), scopeB);
    second.isConnected = false;

    await click(find(second, "lock"));
    await settle();
    assert.ok(!textOf(first).includes("pw-SECRET-1"), "the frame on the page is wiped");
    assert.ok(find(first, "unlock-host") || find(first, "unlock"), "and shows the unlock screen");
    assert.equal(find(second, "unlock-host"), null, "a frame that is not on the page is only emptied");
  });
});

test("a_frame_that_left_the_page_is_wiped_when_the_next_one_is_built", async () => {
  await withDom(async () => {
    const id = "11".repeat(16);
    const engine = fakeEngine({
      items: [{ id, name: "Bank", type: "login", favorite: false, urls: [], username: "", rev: 1, pending: false, damaged: false, quarantined: false, missingOnServer: false, blocked: false, blockedReason: null, readOnly: false }],
      views: { [id]: { item_type: "login", name: "Bank", fields: [{ id: "password", label: "Password", kind: "password", value: null }], urls: [], has_notes: false, read_only: false } },
      secrets: { [id]: ["pw-SECRET-1"] },
    });
    const client = fakeClient(engine);
    const session = fakeSession({ client });
    const make = async (content, scope) => shellView({ t, engine, session, content, scope, lock: async () => {}, touch: () => true, onLocked: () => document.createElement("div") });
    const scopeA = createWipeScope();
    const first = await make(await itemView({ engine, sync: engine, client, id, t, scope: scopeA }), scopeA);
    first.isConnected = true;
    await click(find(first, "reveal", "f0"));
    assert.ok(textOf(first).includes("pw-SECRET-1"));
    // The next route builds its frame while the first is still on the page, then the router swaps them.
    const second = await make(document.createElement("section"), createWipeScope());
    second.isConnected = true;
    first.isConnected = false;
    assert.ok(textOf(first).includes("pw-SECRET-1"), "still there until the next frame is built");
    await make(document.createElement("section"), createWipeScope());
    assert.ok(!textOf(first).includes("pw-SECRET-1"), "a screen that is gone does not keep a revealed secret");
  });
});
