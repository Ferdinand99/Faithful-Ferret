// The attempt counter, the waits and the offline window of the local PIN store
// (src/background/localUnlock.mjs). The unlock itself is a fake that answers
// from a script: no WASM, no Argon2id.
import assert from "node:assert/strict";
import { test } from "node:test";
import { MAX_PIN_FAILURES, OFFLINE_PIN_WINDOW_MS, PIN_STORE, PIN_WAIT_MS, UNLOCK_DB_NAME } from "../../src/background/localUnlock.mjs";
import { ACCOUNT, DAY, SERVER, createWorld, fakeUnlock, makeBlob } from "./localUnlockHelpers.mjs";

/** A world with a PIN saved on disk. */
async function withPin(options = {}) {
  const world = createWorld(options);
  await world.store.save(SERVER, ACCOUNT, makeBlob(), { location: "disk", acknowledged: true });
  return world;
}

/** The one stored record of the disk store. @param {ReturnType<typeof createWorld>} world */
const record = (world) => /** @type {any} */ (world.idb.dump(UNLOCK_DB_NAME, PIN_STORE)[0]?.value);

const never = () => new Promise(() => {});

test("the_waits_are_0_0_5_15_30_seconds", async () => {
  assert.deepEqual([...PIN_WAIT_MS], [0, 0, 5_000, 15_000, 30_000]);
  assert.ok(Object.isFrozen(PIN_WAIT_MS));
  assert.equal(MAX_PIN_FAILURES, 5);
  const world = await withPin();
  const unlock = fakeUnlock(["wrong"]);
  const expected = [0, 5_000, 15_000, 30_000];
  for (let i = 0; i < 4; i++) {
    const answer = await world.store.attempt(SERVER, ACCOUNT, { online: true }, unlock.run);
    assert.deepEqual(answer, { result: "wrong", failuresLeft: 4 - i, waitMs: expected[i] });
    if (expected[i] > 0) {
      // Too early: no attempt, no count, the wait that is left.
      world.clock.advance(expected[i] - 1);
      const early = await world.store.attempt(SERVER, ACCOUNT, { online: true }, unlock.run);
      assert.deepEqual(early, { result: "wait", failuresLeft: 4 - i, waitMs: 1 });
      assert.equal(unlock.calls.count, i + 1, "an attempt in the wait does not run the unlock");
      world.clock.advance(1);
    }
  }
  const status = await world.store.status(SERVER, ACCOUNT);
  assert.equal(status.failuresLeft, 1);
  // The fifth failure wipes the record.
  const last = await world.store.attempt(SERVER, ACCOUNT, { online: true }, unlock.run);
  assert.deepEqual(last, { result: "wiped", failuresLeft: 0, waitMs: 0 });
  assert.equal((await world.store.status(SERVER, ACCOUNT)).set, false);
  assert.equal(world.idb.dump(UNLOCK_DB_NAME, PIN_STORE).length, 0);
});

test("a_clock_set_back_does_not_lock_a_pin_for_longer_than_the_longest_wait", async () => {
  const world = await withPin();
  const unlock = fakeUnlock(["wrong"]);
  for (let i = 0; i < 3; i++) {
    await world.store.attempt(SERVER, ACCOUNT, { online: true }, unlock.run);
    world.clock.advance(60_000);
  }
  world.clock.advance(-5 * DAY);
  const status = await world.store.status(SERVER, ACCOUNT);
  assert.ok(status.waitMs <= 30_000);
});

test("the_counter_is_raised_and_stored_before_the_unlock_runs", async () => {
  const world = await withPin();
  /** @type {{ failures: number, committed: boolean } | null} */
  let seen = null;
  const answer = await world.store.attempt(SERVER, ACCOUNT, { online: true }, async () => {
    const writes = world.idb.log.filter((entry) => entry.mode === "readwrite" && entry.ops.includes(`put:${PIN_STORE}`));
    seen = { failures: record(world).failures, committed: writes.at(-1)?.committed === true };
    return { ok: true };
  });
  assert.deepEqual(seen, { failures: 1, committed: true });
  assert.equal(answer.result, "ok");
  assert.equal(record(world).failures, 0);
});

test("an_interrupted_attempt_counts", async () => {
  const world = await withPin();
  const unlock = { calls: 0 };
  // The process dies during the unlock: it never answers.
  void world.store.attempt(SERVER, ACCOUNT, { online: true }, () => {
    unlock.calls += 1;
    return never();
  });
  while (unlock.calls === 0) await new Promise((resolve) => setImmediate(resolve));
  // A new background: nothing of the first one is left but the stored record.
  const restarted = world.another();
  const status = await restarted.status(SERVER, ACCOUNT);
  assert.equal(status.failuresLeft, 4);
  assert.equal(record(world).failures, 1);
});

test("an_interrupted_attempt_in_the_session_location_counts_too", async () => {
  const world = createWorld();
  await world.store.save(SERVER, ACCOUNT, makeBlob(), { location: "session" });
  let started = false;
  void world.store.attempt(SERVER, ACCOUNT, { online: true }, () => {
    started = true;
    return never();
  });
  while (!started) await new Promise((resolve) => setImmediate(resolve));
  assert.equal((await world.another().status(SERVER, ACCOUNT)).failuresLeft, 4);
});

test("a_counter_at_five_after_an_interrupted_attempt_wipes_without_argon2", async () => {
  const world = await withPin();
  const wrong = fakeUnlock(["wrong"]);
  for (let i = 0; i < 4; i++) {
    const answer = await world.store.attempt(SERVER, ACCOUNT, { online: true }, wrong.run);
    world.clock.advance(60_000);
    assert.equal(answer.result, "wrong");
  }
  assert.equal(record(world).failures, 4);
  // The fifth attempt is interrupted.
  let started = false;
  void world.store.attempt(SERVER, ACCOUNT, { online: true }, () => {
    started = true;
    return never();
  });
  while (!started) await new Promise((resolve) => setImmediate(resolve));
  assert.equal(record(world).failures, 5);
  // After a restart the next attempt finds five and wipes: the unlock never runs.
  const restarted = world.another();
  const probe = fakeUnlock(["ok"]);
  const answer = await restarted.attempt(SERVER, ACCOUNT, { online: true }, probe.run);
  assert.deepEqual(answer, { result: "wiped", failuresLeft: 0, waitMs: 0 });
  assert.equal(probe.calls.count, 0);
  assert.equal(world.idb.dump(UNLOCK_DB_NAME, PIN_STORE).length, 0);
});

test("a_success_resets_the_counter_in_its_own_transaction", async () => {
  const world = await withPin();
  const wrong = fakeUnlock(["wrong"]);
  await world.store.attempt(SERVER, ACCOUNT, { online: true }, wrong.run);
  assert.equal(record(world).failures, 1);
  let atUnlock = -1;
  const answer = await world.store.attempt(SERVER, ACCOUNT, { online: true }, async () => {
    atUnlock = world.idb.log.length;
    return { ok: true };
  });
  assert.deepEqual(answer, { result: "ok", failuresLeft: 5, waitMs: 0 });
  const after = world.idb.log.slice(atUnlock).filter((entry) => entry.mode === "readwrite");
  assert.equal(after.length, 1, "the reset is one transaction of its own, after the unlock");
  assert.ok(after[0].committed);
  assert.equal(record(world).failures, 0);
  assert.equal(record(world).lastFailureAt, null);
  // The raise was a different transaction, committed before the unlock.
  const before = world.idb.log.slice(0, atUnlock).filter((entry) => entry.mode === "readwrite" && entry.committed);
  assert.ok(before.length >= 1);
});

test("a_success_is_reported_even_if_the_reset_cannot_be_written", async () => {
  const world = await withPin();
  const answer = await world.store.attempt(SERVER, ACCOUNT, { online: true }, async () => {
    world.idb.state.failOp = (tx, label) => (tx.mode === "readwrite" && label === `put:${PIN_STORE}` ? new Error("disk full") : null);
    return { ok: true };
  });
  world.idb.state.failOp = null;
  assert.equal(answer.result, "ok");
  // The raised counter stays: the safe direction.
  assert.equal(record(world).failures, 1);
});

test("a_master_password_unlock_resets_the_pin_counter", async () => {
  const world = await withPin();
  const wrong = fakeUnlock(["wrong"]);
  await world.store.attempt(SERVER, ACCOUNT, { online: true }, wrong.run);
  world.clock.advance(60_000);
  await world.store.attempt(SERVER, ACCOUNT, { online: true }, wrong.run);
  assert.equal((await world.store.status(SERVER, ACCOUNT)).failuresLeft, 3);
  await world.store.resetFailures(SERVER, ACCOUNT);
  const status = await world.store.status(SERVER, ACCOUNT);
  assert.equal(status.failuresLeft, 5);
  assert.equal(status.waitMs, 0);
  assert.equal(status.set, true);
  // Nothing to reset where there is no PIN: no record appears.
  await world.store.resetFailures(SERVER, "c3".repeat(16));
  assert.equal(world.idb.dump(UNLOCK_DB_NAME, PIN_STORE).length, 1);
});

test("an_out_of_memory_attempt_counts_and_says_so", async () => {
  const world = await withPin();
  const unlock = fakeUnlock(["out_of_memory"]);
  const answer = await world.store.attempt(SERVER, ACCOUNT, { online: true }, unlock.run);
  assert.deepEqual(answer, { result: "out_of_memory", failuresLeft: 4, waitMs: 0 });
  assert.equal(record(world).failures, 1);
});

test("a_throwing_unlock_counts_as_a_wrong_pin", async () => {
  const world = await withPin();
  const answer = await world.store.attempt(SERVER, ACCOUNT, { online: true }, fakeUnlock(["throw"]).run);
  assert.equal(answer.result, "wrong");
  assert.equal(answer.failuresLeft, 4);
});

test("attempts_run_one_at_a_time", async () => {
  const world = await withPin();
  let running = 0;
  let most = 0;
  /** @type {string[]} */
  const order = [];
  /** @type {() => void} */
  let release = () => {};
  const gate = new Promise((resolve) => {
    release = () => resolve(undefined);
  });
  /** @param {string} name @param {boolean} hold */
  const unlock = (name, hold) => async () => {
    running += 1;
    most = Math.max(most, running);
    order.push(`start ${name}`);
    if (hold) await gate;
    order.push(`end ${name}`);
    running -= 1;
    return /** @type {const} */ ({ ok: false, reason: "wrong" });
  };
  const first = world.store.attempt(SERVER, ACCOUNT, { online: true }, unlock("a", true));
  const second = world.store.attempt(SERVER, ACCOUNT, { online: true }, unlock("b", false));
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.deepEqual(order, ["start a"], "the second attempt waits for the first");
  release();
  const [a, b] = await Promise.all([first, second]);
  assert.deepEqual(order, ["start a", "end a", "start b", "end b"]);
  assert.equal(most, 1);
  // The second one saw the counter of the first (after one failure there is no wait), so both counted.
  assert.equal(a.failuresLeft, 4);
  assert.equal(b.failuresLeft, 3);
});

test("concurrent_tries_cannot_get_more_than_five_attempts", async () => {
  const world = await withPin();
  const unlock = fakeUnlock(["wrong"]);
  const answers = await Promise.all(Array.from({ length: 8 }, () => world.store.attempt(SERVER, ACCOUNT, { online: true }, unlock.run)));
  // Attempt 3 and later wait for the clock, which does not move: nothing past the third failure runs.
  assert.ok(unlock.calls.count <= MAX_PIN_FAILURES);
  assert.equal(answers.filter((a) => a.result === "wrong").length, 2);
  assert.equal(answers.filter((a) => a.result === "wait").length, 6);
});

test("durability_strict_is_used_or_the_default_is_shown_durable", async () => {
  // An engine that knows the option gets it on every write.
  const world = await withPin();
  await world.store.attempt(SERVER, ACCOUNT, { online: true }, fakeUnlock(["wrong"]).run);
  const writes = world.idb.log.filter((entry) => entry.mode === "readwrite");
  assert.ok(writes.length >= 3);
  for (const entry of writes) assert.deepEqual(entry.options, { durability: "strict" });
  // An engine that rejects the option (a TypeError) gets the plain transaction, and the counter is still written
  // before the unlock: the default of IndexedDB commits a transaction before `complete` fires, which is what the
  // attempt waits for. Whether the engine has flushed that commit to disk cannot be seen from script; Firefox's default
  // durability is the strict one, and that is the engine this extension runs in.
  const plain = await withPin({ acceptDurability: false });
  /** @type {number | null} */
  let failures = null;
  await plain.store.attempt(SERVER, ACCOUNT, { online: true }, async () => {
    failures = record(plain).failures;
    return { ok: true };
  });
  assert.equal(failures, 1);
  for (const entry of plain.idb.log.filter((e) => e.mode === "readwrite")) assert.equal(entry.options, undefined);
});

test("a_stale_blob_is_deleted_without_counting", async () => {
  const world = await withPin();
  const answer = await world.store.attempt(SERVER, ACCOUNT, { online: true }, fakeUnlock(["stale"]).run);
  assert.deepEqual(answer, { result: "stale", failuresLeft: 0, waitMs: 0 });
  assert.equal(world.idb.dump(UNLOCK_DB_NAME, PIN_STORE).length, 0);
  assert.equal((await world.store.status(SERVER, ACCOUNT)).set, false);
  // Nothing was left behind to count: another attempt finds no PIN.
  assert.equal((await world.store.attempt(SERVER, ACCOUNT, { online: true }, fakeUnlock(["ok"]).run)).result, "none");
});

test("a_record_wiped_while_the_unlock_runs_is_not_reported_as_an_unlock", async () => {
  const world = await withPin();
  const answer = await world.store.attempt(SERVER, ACCOUNT, { online: true }, async () => {
    await world.store.wipe(SERVER, ACCOUNT, "signed_out");
    return { ok: true };
  });
  assert.equal(answer.result, "none");
  assert.equal(world.idb.dump(UNLOCK_DB_NAME, PIN_STORE).length, 0, "the record is not written back");
});

test("the_blob_handed_to_the_unlock_is_zeroed_afterwards", async () => {
  const world = await withPin();
  const unlock = fakeUnlock(["ok"]);
  await world.store.attempt(SERVER, ACCOUNT, { online: true }, unlock.run);
  const [blob] = unlock.calls.blobs;
  assert.ok(blob.wrap.every((b) => b === 0) && blob.deviceSalt.every((b) => b === 0) && blob.methodId.every((b) => b === 0));
  assert.deepEqual(Object.keys(blob).sort(), ["deviceSalt", "methodId", "pinProfile", "rule", "vkEpoch", "wrap"]);
});

test("a_record_missing_a_field_is_wiped_not_repaired", async () => {
  // Deleting the counter (or any single key) of the record does not reset anything: the record is wiped.
  const world = await withPin();
  const { failures, ...broken } = record(world);
  void failures;
  world.idb.plant(UNLOCK_DB_NAME, PIN_STORE, [SERVER, ACCOUNT], broken);
  const unlock = fakeUnlock(["ok"]);
  const answer = await world.store.attempt(SERVER, ACCOUNT, { online: true }, unlock.run);
  assert.equal(answer.result, "none");
  assert.equal(unlock.calls.count, 0);
  assert.equal(world.idb.dump(UNLOCK_DB_NAME, PIN_STORE).length, 0);
});

test("offline_pin_works_within_seven_days_of_the_last_contact", async () => {
  const world = await withPin();
  world.clock.advance(OFFLINE_PIN_WINDOW_MS - 1);
  assert.equal((await world.store.status(SERVER, ACCOUNT)).offlineOk, true);
  const unlock = fakeUnlock(["ok"]);
  const answer = await world.store.attempt(SERVER, ACCOUNT, { online: false }, unlock.run);
  assert.equal(answer.result, "ok");
  // Exactly seven days is still inside; one millisecond more is not.
  world.clock.advance(1);
  assert.equal((await world.store.status(SERVER, ACCOUNT)).offlineOk, true);
  world.clock.advance(1);
  assert.equal((await world.store.status(SERVER, ACCOUNT)).offlineOk, false);
});

test("offline_pin_needs_the_server_after_seven_days_and_works_again_after_contact", async () => {
  const world = await withPin();
  world.clock.advance(7 * DAY + 1);
  const unlock = fakeUnlock(["ok"]);
  const expired = await world.store.attempt(SERVER, ACCOUNT, { online: false }, unlock.run);
  assert.deepEqual(expired, { result: "offline_expired", failuresLeft: 5, waitMs: 0 });
  assert.equal(unlock.calls.count, 0);
  assert.equal(record(world).failures, 0, "an expired window does not count");
  // Being online does not relax the window: a renewal has to succeed first (and the PIN is not deleted meanwhile).
  const stillExpired = await world.store.attempt(SERVER, ACCOUNT, { online: true }, unlock.run);
  assert.equal(stillExpired.result, "offline_expired");
  assert.equal(unlock.calls.count, 0);
  assert.equal(record(world).failures, 0);
  assert.equal((await world.store.status(SERVER, ACCOUNT)).set, true);
  // After the renewal (the caller calls markContact) the PIN works, online or not.
  await world.store.markContact(SERVER, ACCOUNT);
  assert.equal((await world.store.attempt(SERVER, ACCOUNT, { online: true }, unlock.run)).result, "ok");
  assert.equal((await world.store.attempt(SERVER, ACCOUNT, { online: false }, unlock.run)).result, "ok");
});

test("after_seven_days_a_token_renewal_while_locked_allows_the_pin", async () => {
  const world = await withPin();
  world.clock.advance(8 * DAY);
  assert.equal((await world.store.status(SERVER, ACCOUNT)).offlineOk, false);
  // The vault is locked: no unlock has run. The renewal alone moves the window.
  await world.store.markContact(SERVER, ACCOUNT);
  const status = await world.store.status(SERVER, ACCOUNT);
  assert.equal(status.offlineOk, true);
  assert.equal(status.failuresLeft, 5);
  world.clock.advance(7 * DAY);
  assert.equal((await world.store.status(SERVER, ACCOUNT)).offlineOk, true);
  world.clock.advance(1);
  assert.equal((await world.store.status(SERVER, ACCOUNT)).offlineOk, false);
});

test("a_revoked_answer_to_that_renewal_wipes_the_pin", async () => {
  for (const reason of /** @type {const} */ (["device_revoked", "token_reused", "token_expired"])) {
    const world = await withPin();
    world.clock.advance(8 * DAY);
    const unlock = fakeUnlock(["ok"]);
    // The caller's renewal answers `reason`: it wipes. No unlock runs and nothing counts.
    await world.store.wipe(SERVER, ACCOUNT, reason);
    assert.equal((await world.store.status(SERVER, ACCOUNT)).set, false);
    assert.equal((await world.store.attempt(SERVER, ACCOUNT, { online: false }, unlock.run)).result, "none");
    assert.equal(unlock.calls.count, 0);
    assert.equal(world.idb.dump(UNLOCK_DB_NAME, PIN_STORE).length, 0);
  }
});

test("mark_online_needs_the_post_unlock_checks", async () => {
  const world = await withPin();
  const saved = record(world).lastOnlineAt;
  world.clock.advance(2 * DAY);
  // An unlock alone (the checks after it have not passed yet) does not touch lastOnlineAt ...
  await world.store.attempt(SERVER, ACCOUNT, { online: true }, fakeUnlock(["ok"]).run);
  assert.equal(record(world).lastOnlineAt, saved);
  assert.equal((await world.store.status(SERVER, ACCOUNT)).lastOnlineAt, saved);
  // ... only markOnline does, and it is not a contact: the window does not move.
  await world.store.markOnline(SERVER, ACCOUNT);
  assert.equal(record(world).lastOnlineAt, world.clock.now());
  const contact = record(world).lastContactAt;
  assert.equal(contact, world.clock.now() - 2 * DAY);
  world.clock.advance(6 * DAY);
  assert.equal((await world.store.status(SERVER, ACCOUNT)).offlineOk, false);
  // No record, no write.
  await world.store.markOnline(SERVER, "c3".repeat(16));
  assert.equal(world.idb.dump(UNLOCK_DB_NAME, PIN_STORE).length, 1);
});

test("the_window_counts_from_the_last_contact_and_highest_seen_only_guards_rollback", async () => {
  const world = await withPin();
  const start = world.clock.now();
  world.clock.advance(5 * DAY);
  await world.store.tick();
  assert.equal(record(world).highestSeenAt, start + 5 * DAY);
  assert.equal(record(world).lastContactAt, start);
  // Seven days after the contact, not seven days after the highest time seen.
  world.clock.set(start + 7 * DAY);
  assert.equal((await world.store.status(SERVER, ACCOUNT)).offlineOk, true);
  world.clock.set(start + 7 * DAY + 1);
  assert.equal((await world.store.status(SERVER, ACCOUNT)).offlineOk, false);
  assert.equal((await world.store.attempt(SERVER, ACCOUNT, { online: false }, fakeUnlock(["ok"]).run)).result, "offline_expired");
});

test("a_clock_set_back_below_the_highest_seen_time_needs_the_server", async () => {
  const world = await withPin();
  const start = world.clock.now();
  world.clock.advance(3 * DAY);
  await world.store.tick();
  // Back to a time inside the window of the contact, but below what was seen.
  world.clock.set(start + 2 * DAY);
  assert.equal((await world.store.status(SERVER, ACCOUNT)).offlineOk, false);
  const unlock = fakeUnlock(["ok"]);
  assert.equal((await world.store.attempt(SERVER, ACCOUNT, { online: false }, unlock.run)).result, "offline_expired");
  assert.equal(unlock.calls.count, 0);
  assert.equal((await world.store.status(SERVER, ACCOUNT)).set, true, "the PIN is not deleted");
  // A renewal that succeeds gives it back.
  await world.store.markContact(SERVER, ACCOUNT);
  assert.equal((await world.store.attempt(SERVER, ACCOUNT, { online: false }, unlock.run)).result, "ok");
});

test("tick_writes_only_when_the_time_has_moved_on_and_never_down", async () => {
  const world = await withPin();
  const writes = () => world.idb.log.filter((entry) => entry.mode === "readwrite").length;
  const before = writes();
  world.clock.advance(1_000);
  await world.store.tick();
  assert.equal(writes(), before, "a few seconds do not cost a disk write");
  const high = record(world).highestSeenAt;
  world.clock.advance(-DAY);
  await world.store.tick();
  assert.equal(record(world).highestSeenAt, high);
});

test("a_clock_set_back_needs_a_renewal_also_when_the_caller_says_online", async () => {
  const world = await withPin();
  const start = world.clock.now();
  world.clock.advance(3 * DAY);
  await world.store.tick();
  world.clock.set(start + 2 * DAY);
  const unlock = fakeUnlock(["ok"]);
  assert.equal((await world.store.attempt(SERVER, ACCOUNT, { online: true }, unlock.run)).result, "offline_expired");
  assert.equal(unlock.calls.count, 0);
  await world.store.markContact(SERVER, ACCOUNT);
  assert.equal((await world.store.attempt(SERVER, ACCOUNT, { online: true }, unlock.run)).result, "ok");
});

test("a_pin_saved_while_an_old_attempt_runs_is_not_wiped_by_that_attempt", async () => {
  const world = await withPin();
  // The old blob turns out stale while a new PIN is being saved: only the old blob may go.
  const answer = await world.store.attempt(SERVER, ACCOUNT, { online: true }, async () => {
    await world.store.save(SERVER, ACCOUNT, makeBlob({ fill: 50 }), { location: "disk", acknowledged: true });
    return { ok: false, reason: "stale" };
  });
  assert.equal(answer.result, "stale");
  const status = await world.store.status(SERVER, ACCOUNT);
  assert.equal(status.set, true);
  assert.equal(status.failuresLeft, 5);
  assert.equal(record(world).methodId[0], 50);
});
