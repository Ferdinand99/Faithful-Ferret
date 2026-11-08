// The sync matrix against the engine: the seven scenarios of the first prototype, then seeded random runs of two or three browsers (a browser
// can have two or three tabs: one holds the owner lock and runs the engine, the others are on standby, and the user moves the engine with "Use
// here") against a model of the server that has every rule of the sync routes and can fail on request, with the invariants of the design checked
// after every step and at rest. Spec: Fase 1 section 8 and section 14.7.
//
// `FERRET_MATRIX_RUNS` sets how many seeded runs the randomised tests make (500 by default, 5000 at the gate); a failing run names its
// seed, and `FERRET_MATRIX_SEED=<seed>[,<seed>...]` runs the named seeds of the randomised tests alone.
//
// What the model does not assert, because it is reported (the todo tests below). `FERRET_MATRIX_STRICT=1` takes every one of these tolerances
// away (`KNOWN_GAPS` in `syncModel.mjs`), and the random runs then fail on them; `FERRET_MATRIX_TOLERATE=purge` names the ones that are still
// let through in a strict run:
//   known gap, purged tombstone  a checkpoint can list the item of a purged tombstone live, and a device that still holds a purged tombstone is
//            at odds with a checkpoint that lacks it (todo tests `a_purged_tombstone_that_the_checkpoint_still_lists_live_is_no_alarm` and
//            `a_device_that_still_holds_a_purged_tombstone_is_no_alarm_for_a_checkpoint_that_lacks_it`); the model purges only what the checkpoint
//            lists and no device holds
import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError } from "../../src/api.mjs";
import { outbox } from "../../src/store/outbox.mjs";
import { createLiveChannel } from "../../src/sync/events.mjs";
import { loadSyncState } from "../../src/store/syncState.mjs";
import { setSetting } from "../../src/store/settings.mjs";
import { saveSyncState } from "../../src/store/syncState.mjs";
import { ACCOUNT, scope, SERVER } from "./idbHelpers.mjs";
import { fakePageEvents, fakeStreamApi } from "./liveHelpers.mjs";
import { currentRev, memoryBytes, settle, until } from "./syncHelpers.mjs";
import { ACTIONS, CALM_ACTIONS, POLL_MS, rngOf, Sim } from "./syncModel.mjs";

const RUNS = Number(process.env.FERRET_MATRIX_RUNS ?? 500);
const ONLY = process.env.FERRET_MATRIX_SEED ? process.env.FERRET_MATRIX_SEED.split(",").map(Number) : null;
const STEPS = 40;
const YEARS_MS = 10 * 365 * 86_400 * 1000;

const draft = (name) => ({ item_type: "login", name });
const shows = (dev, id) => dev.engine.list().find((item) => item.id === id);
const nameOf = async (dev, id) => {
  const open = await dev.engine.open(id);
  try {
    return open.view.name;
  } finally {
    await open.close();
  }
};
/** The device reads the feed and sends what waits, after the time it takes the engine to try again has gone by. */
async function pump(dev) {
  dev.d.timers.advance(POLL_MS + 1_000);
  await dev.engine.syncNow();
  await settle(20);
}
const online = (...devs) => {
  for (const dev of devs) dev.offline = false;
};
const offline = (...devs) => {
  for (const dev of devs) dev.offline = true;
};
/** Waits until the server holds the item at this revision. */
const untilServerRev = (sim, id, rev) => until(() => sim.server.items.get(id)?.rev === rev, `the server has ${id.slice(0, 4)} at rev ${rev}`);
const queued = (dev) => outbox.all(dev.d.store.database.store, scope());

/** Starts the devices of a scenario. */
async function world(layout = [1, 1], options = {}) {
  const sim = new Sim(1, { layout, ...options });
  await sim.start();
  return sim;
}

// ------------------------------------------------------------------------- the seven scenarios

test("seven_phase_0a_scenarios_against_the_engine", async (t) => {
  await t.test("concurrent_edit_conflict", async () => {
    const sim = await world();
    const [a, b] = sim.devices;
    const id = await a.engine.create(draft("v0"));
    await untilServerRev(sim, id, 1);
    await b.engine.syncNow();
    assert.equal(await nameOf(b, id), "v0");

    // Both change it. The laptop gets there first; the phone has no network when it edits.
    offline(b);
    await a.engine.update(id, { name: "from the laptop" }, currentRev(a.engine, id));
    await b.engine.update(id, { name: "from the phone" }, currentRev(b.engine, id));
    await untilServerRev(sim, id, 2);
    online(b);
    await pump(b);

    // The phone has a conflict: nothing is merged and nothing is sent over the laptop's row.
    assert.equal(shows(b, id).conflict, true);
    const writes = sim.server.writes.length;
    await pump(b);
    assert.equal(sim.server.writes.length, writes, "syncing again does not send the draft over the other one either");
    const both = await b.engine.conflict(id);
    assert.equal(both.local.view.name, "from the phone");
    assert.equal(both.server.view.name, "from the laptop");
    await both.close();
    assert.equal(await nameOf(a, id), "from the laptop");

    // "Keep mine": the draft goes out on top of the laptop's row.
    await b.engine.resolve(id, "mine");
    await pump(b);
    await pump(a);
    for (const dev of [a, b]) {
      assert.equal(await nameOf(dev, id), "from the phone");
      assert.equal(shows(dev, id).rev, 3);
      assert.equal(shows(dev, id).conflict, false);
      assert.equal(shows(dev, id).pending, false);
    }

    // The other way in: "keep theirs" drops the draft.
    offline(b);
    await a.engine.update(id, { name: "laptop again" }, currentRev(a.engine, id));
    await b.engine.update(id, { name: "phone again" }, currentRev(b.engine, id));
    await untilServerRev(sim, id, 4);
    online(b);
    await pump(b);
    assert.equal(shows(b, id).conflict, true);
    await b.engine.resolve(id, "theirs");
    await pump(b);
    await pump(a);
    for (const dev of [a, b]) {
      assert.equal(await nameOf(dev, id), "laptop again");
      assert.equal(shows(dev, id).rev, 4);
    }
    assert.equal((await queued(b)).length, 0, "the draft is gone");
    assert.equal(sim.server.items.get(id).rev, 4);
    await sim.stopAll();
    assert.deepEqual(sim.problems, []);
  });

  await t.test("different_items_no_conflict", async () => {
    const sim = await world();
    const [a, b] = sim.devices;
    offline(a, b);
    const one = await a.engine.create(draft("laptop's"));
    const two = await b.engine.create(draft("phone's"));
    await a.engine.syncNow();
    await b.engine.syncNow();
    assert.equal(sim.server.items.size, 0, "offline, nothing leaves the device");

    online(a, b);
    await pump(a);
    await pump(b);
    await pump(a);
    for (const dev of [a, b]) {
      assert.equal(await nameOf(dev, one), "laptop's");
      assert.equal(await nameOf(dev, two), "phone's");
      assert.deepEqual([shows(dev, one).rev, shows(dev, two).rev], [1, 1]);
      assert.equal(dev.engine.list().some((item) => item.conflict || item.blocked), false);
      assert.equal(dev.d.events.error.some((e) => e.code === "conflict"), false);
    }
    assert.equal(sim.server.seq, 2);
    await sim.stopAll();
  });

  await t.test("offline_delete_vs_edit", async () => {
    const sim = await world();
    const [a, b] = sim.devices;

    // Deleted here, edited there.
    const one = await a.engine.create(draft("v0"));
    await untilServerRev(sim, one, 1);
    await b.engine.syncNow();
    offline(a);
    await a.engine.remove(one);
    assert.equal(shows(a, one), undefined, "deleted on the laptop");
    await b.engine.update(one, { name: "edited on the phone" }, currentRev(b.engine, one));
    await untilServerRev(sim, one, 2);
    online(a);
    await pump(a);
    assert.equal(shows(a, one).conflict, true, "the deletion is not sent over an edit");
    const shown = await a.engine.conflict(one);
    assert.equal(shown.local.deleted, true);
    assert.equal(shown.server.view.name, "edited on the phone");
    await shown.close();
    assert.equal(sim.server.items.get(one).deleted, false);
    await pump(b);
    assert.equal(await nameOf(b, one), "edited on the phone", "the phone still has its item");
    // The user chooses to delete: the tombstone goes out on top of the edit.
    await a.engine.resolve(one, "mine");
    await pump(a);
    await pump(b);
    assert.equal(shows(b, one), undefined);
    assert.deepEqual([sim.server.items.get(one).rev, sim.server.items.get(one).deleted], [3, true]);

    // Edited here, deleted there. The deletion is not undone by the edit.
    const two = await a.engine.create(draft("w0"));
    await untilServerRev(sim, two, 1);
    await b.engine.syncNow();
    offline(a);
    await a.engine.update(two, { name: "a late edit" }, currentRev(a.engine, two));
    await b.engine.remove(two);
    await untilServerRev(sim, two, 2);
    online(a);
    await pump(a);
    assert.equal(shows(a, two).conflict, true);
    const late = await a.engine.conflict(two);
    assert.equal(late.local.view.name, "a late edit");
    assert.equal(late.server.deleted, true);
    await late.close();
    // A new device sees a deleted item: the edit has not brought it back.
    const c = await sim.addDevice();
    assert.equal(shows(c, two), undefined);
    // The user chooses to keep the edit: only now is the item brought back.
    await a.engine.resolve(two, "mine");
    await pump(a);
    await pump(c);
    assert.equal(await nameOf(c, two), "a late edit");
    assert.equal(shows(c, two).rev, 3);
    assert.equal(sim.server.accepted().filter((w) => w.resurrect).length, 1);
    await sim.stopAll();
    assert.deepEqual(sim.problems, []);
  });

  await t.test("tombstone_no_resurrection", async () => {
    const sim = await world();
    const [a, b] = sim.devices;
    const id = await a.engine.create(draft("short-lived"));
    await untilServerRev(sim, id, 1);
    await b.engine.syncNow();
    offline(b);
    await a.engine.remove(id);
    await untilServerRev(sim, id, 2);

    // Against a tombstone at rev 2 nothing brings the item back without the flag and the right base (the rules of the server).
    const sealed = (rev) => sim.client.wireRow(id, rev, { item_type: "login", name: "again" });
    let n = 100;
    const attempts = [["old base", 1, false], ["right base, no flag", 2, false], ["base 0", 0, false], ["flag on an old base", 1, true], ["flag on a base above", 3, true]];
    for (const [name, base, resurrect] of attempts) {
      n += 1;
      const body = JSON.stringify({ base_rev: base, ...sealed(base + 1), idem: n.toString(16).padStart(32, "0"), ...(resurrect ? { resurrect: true } : {}) });
      assert.throws(() => sim.server.put(id, body), (error) => error instanceof ApiError && error.status === 409, name);
    }
    assert.equal(sim.server.items.get(id).deleted, true);
    assert.equal(sim.server.seq, 2);

    // The phone edits the item it still has while the laptop's deletion is unknown to it. It is a conflict, never a resurrection.
    await b.engine.update(id, { name: "edited a deleted item" }, currentRev(b.engine, id));
    online(b);
    for (let round = 0; round < 4; round += 1) {
      await pump(b);
      await pump(a);
    }
    assert.equal(sim.server.items.get(id).deleted, true, "still deleted");
    assert.equal(sim.server.accepted().some((w) => w.resurrect), false);
    // "Keep theirs" leaves it deleted, for good.
    if (shows(b, id)?.conflict) await b.engine.resolve(id, "theirs");
    for (let round = 0; round < 3; round += 1) {
      await pump(b);
      await pump(a);
    }
    assert.equal(shows(b, id), undefined);
    assert.equal(shows(a, id), undefined);
    assert.equal(sim.server.items.get(id).deleted, true);
    assert.equal(sim.server.accepted().some((w) => w.resurrect), false);
    await sim.stopAll();
    assert.deepEqual(sim.problems, []);
  });

  await t.test("retry_idempotent", async () => {
    // The web vault writes with `PUT` (batches are not used in this milestone: the server's own matrix covers them).
    const sim = await world([1]);
    const [a] = sim.devices;
    // The answer is lost: the server wrote, the device does not know.
    a.d.api.faults.push({ kind: "lost" });
    const id = await a.engine.create(draft("once"));
    await until(() => a.d.api.puts.length >= 1, "the first request");
    assert.equal(sim.server.writes.length, 1, "the server took it");
    for (let round = 0; round < 10 && (await queued(a)).length > 0; round += 1) await pump(a);
    assert.equal((await queued(a)).length, 0);
    assert.ok(a.d.api.puts.length >= 2, "and the device asked again");
    assert.equal(new Set(a.d.api.puts.map((put) => put.text)).size, 1, "with the same bytes, so the same key");
    assert.equal(sim.server.writes.length, 1, "which the server counts once");
    assert.equal(sim.server.items.get(id).rev, 1);
    // The same for a change, with the request lost on the way.
    a.d.api.faults.push({ kind: "network" }, { kind: "lost" });
    await a.engine.update(id, { name: "twice" }, currentRev(a.engine, id));
    for (let round = 0; round < 10 && (await queued(a)).length > 0; round += 1) await pump(a);
    assert.equal(sim.server.writes.length, 2);
    assert.equal(sim.server.items.get(id).rev, 2);
    assert.equal(shows(a, id).conflict, false);
    await sim.stopAll();
    assert.deepEqual(sim.problems, []);
  });

  await t.test("skewed_clock_irrelevant", async () => {
    // The same conflict twice: with honest clocks, and with one device ten years ahead, the other ten years behind, the clock of the
    // device jumping between the steps. What each device ends up showing is the same: only `rev` decides.
    const outcome = async (skews, jump) => {
      const sim = await world([1, 1], { skews });
      const [a, b] = sim.devices;
      const id = await a.engine.create(draft("v0"));
      await untilServerRev(sim, id, 1);
      await b.engine.syncNow();
      offline(b);
      await a.engine.update(id, { name: "from the laptop" }, currentRev(a.engine, id));
      await b.engine.update(id, { name: "from the phone" }, currentRev(b.engine, id));
      await untilServerRev(sim, id, 2);
      online(b);
      if (jump) a.d.timers.advance(5 * 3_600_000);
      await pump(b);
      const log = [shows(b, id).conflict, shows(a, id).conflict];
      await b.engine.resolve(id, "mine");
      await pump(b);
      await pump(a);
      for (const dev of [a, b]) log.push(await nameOf(dev, id), shows(dev, id).rev, shows(dev, id).conflict);
      log.push(sim.server.seq);
      await sim.stopAll();
      assert.deepEqual(sim.problems, []);
      return log;
    };
    const honest = await outcome([0, 0], false);
    assert.deepEqual(await outcome([YEARS_MS, -YEARS_MS], true), honest);
    // The skew is real: the phone's body says it was written twenty years before the laptop's.
    const sim = await world([1, 1], { skews: [YEARS_MS, -YEARS_MS] });
    const [a, b] = sim.devices;
    const one = await a.engine.create(draft("a"));
    const two = await b.engine.create(draft("b"));
    const dated = async (dev, id) => {
      const open = await dev.engine.open(id);
      try {
        return open.view.modified;
      } finally {
        await open.close();
      }
    };
    const later = await dated(a, one);
    const earlier = await dated(b, two);
    assert.ok(later - earlier > 19 * 365 * 86_400 * 1000, "the laptop's body is dated later than the phone's");
    await sim.stopAll();
  });

  await t.test("sse_convergence", async () => {
    const sim = await world();
    const [a, b] = sim.devices;
    const id = await a.engine.create(draft("v1"));
    await untilServerRev(sim, id, 1);
    await b.engine.syncNow();

    // The phone listens. An event carries a `seq` and nothing else; the phone reads the row itself.
    const stream = fakeStreamApi();
    const hints = [];
    const channel = createLiveChannel({ api: stream, win: fakePageEvents(), onHint: (seq) => (hints.push(seq), b.engine.syncNow()) });
    sim.server.onWrite = (seq) => stream.last?.sync(seq);
    channel.start();
    try {
      await until(() => stream.connections.length === 1, "the stream is open");
      stream.last.hello(sim.server.seq);
      await until(() => channel.state() === "live", "the channel is live");
      const started = Date.now();
      await a.engine.update(id, { name: "v2" }, currentRev(a.engine, id));
      await until(() => shows(b, id)?.rev === 2 && shows(b, id).name === "v2", "the phone shows v2");
      assert.ok(Date.now() - started < 5_000, "within five seconds");
      assert.ok(hints.every((seq) => seq === null || Number.isSafeInteger(seq)), "the hints are numbers");
      assert.equal(shows(b, id).conflict, false);
      assert.equal(shows(b, id).rev, shows(a, id).rev);
    } finally {
      channel.stop();
      sim.server.onWrite = null;
    }
    await sim.stopAll();
    assert.deepEqual(sim.problems, []);
  });
});

// ------------------------------------------------------------------------- random runs

/** Two or three browsers, and one to three tabs in each (the first tab runs the engine, the others are on standby). */
const LAYOUTS = [[1, 1], [1, 1], [1, 1, 1], [1, 1, 1], [2], [3], [2, 1]];

/** What must be true of a run that is over: the checks of the design, against the model. */
async function check(sim) {
  await sim.calm();
  if (sim.tabs) {
    // The pages are closed and opened again: what is stored decides what the tabs show.
    await sim.reloadAll();
    await sim.calm();
  }
  sim.checkHealthy();
  await sim.checkConverged();
  sim.checkOwners();
  await sim.checkWrites();
  sim.checkResurrections();
  await sim.checkFloorsCoverRows();
  await sim.checkCheckpointLive();
  await sim.checkNoPlaintext();
  await sim.stopAll();
}

/** One seeded run of `steps` random steps. */
async function randomRun(seed, { layouts = LAYOUTS, steps = STEPS, actions = ACTIONS } = {}) {
  const pick = rngOf(seed * 7919 + 13);
  const sim = new Sim(seed, { layout: pick.pick(layouts), pageSize: pick.between(1, 4) });
  try {
    await sim.start();
    await sim.run(steps, { actions });
    await check(sim);
  } finally {
    for (const dev of sim.devices) dev.engine.stop();
  }
  if (sim.problems.length > 0) assert.fail(sim.report());
  return sim.tally();
}

/** Runs the seeds; every failing seed is named, the first few come with their log. Answers the sum of what the runs counted. */
async function runSeeds(seeds, run) {
  const started = Date.now();
  const total = {};
  const failed = [];
  for (const seed of seeds) {
    try {
      const stats = await run(seed);
      for (const [key, value] of Object.entries(stats ?? {})) total[key] = (total[key] ?? 0) + value;
    } catch (error) {
      failed.push({ seed, message: error instanceof Error ? error.message : String(error) });
      console.log(`seed ${seed}: ${failed.at(-1).message.split("\n").slice(0, 3).join(" | ")}`);
    }
  }
  console.log(`${seeds.length} runs in ${Date.now() - started} ms`, JSON.stringify(total));
  if (failed.length > 0) {
    const heads = failed.map((f) => f.seed).join(", ");
    const logs = failed.slice(0, 3).map((f) => f.message).join("\n\n");
    assert.fail(`${failed.length} of ${seeds.length} runs failed, seeds ${heads} (FERRET_MATRIX_SEED=<seed> runs one of them alone)\n\n${logs}`);
  }
  return total;
}

const seedsOf = (count) => (ONLY !== null ? ONLY : Array.from({ length: count }, (_, n) => n + 1));
/** How many runs a test makes that is not the main one: a fifth of them, and at least 50. */
const fewer = () => Math.max(50, Math.ceil(RUNS / 5));

test("random_runs_keep_every_write_and_converge", async () => {
  const total = await runSeeds(seedsOf(RUNS), (seed) => randomRun(seed));
  // The runs do what they are meant to do: writes, conflicts, choices, restarts, listings after a 410, checkpoints verified and uploaded, and the vault
  // moved from one tab to another (asked, stolen, the owner tab closed).
  if (ONLY === null && RUNS >= 100) {
    for (const key of ["server_writes", "error:conflict", "resurrect_writes", "act:restart", "listings", "verify_checkpoint_calls", "server_checkpoint_puts", "owner:ask", "owner:steal", "owner:closed"]) {
      assert.ok((total[key] ?? 0) > 0, `the runs never made ${key}`);
    }
  }
});

test("two_engines_on_one_store_never_lower_a_floor_under_random_runs", async () => {
  // Tabs of one browser: the vault moves between them all the time, with a pass in the air (`race`) and while the engine reads (`both`), so the
  // sync memory is read and saved by one engine after another, and for a moment by two (an old pass that is let go after the new engine has
  // stored a newer feed). The floors are read from the store after every step (`checkFloors`).
  const tabsActions = [["sync", 20], ["poll", 16], ["restart", 6], ["fault", 6], ["offline", 4], ["create", 8], ["update", 12], ["remove", 3], ["jump", 2], ["both", 10], ["race", 12], ["useHere", 12]];
  const total = await runSeeds(seedsOf(Math.max(50, Math.ceil(RUNS / 2))), async (seed) => {
    const sim = new Sim(seed, { layout: [[2], [3], [2, 1]][seed % 3], pageSize: 1 + (seed % 4) });
    try {
      await sim.start();
      await sim.run(STEPS, { actions: tabsActions });
      await check(sim);
    } finally {
      for (const dev of sim.devices) dev.engine.stop();
    }
    if (sim.problems.length > 0) assert.fail(sim.report());
    return sim.tally();
  });
  assert.ok((total["act:both"] ?? 0) > 0);
  assert.ok((total["act:race"] ?? 0) > 0);
  assert.ok((total["owner:ask"] ?? 0) > 0 && (total["owner:steal"] ?? 0) > 0 && (total["owner:closed"] ?? 0) > 0, "the vault moved in every way");
});

// ------------------------------------------------------------------------- a restored server

/**
 * Two devices that hold the same state; a backup; changes after it; the server is restored from the backup. Then each device meets the
 * server and its user accepts the older state, in either order, with edits between (`afterwards`).
 */
async function restoreRun(seed, { afterwards }) {
  const rng = rngOf(seed * 104729 + 7);
  const sim = new Sim(seed, { layout: [1, 1], pageSize: rng.between(1, 4) });
  try {
    await sim.start();
    await sim.run(rng.between(8, 16), { actions: CALM_ACTIONS });
    await sim.calm();
    const backup = sim.server.backup();
    const [a, b] = sim.devices;
    // Changes after the backup. One of the devices may be away for them (no network), holding what it had, and may even have edited.
    const away = rng.chance(0.4) ? rng.pick([a, b]) : null;
    if (away) offline(away);
    const present = sim.devices.filter((dev) => dev !== away);
    await sim.run(rng.between(4, 12), { pool: present, actions: CALM_ACTIONS });
    if (away && rng.chance(0.5)) {
      await sim.create(away);
      await sim.update(away);
    }
    await sim.calm(present);
    const held = new Map();
    for (const dev of sim.devices) held.set(dev.label, await sim.held(dev));

    await sim.restoreServer(backup);
    const frozen = new Map(sim.server.frozen);
    sim.heal();
    // The devices meet the restored server in either order, and the one that accepts first may write to it before the other has met it: a device that holds
    // what the restore lost stops whatever the server's seq has come to (`checkStopped`).
    const order = rng.chance(0.5) ? [a, b] : [b, a];
    for (const dev of order) {
      await dev.engine.syncNow();
      await settle(10);
      await sim.accept(dev);
      await settle(10);
      if (afterwards) await sim.run(rng.between(1, 3), { pool: [dev], actions: [["update", 6], ["create", 2], ["remove", 1], ["sync", 3]] });
      for (const other of sim.devices) {
        if (other !== dev && rng.chance(0.5)) await pump(other);
      }
    }
    await sim.calm();
    await sim.checkStopped();
    sim.checkHealthy(["server_restored", "restore_epoch_raised"]);
    await sim.checkConverged();
    // Accepting an older state is the choice that brings back what a device holds above a tombstone of the restored state (and only that).
    sim.checkResurrections(new Map([...frozen].filter(([, row]) => row.hash === null).map(([id]) => [id, sim.devices.length])));
    await sim.checkWrites({ fromWrite: sim.restoreWrites });
    await sim.checkFloorsCoverRows();
    await sim.checkNoPlaintext();

    // What was written after the restore, by item.
    const after = sim.writes.slice(sim.restoreWrites);
    const afterIds = new Set(after.map((w) => w.id));
    const pending = (id) => sim.devices.some((dev) => held.get(dev.label).get(id)?.pending);
    const label = (id) => `${id.slice(0, 4)}..${id.slice(-2)}`;
    // A device holds a version above the restored one when it has seen a change since the backup. Two devices that both do, and have
    // sealed it each for itself, cannot tell that they hold the same thing: the second one gets a conflict (a known limit: the copies cannot be compared without showing the secrets).
    const above = (id) => sim.devices.filter((dev) => {
      const version = held.get(dev.label).get(id);
      const row = frozen.get(id);
      return version !== undefined && (row === undefined || version.rev > row.rev);
    }).length;
    for (const id of sim.conflictsSinceRestore()) {
      if (above(id) < 2 && !afterIds.has(id) && !pending(id)) sim.fail(`${label(id)} is a conflict, and no device changed it after the restore or holds a change the other has not seen`);
    }
    // Nothing is lost: what the devices held, above the restored state, is on the server again, as it was.
    const live = await sim.serverLive();
    const ids = new Set([...held.values()].flatMap((versions) => [...versions.keys()]));
    for (const id of ids) {
      if (afterIds.has(id) || pending(id)) continue;
      const versions = sim.devices.map((dev) => held.get(dev.label).get(id)).filter(Boolean);
      const top = Math.max(...versions.map((v) => v.rev));
      const row = frozen.get(id);
      if (row !== undefined && top <= row.rev) continue; // nothing above the backup: the restored row stands
      const best = versions.filter((v) => v.rev === top);
      if (new Set(best.map((v) => (v.deleted ? "deleted" : v.name))).size > 1) continue; // two lines of history: that is a conflict
      const server = sim.server.items.get(id);
      if (best[0].deleted) {
        if (server && !server.deleted) sim.fail(`${label(id)} was deleted on the devices and is live on the server`);
      } else if (!live.has(id) || live.get(id).name !== best[0].name) {
        sim.fail(`${label(id)} held as ${best[0].name} rev ${top} is on the server as ${live.get(id)?.name ?? (server ? "deleted" : "nothing")}`);
      }
    }
    // Nothing written after the restore is overwritten: by the last write after it, unless it was a conflict that a user decided.
    const conflicts = sim.conflictsSinceRestore();
    for (const id of afterIds) {
      if (conflicts.has(id)) continue;
      const last = after.filter((w) => w.id === id).at(-1);
      const server = sim.server.items.get(id);
      if (last.kind === "remove") {
        if (server && !server.deleted) sim.fail(`${label(id)} was deleted after the restore and is live on the server`);
      } else if (!live.has(id) || live.get(id).name !== last.marker) {
        sim.fail(`${label(id)} written as ${last.marker} after the restore is on the server as ${live.get(id)?.name ?? "nothing"}`);
      }
    }
    await sim.stopAll();
  } finally {
    for (const dev of sim.devices) dev.engine.stop();
  }
  if (sim.problems.length > 0) assert.fail(sim.report());
  return sim.tally();
}

/** The seeds of the restore tests: the runs where nobody writes after the restore are the seeds below 100000, the others from 100000 on. */
const RESTORE_OFFSET = 100_000;
const restoreSeeds = (afterwards) => {
  if (ONLY !== null) return ONLY.filter((seed) => (seed >= RESTORE_OFFSET) === afterwards);
  const base = Array.from({ length: fewer() }, (_, n) => n + 1);
  return afterwards ? base.map((seed) => seed + RESTORE_OFFSET) : base;
};

test("restore_with_two_devices_loses_nothing_and_overwrites_nothing", async () => {
  // Nobody changes anything after the restore: no conflict that is not one of the known kinds, and nothing is lost.
  await runSeeds(restoreSeeds(false), (seed) => restoreRun(seed, { afterwards: false }));
  // Devices change things between their acceptances: what is written after the restore stands.
  const total = await runSeeds(restoreSeeds(true), (seed) => restoreRun(seed, { afterwards: true }));
  assert.ok((total["state:halted:server_restored"] ?? 0) > 0, "the runs do stop for a restored server");
});

test("a_restore_in_the_middle_of_a_run_never_lands_a_write_on_the_restored_state", async () => {
  const total = await runSeeds(seedsOf(fewer()), async (seed) => {
    const rng = rngOf(seed * 15485863 + 3);
    const sim = new Sim(seed, { layout: rng.pick(LAYOUTS), pageSize: rng.between(1, 4) });
    try {
      await sim.start();
      await sim.run(rng.between(6, 12));
      await sim.calm();
      const backup = sim.server.backup();
      await sim.run(rng.between(5, 12)); // the devices see more than the backup holds
      await sim.restoreServer(backup);
      const before = sim.server.writes.length;
      // The users keep working, and nobody accepts anything; the retention job runs and other writers write to the server as in any run.
      await sim.run(rng.between(12, 24), { actions: ACTIONS });
      sim.heal();
      for (let round = 0; round < 3; round += 1) {
        for (const dev of sim.devices) await pump(dev);
      }
      // Every write the server took since carries the new epoch, and none came from a device that had seen more than the backup shows.
      for (const write of sim.server.accepted().slice(before)) {
        if (write.restoreEpoch !== sim.server.restoreEpoch) sim.fail(`a write to ${write.id.slice(0, 4)} was taken with the restore epoch ${write.restoreEpoch}, the server is at ${sim.server.restoreEpoch}`);
      }
      await sim.checkStopped();
      await sim.checkFloors();
      await sim.checkNoPlaintext();
      await sim.stopAll();
    } finally {
      for (const dev of sim.devices) dev.engine.stop();
    }
    if (sim.problems.length > 0) assert.fail(sim.report());
    return sim.tally();
  });
  assert.ok((total["state:halted:server_restored"] ?? 0) > 0, "the runs do stop for a restored server");
});

// ------------------------------------------------------------------------- a dropped connection

test("network_drop_mid_write_is_retried_with_the_same_idem_and_counts_once", async () => {
  const kinds = [
    { kind: "lost" }, { kind: "network" }, { kind: "status", status: 503, code: "busy", retryAfter: 2 },
    { kind: "status", status: 429, code: "throttled", retryAfter: 30 },
  ];
  await runSeeds(seedsOf(fewer()), async (seed) => {
    const rng = rngOf(seed * 2654435761);
    const sim = new Sim(seed, { layout: [1] });
    try {
      await sim.start();
      let [a] = sim.devices;
      // A write with some failures before it goes through, at least one of them after the server has taken it: the page may be closed
      // and opened again meanwhile, and the bytes that come out of the outbox are the same.
      const faults = Array.from({ length: rng.between(1, 4) }, () => rng.pick(kinds));
      if (!faults.some((f) => f.kind === "lost")) faults.splice(rng.int(faults.length + 1), 0, { kind: "lost" });
      a.d.api.faults.push(...faults);
      const id = await a.engine.create(draft("dropped"));
      let reloaded = false;
      const sent = [];
      for (let round = 0; round < 40 && (sim.server.items.get(id)?.rev !== 1 || (await queued(a)).length > 0); round += 1) {
        if (!reloaded && rng.chance(0.3) && a.d.api.puts.length > 0) {
          reloaded = true;
          sent.push(...a.d.api.puts); // what the page sent before it was closed counts too
          a = await sim.restart(a);
        }
        await pump(a);
      }
      sent.push(...a.d.api.puts);
      assert.equal((await queued(a)).length, 0, "the write got through");
      assert.equal(sim.server.writes.length, 1, "and the server counts it once");
      assert.equal(sim.server.items.get(id).rev, 1);
      assert.equal(new Set(sent.map((put) => put.text)).size, 1, "every try was the same bytes");
      assert.equal(new Set(sent.map((put) => JSON.parse(put.text).idem)).size, 1, "under one key");
      assert.equal(sim.server.idems.size, 1);
      assert.equal(a.d.events.error.some((e) => e.code === "conflict"), false, "a retry is no conflict");
      assert.equal(shows(a, id).pending, false);
      await sim.stopAll();
      assert.deepEqual(sim.problems, []);
    } finally {
      for (const dev of sim.devices) dev.engine.stop();
    }
  });
});

// ------------------------------------------------------------------------- the checks themselves

test("the_invariant_checks_find_what_they_look_for", async (t) => {
  // A check that never fails proves nothing: each is shown the thing it is there for.
  const fresh = async () => {
    const sim = await world();
    sim.tolerated = new Set();
    return sim;
  };
  const complains = (sim, text) => assert.ok(sim.problems.some((problem) => problem.includes(text)), `expected a problem with "${text}", got ${JSON.stringify(sim.problems)}`);

  await t.test("a write that is nowhere", async () => {
    const sim = await fresh();
    const id = await sim.devices[0].engine.create(draft("kept"));
    await untilServerRev(sim, id, 1);
    sim.writes.push({ dev: sim.devices[0].label, id, kind: "update", marker: "SECRET-never-sent", step: 1 });
    await sim.checkWrites();
    complains(sim, "is not on the server");
    await sim.stopAll();
  });

  await t.test("a floor that goes down", async () => {
    const sim = await fresh();
    const [a] = sim.devices;
    await a.engine.create(draft("one"));
    await a.engine.syncNow();
    await settle(20);
    await sim.checkFloors();
    const state = await loadSyncState(a.group.db.store, SERVER, ACCOUNT);
    await saveSyncState(a.group.db.store, SERVER, ACCOUNT, { ...state, memory: memoryBytes({ maxSeq: 0, checkpointSeq: 0, revs: {} }) });
    await sim.checkFloors();
    complains(sim, "went down");
    await sim.stopAll();
  });

  await t.test("a secret in the storage", async () => {
    const sim = await fresh();
    await setSetting(sim.devices[0].d.store.database.store, "leak", "SECRET-in-a-setting");
    await sim.checkNoPlaintext();
    complains(sim, "a secret is in the browser storage");
    await sim.stopAll();
  });

  await t.test("a request after stop", async () => {
    const sim = await fresh();
    const [a] = sim.devices;
    a.stopped = true;
    a.engine.stop();
    await a.d.api.put("/api/sync/items/00000000000000000000000000000001", "{}").catch(() => {});
    await sim.stopAll();
    complains(sim, "asked the server after stop()");
  });

  await t.test("an item that comes back without a choice", async () => {
    const sim = await fresh();
    const [a] = sim.devices;
    const id = await a.engine.create(draft("short-lived"));
    await untilServerRev(sim, id, 1);
    await a.engine.remove(id);
    await untilServerRev(sim, id, 2);
    const body = { base_rev: 2, ...sim.client.wireRow(id, 3, { item_type: "login", name: "back" }), idem: "ab".repeat(16), resurrect: true };
    sim.server.put(id, JSON.stringify(body));
    sim.checkResurrections();
    complains(sim, "was brought back");
    await sim.stopAll();
  });

  await t.test("a device that does not show the server", async () => {
    const sim = await fresh();
    const id = "cd".repeat(16);
    sim.server.set(id, { rev: 1, ...sim.client.wireRow(id, 1, { item_type: "login", name: "unseen" }) });
    await sim.checkConverged();
    complains(sim, "lacks");
    await sim.stopAll();
  });

  await t.test("a device that is stopped", async () => {
    const sim = await fresh();
    const [a] = sim.devices;
    const id = "ef".repeat(16);
    sim.server.set(id, { rev: 1, ...sim.client.wireRow(id, 1, { item_type: "login", name: "x" }), seq: 5 });
    await a.engine.syncNow();
    sim.server.latestSeqLie = 1; // a server that shows a top below the one the device has seen
    await a.engine.syncNow();
    sim.checkHealthy();
    complains(sim, "is halted");
    await sim.stopAll();
  });
});

// ------------------------------------------------------------------------- what the matrix found, and the engine now does right
// The smallest runs that showed a gap, kept as plain tests. The ones that follow the last of them (two tabs, a purged tombstone) are still `todo`.

/** A device that has an item at revision 1 together with another one; both hold it and are online. */
async function sharedItem(layout = [1, 1], options = {}) {
  const sim = await world(layout, options);
  const [a, b] = sim.devices;
  const id = await a.engine.create(draft("v0"));
  await untilServerRev(sim, id, 1);
  await b.engine.syncNow();
  return { sim, a, b, id };
}

test("a_chain_that_restores_and_deletes_again_is_kept_when_another_device_brought_the_item_back_first", async () => {
  // B holds the tombstone of the item and has it in its trash. Offline, B restores it and deletes it again (a chain of two writes). Meanwhile
  // A restores it, so the server shows it live again. B's first write is refused (the server says live, at a revision above the tombstone B holds):
  // B has not read that yet, so its tombstone is out of date, and the chain must not be dropped as moot: that would leave a live item hidden.
  const { sim, a, b, id } = await sharedItem();
  await a.engine.remove(id);
  await untilServerRev(sim, id, 2);
  await pump(b); // B holds the tombstone
  offline(b);
  await b.engine.restoreFromTrash(id);
  await b.engine.remove(id);
  assert.equal((await queued(b)).length, 2);
  await a.engine.restoreFromTrash(id);
  await untilServerRev(sim, id, 3);
  online(b);
  b.d.timers.advance(3_000);
  await settle(40);
  assert.equal(sim.server.items.get(id)?.deleted, false, "the server shows the item live");
  assert.equal((await queued(b)).length >= 1, true, "the chain was not dropped");
  const shown = shows(b, id);
  assert.ok(shown, "the live item is not hidden on B");
  assert.equal(shown.blocked || shown.pending, true, "it says that something waits or needs a choice");
  await sim.stopAll();
});

test("a_write_refused_over_a_tombstone_the_feed_has_already_brought_stays_on_screen", async () => {
  const { sim, a, b, id } = await sharedItem();
  offline(b);
  await b.engine.update(id, { name: "edited while the other device deleted it" }, currentRev(b.engine, id)); // waits in the outbox
  await a.engine.remove(id);
  await untilServerRev(sim, id, 2);
  online(b);
  await b.engine.syncNow(); // the feed brings the tombstone first, the write waits for its next try
  await pump(b); // now it is sent, and refused
  await pump(b);
  assert.equal(sim.server.items.get(id).deleted, true);
  // The user's edit must not vanish: it is a conflict with a deleted row, on screen, with the choice.
  assert.equal(shows(b, id)?.conflict, true, "the refused edit is on screen as a conflict");
  assert.equal((await queued(b)).length, 1, "and the draft is kept");
  await sim.stopAll();
});

test("a_chain_of_edits_refused_over_a_tombstone_the_feed_has_already_brought_stays_on_screen", async () => {
  const { sim, a, b, id } = await sharedItem();
  offline(b);
  for (const name of ["first", "second", "third"]) await b.engine.update(id, { name }, currentRev(b.engine, id)); // three writes wait
  await a.engine.remove(id);
  await untilServerRev(sim, id, 2);
  online(b);
  await b.engine.syncNow();
  await pump(b);
  await pump(b);
  assert.equal(sim.server.items.get(id).deleted, true);
  assert.equal(shows(b, id)?.conflict, true, "the refused edits are on screen as a conflict");
  assert.equal((await queued(b)).length, 3, "and none of them is dropped: the chain does not end in a deletion");
  await sim.stopAll();
});

/** Device B edits and then deletes the item while offline; device A edits it and deletes it (the tombstone is at revision 3). */
async function bothDelete() {
  const { sim, a, b, id } = await sharedItem();
  offline(b);
  await b.engine.update(id, { name: "edited, then deleted" }, currentRev(b.engine, id)); // base 1
  await b.engine.remove(id); // base 2: the two writes wait
  await a.engine.update(id, { name: "v1" }, currentRev(a.engine, id));
  await untilServerRev(sim, id, 2);
  await a.engine.remove(id);
  await untilServerRev(sim, id, 3);
  return { sim, a, b, id };
}

test("a_deletion_refused_over_a_tombstone_the_feed_has_already_brought_leaves_no_blocked_draft", async () => {
  const { sim, b, id } = await bothDelete();
  online(b);
  await b.engine.syncNow();
  await pump(b);
  await pump(b);
  // Both devices deleted the item: there is nothing to choose, and nothing may stay behind that stops the device from storing checkpoints.
  assert.equal((await queued(b)).length, 0);
  assert.equal(shows(b, id), undefined, "the deleted item is on no screen");
  assert.equal(b.engine.list().some((item) => item.blocked || item.conflict), false);
  assert.equal(b.d.events.error.some((e) => e.code === "conflict"), false, "and no conflict was announced for it");
  await sim.stopAll();
});

test("uploads_resume_after_a_refused_chain_over_a_tombstone_is_dropped", async () => {
  const { sim, b } = await bothDelete();
  online(b);
  await b.engine.syncNow();
  await pump(b);
  await pump(b);
  assert.equal((await queued(b)).length, 0);
  b.d.timers.advance(11 * 60_000);
  await b.engine.syncNow();
  await settle(20);
  assert.equal(sim.server.checkpoint.seq, sim.server.seq, "the device stores a checkpoint again");
  await sim.stopAll();
});

test("a_chain_that_is_dropped_with_the_deletion_at_its_end_takes_every_edit_before_it", async () => {
  const { sim, a, b, id } = await sharedItem();
  offline(b);
  for (const name of ["one", "two"]) await b.engine.update(id, { name }, currentRev(b.engine, id));
  await b.engine.remove(id); // three writes wait, the last is the deletion
  await a.engine.remove(id);
  await untilServerRev(sim, id, 2);
  online(b);
  await b.engine.syncNow();
  await pump(b);
  await pump(b);
  assert.equal((await queued(b)).length, 0);
  assert.equal(sim.server.writes.filter((w) => JSON.parse(w.body).idem && w.id === id).length, 2, "the server took the creation and the other device's deletion, nothing of the dropped chain");
  await sim.stopAll();
});

test("a_409_that_says_deleted_does_not_drop_a_chain_while_the_row_the_device_holds_is_live", async () => {
  const { sim, a, b, id } = await sharedItem();
  offline(b);
  await b.engine.update(id, { name: "edited, then deleted" }, currentRev(b.engine, id));
  await b.engine.remove(id); // the chain ends in a deletion
  // A server that says "deleted" about a row the feed still shows live: nothing is dropped on its word.
  b.d.api.faults.push({ kind: "status", status: 409, code: "conflict", body: { current_rev: 2, deleted: true } });
  online(b);
  b.d.timers.advance(3_000);
  await settle(30);
  assert.equal((await queued(b)).length, 2, "the chain stays");
  assert.equal(shows(b, id)?.blocked, true, "and the item is blocked, on screen as the server's live version");
  // Now the server really deletes it: the verified tombstone is what lets the chain go.
  await a.engine.remove(id);
  await untilServerRev(sim, id, 2);
  await pump(b);
  assert.equal((await queued(b)).length, 0, "the chain is dropped once the tombstone is held");
  assert.equal(b.engine.list().some((item) => item.blocked), false);
  await sim.stopAll();
});

test("a_refused_chain_over_a_tombstone_that_is_held_when_the_page_starts_is_dropped_at_start_up", async () => {
  // Two browsers. The first one's chain is refused while its row is live (a server that says "deleted" too early): blocked, the chain kept. Then
  // the tombstone is cached by another engine over the same storage (the vault was in another tab for a moment, here a bare engine), and the
  // page is opened again: with a verified tombstone held and a chain that ends in a deletion, nothing is left to choose.
  const sim = await world([1, 1]);
  const [writer, other] = sim.devices;
  const id = await writer.engine.create(draft("v0"));
  await untilServerRev(sim, id, 1);
  await other.engine.syncNow();
  offline(writer);
  await writer.engine.update(id, { name: "edited, then deleted" }, currentRev(writer.engine, id));
  await writer.engine.remove(id);
  writer.d.api.faults.push({ kind: "status", status: 409, code: "conflict", body: { current_rev: 2, deleted: true } });
  online(writer);
  writer.d.timers.advance(3_000);
  await settle(30);
  assert.equal(shows(writer, id)?.blocked, true, "refused while the row is live: the chain is kept");
  assert.equal((await queued(writer)).length, 2);
  await other.engine.remove(id);
  await untilServerRev(sim, id, 2);
  sim.retire(writer); // the page is closed
  const helper = await sim.spawn(writer.group, "helper", 1);
  await helper.engine.start();
  await helper.engine.syncNow(); // an engine of the same storage caches the tombstone
  await settle(20);
  helper.engine.stop();
  const reloaded = await sim.restart(writer);
  await settle(20);
  assert.equal((await queued(reloaded)).length, 0, "the chain was dropped at start-up");
  assert.equal(reloaded.engine.list().some((item) => item.blocked || item.conflict), false);
  await sim.stopAll();
});

test("a_refusal_that_comes_in_while_the_tombstone_page_is_being_used_leaves_the_draft_on_screen", async () => {
  const { sim, a, b, id } = await sharedItem();
  offline(b);
  await b.engine.update(id, { name: "edited while the other device deleted it" }, currentRev(b.engine, id)); // waits for its retry
  await a.engine.remove(id);
  await untilServerRev(sim, id, 2);
  online(b);
  // The pass that brings the tombstone is held at the sync memory (the page is judged and planned, not yet used) while the write is sent and refused.
  const withLock = b.d.memory.withLock.bind(b.d.memory);
  let gate = null;
  let arrived = false;
  b.d.memory.withLock = async (...args) => {
    if (gate) {
      const wait = gate;
      gate = null;
      arrived = true;
      await wait;
    }
    return withLock(...args);
  };
  let release;
  gate = new Promise((resolve) => (release = resolve));
  const pass = b.engine.syncNow();
  await until(() => arrived, "the pass is at the memory");
  b.d.timers.advance(3_000); // the retry of the write: the server refuses it (the item is deleted)
  await until(() => b.d.events.error.some((e) => e.code === "conflict"), "the refusal");
  release();
  await pass;
  await settle(20);
  assert.equal(sim.server.items.get(id).deleted, true);
  assert.equal(shows(b, id)?.conflict, true, "the refused edit is on screen as a conflict with the deleted row");
  assert.equal((await queued(b)).length, 1);
  await sim.stopAll();
});

test("a_pass_that_is_stopped_while_it_reads_the_memory_does_not_ask_the_server", async () => {
  const sim = await world([1]);
  const [a] = sim.devices;
  const load = a.d.memory.load.bind(a.d.memory);
  let hold = null;
  a.d.memory.load = async () => {
    if (hold) await hold;
    return load();
  };
  let release;
  hold = new Promise((resolve) => (release = resolve));
  const pass = a.engine.syncNow();
  await settle(10);
  a.stopped = true;
  a.engine.stop();
  const asked = a.d.api.gets.length;
  hold = null;
  release();
  await pass;
  await settle(20);
  assert.equal(a.d.api.gets.length, asked, "no request after stop()");
  assert.deepEqual(a.lateCalls, []);
});

test("a_listing_that_is_stopped_while_it_reads_the_memory_does_not_ask_the_server", async () => {
  const sim = await world([1]);
  const [a] = sim.devices;
  const first = "10".repeat(16);
  sim.server.set(first, { rev: 1, ...sim.client.wireRow(first, 1, { item_type: "login", name: "one" }) });
  // The feed answers 410 once: the engine lists the vault, and the pass is held at the memory just before the first page of the listing.
  const get = a.d.api.get;
  let told = false;
  a.d.api.get = async (path, ...rest) => {
    if (path.startsWith("/api/sync/changes") && !told) {
      told = true;
      throw new ApiError(410, "gone", null, { error: "gone", min_valid_since: 1 });
    }
    return get(path, ...rest);
  };
  const load = a.d.memory.load.bind(a.d.memory);
  let hold = null;
  a.d.memory.load = async () => {
    if (told && hold === null) hold = new Promise((resolve) => (release = resolve));
    if (hold) await hold;
    return load();
  };
  let release = () => {};
  const pass = a.engine.syncNow();
  await until(() => told, "the 410");
  await settle(10);
  a.stopped = true;
  a.engine.stop();
  const asked = a.d.api.gets.length;
  const wait = hold;
  hold = null;
  release();
  await wait;
  await pass;
  await settle(20);
  assert.equal(a.d.api.gets.length, asked, "no request after stop()");
  assert.deepEqual(a.lateCalls, []);
});

/**
 * Two devices that hold the same state; the first leaves behind a backup, then the vault takes more writes; the server is restored from
 * the backup (restore epoch 1). Answers the devices and the ids: `kept` (in the backup), `lost` (written after it, held by both).
 */
async function restoredWorld() {
  const sim = await world();
  const [a, b] = sim.devices;
  const kept = await a.engine.create(draft("before the backup"));
  await untilServerRev(sim, kept, 1);
  await b.engine.syncNow();
  const backup = sim.server.backup(); // seq 1
  const lost = await a.engine.create(draft("after the backup"));
  await untilServerRev(sim, lost, 1);
  await a.engine.update(lost, { name: "edited after the backup" }, currentRev(a.engine, lost));
  await untilServerRev(sim, lost, 2);
  await b.engine.syncNow();
  assert.equal(shows(b, lost)?.rev, 2);
  await sim.restoreServer(backup);
  return { sim, a, b, kept, lost };
}

/** Rows written to the server by someone else until its seq is `to`. */
function writeUntil(sim, to, prefix = "f0") {
  const ids = [];
  while (sim.server.seq < to) {
    const id = `${prefix}${String(sim.server.seq + 1).padStart(2, "0")}`.repeat(16).slice(0, 32);
    sim.server.set(id, { rev: 1, ...sim.client.wireRow(id, 1, { item_type: "login", name: `written elsewhere ${sim.server.seq + 1}` }) });
    ids.push(id);
  }
  return ids;
}

test("a_device_that_meets_a_restored_server_late_does_not_miss_what_was_written_to_it", async () => {
  const sim = await world();
  const [a, b] = sim.devices;
  const first = await a.engine.create(draft("before the backup"));
  await untilServerRev(sim, first, 1);
  await b.engine.syncNow();
  const backup = sim.server.backup(); // seq 1
  // After the backup: one item, edited four times (seq 2 to 6). Both devices have it.
  const item = await a.engine.create(draft("v1"));
  await untilServerRev(sim, item, 1);
  for (let rev = 1; rev < 5; rev += 1) {
    await a.engine.update(item, { name: `v${rev + 1}` }, currentRev(a.engine, item));
    await untilServerRev(sim, item, rev + 1);
  }
  await b.engine.syncNow();
  assert.equal(sim.server.seq, 6);
  await sim.restoreServer(backup);
  // The first device meets the restored server, accepts, and goes on: its copy of the item goes up again (one row, seq 2), and it adds
  // an item and changes it twice more, so that the server's seq is 6 again, as the second device remembers it.
  await a.engine.syncNow();
  assert.equal(a.engine.health().halted, "server_restored");
  await sim.accept(a);
  await untilServerRev(sim, item, 1);
  const added = await a.engine.create(draft("added after the restore"));
  await untilServerRev(sim, added, 1);
  for (let rev = 1; rev < 3; rev += 1) {
    await a.engine.update(added, { name: `added ${rev + 1}` }, currentRev(a.engine, added));
    await untilServerRev(sim, added, rev + 1);
  }
  assert.equal(sim.server.seq, 5);
  await a.engine.update(added, { name: "added 4" }, currentRev(a.engine, added));
  await untilServerRev(sim, added, 4);
  assert.equal(sim.server.seq, 6);
  // The second device meets the server now. It must stop for the restore: it holds the item at revision 5, the server shows it at revision 1.
  await b.engine.syncNow();
  assert.equal(b.engine.health().halted, "server_restored");
  assert.equal(shows(b, item)?.rev, 5, "what the device holds is left as it is");
  await sim.stopAll();
});

test("an_idle_device_meeting_a_restored_server_after_seq_passed_its_cursor_stops_with_server_restored", async () => {
  const { sim, b, lost } = await restoredWorld();
  // Someone else writes to the restored server until its seq is above the cursor of the idle device (3): that device is shown no
  // top below what it remembers, and the feed from its cursor holds nothing it has lost.
  writeUntil(sim, 5);
  sim.heal();
  const gets = b.d.api.gets.length;
  await b.engine.syncNow();
  assert.equal(b.engine.health().halted, "server_restored", "it holds an item the restored server does not have");
  assert.ok(b.d.api.gets.slice(gets).some((path) => path.startsWith("/api/sync/items")), "the vault was listed before anything was decided");
  assert.equal(shows(b, lost)?.rev, 2, "nothing it holds is dropped");
  assert.equal((await loadSyncState(b.group.db.store, SERVER, ACCOUNT)).restoreEpoch, 0, "the new epoch is not stored");
  assert.equal(sim.server.writes.length, 3, "and it wrote nothing");
  await sim.stopAll();
});

test("a_device_with_nothing_lower_stores_the_epoch_after_a_full_listing_and_gets_the_rows_written_at_reused_seqs", async () => {
  const sim = await world();
  const [a, b] = sim.devices;
  const kept = await a.engine.create(draft("before the backup"));
  await untilServerRev(sim, kept, 1);
  await b.engine.syncNow();
  const backup = sim.server.backup(); // seq 1
  // An item that is created and deleted after the backup: the device holds its tombstone (seq 3) and nothing live that the restore loses.
  const gone = await a.engine.create(draft("short-lived"));
  await untilServerRev(sim, gone, 1);
  await a.engine.remove(gone);
  await untilServerRev(sim, gone, 2);
  await b.engine.syncNow();
  assert.equal(sim.server.seq, 3);
  await sim.restoreServer(backup);
  // Rows are written at seq 2, 3 and 4: the cursor of the device is 3, and the feed from it brings only the last.
  const written = writeUntil(sim, 4);
  sim.heal();
  await b.engine.syncNow();
  await settle(20);
  assert.equal(b.engine.health().halted, null, "nothing it holds is lower than what the server shows");
  assert.deepEqual(
    b.engine.list().map((item) => item.name).sort(),
    ["before the backup", ...written.map((id, at) => `written elsewhere ${at + 2}`)].sort(),
    "every row of the restored server is shown, also the ones below the old cursor",
  );
  assert.equal((await loadSyncState(b.group.db.store, SERVER, ACCOUNT)).restoreEpoch, 1, "the epoch is stored");
  assert.ok(b.d.events.state.some((e) => e.kind === "warning" && e.code === "restore_epoch_raised"));
  await sim.stopAll();
});

test("a_raised_epoch_is_listed_once_and_the_feed_goes_on_from_the_first_page_of_the_listing", async () => {
  const sim = await world([1], { pageSize: 2 });
  const [a] = sim.devices;
  const ids = [];
  for (let n = 0; n < 5; n += 1) ids.push(await a.engine.create(draft(`item ${n}`)));
  await untilServerRev(sim, ids[4], 1);
  await a.engine.syncNow(); // the device has read its own rows, and nothing is in flight when the server is restored
  await settle(20);
  const backup = sim.server.backup();
  await sim.restoreServer(backup);
  const gets = a.d.api.gets.length;
  await a.engine.syncNow();
  await settle(20);
  assert.equal(a.engine.health().halted, null, "a device that holds what the backup holds has nothing to be asked about");
  const paths = a.d.api.gets.slice(gets);
  assert.equal(paths.filter((path) => path.startsWith("/api/sync/items")).length, 3, "one listing of three pages");
  await a.engine.syncNow();
  assert.equal(a.d.api.gets.slice(gets).filter((path) => path.startsWith("/api/sync/items")).length, 3, "and not again once the epoch is stored");
  await sim.stopAll();
});

test("a_listing_left_behind_by_a_failed_pass_is_not_reused_for_a_raised_epoch", async () => {
  const sim = await world([1]);
  const [a] = sim.devices;
  const backup = sim.server.backup(); // an empty vault
  const lost = await a.engine.create(draft("written after the backup"));
  await untilServerRev(sim, lost, 1);
  const other = await a.engine.create(draft("and another"));
  await untilServerRev(sim, other, 1);
  await a.engine.syncNow();
  await settle(20);
  assert.equal(shows(a, lost)?.rev, 1);
  // A pass lists the vault after a 410 (the epoch is still 0), and the feed fails after it: the listing is left behind.
  const get = a.d.api.get;
  let reads = 0;
  a.d.api.get = async (path, ...rest) => {
    if (path.startsWith("/api/sync/changes")) {
      reads += 1;
      if (reads === 1) throw new ApiError(410, "gone", null, { error: "gone", min_valid_since: 1 });
      if (reads === 2) throw new ApiError(0, "network");
    }
    return get(path, ...rest);
  };
  await a.engine.syncNow();
  await settle(20);
  assert.equal(reads, 2, "the pass listed, then failed on the feed");
  // The server is restored, and someone else writes past the cursor of the device.
  await sim.restoreServer(backup);
  writeUntil(sim, 4);
  const asked = a.d.api.gets.length;
  await a.engine.syncNow();
  assert.ok(a.d.api.gets.slice(asked).some((path) => path.startsWith("/api/sync/items")), "the vault is listed again for the raised epoch");
  assert.equal(a.engine.health().halted, "server_restored", "the device holds items the restored server lacks");
  assert.equal(shows(a, lost)?.rev, 1, "and keeps them");
  await sim.stopAll();
});

test("a_device_that_was_reloaded_stores_a_checkpoint_within_minutes", async () => {
  // A device that has verified stores a checkpoint ten minutes after the vault changed, in the session that verified (the control). After
  // a reload within a day of that verification the new session verifies when it has a checkpoint to store, and stores it.
  const sim = await world([1]);
  const [first] = sim.devices;
  const one = await first.engine.create(draft("one"));
  await untilServerRev(sim, one, 1);
  first.d.timers.advance(11 * 60_000);
  await first.engine.syncNow();
  await settle(20);
  assert.equal(sim.server.checkpoint.seq, sim.server.seq, "the session that verified stores a checkpoint");
  const two = await first.engine.create(draft("two"));
  await untilServerRev(sim, two, 1);
  const reloaded = await sim.restart(first);
  reloaded.d.timers.advance(11 * 60_000);
  await reloaded.engine.syncNow();
  await settle(20);
  assert.equal(sim.server.checkpoint.seq, sim.server.seq, "the vault changed more than ten minutes ago and the device has read it");
  await sim.stopAll();
});

test("a_reload_verifies_only_when_there_is_a_checkpoint_to_store", async () => {
  const sim = await world([1]);
  const [first] = sim.devices;
  const one = await first.engine.create(draft("one"));
  await untilServerRev(sim, one, 1);
  first.d.timers.advance(11 * 60_000);
  await first.engine.syncNow();
  await settle(20);
  assert.equal(sim.server.checkpoint.seq, sim.server.seq);
  const verified = () => sim.client.vault.calls.filter((call) => call[0] === "verify_checkpoint").length;
  const before = verified();
  const reloaded = await sim.restart(first);
  reloaded.d.timers.advance(11 * 60_000);
  await reloaded.engine.syncNow();
  await settle(20);
  assert.equal(verified(), before, "nothing new to store: the reloaded session does not verify before a day has passed");
  await sim.stopAll();
});

test("a_listing_that_is_cut_short_does_not_hide_the_rows_it_did_not_reach", async () => {
  // A listing hands out rows in the order of the ids, so after its first page the cache can hold a row with a high `seq` while rows with a lower
  // one are still to come. If the page is closed there, the next start must not read the feed from that `seq`: it lists the vault again.
  const sim = await world([1], { pageSize: 1 });
  const [a] = sim.devices;
  const sealed = (id, name) => ({ rev: 1, ...sim.client.wireRow(id, 1, { item_type: "login", name }) });
  const [low, middle, high] = ["10".repeat(16), "20".repeat(16), "30".repeat(16)];
  sim.server.set(high, sealed(high, "written first")); // seq 1, the highest id
  await a.engine.syncNow();
  const gone = "ee".repeat(16);
  sim.server.set(gone, { rev: 2, deleted: true, tomb: sim.client.wireTomb(gone, 2) }); // seq 2, purged: the feed floor goes above the device's cursor
  sim.server.pinCheckpoint();
  sim.server.purgeTombstones(() => false, false);
  sim.server.set(middle, sealed(middle, "written second")); // seq 3
  sim.server.set(low, sealed(low, "written third")); // seq 4, the lowest id: the first row of the listing
  // The second page of the listing is never read: the page is closed after the first.
  const get = a.d.api.get;
  let pages = 0;
  a.d.api.get = async (path, ...rest) => {
    if (path.startsWith("/api/sync/items") && (pages += 1) === 2) {
      a.stopped = true;
      a.engine.stop();
      throw new ApiError(0, "network");
    }
    return get(path, ...rest);
  };
  await a.engine.syncNow();
  await settle(20);
  const reopened = await sim.restart(a);
  await pump(reopened);
  await pump(reopened);
  assert.deepEqual(reopened.engine.list().map((item) => item.name).sort(), ["written first", "written second", "written third"], "every row of the vault is shown");
  await sim.stopAll();
});

test("a_start_after_a_listing_that_was_cut_short_lists_the_vault_again_from_the_beginning_and_the_start_after_that_does_not", async () => {
  const sim = await world([1], { pageSize: 1 });
  const [a] = sim.devices;
  const ids = ["10", "20", "30"].map((n) => n.repeat(16));
  const key = `sync.flags.${scope().accountId}.${scope().vaultId}.${scope().vkEpoch}.listing`;
  const noted = async (dev) => (await dev.d.store.getSetting(dev.d.store.database.store, key)) != null;
  const listed = (dev) => dev.d.api.gets.filter((path) => path.startsWith("/api/sync/items"));
  sim.server.set(ids[2], { rev: 1, ...sim.client.wireRow(ids[2], 1, { item_type: "login", name: "row 2" }) });
  await a.engine.syncNow();
  assert.equal(await noted(a), false, "a pass that lists nothing leaves no note");
  const gone = "ee".repeat(16);
  sim.server.set(gone, { rev: 2, deleted: true, tomb: sim.client.wireTomb(gone, 2) });
  sim.server.pinCheckpoint();
  sim.server.purgeTombstones(() => false, false); // the floor is above the cursor of the device
  ids.slice(0, 2).forEach((id, at) => sim.server.set(id, { rev: 1, ...sim.client.wireRow(id, 1, { item_type: "login", name: `row ${at}` }) }));
  const get = a.d.api.get;
  let pages = 0;
  a.d.api.get = async (path, ...rest) => {
    if (path.startsWith("/api/sync/items") && (pages += 1) === 2) {
      a.stopped = true;
      a.engine.stop();
      throw new ApiError(0, "network");
    }
    return get(path, ...rest);
  };
  await a.engine.syncNow();
  await settle(20);
  assert.equal(await noted(a), true, "the note of the unfinished listing is stored");
  const reopened = await sim.restart(a);
  await pump(reopened);
  assert.equal(listed(reopened)[0].includes("after="), false, "the listing begins again, from the first id");
  assert.equal(listed(reopened).length, 3, "and is read to its end");
  assert.equal(await noted(reopened), false, "the note is gone once the feed after the listing has been read");
  assert.deepEqual(reopened.engine.list().map((item) => item.name).sort(), ["row 0", "row 1", "row 2"]);
  const again = await sim.restart(reopened);
  await pump(again);
  assert.equal(listed(again).length, 0, "the next start reads on from the cached rows");
  await sim.stopAll();
});

test("a_refused_edit_of_a_deleted_item_is_on_screen_in_every_run", async () => {
  await runSeeds([3406, 3591], (seed) => randomRun(seed));
});

test("a_device_that_lists_the_vault_again_shows_every_row_in_every_run", async () => {
  await runSeeds([3176, 3359], (seed) => randomRun(seed));
});

test("tabs_that_only_read_hold_no_unsent_write_after_a_reload", async () => {
  // A tab that does not run the engine holds nothing: no engine, no queue, no marks. After every page is opened again the writes of the browser are in
  // the outbox, once, and they leave from the tab that holds the vault.
  const sim = await world([3]);
  const [dev] = sim.devices;
  assert.equal(dev.tab, 0);
  assert.deepEqual(dev.group.owners.map((owner) => owner.isOwner()), [true, false, false], "the other tabs have no engine and hold no lock");
  offline(dev);
  const id = await dev.engine.create(draft("written offline"));
  await dev.engine.update(id, { name: "edited offline" }, currentRev(dev.engine, id));
  assert.equal((await queued(dev)).length >= 1, true);
  const reloaded = await sim.restart(dev);
  assert.equal(reloaded.engine.list().find((item) => item.id === id)?.pending, true, "what was not sent is shown after the reload");
  online(reloaded);
  await pump(reloaded);
  await untilServerRev(sim, id, 2);
  assert.equal((await queued(reloaded)).length, 0);
  sim.checkOwners();
  assert.deepEqual(sim.problems, []);
  await sim.stopAll();
  // The seeds that found the reader-tab gap, before the vault had one owner per browser.
  await runSeeds([1494, 4347], (seed) => randomRun(seed));
});

test("two_tabs_that_both_write_keep_every_write", async () => {
  // The user writes in one tab, moves the vault to another ("Use here") and writes there, again and again, while the network drops and answers get lost.
  const total = await runSeeds(seedsOf(fewer()), (seed) => randomRun(seed, { layouts: [[2], [2, 1], [3]] }));
  assert.ok((total["owner:ask"] ?? 0) + (total["owner:steal"] ?? 0) + (total["owner:closed"] ?? 0) > 0, "the vault moved");
});

test("use_here_moves_the_vault_and_a_write_that_was_queued_goes_out_once_from_the_new_tab", async () => {
  for (const variant of ["ask", "steal", "closed"]) {
    const sim = await world([2]);
    const [first] = sim.devices;
    offline(first);
    const id = await first.engine.create(draft(`queued before ${variant}`));
    await settle(10);
    assert.equal((await queued(first)).length, 1);
    online(first);
    const second = await sim.useHere(first, { variant });
    assert.ok(second, variant);
    assert.equal(second.tab, 1);
    assert.equal(first.stopped, true, "the first tab has stopped its engine");
    assert.deepEqual(second.group.owners.map((owner) => owner.isOwner()), [false, true], "and let go of the lock");
    await untilServerRev(sim, id, 1);
    await pump(second);
    assert.equal((await queued(second)).length, 0, variant);
    assert.equal(sim.server.accepted().filter((write) => write.id === id).length, 1, `${variant}: once on the server`);
    assert.equal(second.engine.list().find((item) => item.id === id)?.pending, false);
    await sim.stopAll();
    assert.deepEqual(sim.problems, [], variant);
  }
});

test("a_pass_of_the_old_owner_that_is_let_go_after_the_vault_moved_does_nothing", async () => {
  // The first tab has a pass in the air (the server has answered, the engine has not used the answer); the vault moves to the second tab, which reads
  // and stores a newer feed; then the old pass is let go. It asks nothing, writes nothing and lowers no floor.
  for (const variant of ["ask", "steal"]) {
    const sim = await world([2]);
    const [first] = sim.devices;
    const id = await first.engine.create(draft("one"));
    await untilServerRev(sim, id, 1);
    await pump(first);
    const gate = { arrived: false, release: () => {}, promise: null };
    gate.promise = new Promise((resolve) => (gate.release = resolve));
    first.hold = gate;
    sim.elsewhere();
    const pass = first.engine.syncNow().catch(() => {});
    await until(() => gate.arrived, "the pass is in the air");
    first.hold = null;
    sim.elsewhere();
    const second = await sim.useHere(first, { variant, during: (made) => made.engine.syncNow() });
    const floorBefore = await sim.floorsOfGroup(first.group);
    gate.release();
    await pass;
    await settle(30);
    const floorAfter = await sim.floorsOfGroup(first.group);
    assert.ok(floorAfter.maxSeq >= floorBefore.maxSeq, `${variant}: no floor went down`);
    assert.deepEqual(first.lateCalls, [], `${variant}: the old engine asked the server after it stopped`);
    assert.equal(second.engine.list().length, 3, variant);
    await sim.checkFloors();
    await sim.stopAll();
    assert.deepEqual(sim.problems, [], variant);
  }
});

test("a_device_that_still_holds_a_purged_tombstone_is_no_alarm_for_a_checkpoint_that_lacks_it", { todo: "a purged tombstone can look like a rollback" }, async () => {
  // Device A deleted an item and holds the tombstone. The tombstone is purged on the server (400 days), and a checkpoint that a device
  // stored after that, one that never saw the item, does not list it. At the top of that checkpoint A holds a row it does not list.
  const sim = new Sim(1, { layout: [1] });
  await sim.start();
  const [a] = sim.devices;
  const id = await a.engine.create(draft("short-lived"));
  await untilServerRev(sim, id, 1);
  await a.engine.remove(id);
  await untilServerRev(sim, id, 2);
  await a.engine.syncNow();
  sim.server.items.delete(id); // purged
  sim.server.minValidSince = 2;
  sim.server.pinCheckpoint(); // what another device stored: no entry for the item
  assert.equal(await a.engine.verifyNow(), "ok", "an honest server that has purged a tombstone is no reason for an alarm");
  assert.deepEqual(a.engine.health().warnings, []);
  await sim.stopAll();
});

test("a_purged_tombstone_that_the_checkpoint_still_lists_live_is_no_alarm", { todo: "a purged tombstone can look like a rollback" }, async () => {
  // The last checkpoint was stored when the item was live; the item was deleted and the tombstone has been purged after 400 days, and
  // no device has stored a newer checkpoint since. A device that starts now lists the vault, finds no row, and the checkpoint lists the item.
  const sim = new Sim(1, { layout: [1] });
  const id = "ab".repeat(16);
  sim.server.set(id, { rev: 1, ...sim.client.wireRow(id, 1, { item_type: "login", name: "gone" }) });
  sim.server.pinCheckpoint();
  sim.server.items.delete(id); // deleted at seq 2 and purged: the row is gone
  sim.server.seq = 2;
  sim.server.minValidSince = 2;
  await sim.start();
  await sim.devices[0].engine.syncNow();
  assert.deepEqual(sim.devices[0].engine.health().warnings, [], "an honest server that has purged a tombstone is no reason for an alarm");
  await sim.stopAll();
});
