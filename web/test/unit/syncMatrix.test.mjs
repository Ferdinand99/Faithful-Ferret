// The sync matrix against the engine: the seven scenarios of the first prototype, then seeded random runs of two or three engines (on
// storages of their own, and as tabs over one) against a model of the server that has every rule of the sync routes and can fail on
// request, with the invariants of the design checked after every step and at rest. Spec: Fase 1 section 8 and section 14.7.
//
// `FERRET_MATRIX_RUNS` sets how many seeded runs the randomised tests make (500 by default, 5000 at the gate); a failing run names its
// seed, and `FERRET_MATRIX_SEED=<seed>[,<seed>...]` runs the named seeds of the randomised tests alone.
//
// What the model does not assert, because it is reported (each has a todo test below):
//   known gap, hidden draft  a write that waits in the outbox when the feed brings the tombstone of its item is refused afterwards and is then a blocked
//            draft that is on no screen (todo tests `a_write_refused_over_a_tombstone...` and `a_deletion_refused_over_a_tombstone...`)
//   known gap, request after stop  a feed read can still go out when `stop()` comes while a pass reads the sync memory (todo test
//            `a_pass_that_is_stopped_while_it_reads_the_memory_does_not_ask_the_server`)
//   known gap, writing tabs  two tabs of one browser that both change things can drop or hide each other's queued writes (the outbox and the marks are
//            stored once and kept in memory by each tab); in the runs only the first tab of a browser changes things (todo test
//            `two_tabs_that_both_write_keep_every_write`)
//   known gap, purged tombstone  the checkpoint of the server can list the item of a purged tombstone live (todo test
//            `a_purged_tombstone_that_the_checkpoint_still_lists_live_is_no_alarm`); the model purges only what the checkpoint lists
// Each of them is a gap the engine has today, not a rule of the design; when one is closed its todo test starts to pass and the
// matching switch (`knownGaps` in `syncModel.mjs`) goes.
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

/** Two or three engines: on storages of their own, and two or three tabs over one. */
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
  await sim.checkWrites();
  sim.checkResurrections();
  await sim.checkFloorsCoverRows();
  await sim.checkNoPlaintext();
  sim.tally();
  await sim.stopAll();
}

/** One seeded run of `steps` random steps. */
async function randomRun(seed, { layouts = LAYOUTS, steps = STEPS, actions = ACTIONS, tabsWrite = false } = {}) {
  const pick = rngOf(seed * 7919 + 13);
  const sim = new Sim(seed, { layout: pick.pick(layouts), tabsWrite });
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
  // The runs do what they are meant to do: writes, conflicts, choices, restarts, listings after a 410, checkpoints verified and uploaded.
  if (ONLY === null && RUNS >= 100) {
    for (const key of ["server_writes", "error:conflict", "resurrect_writes", "act:restart", "listings", "verify_checkpoint_calls", "server_checkpoint_puts"]) {
      assert.ok((total[key] ?? 0) > 0, `the runs never made ${key}`);
    }
  }
});

test("two_engines_on_one_store_never_lower_a_floor_under_random_runs", async () => {
  // Tabs of one browser: more reading than writing, restarts, and passes that run at the same time, so the sync memory is read and
  // saved by two engines in turns. The floors are read from the store after every step (`checkFloors`).
  const tabsActions = [["sync", 20], ["poll", 16], ["restart", 8], ["fault", 6], ["offline", 4], ["create", 8], ["update", 12], ["remove", 3], ["jump", 2], ["both", 14], ["race", 12]];
  const total = await runSeeds(seedsOf(Math.max(50, Math.ceil(RUNS / 2))), async (seed) => {
    const sim = new Sim(seed, { layout: [[2], [3], [2, 1]][seed % 3] });
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
});

// ------------------------------------------------------------------------- a restored server

/**
 * Two devices that hold the same state; a backup; changes after it; the server is restored from the backup. Then each device meets the
 * server and its user accepts the older state, in either order, with edits between (`afterwards`).
 */
async function restoreRun(seed, { afterwards }) {
  const rng = rngOf(seed * 104729 + 7);
  const sim = new Sim(seed, { layout: [1, 1] });
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

    // A device that meets a server which another device has already brought back to its own state may find nothing lower, store the new
    // epoch and go on without a question: so here a device that has not accepted is not expected to stop.
    await sim.restoreServer(backup, { watch: false });
    const frozen = new Map(sim.server.frozen);
    sim.heal();
    // Both devices meet the restored server before either accepts (known gap, late restore contact: a device that first meets it after the other has written to it
    // can keep a cursor above the new rows and miss them).
    for (const dev of sim.devices) {
      await dev.engine.syncNow();
      await settle(10);
    }
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
    sim.tally();
    await sim.stopAll();
  } finally {
    for (const dev of sim.devices) dev.engine.stop();
  }
  if (sim.problems.length > 0) assert.fail(sim.report());
  return sim.tally();
}

test("restore_with_two_devices_loses_nothing_and_overwrites_nothing", async () => {
  // Nobody changes anything after the restore: no conflict that is not one of the known kinds, and nothing is lost.
  await runSeeds(seedsOf(fewer()), (seed) => restoreRun(seed, { afterwards: false }));
  // Devices change things between their acceptances: what is written after the restore stands.
  const total = await runSeeds(seedsOf(fewer()), (seed) => restoreRun(seed + 100_000, { afterwards: true }));
  assert.ok((total["state:halted:server_restored"] ?? 0) > 0, "the runs do stop for a restored server");
});

test("a_restore_in_the_middle_of_a_run_never_lands_a_write_on_the_restored_state", async () => {
  const total = await runSeeds(seedsOf(fewer()), async (seed) => {
    const rng = rngOf(seed * 15485863 + 3);
    const sim = new Sim(seed, { layout: rng.pick(LAYOUTS) });
    try {
      await sim.start();
      await sim.run(rng.between(6, 12));
      await sim.calm();
      const backup = sim.server.backup();
      await sim.run(rng.between(5, 12)); // the devices see more than the backup holds
      await sim.restoreServer(backup);
      const before = sim.server.writes.length;
      // The users keep working, and nobody accepts anything. The retention job does not run and nobody writes to the server but the devices:
      // a server whose seq has passed what a device remembers is one that device finds nothing lower on (known gap, late restore contact).
      await sim.run(rng.between(12, 24), { actions: ACTIONS.filter(([name]) => !["retention", "purge", "race"].includes(name)) });
      sim.heal();
      for (let round = 0; round < 3; round += 1) {
        for (const dev of sim.devices) await pump(dev);
      }
      // Every write the server took since carries the new epoch, and none came from a device that had seen more than the backup shows.
      for (const write of sim.server.accepted().slice(before)) {
        if (write.restoreEpoch !== sim.server.restoreEpoch) sim.fail(`a write to ${write.id.slice(0, 4)} was taken with the restore epoch ${write.restoreEpoch}, the server is at ${sim.server.restoreEpoch}`);
      }
      // A device that has been shown a top below what it remembers has stopped, and still is. (One that first meets a server whose seq has
      // passed what it remembers finds nothing lower: known gap, late restore contact.)
      for (const dev of sim.devices) {
        const remembered = (await sim.floorsOf(dev)).maxSeq;
        if (remembered > sim.server.seq && dev.engine.health().halted !== "server_restored") sim.fail(`${dev.label} has seen more than the restored server shows and is ${dev.engine.health().halted ?? "not stopped"}`);
      }
      await sim.checkFloors();
      await sim.checkNoPlaintext();
      sim.tally();
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
    sim.knownGaps = false;
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

// ------------------------------------------------------------------------- findings of the matrix (todo)
// Each todo test is the smallest run found that shows a gap (two live-draft ones are controls that pass). They are `todo`, so that a fix turns them green without anyone having to find
// them again.

test("a_write_refused_over_a_tombstone_the_feed_has_already_brought_stays_on_screen", async () => {
  const sim = await world();
  const [a, b] = sim.devices;
  const id = await a.engine.create(draft("v0"));
  await untilServerRev(sim, id, 1);
  await b.engine.syncNow();
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
  await sim.stopAll();
});

test("a_chain_of_edits_refused_over_a_tombstone_the_feed_has_already_brought_stays_on_screen", async () => {
  const sim = await world();
  const [a, b] = sim.devices;
  const id = await a.engine.create(draft("v0"));
  await untilServerRev(sim, id, 1);
  await b.engine.syncNow();
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
  await sim.stopAll();
});

test("a_deletion_refused_over_a_tombstone_the_feed_has_already_brought_leaves_no_blocked_draft", { todo: "a refused write is left hidden once the tombstone is known" }, async () => {
  const sim = await world();
  const [a, b] = sim.devices;
  const id = await a.engine.create(draft("v0"));
  await untilServerRev(sim, id, 1);
  await b.engine.syncNow();
  offline(b);
  await b.engine.update(id, { name: "edited, then deleted" }, currentRev(b.engine, id)); // base 1
  await b.engine.remove(id); // base 2: the two writes wait
  await a.engine.update(id, { name: "v1" }, currentRev(a.engine, id));
  await untilServerRev(sim, id, 2);
  await a.engine.remove(id);
  await untilServerRev(sim, id, 3);
  online(b);
  await b.engine.syncNow();
  await pump(b);
  await pump(b);
  // Both devices deleted the item: there is nothing to choose, and nothing may stay behind that stops the device from storing checkpoints.
  assert.equal((await queued(b)).length, 0);
  await sim.stopAll();
});

test("a_pass_that_is_stopped_while_it_reads_the_memory_does_not_ask_the_server", { todo: "a feed read goes out after stop()" }, async () => {
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

test("a_device_that_meets_a_restored_server_late_does_not_miss_what_was_written_to_it", { todo: "a device that meets a restored server late misses it" }, async () => {
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
  await sim.restoreServer(backup, { watch: false });
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
  // The second device meets the server now. It must either stop for the restore or show what the first device wrote.
  await b.engine.syncNow();
  const stopped = b.engine.health().halted !== null;
  assert.ok(stopped || shows(b, added)?.name === "added 4", "it neither stops nor shows the item that was added after the restore");
  await sim.stopAll();
});

test("two_tabs_that_both_write_keep_every_write", { todo: "two tabs that both write can lose writes" }, async () => {
  await runSeeds(seedsOf(fewer()), (seed) => randomRun(seed, { layouts: [[2], [2, 1]], tabsWrite: true }));
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
