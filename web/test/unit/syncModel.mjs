// A model of the sync server and of a few devices, for the matrix tests (`syncMatrix.test.mjs`, `engineScale.test.mjs`).
//
// `SimServer` is the item store of the fake server of `syncHelpers.mjs` with the rest of what the sync rules of the server
// give: a checkpoint that is stored (structure only) and replaced, the key of a write before the restore epoch before the
// revision, resurrection only with the flag and the tombstone's revision, the retention of tombstones (a 410 for a device that
// is behind the purge), backups, and a restore that is recorded the way `ferret restore-epoch bump` records it.
//
// `Sim` runs devices (engines over their own fake browser storage; a browser can have several tabs, of which one holds the owner
// lock and runs the engine, and the others are on standby until the user presses "Use here") against it, with the faults a
// network and a server can give (a request that never arrives, an answer that is lost, 429, 503, a feed that fails), and a seeded
// random choice of what happens next. It keeps the facts the invariants of the matrix need: every write a user made, every
// choice the user made, the floors of the sync memory over time, and every request an engine made after `stop()`.
import { ApiError } from "../../src/api.mjs";
import { b64u, hex16 } from "../../src/b64.mjs";
import { cache } from "../../src/store/cache.mjs";
import { STORES } from "../../src/store/idb.mjs";
import { outbox } from "../../src/store/outbox.mjs";
import { loadSyncState } from "../../src/store/syncState.mjs";
import { serverKey } from "../../src/store/idb.mjs";
import { createSyncEngine } from "../../src/sync/engine.mjs";
import { createOwner, ownerName } from "../../src/sync/owner.mjs";
import { ACCOUNT, freshStore, scope, SERVER } from "./idbHelpers.mjs";
import {
  counterRand, createFakeApi, createFakeClient, createFakeStore, FakeChannels, FakeLocks, FakeTimers, fakeMemory, memoryOf, Model, settle,
} from "./syncHelpers.mjs";

/** An item id as a log line shows it: the first two bytes and the last one (the last byte belongs to the random source of one engine). */
const short = (id) => `${id.slice(0, 4)}..${id.slice(-2)}`;

/** The top of the call stack, for a report: function names and line numbers, no paths. */
const frames = () => (new Error().stack ?? "").split("\n").slice(3, 10).map((line) => line.trim().replace("at ", "").split("/").at(-1)).join(" < ");

/**
 * The gaps of the engine that the runs still tolerate (each has a todo test in `syncMatrix.test.mjs`): `purge` (a purged tombstone can look
 * like a rollback). Tolerated by default. `FERRET_MATRIX_STRICT=1` tolerates none; `FERRET_MATRIX_TOLERATE=purge` names the ones that are still
 * let through (to see what a strict run finds besides them).
 */
export const KNOWN_GAPS = Object.freeze(["purge"]);
const tolerated = () => (process.env.FERRET_MATRIX_STRICT
  ? new Set((process.env.FERRET_MATRIX_TOLERATE ?? "").split(",").map((name) => name.trim()).filter(Boolean))
  : new Set(KNOWN_GAPS));

/** The text every secret the matrix writes starts with: a store or a request that holds it has leaked a secret. */
export const SECRET = "SECRET-";

/** The wait between two polls of an engine. A run moves the clock of an engine by minutes, so this is long enough for one poll per move. */
export const POLL_MS = 300_000;

/** A seeded source of numbers (mulberry32), so a failing run can be run again. */
export function rngOf(seed) {
  let state = seed >>> 0;
  const next = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return {
    next,
    int: (n) => Math.floor(next() * n),
    between: (a, b) => a + Math.floor(next() * (b - a + 1)),
    chance: (p) => next() < p,
    pick: (list) => list[Math.floor(next() * list.length)],
    weighted(pairs) {
      const total = pairs.reduce((sum, [, weight]) => sum + weight, 0);
      let at = next() * total;
      for (const [value, weight] of pairs) {
        at -= weight;
        if (at < 0) return value;
      }
      return pairs[pairs.length - 1][0];
    },
  };
}

/** The server: the model of `syncHelpers.mjs` with an honest checkpoint of an empty vault, tombstone retention and backups. */
export class SimServer extends Model {
  constructor() {
    super();
    this.checkpoint = this.autoCheckpoint(0); // registration stores one; a device replaces it when it has something newer
    this.onWrite = null; // (seq) => void, called after every accepted write (the event stream)
    this.revived = []; // every write that took a live row over a tombstone: { id, at }
  }

  put(id, body) {
    const before = this.seq;
    const was = this.items.get(id);
    const result = super.put(id, body);
    if (this.seq !== before) {
      if (was?.deleted === true) this.revived.push({ id, at: this.writes.length - 1 }); // a live row over a tombstone: the item came back
      this.onWrite?.(this.seq);
    }
    return result;
  }

  /**
   * The retention job: the tombstones `keep(id)` does not name are removed and `min_valid_since` rises to the highest `seq` that was
   * removed, so a device whose cursor is below it is told 410 and lists. The job runs on time on the real server; the matrix chooses
   * the ids, because a device that holds a live copy of an item whose tombstone was removed would bring it back (nothing is deleted
   * on the server's word), which is what a device that was away for more than the retention does. A tombstone that the stored
   * checkpoint does not list yet is kept: after 400 days some device has nearly always stored a newer checkpoint, and the one case
   * where none has (a checkpoint that lists an item live and no row, no tombstone) is a false alarm that has a test of its own.
   * @returns {number} how many tombstones went
   */
  purgeTombstones(keep = () => false, narrow = true) {
    let top = 0;
    let gone = 0;
    const covered = this.checkpoint === "auto" ? this.seq : (this.checkpoint?.seq ?? 0);
    for (const [id, row] of [...this.items]) {
      if (!row.deleted || (narrow && (keep(id) || row.seq > covered))) continue;
      this.items.delete(id);
      top = Math.max(top, row.seq);
      gone += 1;
    }
    this.minValidSince = Math.max(this.minValidSince, top);
    return gone;
  }

  /** What a backup of the database holds now. */
  backup() {
    return {
      items: new Map([...this.items].map(([id, row]) => [id, { ...row }])),
      seq: this.seq,
      minValidSince: this.minValidSince,
      idems: new Map(this.idems),
      checkpoint: this.checkpoint === "auto" ? this.autoCheckpoint() : this.checkpoint,
    };
  }

  /**
   * The database is put back from a backup and `ferret restore-epoch bump` is run: the restore epoch goes up, `restore_seq` is the `seq`
   * of the restored vault, and its rows are frozen.
   */
  restoreFrom(backup) {
    this.items = new Map([...backup.items].map(([id, row]) => [id, { ...row }]));
    this.seq = backup.seq;
    this.minValidSince = backup.minValidSince;
    this.idems = new Map(backup.idems);
    this.checkpoint = backup.checkpoint;
    this.hidden = new Set();
    this.bumpRestore();
  }

  /** Every accepted write, with the item it was for and the parts of its request the matrix reads (the order is the order they were accepted). */
  accepted() {
    return this.writes.map(({ id, body }, at) => {
      const request = JSON.parse(body);
      return { at, id, baseRev: request.base_rev, rev: request.base_rev + 1, deleted: request.deleted === true, resurrect: request.resurrect === true, restoreEpoch: request.restore_epoch, blob: request.blob ?? null, tag: request.tag ?? null };
    });
  }
}

const rowsOfDb = async (database, name) => {
  const tx = database.store.db.transaction(name, "readonly");
  const objects = tx.objectStore(name);
  const read = (request) => new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  return { keys: await read(objects.getAllKeys()), values: await read(objects.getAll()) };
};

/** Everything a fake browser database holds, every object store, keys and values. */
export async function dumpDatabase(database) {
  const out = {};
  for (const name of STORES) out[name] = await rowsOfDb(database, name);
  return out;
}

/** Whether `needle` is in a value anywhere: a string, bytes or a structure of them. */
export function holds(value, needle) {
  const wanted = Buffer.from(needle);
  let found = false;
  const walk = (v) => {
    if (found || v === null || v === undefined) return;
    if (v instanceof Uint8Array) found = Buffer.from(v).includes(wanted);
    else if (typeof v === "string") found = Buffer.from(v).includes(wanted);
    else if (v instanceof Map) [...v].forEach(walk);
    else if (typeof v === "object") Object.entries(v).forEach(([k, x]) => (walk(k), walk(x)));
  };
  walk(value);
  return found;
}

/**
 * One device: the engine of `syncDevice` (a fake store, a fake clock, a fake core), with the clock of the device and the clock of the
 * bodies it writes set by the caller, and a seed for its random source.
 */
export async function simEngine({ model, client, seed, pollMs = POLL_MS, db = null, locks = new FakeLocks(), deviceName, win = null, skewMs = 0 }) {
  const store = await createFakeStore({ db });
  const api = createFakeApi(model, { order: store.spy.log });
  const timers = new FakeTimers();
  const events = { changed: [], error: [], state: [] };
  // A device whose clock is off writes bodies dated by that clock (the same vault key, so every device opens every body).
  const own = skewMs === 0 ? client : createFakeClient({ now: () => 1_700_000_000_000 + skewMs + timers.time });
  const memory = fakeMemory({ store, client: own, locks });
  const engine = createSyncEngine({
    api, client: { vault: own.vault }, store, scope: scope(), memory, timers, rand: counterRand(seed), pollMs, win, deviceName,
    now: () => 1_700_000_000_000 + skewMs + timers.time,
  });
  for (const name of Object.keys(events)) engine.on(name, (payload) => events[name].push(payload));
  return { model, client, store, api, timers, engine, events, memory, locks };
}

/** What happens in a step, and how often. */
export const ACTIONS = [
  ["create", 14], ["update", 22], ["remove", 6], ["sync", 14], ["poll", 10], ["offline", 6], ["fault", 8], ["resolve", 8],
  ["trash", 3], ["restart", 3], ["purge", 2], ["retention", 2], ["jump", 1], ["race", 3], ["useHere", 4],
];

/** Changes by the user and the engine's own pace, with nothing going wrong: no faults, nothing off the network, no restart, no purge. */
export const CALM_ACTIONS = [["create", 14], ["update", 22], ["remove", 6], ["sync", 14], ["poll", 10], ["resolve", 8], ["trash", 3]];

const EXPECTED = new Set(["conflict_unsettled", "conflict_changed", "invalid_state", "item_changed", "not_found", "blocked", "busy", "damaged", "quarantined", "missing_on_server", "reuploaded"]);

/** @param {unknown} error */
const codeOf = (error) => (error && typeof error === "object" && "code" in error ? String(error.code) : String(error));

/** A run of devices against one server. See the top of the file. */
export class Sim {
  /**
   * @param {number} seed
   * @param {{ layout?: number[], skews?: number[] }} [options] `layout`: the number of tabs of each browser (`[1, 1]` two devices, `[2, 1]`
   *   two tabs of one browser and a second browser: the first tab of a browser runs the engine, the others are on standby, and the user can move the
   *   engine to a standby tab with "Use here"); `skews`: the clock of each device is that many ms off
   */
  constructor(seed, { layout = [1, 1], skews = [], pageSize = 500 } = {}) {
    this.seed = seed;
    this.rng = rngOf(seed);
    this.server = new SimServer();
    this.server.pageSize = pageSize; // the server never answers with more rows than this: the feed, the listing and the frozen rows come in pages
    this.client = createFakeClient();
    const verify = this.client.vault.verify_checkpoint;
    this.client.vault.verify_checkpoint = async (...args) => {
      try {
        return await verify(...args);
      } catch (error) {
        const listed = new Set();
        for (let at = 0; at < args[0].entries.length; at += 56) listed.add(Buffer.from(args[0].entries.subarray(at, at + 16)).toString("hex"));
        const unlisted = args[1].map((row) => hex16.encode(row.item_id)).filter((id) => !listed.has(id)).map((id) => {
          const row = this.server.items.get(id);
          return `${short(id)} (${row ? `server rev ${row.rev}${row.deleted ? " deleted" : ""} seq ${row.seq}` : "not on the server"})`;
        });
        this.note(`  the core refused a checkpoint: ${error.code} (checkpoint seq ${args[0].seq}, top ${args[2]}, ${args[1].length} rows, server seq ${this.server.seq}; rows it does not list: ${unlisted.join(", ") || "none"})`);
        throw error;
      }
    };
    this.layout = layout;
    this.skews = skews;
    this.tabs = layout.some((n) => n > 1); // some browsers have several tabs
    this.ownerClock = new FakeTimers(); // the wait of a tab that asks for the vault before it takes it
    this.ownerTimers = { setTimeout: this.ownerClock.set, clearTimeout: this.ownerClock.clear };
    this.devices = []; // the engines that run now: one for each browser, in the tab that holds its owner lock
    this.retired = []; // the ones that were stopped (their late requests are still counted)
    this.groups = []; // { db, locks, channels, label, tabs, owners }: one per browser
    this.instances = 0;
    this.names = 0;
    this.log = [];
    this.writes = []; // what users did: { dev, id, kind, marker, step }
    this.discarded = new Set(); // `${dev}:${id}`: the user dropped the draft of the device for the item (keep theirs, discard)
    this.conflicted = new Set(); // `${dev}:${id}`: the item had a conflict on the device
    this.choices = new Map(); // item id -> how many times a user chose to bring it back (keep mine over a deleted row, the trash)
    this.floors = new Map(); // group label -> the last sync memory read
    this.problems = [];
    this.step = 0;
    this.seen = new Map(); // browser label -> Set of "id:rev": the rows its engines were shown by the feed and the listing, and wrote themselves
    this.keptMine = new Set(); // "browser:id": the user chose "keep mine" for the item in that browser
    this.tallied = false;
    this.tolerated = tolerated(); // the known gaps that are not asserted against (the todo tests hold them); FERRET_MATRIX_STRICT=1 asserts against them too
    this.stats = {}; // how often each thing happened, to see that a run does what it is meant to
    this.restoredAt = null; // the write index of the server when it was restored
    this.ghosts = new Map(); // id -> rev of the rows that the model wrote itself (a device that is not one of ours)
    this.accepted = new Set(); // devices that have accepted an older state
    this.restoreMark = new Map(); // device -> how many error events it had when the server was restored
    this.restoreWrites = 0; // how many writes the users had made when the server was restored
  }

  /** Whether a known gap (`KNOWN_GAPS`) is let through in this run. @param {string} gap */
  tolerates(gap) {
    return this.tolerated.has(gap);
  }

  fail(message) {
    this.problems.push(`step ${this.step}: ${message}`);
  }

  note(line) {
    this.log.push(`${String(this.step).padStart(3)} ${line}`);
  }

  count(what, n = 1) {
    this.stats[what] = (this.stats[what] ?? 0) + n;
  }

  /** The counts of what the engines said (errors, states) over the whole run. */
  tally() {
    if (this.tallied) return this.stats;
    this.tallied = true;
    for (const dev of [...this.devices, ...this.retired]) {
      for (const event of dev.d.events.error) this.count(`error:${event.code}`);
      for (const event of dev.d.events.state) this.count(`state:${event.kind}${event.code ? `:${event.code}` : ""}`);
    }
    for (const dev of [...this.devices, ...this.retired]) this.count("listings", dev.d.api.gets.filter((path) => path.startsWith("/api/sync/items")).length);
    this.count("verify_checkpoint_calls", this.client.vault.calls.filter((call) => call[0] === "verify_checkpoint").length);
    this.count("server_writes", this.server.writes.length);
    this.count("server_checkpoint_puts", this.server.checkpointPuts.length);
    this.count("resurrect_writes", this.server.revived.length);
    return this.stats;
  }

  // ------------------------------------------------------------ building

  async start() {
    for (const tabs of this.layout) {
      const group = await this.newGroup(tabs);
      await this.openTabs(group);
      this.devices.push(await this.spawn(group, group.label, 0, this.skews[this.devices.length] ?? 0));
    }
    for (const dev of this.devices) await dev.engine.start();
    await this.checkFloors();
  }

  /** A new browser: a storage, the locks and the channels that its tabs share. */
  async newGroup(tabs = 1) {
    const group = { db: await freshStore(), locks: new FakeLocks(), channels: new FakeChannels(), label: `browser${this.groups.length + 1}`, tabs, owners: [] };
    this.groups.push(group);
    return group;
  }

  /**
   * The owner lock of tab `tab` of a browser. `onYield` and `onLost` stop the engine of the tab, as the sync service does: the tab that
   * runs the engine is the tab that holds the lock.
   */
  makeOwner(group, tab) {
    return createOwner({
      locks: group.locks, server: serverKey(SERVER), accountId: ACCOUNT, tabId: `${group.label}-tab${tab + 1}`, timers: this.ownerTimers,
      makeChannel: () => group.channels.channel(ownerName(serverKey(SERVER), ACCOUNT)),
      onYield: () => this.giveUp(group, tab, "asked"),
      onLost: () => this.giveUp(group, tab, "stolen"),
    });
  }

  /** The engine of a browser stops because its tab was asked for the vault (or lost the lock): the outbox and the marks are stored. */
  giveUp(group, tab, why) {
    const dev = this.devices.find((d) => d.group === group && d.tab === tab && !d.stopped);
    if (!dev) return;
    this.count(`owner:gave_up_${why}`);
    this.note(`${dev.label} tab ${tab + 1} gives the vault up (${why})`);
    this.retire(dev);
  }

  /** The engine of a device is stopped; late requests are still counted. */
  retire(dev) {
    dev.stopped = true;
    dev.stoppedAt = this.step;
    dev.engine.stop();
    this.retired.push(dev);
  }

  /** The tabs of a browser are opened: the first gets the lock and the others are on standby (a second tab never starts an engine). */
  async openTabs(group) {
    for (let tab = 0; tab < group.tabs; tab += 1) {
      group.owners[tab] = this.makeOwner(group, tab);
      const role = await group.owners[tab].acquire();
      if (role !== (tab === 0 ? "owner" : "standby")) this.fail(`${group.label} tab ${tab + 1} opened as ${role}`);
    }
  }

  /** A device that joins later, in a browser of its own (it has seen nothing). */
  async addDevice({ skewMs = 0 } = {}) {
    const group = await this.newGroup(1);
    await this.openTabs(group);
    const dev = await this.spawn(group, group.label, 0, skewMs);
    this.devices.push(dev);
    await dev.engine.start();
    return dev;
  }

  /** A device over the storage of `group` (`tab`: the number of the tab that runs it, in a browser that has several). */
  async spawn(group, label, tab = 0, skewMs = 0) {
    this.instances += 1;
    if (this.instances > 250) throw new Error("too many engines for the random sources");
    const d = await simEngine({ model: this.server, client: this.client, seed: this.instances, db: group.db, locks: group.locks, deviceName: label, skewMs });
    const dev = { label, group, tab, skewMs, d, engine: d.engine, offline: false, stopped: false, lateCalls: [], landed: [] };
    this.patch(dev);
    return dev;
  }

  /** The api of a device: it can be off the network, it notes a call after `stop()`, and it notes the writes that landed. */
  patch(dev) {
    const { api } = dev.d;
    const { get, put } = api;
    const guard = (what, path) => {
      if (dev.stopped) dev.lateCalls.push(`${what} ${path} (stopped at step ${dev.stoppedAt}, now step ${this.step}) ${frames()}`);
      if (dev.offline) throw new ApiError(0, "network");
    };
    api.get = async (path, ...rest) => {
      guard("get", path);
      const answer = await get(path, ...rest);
      const shown = answer?.changes ?? answer?.items;
      if (Array.isArray(shown)) {
        const rows = this.seen.get(dev.group.label) ?? new Set();
        this.seen.set(dev.group.label, rows);
        for (const row of shown) rows.add(`${row.id}:${row.rev}`);
      }
      // A read that is held after the server has answered, so that something else can happen before the engine uses the answer.
      if (dev.hold && path.startsWith("/api/sync/changes")) {
        const gate = dev.hold;
        dev.hold = null;
        gate.arrived = true;
        await gate.promise;
      }
      return answer;
    };
    api.put = async (path, body, ...rest) => {
      guard("put", path);
      // The model takes a request the moment it is made (nothing is awaited before), so whether it took this one is known here, and
      // whether it took it after the restore too, whatever happens to the answer.
      const writes = this.server.writes.length + this.server.checkpointPuts.length;
      const answer = put(path, body, ...rest);
      if (this.server.writes.length + this.server.checkpointPuts.length > writes) {
        dev.landed.push(path);
        this.checkBuiltOnSeen(dev, path, body);
      }
      return answer;
    };
  }

  /**
   * No blind overwrite: a write the server took over a row (`base_rev` above 0) was built on a row of that revision that this browser had been
   * shown (by the feed or the listing) or had written itself, or it follows a "keep mine" the user chose for the item.
   */
  checkBuiltOnSeen(dev, path, body) {
    if (path === "/api/sync/checkpoint") return;
    const request = JSON.parse(body instanceof Uint8Array ? new TextDecoder().decode(body) : String(body));
    const id = path.split("/").pop();
    const rows = this.seen.get(dev.group.label) ?? new Set();
    this.seen.set(dev.group.label, rows);
    if (request.base_rev > 0 && !rows.has(`${id}:${request.base_rev}`) && !this.keptMine.has(`${dev.group.label}:${id}`)) {
      this.fail(`${dev.label} overwrote ${short(id)} at rev ${request.base_rev} that it had never been shown, with no "keep mine"`);
    }
    rows.add(`${id}:${request.base_rev + 1}`);
  }


  /**
   * The page of the tab that runs the engine is closed and opened again: the engine stops and the lock is let go; the page takes the lock again
   * (nobody else asked: the other tabs are on standby) and starts a new engine over the same storage.
   */
  async restart(dev) {
    const { group } = dev;
    this.retire(dev);
    await group.owners[dev.tab].release();
    group.owners[dev.tab] = this.makeOwner(group, dev.tab);
    const role = await group.owners[dev.tab].acquire();
    if (role !== "owner") this.fail(`${dev.label} tab ${dev.tab + 1} did not get the lock back after it was opened again (${role})`);
    const fresh = await this.spawn(group, dev.label, dev.tab, dev.skewMs);
    fresh.offline = dev.offline;
    this.devices[this.devices.indexOf(dev)] = fresh;
    await fresh.engine.start();
    return fresh;
  }

  /**
   * "Use here" in another tab of the browser. `ask`: the owner is asked and stops by itself; `steal`: the owner tab is frozen (it does not hear the
   * question) and the lock is taken after about three seconds; `closed`: the owner tab was closed, so the lock is free. The engine then runs in
   * the tab that asked, over the same storage. `during` runs after the new engine has started, before the answer. Answers the new device, or null
   * when the browser has no other tab.
   */
  async useHere(dev, { variant = this.rng.weighted([["ask", 6], ["steal", 2], ["closed", 2]]), during = null } = {}) {
    const { group } = dev;
    if (group.tabs < 2 || dev.stopped) return null;
    const tab = this.rng.pick([...Array(group.tabs).keys()].filter((n) => n !== dev.tab));
    const was = dev.tab;
    this.count(`owner:${variant}`);
    this.note(`${dev.label} tab ${tab + 1} uses the vault here (${variant}, tab ${was + 1} had it)`);
    if (variant === "closed") {
      // The page is gone: the engine stops with it and the lock is let go; the tab is opened again later, on standby.
      this.retire(dev);
      await group.owners[was].release();
    } else if (variant === "steal") {
      for (const channel of group.channels.all) if (channel.listeners.size > 0) channel.muted = true;
    }
    const taking = group.owners[tab].takeOver();
    await Promise.race([taking, settle(80)]);
    let waited = false;
    if (variant === "steal") {
      this.ownerClock.advance(3000);
      waited = true;
    }
    const settled = await Promise.race([taking.then(() => true), settle(80).then(() => false)]);
    if (!settled) {
      this.fail(`${dev.label} tab ${tab + 1}: "use here" did not finish${waited ? "" : " (the owner was asked and did not let go)"}`);
      this.ownerClock.advance(3000);
    }
    await taking;
    for (const channel of group.channels.all) channel.muted = false;
    if (variant === "closed") {
      group.owners[was] = this.makeOwner(group, was); // the tab is opened again
      const role = await group.owners[was].acquire();
      if (role !== "standby") this.fail(`${dev.label} tab ${was + 1} opened as ${role} after the vault was moved`);
    }
    if (!dev.stopped) this.fail(`${dev.label} tab ${was + 1} still runs its engine after the vault was moved to tab ${tab + 1}`);
    const fresh = await this.spawn(group, dev.label, tab, dev.skewMs);
    fresh.offline = dev.offline;
    this.devices[this.devices.indexOf(dev)] = fresh;
    await fresh.engine.start();
    if (during) await during(fresh);
    return fresh;
  }

  // ------------------------------------------------------------ the user's actions

  marker() {
    this.names += 1;
    return `${SECRET}${this.seed}-${this.names}`;
  }

  keyOf(dev, id) {
    return `${dev.label}:${id}`;
  }

  /** Runs what a user does and sorts the refusals that are part of the rules from the ones that are not. */
  async attempt(what, work) {
    try {
      return await work();
    } catch (error) {
      if (EXPECTED.has(codeOf(error))) {
        this.note(`  ${what} refused: ${codeOf(error)}`);
        return undefined;
      }
      this.fail(`${what} threw ${codeOf(error)}: ${error instanceof Error ? error.message : ""}`);
      return undefined;
    }
  }

  async create(dev) {
    const marker = this.marker();
    const id = await this.attempt(`${dev.label} create`, () =>
      dev.engine.create({ item_type: "login", name: marker, fields: [{ id: "pw", kind: "password", label: "Password", value: `PW-${marker}` }] }));
    if (id) {
      this.writes.push({ dev: dev.label, id, kind: "create", marker, step: this.step });
      this.note(`${dev.label} create ${short(id)} ${marker}`);
    }
  }

  /** The items of a device that a user can change now. */
  editable(dev) {
    return dev.engine.list().filter((item) => !item.blocked && !item.damaged && !item.quarantined && !item.missingOnServer && !item.conflict);
  }

  async update(dev) {
    const item = this.rng.pick(this.editable(dev));
    if (!item) return;
    const marker = this.marker();
    const done = await this.attempt(`${dev.label} update`, async () => {
      await dev.engine.update(item.id, { name: marker }, item.rev);
      return true;
    });
    if (done) {
      this.writes.push({ dev: dev.label, id: item.id, kind: "update", marker, step: this.step });
      this.note(`${dev.label} update ${short(item.id)} rev ${item.rev} ${marker}`);
    }
  }

  async remove(dev) {
    const item = this.rng.pick(this.editable(dev));
    if (!item) return;
    const done = await this.attempt(`${dev.label} remove`, async () => {
      await dev.engine.remove(item.id);
      return true;
    });
    if (done) {
      this.writes.push({ dev: dev.label, id: item.id, kind: "remove", marker: null, step: this.step });
      this.note(`${dev.label} remove ${short(item.id)} rev ${item.rev}`);
    }
  }

  /** The user opens the conflict of a device and chooses. */
  async resolve(dev, choice = null) {
    const item = this.rng.pick(dev.engine.list().filter((i) => i.conflict));
    if (!item) return false;
    return this.attempt(`${dev.label} resolve`, async () => {
      const shown = await dev.engine.conflict(item.id);
      const serverDeleted = shown.server.deleted;
      await shown.close();
      const pick = choice ?? this.rng.pick(["mine", "theirs"]);
      if (pick === "mine") this.keptMine.add(`${dev.group.label}:${item.id}`); // before the write can leave
      await dev.engine.resolve(item.id, pick, shown.seen);
      const key = this.keyOf(dev, item.id);
      this.conflicted.add(key);
      if (pick === "theirs") this.discarded.add(key);
      // "Keep mine" is the one choice that can bring a deleted item back, and only over a row the user was shown deleted: the choice carries the row it
      // was made against, and the engine refuses it (`conflict_changed`) when the row has changed since.
      else if (serverDeleted) this.choices.set(item.id, (this.choices.get(item.id) ?? 0) + 1);
      this.note(`${dev.label} resolve ${short(item.id)} ${pick}${serverDeleted ? " over a deleted row" : ""}`);
      return true;
    });
  }

  async fromTrash(dev) {
    const entries = await this.attempt(`${dev.label} trash`, () => dev.engine.trash());
    const entry = entries ? this.rng.pick(entries) : null;
    if (!entry) return;
    const done = await this.attempt(`${dev.label} restoreFromTrash`, async () => {
      await dev.engine.restoreFromTrash(entry.id);
      return true;
    });
    if (done) {
      this.choices.set(entry.id, (this.choices.get(entry.id) ?? 0) + 1);
      this.note(`${dev.label} restoreFromTrash ${short(entry.id)}`);
    }
  }

  /** A fault for the next requests of a device. */
  fault(dev) {
    const { api } = dev.d;
    const kind = this.rng.weighted([["lost", 4], ["network", 4], ["busy", 2], ["throttled", 2], ["feed", 3], ["checkpoint", 2]]);
    if (kind === "lost") api.faults.push({ kind: "lost" });
    else if (kind === "network") api.faults.push({ kind: "network" });
    else if (kind === "busy") api.faults.push({ kind: "status", status: 503, code: "busy", retryAfter: 2 });
    else if (kind === "throttled") api.faults.push({ kind: "status", status: 429, code: "throttled", retryAfter: 30 });
    else if (kind === "feed") {
      api.failFeed = this.rng.chance(0.5) ? new ApiError(0, "network") : new ApiError(503, "busy", 2);
      api.failFeedTimes = this.rng.between(1, 3);
    } else if (this.rng.chance(0.5)) api.checkpointFaults.push({ kind: "network" });
    else api.checkpointPutFaults.push({ kind: "status", status: 429, code: "throttled", retryAfter: 60 });
    this.note(`${dev.label} fault ${kind}`);
  }

  /**
   * The ids that a device holds a row or a waiting write for, live or deleted: a retention job that has removed a tombstone another
   * device still has leaves the checkpoint of a device that never saw it at odds with that device's rows (known gap, purged tombstone, second todo test).
   */
  async heldIds() {
    const ids = new Set();
    for (const dev of this.devices) {
      const db = dev.d.store.database.store;
      const cached = new Set();
      for (const row of await cache.getRows(db, scope())) {
        ids.add(row.itemId);
        cached.add(row.itemId);
      }
      for (const entry of await outbox.all(db, scope())) ids.add(entry.itemId);
      // What the device wrote and the server took, but the device has not read back yet (its feed has been failing): the engine still
      // knows the item by its own write, though no row of it is stored.
      for (const write of this.writes) if (write.dev === dev.label && !cached.has(write.id)) ids.add(write.id);
    }
    return ids;
  }

  /** A row written by a device that is not one of ours (the model is honest about them): a new one, or a newer revision of one it wrote. */
  elsewhere() {
    this.names += 1;
    // Only a row that nobody has changed since is given a newer revision (a device may have edited it, or deleted it).
    const known = [...this.ghosts].filter(([id, rev]) => this.server.items.get(id)?.rev === rev && this.server.items.get(id)?.deleted === false);
    const old = known.length > 0 && this.rng.chance(0.5) ? this.rng.pick(known) : null;
    const id = old ? old[0] : (0xf0000 + this.names).toString(16).padStart(32, "0");
    const rev = old ? old[1] + 1 : 1;
    this.server.set(id, { rev, ...this.client.wireRow(id, rev, { item_type: "login", name: `Written elsewhere ${this.names}` }) });
    this.ghosts.set(id, rev);
  }

  /**
   * The vault is moved to another tab of the browser while a pass of the engine is in the air. The pass is held after the server has answered, the
   * server changes, the vault is moved (the old engine stops, the new one starts and reads the feed and stores what it saw), and then the old pass is
   * let go with its answer, which is older than what the sync memory holds. The engine that has stopped must do nothing with it: no request, no write
   * to the stores, no floor that goes down.
   */
  async race(dev) {
    if (dev.group.tabs < 2 || dev.offline || dev.stopped) return false;
    const gate = { arrived: false, release: () => {}, promise: null };
    gate.promise = new Promise((resolve) => (gate.release = resolve));
    dev.hold = gate;
    const pass = dev.engine.syncNow().catch(() => {});
    for (let turn = 0; turn < 40 && !gate.arrived; turn += 1) await settle(1);
    if (gate.arrived) this.elsewhere();
    dev.hold = null;
    let fresh = null;
    try {
      fresh = await this.useHere(dev, { variant: this.rng.pick(["ask", "steal"]), during: (made) => made.engine.syncNow() });
    } finally {
      gate.release();
    }
    await pass;
    this.note(`${dev.label} had a pass in the air (${gate.arrived ? "after the answer" : "not reached"}) when the vault moved to tab ${fresh ? fresh.tab + 1 : "?"}`);
    return gate.arrived;
  }

  /** One random action. */
  async act({ pool = this.devices, actions = ACTIONS } = {}) {
    this.step += 1;
    const dev = this.rng.pick(pool);
    let action = this.rng.weighted(actions);
    switch (action) {
      case "create": await this.create(dev); break;
      case "update": await this.update(dev); break;
      case "remove": await this.remove(dev); break;
      case "resolve": await this.resolve(dev); break;
      case "trash": await this.fromTrash(dev); break;
      case "fault": this.fault(dev); break;
      case "sync":
        this.note(`${dev.label} sync`);
        await dev.engine.syncNow();
        break;
      case "race":
        if (!(await this.race(dev))) action = "sync";
        break;
      case "useHere":
        if (!(await this.useHere(dev))) action = "sync";
        break;
      case "both": {
        // The engine reads the feed at the moment another tab asks for the vault.
        this.note(`${dev.group.label} reads while another tab asks for the vault`);
        const reading = dev.engine.syncNow().catch(() => {});
        const moved = await this.useHere(dev, { variant: "ask" });
        await reading;
        if (!moved) await dev.engine.syncNow();
        break;
      }
      case "poll": {
        const ms = this.rng.between(1_000, 400_000);
        this.note(`${dev.label} clock +${ms}ms`);
        dev.d.timers.advance(ms);
        break;
      }
      case "jump":
        this.note(`${dev.label} clock +25h`);
        dev.d.timers.advance(25 * 3_600_000);
        break;
      case "offline":
        dev.offline = !dev.offline;
        this.note(`${dev.label} ${dev.offline ? "offline" : "online"}`);
        break;
      case "restart":
        this.note(`${dev.label} restart`);
        await this.restart(dev);
        break;
      case "retention": {
        // Long ago another device deleted an item, a checkpoint that lists the tombstone was stored, and the tombstone was purged: every
        // device that has not read the feed since is told 410 and lists the vault.
        this.names += 1;
        const id = (0xe0000 + this.names).toString(16).padStart(32, "0");
        const held = await this.heldIds();
        // No waiting from here to the purge: no device reads the tombstone in between.
        this.server.set(id, { rev: 2, deleted: true, tomb: this.client.wireTomb(id, 2) });
        this.server.pinCheckpoint();
        const gone = this.server.purgeTombstones((other) => held.has(other), this.tolerates("purge"));
        this.note(`retention: ${gone} tombstones purged, min_valid_since ${this.server.minValidSince}`);
        break;
      }
      case "purge": {
        const held = await this.heldIds();
        const gone = this.server.purgeTombstones((id) => held.has(id), this.tolerates("purge"));
        this.note(`server purged ${gone} tombstones, min_valid_since ${this.server.minValidSince}`);
        break;
      }
      default: throw new Error(action);
    }
    this.count(`act:${action}`);
    await settle(6);
    await this.checkFloors();
    this.checkOwners();
  }

  async run(steps, options) {
    for (let n = 0; n < steps; n += 1) await this.act(options);
  }

  // ------------------------------------------------------------ calm

  /** What there is to see of the state of all devices and of the server, to know when nothing moves any more. */
  signature(devs) {
    return JSON.stringify([
      this.server.seq,
      devs.map((dev) => dev.engine.list().map((i) => [i.id, i.rev, i.pending, i.blocked, i.conflict])),
    ]);
  }

  /** Every device is online, no fault is left. */
  heal(devs = this.devices) {
    for (const dev of devs) {
      dev.offline = false;
      const { api } = dev.d;
      api.faults.length = 0;
      api.failFeedTimes = 0;
      api.checkpointFaults.length = 0;
      api.checkpointPutFaults.length = 0;
    }
  }

  /** The devices read the feed and send what they hold, and the user settles every conflict, until nothing moves. */
  async calm(devs = this.devices, { choose = null } = {}) {
    this.heal(devs);
    let quiet = 0;
    for (let round = 0; round < 60 && quiet < 2; round += 1) {
      const before = this.signature(devs);
      for (const dev of devs) {
        dev.d.timers.advance(POLL_MS + 1_000);
        await dev.engine.syncNow();
        await settle(8);
      }
      for (const dev of devs) while (await this.resolve(dev, choose)) await settle(8);
      quiet = this.signature(devs) === before ? quiet + 1 : 0;
      if (round === 59) this.fail("the devices did not come to rest in 60 rounds");
    }
    await settle(20);
    await this.checkFloors();
  }

  /** Every page is closed and opened again: what is stored decides what each tab shows, not what a tab remembered. */
  async reloadAll() {
    this.note("every page is closed and opened again");
    for (const dev of [...this.devices]) await this.restart(dev);
  }

  // ------------------------------------------------------------ what a device holds

  /** The newest local version of every item a device has (a row, or the last write waiting in the outbox), without opening anything. */
  async held(dev) {
    const db = dev.d.store.database.store;
    const rows = await cache.getRows(db, scope());
    const queued = await outbox.all(db, scope());
    /** @type {Map<string, { rev: number, deleted: boolean, pending: boolean, name: string | null }>} */
    const out = new Map();
    for (const row of rows) {
      out.set(row.itemId, { rev: row.rev, deleted: row.deleted, pending: false, name: row.deleted ? null : await this.nameOf(row.itemId, row.rev, row.envelope, row.tag) });
    }
    for (const entry of queued) {
      const deleted = "tomb" in entry.body;
      out.set(entry.itemId, { rev: entry.baseRev + 1, deleted, pending: true, name: deleted ? null : await this.nameOf(entry.itemId, entry.baseRev + 1, entry.body.blob, entry.body.tag) });
    }
    return out;
  }

  /** The name inside a sealed row, opened with the key of the vault (the matrix reads what the server holds; it is not an engine). */
  async nameOf(id, rev, blob, tag) {
    const bytes = (v) => (typeof v === "string" ? b64u.decode(v) : v);
    let handle = null;
    try {
      handle = await this.client.vault.open_item(hex16.decode(id), rev, bytes(blob), bytes(tag));
      return (await this.client.vault.item_view(handle)).name;
    } finally {
      if (handle !== null) await this.client.vault.close_item(handle);
    }
  }

  /** The live rows of the server: id -> { rev, name }. */
  async serverLive() {
    const out = new Map();
    for (const [id, row] of this.server.items) if (!row.deleted) out.set(id, { rev: row.rev, name: await this.nameOf(id, row.rev, row.blob, row.tag) });
    return out;
  }

  // ------------------------------------------------------------ the invariants

  /** The floors of the sync memory of every browser never go down (unless an older state was accepted: `floorReset`). */
  async checkFloors() {
    for (const group of this.groups) {
      const state = await loadSyncState(group.db.store, SERVER, ACCOUNT);
      if (!state) continue;
      const next = memoryOf(state.memory);
      const last = this.floors.get(group.label);
      if (last) {
        if (next.maxSeq < last.memory.maxSeq) this.fail(`${group.label}: top seq went down ${last.memory.maxSeq} -> ${next.maxSeq}`);
        if (next.checkpointSeq < last.memory.checkpointSeq) this.fail(`${group.label}: checkpoint seq went down ${last.memory.checkpointSeq} -> ${next.checkpointSeq}`);
        for (const [id, rev] of Object.entries(last.memory.revs)) {
          if ((next.revs[id] ?? 0) < rev) this.fail(`${group.label}: floor of ${short(id)} went down ${rev} -> ${next.revs[id] ?? "none"}`);
        }
        if ((state.restoreEpoch ?? 0) < (last.epoch ?? 0)) this.fail(`${group.label}: restore epoch went down ${last.epoch} -> ${state.restoreEpoch}`);
      }
      this.floors.set(group.label, { memory: next, epoch: state.restoreEpoch });
    }
  }

  /** The floors of the sync memory a device's browser stores now. */
  async floorsOf(dev) {
    return this.floorsOfGroup(dev.group);
  }

  async floorsOfGroup(group) {
    const state = await loadSyncState(group.db.store, SERVER, ACCOUNT);
    return state ? memoryOf(state.memory) : { maxSeq: 0, checkpointSeq: 0, revs: {} };
  }

  /**
   * After a restore, a device that has not accepted the older state and has not stopped holds nothing the restored server lacks or shows lower,
   * however far the seq of the server has come since: every live row it caches is on the server at the same or a higher revision (and at the
   * same revision with the same bytes). A device that goes on without asking has missed the restore.
   */
  async checkStopped() {
    for (const dev of this.devices) {
      if (this.accepted.has(dev.label) || dev.engine.health().halted !== null) continue;
      for (const row of await cache.getRows(dev.d.store.database.store, scope())) {
        if (row.deleted) continue;
        const server = this.server.items.get(row.itemId);
        if (!server || server.rev < row.rev || (server.rev === row.rev && (server.deleted || server.blob !== b64u.encode(row.envelope)))) {
          this.fail(`${dev.label} goes on without a question and holds ${short(row.itemId)} at rev ${row.rev}, which the restored server ${server ? `shows at rev ${server.rev}${server.deleted ? " deleted" : ""}` : "does not have"}`);
        }
      }
    }
  }

  /** An older state was accepted by a browser: its floors are allowed to start again. */
  floorReset(dev) {
    this.floors.delete(dev.group.label);
  }

  /**
   * One engine per browser: the browser has one device, and of its tabs exactly the tab of that device holds the owner lock; a tab on standby holds
   * nothing and has no engine.
   */
  checkOwners() {
    for (const group of this.groups) {
      const running = this.devices.filter((dev) => dev.group === group && !dev.stopped);
      if (running.length !== 1) {
        this.fail(`${group.label} runs ${running.length} engines`);
        continue;
      }
      const holders = group.owners.map((owner, tab) => (owner.isOwner() ? tab : -1)).filter((tab) => tab >= 0);
      if (holders.length !== 1 || holders[0] !== running[0].tab) {
        this.fail(`${group.label}: the engine runs in tab ${running[0].tab + 1} and the lock is held by ${holders.length === 0 ? "no tab" : `tab ${holders.map((tab) => tab + 1).join(", ")}`}`);
      }
    }
  }

  /** The engines and their messages: nothing stopped, nothing warned, in a run against an honest server. */
  checkHealthy(allowed = []) {
    for (const dev of this.devices) {
      const health = dev.engine.health();
      if (health.halted !== null) this.fail(`${dev.label} is halted: ${health.halted}`);
      for (const warning of health.warnings) this.fail(`${dev.label} shows a warning: ${warning}`);
      for (const state of dev.d.events.state) if (state.kind === "halted" && !allowed.includes(state.code)) this.fail(`${dev.label} halted with ${state.code} during the run`);
      for (const event of dev.d.events.state) if (event.kind === "warning" && !allowed.includes(event.code)) this.fail(`${dev.label} raised the warning ${event.code} during the run`);
    }
  }

  /** The devices show what the server holds, and nothing waits, is blocked or is marked. */
  async checkConverged() {
    const live = await this.serverLive();
    for (const dev of this.devices) {
      const shown = new Map(dev.engine.list().map((item) => [item.id, item]));
      for (const [id, row] of live) {
        const item = shown.get(id);
        if (!item) this.fail(`${dev.label} lacks ${short(id)}, the server has ${row.name} at rev ${row.rev}`);
        else if (item.rev !== row.rev || item.name !== row.name) this.fail(`${dev.label} shows ${short(id)} as ${item.name} rev ${item.rev}, the server has ${row.name} rev ${row.rev}`);
      }
      for (const [id, item] of shown) {
        if (!live.has(id)) this.fail(`${dev.label} shows ${short(id)} (${item.name}), the server holds it deleted or not at all`);
        if (item.pending || item.blocked || item.conflict || item.damaged || item.quarantined || item.missingOnServer) {
          this.fail(`${dev.label} still has ${short(id)} pending=${item.pending} blocked=${item.blockedReason} conflict=${item.conflict} damaged=${item.damaged} quarantined=${item.quarantined} missing=${item.missingOnServer}`);
        }
      }
      const queued = await outbox.all(dev.d.store.database.store, scope());
      if (queued.length > 0) this.fail(`${dev.label} still has ${queued.length} writes in the outbox: ${queued.map((e) => `${short(e.itemId)} base ${e.baseRev} ${"tomb" in e.body ? "tombstone" : "live"}`).join(", ")}; last errors ${JSON.stringify(dev.d.events.error.slice(-4))}; server has ${JSON.stringify(queued.map((e) => { const row = this.server.items.get(e.itemId); return row ? { rev: row.rev, deleted: row.deleted } : null; }))}`);
    }
  }

  /**
   * Checkpoints stay alive: when everything is at rest, more than ten minutes pass and every device reads once more, the checkpoint the server
   * holds is for the `seq` the server is at.
   */
  async checkCheckpointLive() {
    const held = () => (this.server.checkpoint === "auto" ? this.server.seq : (this.server.checkpoint?.seq ?? 0));
    const readAgain = async (jump) => {
      for (const dev of this.devices) {
        if (jump > 0) dev.d.timers.time += jump;
        dev.d.timers.advance(11 * 60_000);
        await dev.engine.syncNow();
        await settle(10);
      }
      await settle(20);
    };
    await readAgain(0);
    if (held() === this.server.seq) return;
    const states = [];
    for (const dev of this.devices) {
      const state = await loadSyncState(dev.group.db.store, SERVER, ACCOUNT);
      states.push(`${dev.label}: ${JSON.stringify(dev.engine.health())} stored ${JSON.stringify({ verifiedAt: state?.verifiedAt, uploadedAt: state?.uploadedAt, uploadedSeq: state?.uploadedSeq, hardWarning: state?.hardWarning })} last errors ${JSON.stringify(dev.d.events.error.slice(-3))} marks ${JSON.stringify(dev.engine.list().filter((i) => i.pending || i.blocked || i.missingOnServer).map((i) => short(i.id)))}`);
    }
    this.fail(`the checkpoint of the server is at seq ${held()} and the server at ${this.server.seq}, though every device has read the feed to its end more than ten minutes after the last change; ${states.join("; ")}`);
  }

  /** Every write a user made is on the server, unless the user dropped it; and a deletion is on the server too. */
  async checkWrites({ fromWrite = 0 } = {}) {
    const accepted = this.server.accepted();
    const names = new Set();
    for (const write of accepted) if (write.blob !== null) names.add(await this.nameOf(write.id, write.rev, write.blob, write.tag));
    const last = new Map();
    for (const write of this.writes) last.set(this.keyOf({ label: write.dev }, write.id), write);
    for (const write of this.writes.slice(fromWrite)) {
      const key = this.keyOf({ label: write.dev }, write.id);
      if (this.discarded.has(key)) continue;
      if (this.conflicted.has(key) && last.get(key) !== write) continue; // a version that was replaced by a newer one of the same device in a conflict
      // The same user deleted the item after the edit and the server holds it deleted: the edit went with the deletion (a draft that only
      // deletes, or a chain that ends in a deletion, is moot once the server has deleted the item), as the user's last word was the deletion.
      if (last.get(key).kind === "remove" && last.get(key) !== write && accepted.some((a) => a.id === write.id && a.deleted)) continue;
      if (write.kind === "remove") {
        if (!accepted.some((a) => a.id === write.id && a.deleted)) this.fail(`the deletion of ${short(write.id)} by ${write.dev} (step ${write.step}) never reached the server`);
      } else if (!names.has(write.marker)) {
        const history = [];
        for (const a of accepted.filter((x) => x.id === write.id)) {
          history.push(`#${a.at} rev ${a.rev}${a.deleted ? " deleted" : ` ${a.blob === null ? "?" : await this.nameOf(a.id, a.rev, a.blob, a.tag)}`}${a.resurrect ? " resurrect" : ""}`);
        }
        this.fail(`the write ${write.marker} of ${write.dev} to ${short(write.id)} (step ${write.step}) is not on the server and was not dropped by a choice; the server took: ${history.join("; ")}`);
      }
    }
  }

  /** A deleted item comes back only when a user chose it. */
  checkResurrections(allowed = new Map()) {
    const counts = new Map();
    for (const { id } of this.server.revived) counts.set(id, (counts.get(id) ?? 0) + 1);
    for (const [id, times] of counts) {
      const chosen = (this.choices.get(id) ?? 0) + (allowed.get(id) ?? 0);
      if (times > chosen) this.fail(`${short(id)} was brought back ${times} times and the users chose it ${chosen} times`);
    }
  }

  /** No device holds a floor below a row it shows. */
  async checkFloorsCoverRows() {
    for (const group of this.groups) {
      const state = await loadSyncState(group.db.store, SERVER, ACCOUNT);
      if (!state) continue;
      const memory = memoryOf(state.memory);
      for (const dev of this.devices.filter((d) => d.group === group)) {
        for (const item of dev.engine.list().filter((i) => !i.pending && !i.blocked)) if ((memory.revs[item.id] ?? 0) < item.rev) this.fail(`${dev.label}: the floor of ${short(item.id)} is ${memory.revs[item.id] ?? "none"}, below the rev ${item.rev} it shows`);
      }
    }
  }

  /** No secret is in any store of any browser, in anything sent to the server or in what the server holds. */
  async checkNoPlaintext() {
    for (const group of this.groups) {
      const dump = await dumpDatabase(group.db);
      if (holds(dump, SECRET)) this.fail(`${group.label}: a secret is in the browser storage`);
    }
    for (const dev of [...this.devices, ...this.retired]) {
      for (const sent of dev.d.api.puts) if (holds(sent.text, SECRET) || holds(sent.bytes, SECRET)) this.fail(`${dev.label} sent a secret to the server`);
      for (const spied of [dev.d.store.spy.putRows, dev.d.store.spy.enqueued, dev.d.store.spy.settings, dev.d.store.spy.trashed]) {
        if (holds(spied, SECRET)) this.fail(`${dev.label} gave a secret to the store`);
      }
    }
    if (holds([...this.server.items.values()], SECRET) || holds(this.server.writes, SECRET)) this.fail("the server holds a secret");
  }

  /** The engines are stopped, and nothing asks the server after that. */
  async stopAll() {
    for (const dev of this.devices) {
      dev.stopped = true;
      dev.stoppedAt = this.step;
      dev.engine.stop();
    }
    for (const group of this.groups) for (const owner of group.owners) owner.release();
    await settle(40);
    for (const dev of [...this.devices, ...this.retired]) {
      const late = dev.lateCalls;
      if (late.length > 0) this.fail(`${dev.label} asked the server after stop(): ${late.slice(0, 3).join(", ")}`);
    }
  }

  // ------------------------------------------------------------ a restored server

  /** The database of the server is put back from `backup` and the restore is recorded (`ferret restore-epoch bump`). */
  async restoreServer(backup) {
    this.restoredAt = this.server.writes.length;
    this.restoreWrites = this.writes.length;
    this.restoreMark = new Map([...this.devices, ...this.retired].map((dev) => [dev, dev.d.events.error.length]));
    this.server.restoreFrom(backup);
    this.note(`server restored to seq ${backup.seq}, restore epoch ${this.server.restoreEpoch}`);
  }

  /** The user of a device that has stopped for a restored server accepts the older state. Answers what the engine did, or null when it is not stopped. */
  async accept(dev) {
    if (dev.engine.health().halted !== "server_restored") return null;
    try {
      const result = await dev.engine.acceptOlderState();
      this.accepted.add(dev.label);
      this.floorReset(dev);
      this.note(`${dev.label} accepts the older state: ${JSON.stringify(result)}`);
      return result;
    } catch (error) {
      this.fail(`${dev.label} could not accept the older state: ${codeOf(error)} ${error instanceof Error ? error.message : ""}`);
      return null;
    }
  }

  /** The items that had a conflict after the server was restored, on any device. */
  conflictsSinceRestore() {
    const ids = new Set();
    for (const dev of [...this.devices, ...this.retired]) {
      for (const event of dev.d.events.error.slice(this.restoreMark.get(dev) ?? 0)) if (event.code === "conflict") ids.add(event.id);
    }
    return ids;
  }

  /** The text for a failed run: the problems, then the last of the log. */
  report() {
    return [`seed ${this.seed} (layout ${JSON.stringify(this.layout)})`, ...this.problems.slice(0, 12), "--- log (last 50 lines)", ...this.log.slice(-50)].join("\n");
  }
}
