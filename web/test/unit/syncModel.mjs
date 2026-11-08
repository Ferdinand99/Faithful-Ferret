// A model of the sync server and of a few devices, for the matrix tests (`syncMatrix.test.mjs`, `engineScale.test.mjs`).
//
// `SimServer` is the item store of the fake server of `syncHelpers.mjs` with the rest of what the sync rules of the server
// give: a checkpoint that is stored (structure only) and replaced, the key of a write before the restore epoch before the
// revision, resurrection only with the flag and the tombstone's revision, the retention of tombstones (a 410 for a device that
// is behind the purge), backups, and a restore that is recorded the way `ferret restore-epoch bump` records it.
//
// `Sim` runs devices (engines over their own fake browser storage, or two tabs over one) against it, with the faults a
// network and a server can give (a request that never arrives, an answer that is lost, 429, 503, a feed that fails), and a seeded
// random choice of what happens next. It keeps the facts the invariants of the matrix need: every write a user made, every
// choice the user made, the floors of the sync memory over time, and every request an engine made after `stop()`.
import { ApiError } from "../../src/api.mjs";
import { b64u, hex16 } from "../../src/b64.mjs";
import { cache } from "../../src/store/cache.mjs";
import { STORES } from "../../src/store/idb.mjs";
import { outbox } from "../../src/store/outbox.mjs";
import { loadSyncState } from "../../src/store/syncState.mjs";
import { createSyncEngine } from "../../src/sync/engine.mjs";
import { ACCOUNT, freshStore, scope, SERVER } from "./idbHelpers.mjs";
import {
  counterRand, createFakeApi, createFakeClient, createFakeStore, FakeLocks, FakeTimers, fakeMemory, memoryOf, Model, settle,
} from "./syncHelpers.mjs";

/** An item id as a log line shows it: the first two bytes and the last one (the last byte belongs to the random source of one engine). */
const short = (id) => `${id.slice(0, 4)}..${id.slice(-2)}`;

/** The top of the call stack, for a report: function names and line numbers, no paths. */
const frames = () => (new Error().stack ?? "").split("\n").slice(3, 10).map((line) => line.trim().replace("at ", "").split("/").at(-1)).join(" < ");

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
  ["trash", 3], ["restart", 3], ["purge", 2], ["retention", 2], ["jump", 1], ["race", 3],
];

/** Changes by the user and the engine's own pace, with nothing going wrong: no faults, nothing off the network, no restart, no purge. */
export const CALM_ACTIONS = [["create", 14], ["update", 22], ["remove", 6], ["sync", 14], ["poll", 10], ["resolve", 8], ["trash", 3]];

const EXPECTED = new Set(["conflict_unsettled", "invalid_state", "item_changed", "not_found", "blocked", "busy", "damaged", "quarantined", "missing_on_server", "reuploaded"]);

/** @param {unknown} error */
const codeOf = (error) => (error && typeof error === "object" && "code" in error ? String(error.code) : String(error));

/** A run of devices against one server. See the top of the file. */
export class Sim {
  /**
   * @param {number} seed
   * @param {{ layout?: number[], skews?: number[] }} [options] `layout`: the number of tabs of each browser (`[1, 1]` two devices, `[2, 1]`
   *   two tabs of one browser and a second browser); `skews`: the clock of each device is that many ms off
   */
  constructor(seed, { layout = [1, 1], skews = [], tabsWrite = false, pageSize = 500 } = {}) {
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
    this.tabsWrite = tabsWrite;
    this.skews = skews;
    this.tabs = layout.some((n) => n > 1); // some tabs share one storage
    this.devices = []; // the engines that run now
    this.retired = []; // the ones that were stopped (their late requests are still counted)
    this.groups = []; // { db, locks, label }: one per browser
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
    this.hiddenDrafts = 0; // known gap, hidden draft: how many refused deletions were found left behind
    this.seen = new Map(); // browser label -> Set of "id:rev": the rows its engines were shown by the feed and the listing, and wrote themselves
    this.keptMine = new Set(); // "browser:id": the user chose "keep mine" for the item in that browser
    this.tallied = false;
    this.knownGaps = !process.env.FERRET_MATRIX_STRICT; // the known gaps are not asserted against (the todo tests hold them); FERRET_MATRIX_STRICT=1 asserts against them too
    this.stats = {}; // how often each thing happened, to see that a run does what it is meant to
    this.restoredAt = null; // the write index of the server when it was restored
    this.watching = false; // after a restore: a write from a device that remembers a higher top than the server shows is a failure
    this.ghosts = new Map(); // id -> rev of the rows that the model wrote itself (a device that is not one of ours)
    this.accepted = new Set(); // devices that have accepted an older state
    this.restoreMark = new Map(); // device -> how many error events it had when the server was restored
    this.restoreWrites = 0; // how many writes the users had made when the server was restored
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
      const group = await this.newGroup();
      for (let tab = 0; tab < tabs; tab += 1) {
        this.devices.push(await this.spawn(group, tabs > 1 ? `${group.label}-tab${tab + 1}` : group.label, tab, this.skews[this.devices.length] ?? 0));
      }
    }
    for (const dev of this.devices) await dev.engine.start();
    await this.checkFloors();
  }

  /** A new browser: a storage and the locks that go with it. */
  async newGroup() {
    const group = { db: await freshStore(), locks: new FakeLocks(), label: `browser${this.groups.length + 1}` };
    this.groups.push(group);
    return group;
  }

  /** A device that joins later, in a browser of its own (it has seen nothing). */
  async addDevice({ skewMs = 0 } = {}) {
    const dev = await this.spawn(await this.newGroup(), `browser${this.groups.length}`, 0, skewMs);
    this.devices.push(dev);
    await dev.engine.start();
    return dev;
  }

  /** A device over the storage of `group` (`tab`: the number of the tab in a browser that has several). */
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
      const top = this.server.seq;
      const answer = put(path, body, ...rest);
      if (this.server.writes.length + this.server.checkpointPuts.length > writes) {
        dev.landed.push(path);
        this.onLanded(dev, path, top);
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

  /** A write or a checkpoint of a device was taken by the server. */
  onLanded(dev, path, top) {
    // Strict: a device that remembers more than the backup holds, and has not accepted, writes nothing. With the known gap: the floors are the
    // ones read after the last step (the real ones are not lower), so a floor above the top of the server is surely one.
    if (!this.knownGaps && this.watching && this.restoredAt !== null && this.mustHalt.has(dev.label) && !this.accepted.has(dev.label)) {
      this.fail(`${dev.label} landed ${path.split("/").slice(-2).join("/")} on a restored server it remembers more than and had not accepted`);
      return;
    }
    const remembered = this.floors.get(dev.group.label)?.memory.maxSeq ?? 0;
    if (this.knownGaps && this.watching && this.restoredAt !== null && remembered > top && !this.accepted.has(dev.label)) {
      this.fail(`${dev.label} landed ${path.split("/").slice(-2).join("/")} on a restored server (seq ${top}) that shows less than it remembers (${remembered}) and that it had not accepted`);
    }
  }

  /** Stops the engine of a device and starts a new one over the same storage (the page was closed and opened). */
  async restart(dev) {
    dev.stopped = true;
    dev.stoppedAt = this.step;
    dev.engine.stop();
    this.retired.push(dev);
    const fresh = await this.spawn(dev.group, dev.label, dev.tab, dev.skewMs);
    fresh.offline = dev.offline;
    this.devices[this.devices.indexOf(dev)] = fresh;
    await fresh.engine.start();
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
      await dev.engine.resolve(item.id, pick);
      const key = this.keyOf(dev, item.id);
      this.conflicted.add(key);
      if (pick === "theirs") this.discarded.add(key);
      // "Keep mine" is the one choice that can bring a deleted item back. It counts whatever the screen showed: the server row can turn into a
      // tombstone between the moment the user looked and the moment the choice is made, and the engine builds the write on what it knows then.
      else if (this.knownGaps || serverDeleted) this.choices.set(item.id, (this.choices.get(item.id) ?? 0) + 1);
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
      for (const row of await cache.getRows(db, scope())) ids.add(row.itemId);
      for (const entry of await outbox.all(db, scope())) ids.add(entry.itemId);
    }
    return ids;
  }

  /**
   * Whether the user changes things in this tab. Two tabs of one browser share the outbox and the marks of the store, while each keeps its
   * own copy of both in memory; when both tabs change things, a tab can drop or hide what the other has queued (known gap, writing tabs, the todo test
   * `two_tabs_that_both_write_can_lose_a_queued_write`). So in a browser with several tabs only the first one writes.
   */
  writer(dev) {
    return !this.knownGaps || this.tabsWrite || dev.tab === 0;
  }

  /**
   * Passes of two devices of one browser that are held after the server has answered, while the server changes between the two answers.
   * Either the first pass is held while the second device reads the feed and stores what it saw, and then goes on with an answer that is
   * older than the sync memory; or both are held, the newer answer is let go first and the older one right after it, so that both give
   * their page to the memory at the same moment. The memory is saved under the lock of the account, read again inside it, so that nothing
   * it holds goes down.
   */
  async race(dev) {
    const peers = this.devices.filter((d) => d.group === dev.group && d !== dev && !d.offline);
    if (peers.length === 0 || dev.offline) return false;
    const other = this.rng.pick(peers);
    const hold = (d) => {
      const gate = { arrived: false, release: () => {}, promise: null };
      gate.promise = new Promise((resolve) => (gate.release = resolve));
      d.hold = gate;
      return gate;
    };
    const arrived = async (gate) => {
      for (let turn = 0; turn < 40 && !gate.arrived; turn += 1) await settle(1);
      return gate.arrived;
    };
    // Rows written by a device that is not one of ours (the model is honest about them): a new one and a newer revision of one it wrote.
    const elsewhere = () => {
      this.names += 1;
      // Only a row that nobody has changed since is given a newer revision (a device may have edited it, or deleted it).
      const known = [...this.ghosts].filter(([id, rev]) => this.server.items.get(id)?.rev === rev && this.server.items.get(id)?.deleted === false);
      const old = known.length > 0 && this.rng.chance(0.5) ? this.rng.pick(known) : null;
      const id = old ? old[0] : (0xf0000 + this.names).toString(16).padStart(32, "0");
      const rev = old ? old[1] + 1 : 1;
      this.server.set(id, { rev, ...this.client.wireRow(id, rev, { item_type: "login", name: `Written elsewhere ${this.names}` }) });
      this.ghosts.set(id, rev);
    };
    const first = hold(dev);
    const pass = dev.engine.syncNow();
    const together = this.rng.chance(0.5);
    let second = null;
    let pass2 = null;
    if (await arrived(first)) {
      elsewhere();
      if (together) {
        second = hold(other);
        pass2 = other.engine.syncNow();
        await arrived(second);
      } else {
        await other.engine.syncNow();
      }
    }
    dev.hold = null;
    other.hold = null;
    second?.release(); // the newer answer first, the older one right after it
    first.release();
    await Promise.all([pass, pass2]);
    this.note(`${dev.label} reads ${together ? "at the same moment as" : "while"} ${other.label} ${together ? "(the older answer is given to the memory last)" : "has read and stored a newer feed"}`);
    return first.arrived;
  }

  /** One random action. */
  async act({ pool = this.devices, actions = ACTIONS } = {}) {
    this.step += 1;
    const dev = this.rng.pick(pool);
    let action = this.rng.weighted(actions);
    // known gap, writing tabs: of two tabs of one browser only the first changes things (see `writer`).
    if (["create", "update", "remove", "resolve", "trash"].includes(action) && !this.writer(dev)) action = "sync";
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
      case "both": {
        // Every tab of the browser reads the feed at the same moment.
        this.note(`${dev.group.label} every tab syncs at once`);
        await Promise.all(this.devices.filter((d) => d.group === dev.group).map((d) => d.engine.syncNow()));
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
        const gone = this.server.purgeTombstones((other) => held.has(other), this.knownGaps);
        this.note(`retention: ${gone} tombstones purged, min_valid_since ${this.server.minValidSince}`);
        break;
      }
      case "purge": {
        const held = await this.heldIds();
        const gone = this.server.purgeTombstones((id) => held.has(id), this.knownGaps);
        this.note(`server purged ${gone} tombstones, min_valid_since ${this.server.minValidSince}`);
        break;
      }
      default: throw new Error(action);
    }
    this.count(`act:${action}`);
    await settle(6);
    await this.checkFloors();
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
   * After a restore nobody has accepted: a device the restored server shows less than it remembers stops, and is still stopped. (With the known
   * gap, late restore contact: only a device that is shown a top below what it remembers; one that first meets a server whose seq has passed what
   * it remembers finds nothing lower.) Strict: every device that remembered more than the backup holds.
   */
  async checkStopped() {
    for (const dev of this.devices) {
      const remembered = (await this.floorsOf(dev)).maxSeq;
      const must = this.knownGaps ? remembered > this.server.seq : this.mustHalt.has(dev.label) && !this.accepted.has(dev.label);
      if (must && dev.engine.health().halted !== "server_restored") this.fail(`${dev.label} has seen more than the restored server shows and is ${dev.engine.health().halted ?? "not stopped"}`);
    }
  }

  /** An older state was accepted by a browser: its floors are allowed to start again. */
  floorReset(dev) {
    this.floors.delete(dev.group.label);
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
  async checkConverged({ readers = false } = {}) {
    const live = await this.serverLive();
    for (const dev of this.devices) {
      if (this.knownGaps && !readers && !this.writer(dev)) continue; // known gap, writing tabs: the other tab of a browser shows what the first one stored, with a delay
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
      const everything = await outbox.all(dev.d.store.database.store, scope());
      // known gap, hidden draft (todo test `a_deletion_refused_over_a_tombstone_the_feed_has_already_brought_leaves_no_blocked_draft`): a deletion
      // that waits in the outbox when the feed brings the tombstone of its item is refused with 409 afterwards and stays as a blocked draft that is
      // not on any screen. Only that shape is let through: the last write waiting for the item is a deletion and this device holds a deleted row.
      const rows = new Map((await cache.getRows(dev.d.store.database.store, scope())).map((row) => [row.itemId, row]));
      const last = new Map(everything.map((e) => [e.itemId, e]));
      const stuck = (e) => "tomb" in last.get(e.itemId).body && rows.get(e.itemId)?.deleted === true;
      const queued = everything.filter((e) => !(this.knownGaps && stuck(e)));
      if (queued.length !== everything.length) {
        this.hiddenDrafts += everything.length - queued.length;
        this.count("known:hidden_blocked_draft", everything.length - queued.length);
      }
      if (queued.length > 0) this.fail(`${dev.label} still has ${queued.length} writes in the outbox: ${queued.map((e) => `${short(e.itemId)} base ${e.baseRev} ${"tomb" in e.body ? "tombstone" : "live"}`).join(", ")}; last errors ${JSON.stringify(dev.d.events.error.slice(-4))}; server has ${JSON.stringify(queued.map((e) => { const row = this.server.items.get(e.itemId); return row ? { rev: row.rev, deleted: row.deleted } : null; }))}`);
    }
  }

  /**
   * Checkpoints stay alive: when everything is at rest, more than ten minutes pass and every device reads once more, the checkpoint the server
   * holds is for the `seq` the server is at. A device that was reloaded within a day of its last verification does not verify in its new session
   * and so stores no checkpoint (known gap, checkpoint waits for a verification, todo test
   * `a_device_that_was_reloaded_stores_a_checkpoint_within_minutes`): with the known gaps that is let through when a day later every device has
   * verified and the checkpoint is there (the clock is set a day on without running the polls in between). Also let through are the gaps that
   * keep a device from storing one: a refused deletion left behind, and two tabs over one storage.
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
    if (this.knownGaps) {
      if (this.tabs || this.hiddenDrafts > 0) {
        this.count("known:checkpoint_not_live");
        return;
      }
      await readAgain(25 * 3_600_000);
      if (held() === this.server.seq) {
        this.count("known:checkpoint_waits_for_verification");
        return;
      }
    }
    const states = [];
    for (const dev of this.devices) {
      const state = await loadSyncState(dev.group.db.store, SERVER, ACCOUNT);
      states.push(`${dev.label}: ${JSON.stringify(dev.engine.health())} stored ${JSON.stringify({ verifiedAt: state?.verifiedAt, uploadedAt: state?.uploadedAt, uploadedSeq: state?.uploadedSeq, hardWarning: state?.hardWarning })} last errors ${JSON.stringify(dev.d.events.error.slice(-3))} marks ${JSON.stringify(dev.engine.list().filter((i) => i.pending || i.blocked || i.missingOnServer).map((i) => short(i.id)))}`);
    }
    this.fail(`the checkpoint of the server is at seq ${held()} and the server at ${this.server.seq}, though every device has read the feed to its end more than ten minutes after the last change${this.knownGaps ? " and a day later" : ""}; ${states.join("; ")}`);
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
    await settle(40);
    for (const dev of [...this.devices, ...this.retired]) {
      // known gap, request after stop (todo test `a_pass_that_is_stopped_while_it_reads_the_memory_does_not_ask_the_server`): a feed read can still go out when
      // `stop()` comes while the pass reads the sync memory. A write or a checkpoint upload after `stop()` is never let through.
      const late = dev.lateCalls.filter((call) => !(this.knownGaps && (call.startsWith("get /api/sync/changes") || call.startsWith("get /api/sync/items"))));
      if (late.length < dev.lateCalls.length) this.count("known:get_after_stop", dev.lateCalls.length - late.length);
      if (late.length > 0) this.fail(`${dev.label} asked the server after stop(): ${late.slice(0, 3).join(", ")}`);
    }
  }

  // ------------------------------------------------------------ a restored server

  /** The database of the server is put back from `backup` and the restore is recorded (`ferret restore-epoch bump`). */
  async restoreServer(backup, { watch = true } = {}) {
    this.watching = watch;
    this.mustHalt = new Set();
    if (watch) {
      for (const group of this.groups) {
        if ((await this.floorsOfGroup(group)).maxSeq > backup.seq) for (const dev of this.devices.filter((d) => d.group === group)) this.mustHalt.add(dev.label);
      }
    }
    this.restoredAt = this.server.writes.length;
    this.restoreWrites = this.writes.length;
    this.restoreMark = new Map([...this.devices, ...this.retired].map((dev) => [dev, dev.d.events.error.length]));
    this.server.restoreFrom(backup);
    this.note(`server restored to seq ${backup.seq}, restore epoch ${this.server.restoreEpoch}; ${watch ? "a device that is shown a top below what it remembers must stop" : "no device is watched"}`);
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
