// Fakes for the sync engine tests: a small server model, an API that talks to it
// (with faults on request), a worker client whose "encryption" is a keyed
// stream cipher with a keyed tag (opaque enough that a plaintext leak shows),
// a store that records what it is given, and a clock that only moves when told.
import { createHash, createHmac, randomBytes } from "node:crypto";
import { ApiError } from "../../src/api.mjs";
import { b64u, hex16 } from "../../src/b64.mjs";
import { readWire } from "../../src/wire.mjs";
import { cache } from "../../src/store/cache.mjs";
import { outbox } from "../../src/store/outbox.mjs";
import { trash } from "../../src/store/trash.mjs";
import { deleteSetting, getSetting, setSetting } from "../../src/store/settings.mjs";
import { loadSyncState, saveSyncState } from "../../src/store/syncState.mjs";
import { createSyncEngine } from "../../src/sync/engine.mjs";
import { memoryStore } from "../../src/sync/memory.mjs";
import { ACCOUNT, freshStore, scope, SERVER } from "./idbHelpers.mjs";

/**
 * The Web Locks of a browser, as far as the sync memory uses them: `request(name, callback)`
 * runs the callbacks of one name one at a time. `held` says which names are locked right now,
 * `requests` counts the calls.
 */
export class FakeLocks {
  constructor() {
    this.tails = new Map();
    this.held = new Set();
    this.requests = 0;
  }

  request(name, optionsOrCallback, maybeCallback) {
    const callback = maybeCallback ?? optionsOrCallback;
    this.requests += 1;
    const before = this.tails.get(name) ?? Promise.resolve();
    const run = before.then(async () => {
      this.held.add(name);
      try {
        return await callback({ name, mode: "exclusive" });
      } finally {
        this.held.delete(name);
      }
    });
    this.tails.set(name, run.catch(() => {}));
    return run;
  }
}

/** Waits (real time, in turns of the event loop) until `condition()` is true. */
export async function until(condition, what = "condition") {
  for (let turn = 0; turn < 3000; turn += 1) {
    if (await condition()) return;
    await new Promise((resolve) => setImmediate(resolve));
  }
  throw new Error(`timed out waiting for ${what}`);
}

/** The revision the engine shows for an item, which is what an edit made from that screen names (0 for an unknown id). */
export const currentRev = (engine, id) => engine.list().find((item) => item.id === id)?.rev ?? 0;

/** Lets the engine's pending work run for a few turns. */
export async function settle(turns = 40) {
  for (let turn = 0; turn < turns; turn += 1) await new Promise((resolve) => setImmediate(resolve));
}

/** A clock that only moves with `advance`. `delays` lists every wait that was asked for. */
export class FakeTimers {
  constructor() {
    this.time = 0;
    this.next = 1;
    this.waiting = [];
    this.delays = [];
  }

  set = (fn, ms) => {
    const id = this.next;
    this.next += 1;
    this.delays.push(ms);
    this.waiting.push({ id, at: this.time + ms, fn });
    return id;
  };

  clear = (id) => {
    this.waiting = this.waiting.filter((timer) => timer.id !== id);
  };

  get pending() {
    return this.waiting.length;
  }

  advance(ms) {
    const target = this.time + ms;
    for (;;) {
      const due = this.waiting.filter((timer) => timer.at <= target).sort((a, b) => a.at - b.at || a.id - b.id)[0];
      if (!due) break;
      this.waiting = this.waiting.filter((timer) => timer !== due);
      this.time = due.at;
      due.fn();
    }
    this.time = target;
  }
}

/** The text of a request body. */
const text = (bytes) => new TextDecoder().decode(bytes);

/** A row of the feed or of the listing, as the wire has it. */
function changeOf(id, row) {
  const change = { id, rev: row.rev, seq: row.seq, deleted: row.deleted };
  if (row.blob !== null) change.blob = row.blob;
  if (row.tag !== null) change.tag = row.tag;
  if (row.tomb !== null) change.tomb = row.tomb;
  return change;
}

/** A checkpoint as the fake core signs it: the entries sorted by the bytes of the id, a digest and a keyed mac. */
export function signCheckpoint(key, seq, entries) {
  const sorted = [...entries].sort((a, b) => Buffer.compare(Buffer.from(a.item_id), Buffer.from(b.item_id)));
  const packed = Buffer.concat(sorted.map((e) => Buffer.concat([Buffer.from(e.item_id), rev8(e.rev), Buffer.from(e.hash ?? new Uint8Array(32))])));
  const digest = createHash("sha256").update(packed).digest();
  const mac = createHmac("sha256", key).update(Buffer.concat([Buffer.from("checkpoint"), rev8(seq), digest])).digest();
  return { seq, digest: new Uint8Array(digest), mac: new Uint8Array(mac), entries: new Uint8Array(packed) };
}

/** A tiny model of the server's item store and changes feed. */
export class Model {
  constructor() {
    this.items = new Map(); // id -> { rev, seq, deleted, blob, tag, tomb } (bytes as base64url)
    this.seq = 0;
    this.minValidSince = 0;
    this.pageSize = 500;
    this.vkEpoch = 1;
    this.restoreEpoch = 0;
    this.restoreSeq = 0; // the `seq` the vault had when the restore was recorded (0: none, as on a server from before)
    this.frozen = new Map(); // id -> { rev, seq, hash } what the vault held then (hash: base64url sha-256 of the blob, null for a tombstone)
    this.tamperRestoreRows = null; // (answer) => answer: for a server that lies about the frozen list
    this.latestSeqLie = null;
    this.idems = new Map(); // idem -> { body, result }
    this.writes = []; // every accepted write
    // The checkpoint the server holds: "auto" is an honest one for the state of the model right now (what a device that
    // keeps the checkpoints up to date would have uploaded), null is none, an object ({ seq, digest, mac, entries } as
    // bytes, what `make_checkpoint` returns) is that one.
    this.checkpoint = "auto";
    this.signKey = Buffer.alloc(32, 7);
    this.hidden = new Set(); // ids the listing leaves out (the feed and the item routes still show them)
    this.checkpointPuts = []; // the body of every checkpoint the server stored
  }

  /**
   * `ferret restore-epoch bump`: the restore epoch goes up, `restore_seq` becomes the `seq` of the vault now, and the rows it holds now
   * are frozen. Call it after the model has been set back to the backup's rows.
   */
  bumpRestore() {
    this.restoreEpoch += 1;
    this.restoreSeq = this.seq;
    this.frozen = new Map(
      [...this.items.entries()].map(([id, row]) => [id, {
        rev: row.rev, seq: row.seq, hash: row.deleted || row.blob === null ? null : b64u.encode(new Uint8Array(createHash("sha256").update(b64u.decode(row.blob)).digest())),
      }]),
    );
  }

  /** `GET /api/sync/restore-rows`: the frozen rows in the order of the ids, paged like the listing. */
  restoreRows(after, limit) {
    const ids = [...this.frozen.keys()].filter((id) => after === null || id > after).sort();
    const size = Math.min(limit || 500, this.pageSize);
    const page = ids.slice(0, size);
    const more = ids.length > size;
    const answer = {
      restore_epoch: this.restoreEpoch,
      restore_seq: this.restoreSeq,
      rows: page.map((id) => ({ id, ...this.frozen.get(id) })),
      ...(more ? { next_after: page[page.length - 1] } : {}),
      has_more: more,
    };
    return this.tamperRestoreRows ? this.tamperRestoreRows(answer, after) : answer;
  }

  /** An honest checkpoint of the rows the model holds right now, at its `seq`. */
  autoCheckpoint(seq = this.seq) {
    const entries = [...this.items.entries()].map(([id, row]) => ({
      item_id: hex16.decode(id),
      rev: row.rev,
      hash: row.deleted || row.blob === null ? null : new Uint8Array(createHash("sha256").update(b64u.decode(row.blob)).digest()),
    }));
    return signCheckpoint(this.signKey, seq, entries);
  }

  /** Keeps the honest checkpoint of this moment, as another device would have uploaded it; it stays while the model moves on. */
  pinCheckpoint() {
    this.checkpoint = this.autoCheckpoint();
  }

  /** The checkpoint as the wire has it, or null when the server holds none. */
  checkpointJson() {
    if (this.checkpoint === null) return null;
    const cp = this.checkpoint === "auto" ? this.autoCheckpoint() : this.checkpoint;
    return { seq: cp.seq, digest: b64u.encode(cp.digest), mac: b64u.encode(cp.mac), entries: b64u.encode(cp.entries) };
  }

  /** The server side of `PUT /api/sync/checkpoint`: the structure only, as the real server checks it. */
  putCheckpoint(body) {
    const request = JSON.parse(body);
    this.checkEpoch(request);
    const entries = b64u.decode(request.entries);
    const digest = b64u.decode(request.digest);
    if (entries.length % 56 !== 0 || !createHash("sha256").update(entries).digest().equals(Buffer.from(digest))) {
      throw new ApiError(422, "checkpoint_invalid");
    }
    if (request.seq > this.seq) throw new ApiError(422, "checkpoint_invalid");
    const stored = this.checkpointJson();
    if (stored && request.seq < stored.seq) throw new ApiError(409, "checkpoint_stale", null, { error: "checkpoint_stale", stored_seq: stored.seq });
    if (stored && request.seq === stored.seq && JSON.stringify(stored) !== JSON.stringify(request)) {
      throw new ApiError(409, "checkpoint_stale", null, { error: "checkpoint_stale", stored_seq: stored.seq });
    }
    this.checkpoint = { seq: request.seq, digest, mac: b64u.decode(request.mac), entries };
    this.checkpointPuts.push(request);
    return { seq: request.seq };
  }

  /** The condition of a write or a checkpoint upload: the restore epoch it names, when it names one, has to be the vault's. */
  checkEpoch(request) {
    if (request.restore_epoch !== undefined && request.restore_epoch !== this.restoreEpoch) {
      throw new ApiError(409, "restore_epoch_changed", null, { error: "restore_epoch_changed", restore_epoch: this.restoreEpoch });
    }
  }

  /** The server side of `PUT /api/sync/items/{id}` for the exact body text: the key first, then the epoch, then the revision. */
  put(id, body) {
    const request = JSON.parse(body);
    const seen = this.idems.get(request.idem);
    if (seen) {
      if (seen.body !== body) throw new ApiError(422, "idem_reuse");
      return { ...seen.result, replayed: true };
    }
    this.checkEpoch(request);
    const current = this.items.get(id);
    const currentRev = current?.rev ?? 0;
    // A tombstone takes a live write only with the flag, and only built on the tombstone's own revision.
    const resurrecting = current?.deleted === true && request.resurrect === true && request.base_rev === currentRev;
    if (request.base_rev !== currentRev || (current?.deleted && !resurrecting)) {
      const detail = { current_rev: currentRev, deleted: current?.deleted ?? false };
      if (current && !current.deleted) Object.assign(detail, { blob: current.blob, tag: current.tag });
      throw new ApiError(409, "conflict", null, detail);
    }
    this.seq += 1;
    const row = request.deleted
      ? { rev: currentRev + 1, seq: this.seq, deleted: true, blob: null, tag: null, tomb: request.tomb }
      : { rev: currentRev + 1, seq: this.seq, deleted: false, blob: request.blob, tag: request.tag, tomb: null };
    this.items.set(id, row);
    const result = { rev: row.rev, seq: row.seq, replayed: false };
    this.idems.set(request.idem, { body, result });
    this.writes.push({ id, body });
    return result;
  }

  /** Sets a row directly (an honest write from another device, or a lie). */
  set(id, { rev, deleted = false, blob = null, tag = null, tomb = null, seq = null }) {
    this.seq = seq ?? this.seq + 1;
    this.items.set(id, { rev, seq: this.seq, deleted, blob, tag, tomb });
  }

  changes(since, limit) {
    if (since !== 0 && since < this.minValidSince) {
      throw new ApiError(410, "gone", null, { error: "gone", min_valid_since: this.minValidSince });
    }
    const all = [...this.items.entries()]
      .filter(([, row]) => row.seq > since)
      .sort((a, b) => a[1].seq - b[1].seq);
    const size = Math.min(limit, this.pageSize);
    const page = all.slice(0, size);
    const head = this.checkpointJson();
    return {
      changes: page.map(([id, row]) => changeOf(id, row)),
      latest_seq: this.latestSeqLie ?? this.seq,
      vk_epoch: this.vkEpoch,
      restore_epoch: this.restoreEpoch,
      restore_seq: this.restoreSeq,
      ...(head ? { checkpoint: { seq: head.seq, digest: head.digest, mac: head.mac } } : {}),
      has_more: all.length > size,
    };
  }

  /** `GET /api/sync/items`: every row in the order of the ids, the ones in `hidden` left out, never a 410. */
  listItems(after, limit) {
    const ids = [...this.items.keys()].filter((id) => !this.hidden.has(id) && (after === null || id > after)).sort();
    const size = Math.min(limit || 500, this.pageSize);
    const page = ids.slice(0, size);
    const more = ids.length > size;
    return {
      items: page.map((id) => changeOf(id, this.items.get(id))),
      as_of_seq: this.seq,
      vk_epoch: this.vkEpoch,
      restore_epoch: this.restoreEpoch,
      restore_seq: this.restoreSeq,
      ...(more ? { next_after: page[page.length - 1] } : {}),
      has_more: more,
    };
  }
}

/**
 * An API over the model. `faults` is a queue of failures for the next writes:
 * `{ kind: "network" }` (nothing happened), `{ kind: "lost" }` (the server
 * wrote, the answer never came), `{ kind: "status", status, code }`;
 * `only` limits a fault to one item id.
 */
export function createFakeApi(model, { order = [] } = {}) {
  const api = {
    faults: [],
    gets: [], // paths of the feed calls (the changes and the listing)
    checkpointGets: [], // paths of the calls for the checkpoint
    restoreRowGets: [], // paths of the calls for the frozen restore rows
    checkpointPuts: [], // the text of every checkpoint upload request, faults included
    checkpointFaults: [], // failures for the next checkpoint reads (`{ kind: "network" | "status", status, code }`)
    checkpointPutFaults: [], // and for the next uploads (`{ kind: "network" | "status", status, code, retryAfter }`)
    puts: [], // { id, bytes, text } of every write request, faults included
    failFeed: null, // an ApiError to throw on the next feed calls (count in failFeedTimes)
    failFeedTimes: 0,
    async get(path) {
      const url = new URL(path, "https://vault.invalid");
      if (url.pathname === "/api/sync/checkpoint") {
        api.checkpointGets.push(path);
        const fault = api.checkpointFaults.shift();
        if (fault?.kind === "network") throw new ApiError(0, "network");
        if (fault?.kind === "status") throw new ApiError(fault.status, fault.code);
        const checkpoint = model.checkpointJson();
        if (!checkpoint) throw new ApiError(404, "not_found");
        return checkpoint;
      }
      if (url.pathname === "/api/sync/restore-rows") {
        api.restoreRowGets.push(path);
        const answer = model.restoreRows(url.searchParams.get("after"), Number(url.searchParams.get("limit")));
        // The answer goes through the shape of the wire, as the real client reads it: a shape that cannot be read is a 200 that is no answer.
        try {
          return readWire("restore_rows_res", JSON.stringify(answer));
        } catch {
          throw new ApiError(200, "bad_response");
        }
      }
      api.gets.push(path);
      if (api.failFeed && api.failFeedTimes > 0) {
        api.failFeedTimes -= 1;
        throw api.failFeed;
      }
      if (url.pathname === "/api/sync/items") return model.listItems(url.searchParams.get("after"), Number(url.searchParams.get("limit")));
      return model.changes(Number(url.searchParams.get("since")), Number(url.searchParams.get("limit")));
    },
    async put(path, body) {
      if (path === "/api/sync/checkpoint") {
        const sent = body instanceof Uint8Array ? text(body) : String(body);
        api.checkpointPuts.push(sent);
        const fault = api.checkpointPutFaults.shift();
        if (fault?.kind === "network") throw new ApiError(0, "network");
        if (fault?.kind === "status") throw new ApiError(fault.status, fault.code, fault.retryAfter ?? null, fault.body ?? null);
        return model.putCheckpoint(sent);
      }
      const id = path.split("/").pop();
      const bytes = body instanceof Uint8Array ? new Uint8Array(body) : new TextEncoder().encode(String(body));
      api.puts.push({ id, bytes, text: text(bytes) });
      order.push("put");
      const at = api.faults.findIndex((fault) => !fault.only || fault.only === id);
      const fault = at === -1 ? null : api.faults.splice(at, 1)[0];
      if (fault?.kind === "network") throw new ApiError(0, "network");
      if (fault?.kind === "status") throw new ApiError(fault.status, fault.code, fault.retryAfter ?? null, fault.body ?? null);
      const result = model.put(id, text(bytes));
      if (fault?.kind === "lost") throw new ApiError(0, "network");
      return result;
    },
  };
  return api;
}

/** A failure the way the worker client reports it. */
export class FakeFerretError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

/** The fake core's sync memory is JSON bytes: `{ maxSeq, checkpointSeq, revs: { <item id>: rev } }`. */
export const memoryBytes = (memory) => {
  const revs = Object.fromEntries(Object.entries(memory.revs).sort(([a], [b]) => (a < b ? -1 : 1)));
  return new TextEncoder().encode(JSON.stringify({ maxSeq: memory.maxSeq, checkpointSeq: memory.checkpointSeq, revs }));
};
export const memoryOf = (bytes) => JSON.parse(new TextDecoder().decode(bytes));

const rev8 = (rev) => {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(rev));
  return out;
};

/** The worker client for one vault key. Handles are numbers; the body stays inside. */
export function createFakeClient({ key = Buffer.alloc(32, 7), now = () => 1_700_000_000_000, memoryLimit = 50_000 } = {}) {
  const handles = new Map();
  let nextHandle = 1;
  const mac = (...parts) => createHmac("sha256", key).update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest();
  const stream = (iv, length) => {
    const chunks = [];
    for (let block = 0; chunks.length * 32 < length; block += 1) chunks.push(mac(Buffer.from("stream"), iv, rev8(block)));
    return Buffer.concat(chunks).subarray(0, length);
  };
  const seal = (id, rev, body) => {
    const plain = Buffer.from(JSON.stringify(body));
    const iv = randomBytes(12);
    const envelope = Buffer.concat([iv, plain.map((byte, i) => byte ^ stream(iv, plain.length)[i])]);
    return { rev, envelope: new Uint8Array(envelope), tag: new Uint8Array(mac(Buffer.from("tag"), id, rev8(rev), envelope)) };
  };
  const calls = [];
  const vault = {
    calls,
    handles,
    async open_item(id, rev, envelope, tag) {
      calls.push(["open_item", hex16.encode(id), rev]);
      const good = mac(Buffer.from("tag"), id, rev8(rev), envelope);
      if (!Buffer.from(tag).equals(good)) throw new FakeFerretError("decrypt");
      const iv = Buffer.from(envelope.subarray(0, 12));
      const cipher = Buffer.from(envelope.subarray(12));
      const plain = cipher.map((byte, i) => byte ^ stream(iv, cipher.length)[i]);
      const handle = nextHandle;
      nextHandle += 1;
      handles.set(handle, { id: hex16.encode(id), body: JSON.parse(plain.toString()), envelope });
      return handle;
    },
    async close_item(handle) {
      if (!handles.delete(handle)) throw new FakeFerretError("invalid_handle");
    },
    async item_view(handle) {
      const open = handles.get(handle);
      if (!open) throw new FakeFerretError("invalid_handle");
      const { item_type, name, urls = [], favorite = false, modified = 0, fields = [] } = open.body;
      // Like the core: a secret kind has no value in the view.
      const shown = fields.map((f) => ({
        id: f.id, label: f.label ?? "", kind: f.kind ?? "text",
        value: ["password", "hidden"].includes(f.kind) ? null : (f.value ?? ""),
      }));
      return {
        item_type, name, fields: shown, urls: urls.map((url) => ({ url, matching: "domain" })),
        has_totp: false, passkey: null, has_notes: false, created: modified, modified, favorite,
        device: open.body.device ?? null, read_only: open.body.read_only === true,
      };
    },
    async encrypt_item(id, rev, draft, existing) {
      calls.push(["encrypt_item", hex16.encode(id), rev, existing ?? null]);
      let body;
      if (existing === undefined || existing === null) {
        if (!draft.item_type || !draft.name) throw new FakeFerretError("invalid_input");
        body = { ...draft };
      } else {
        const open = handles.get(existing);
        if (!open || open.id !== hex16.encode(id)) throw new FakeFerretError("invalid_input");
        body = { ...open.body, ...draft };
      }
      body.modified = now();
      const sealed = seal(id, rev, body);
      const open = handles.get(existing);
      if (open) {
        open.body = body;
        open.envelope = sealed.envelope;
      }
      return sealed;
    },
    async make_tombstone(id, rev) {
      calls.push(["make_tombstone", hex16.encode(id), rev]);
      return { rev, tomb: new Uint8Array(Buffer.concat([mac(Buffer.from("tomb"), id, rev8(rev)), mac(Buffer.from("tomb2"), id).subarray(0, 8)])) };
    },
    async verify_tombstone(id, rev, tomb) {
      calls.push(["verify_tombstone", hex16.encode(id), rev]);
      const good = Buffer.concat([mac(Buffer.from("tomb"), id, rev8(rev)), mac(Buffer.from("tomb2"), id).subarray(0, 8)]);
      if (!Buffer.from(tomb).equals(good)) throw new FakeFerretError("tombstone_invalid");
    },
    // ------------------------------------------------ the rollback memory
    // The same floors as the core: nothing here lowers a floor except accept_older_state.
    async sync_memory_new() {
      return memoryBytes({ maxSeq: 0, checkpointSeq: 0, revs: {} });
    },
    async accept_rows(rows, topSeq, memory) {
      calls.push(["accept_rows", rows.map((row) => hex16.encode(row.item_id)), topSeq]);
      const next = memoryOf(memory);
      checkRows(next, rows, topSeq);
      record(next, rows, topSeq, null);
      return { newSyncMemory: memoryBytes(next) };
    },
    async make_checkpoint(seq, entries) {
      calls.push(["make_checkpoint", seq]);
      return signCheckpoint(key, seq, entries);
    },
    async verify_checkpoint(checkpoint, rows, topSeq, memory) {
      calls.push(["verify_checkpoint", checkpoint.seq, topSeq]);
      const next = memoryOf(memory);
      checkCheckpoint(checkpoint, rows, topSeq);
      if (checkpoint.seq < next.checkpointSeq) throw new FakeFerretError("checkpoint_seq_below_remembered");
      checkRows(next, rows, topSeq);
      record(next, rows, topSeq, checkpoint.seq);
      return { newSyncMemory: memoryBytes(next) };
    },
    async accept_older_state(checkpoint, rows, topSeq) {
      calls.push(["accept_older_state", checkpoint.seq, topSeq]);
      checkCheckpoint(checkpoint, rows, topSeq);
      const next = { maxSeq: 0, checkpointSeq: 0, revs: {} };
      record(next, rows, topSeq, checkpoint.seq);
      return { newSyncMemory: memoryBytes(next) };
    },
  };
  const entryOf = (bytes) => ({ id: Buffer.from(bytes.subarray(0, 16)).toString("hex"), rev: Number(Buffer.from(bytes.subarray(16, 24)).readBigUInt64BE()), hash: Buffer.from(bytes.subarray(24, 56)) });
  /** The tag or tombstone of every row is checked, as the core does before it compares anything. */
  function checkRowProofs(rows) {
    for (const row of rows) {
      if (row.state === "deleted") {
        const good = Buffer.concat([mac(Buffer.from("tomb"), row.item_id, rev8(row.rev)), mac(Buffer.from("tomb2"), row.item_id).subarray(0, 8)]);
        if (!Buffer.from(row.tomb).equals(good)) throw new FakeFerretError("tombstone_invalid");
      } else if (!Buffer.from(row.tag).equals(mac(Buffer.from("tag"), row.item_id, rev8(row.rev), row.envelope))) {
        throw new FakeFerretError("decrypt");
      }
    }
  }
  function checkRows(memory, rows, topSeq) {
    checkRowProofs(rows);
    if (topSeq < memory.maxSeq) throw new FakeFerretError("checkpoint_top_seq_below_remembered");
    for (const row of rows) {
      const known = memory.revs[hex16.encode(row.item_id)];
      if (known !== undefined && row.rev < known) throw new FakeFerretError("checkpoint_rev_below_remembered");
    }
  }
  function record(memory, rows, topSeq, checkpointSeq) {
    const added = new Set(rows.map((row) => hex16.encode(row.item_id)).filter((id) => memory.revs[id] === undefined));
    if (Object.keys(memory.revs).length + added.size > memoryLimit) throw new FakeFerretError("too_large");
    for (const row of rows) {
      const id = hex16.encode(row.item_id);
      memory.revs[id] = Math.max(memory.revs[id] ?? 0, row.rev);
    }
    memory.maxSeq = Math.max(memory.maxSeq, topSeq);
    if (checkpointSeq !== null) memory.checkpointSeq = Math.max(memory.checkpointSeq, checkpointSeq);
  }
  /** The checks of Fase 1 section 8.6, "what a recipient checks": the digest and the mac, then the entries against the rows. */
  function checkCheckpoint(checkpoint, rows, topSeq) {
    const digest = createHash("sha256").update(checkpoint.entries).digest();
    if (!Buffer.from(checkpoint.digest).equals(digest)) throw new FakeFerretError("checkpoint_bad_digest");
    if (!Buffer.from(checkpoint.mac).equals(mac(Buffer.from("checkpoint"), rev8(checkpoint.seq), digest))) throw new FakeFerretError("checkpoint_bad_mac");
    if (checkpoint.entries.length % 56 !== 0) throw new FakeFerretError("malformed_entries");
    if (checkpoint.seq > topSeq) throw new FakeFerretError("checkpoint_seq_above_top");
    checkRowProofs(rows);
    const byId = new Map(rows.map((row) => [hex16.encode(row.item_id), row]));
    const zero = Buffer.alloc(32);
    const entries = [];
    for (let at = 0; at < checkpoint.entries.length; at += 56) entries.push(entryOf(checkpoint.entries.subarray(at, at + 56)));
    for (const entry of entries) {
      const row = byId.get(entry.id);
      const tombstone = entry.hash.equals(zero);
      if (!row) {
        if (!tombstone) throw new FakeFerretError("checkpoint_hidden_or_rolled_back");
      } else if (row.rev < entry.rev) {
        throw new FakeFerretError(row.state === "live" && tombstone ? "checkpoint_live_behind_tombstone" : "checkpoint_lower_rev");
      } else if (row.rev === entry.rev) {
        const hash = row.state === "deleted" ? zero : createHash("sha256").update(row.envelope).digest();
        if (!hash.equals(entry.hash)) throw new FakeFerretError("checkpoint_same_rev_different_hash");
      }
    }
    if (topSeq === checkpoint.seq) {
      const listed = new Set(entries.map((entry) => entry.id));
      for (const id of byId.keys()) if (!listed.has(id)) throw new FakeFerretError("checkpoint_top_digest_mismatch");
    }
  }
  /** A sealed row for the model, as the wire has it (base64url). */
  const wireRow = (id, rev, body) => {
    const sealed = seal(hex16.decode(id), rev, body);
    return { blob: b64u.encode(sealed.envelope), tag: b64u.encode(sealed.tag) };
  };
  const wireTomb = (id, rev) => {
    const raw = Buffer.concat([mac(Buffer.from("tomb"), hex16.decode(id), rev8(rev)), mac(Buffer.from("tomb2"), hex16.decode(id)).subarray(0, 8)]);
    return b64u.encode(new Uint8Array(raw));
  };
  return { vault, wireRow, wireTomb };
}

/**
 * The store service over a fake IndexedDB. Every call that carries data is
 * recorded in `spy`, and the ones that matter for ordering are noted in `order`.
 */
export async function createFakeStore({ order = [], db = null } = {}) {
  const database = db ?? (await freshStore());
  const spy = { putRows: [], enqueued: [], settings: [], states: [], trashed: [], log: [] }; // log: "state.save", "trash.put" and "cache.putRows" in the order they happened
  const service = {
    spy,
    database,
    holdOpen: null, // a promise that the next `open()` waits for
    holdSet: null, // a promise that the next settings write waits for
    failPutRows: 0, // the next this many row writes to the cache fail
    failSaveState: 0, // the next this many writes of the sync state fail
    failSaveWhen: null, // a function of the state about to be saved: when it answers true that one write fails (once)
    failEnqueue: 0, // the next this many writes into the outbox fail
    loadSyncState: async (store, serverUrl, accountId) => loadSyncState(store, serverUrl, accountId),
    saveSyncState: async (store, serverUrl, accountId, state) => {
      if (service.failSaveState > 0) {
        service.failSaveState -= 1;
        throw new Error("the disk is full");
      }
      if (service.failSaveWhen?.(state)) {
        service.failSaveWhen = null;
        throw new Error("the disk is full");
      }
      spy.states.push(state);
      spy.log.push("state.save");
      return saveSyncState(store, serverUrl, accountId, state);
    },
    open: async () => {
      if (service.holdOpen) {
        const gate = service.holdOpen;
        service.holdOpen = null;
        await gate;
      }
      return database.store;
    },
    cache: {
      ...cache,
      putRows: async (store, scope, rows) => {
        if (service.failPutRows > 0) {
          service.failPutRows -= 1;
          throw new Error("the cache is full");
        }
        spy.putRows.push(rows);
        spy.log.push("cache.putRows");
        return cache.putRows(store, scope, rows);
      },
    },
    failTrashPut: 0, // the next this many writes into the trash fail
    trash: {
      ...trash,
      put: async (store, scope, entry) => {
        if (service.failTrashPut > 0) {
          service.failTrashPut -= 1;
          throw new Error("the disk is full");
        }
        spy.trashed.push(entry);
        spy.log.push("trash.put");
        return trash.put(store, scope, entry);
      },
    },
    failRemove: 0, // the next this many removals from the outbox fail
    outbox: {
      ...outbox,
      remove: async (store, scope, idem) => {
        if (service.failRemove > 0) {
          service.failRemove -= 1;
          throw new Error("the disk is full");
        }
        return outbox.remove(store, scope, idem);
      },
      swap: async (store, scope, remove, entries, only = null) => {
        if (service.failEnqueue > 0) {
          service.failEnqueue -= 1;
          throw new Error("the disk is full");
        }
        await outbox.swap(store, scope, remove, entries, only);
        for (const entry of entries) {
          spy.log.push("outbox.enqueue");
          spy.enqueued.push(entry);
        }
      },
      enqueue: async (store, scope, entry) => {
        if (service.failEnqueue > 0) {
          service.failEnqueue -= 1;
          throw new Error("the disk is full");
        }
        order.push("outbox.enqueue");
        spy.log.push("outbox.enqueue");
        spy.enqueued.push(entry);
        return outbox.enqueue(store, scope, entry);
      },
    },
    getSetting,
    failSet: 0, // the next this many settings writes fail
    setSetting: async (store, key, value) => {
      if (service.failSet > 0) {
        service.failSet -= 1;
        throw new Error("the disk is full");
      }
      if (service.holdSet) {
        const gate = service.holdSet;
        service.holdSet = null;
        await gate;
      }
      spy.settings.push([key, value]);
      return setSetting(store, key, value);
    },
    deleteSetting,
  };
  return service;
}

/**
 * One device: an engine over its own fake browser storage and a fake clock, as the checkpoint tests use it. `db` and `locks` are
 * shared by the engines that are meant to be the same browser (a reload, a second tab).
 */
export async function syncDevice({ model, client = createFakeClient(), seed = 1, pollMs = 5_000, db = null, locks = new FakeLocks(), deviceName, win = null } = {}) {
  const store = await createFakeStore({ db });
  const api = createFakeApi(model, { order: store.spy.log }); // the writes to the server are in the log of the store, in order
  const timers = new FakeTimers();
  const events = { changed: [], error: [], state: [] };
  const memory = fakeMemory({ store, client, locks });
  const engine = createSyncEngine({
    api, client: { vault: client.vault }, store, scope: scope(), memory, timers, rand: counterRand(seed), pollMs, win, deviceName,
    now: () => 1_700_000_000_000 + timers.time,
  });
  for (const name of Object.keys(events)) engine.on(name, (payload) => events[name].push(payload));
  return { model, client, store, api, timers, engine, events, memory, locks };
}

/**
 * The sync memory of the test account over a fake store, with the fake locks. `locks` is shared by
 * the engines that are meant to be tabs of one browser.
 */
export function fakeMemory({ store, client, locks = new FakeLocks(), accountId = ACCOUNT, serverUrl = SERVER }) {
  return memoryStore({ store, serverUrl, accountId, locks, newMemory: () => client.vault.sync_memory_new() });
}

/** A source of random bytes that never repeats (a counter in the first bytes, `seed` in the last). */
export function counterRand(seed = 0) {
  let count = 0;
  return (bytes) => {
    count += 1;
    bytes.fill(0);
    bytes[0] = count & 0xff;
    bytes[1] = (count >> 8) & 0xff;
    bytes[15] = seed;
    return bytes;
  };
}
