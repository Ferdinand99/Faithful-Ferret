// Fakes for the sync engine tests: a small server model, an API that talks to it
// (with faults on request), a worker client whose "encryption" is a keyed
// stream cipher with a keyed tag (opaque enough that a plaintext leak shows),
// a store that records what it is given, and a clock that only moves when told.
import { createHmac, randomBytes } from "node:crypto";
import { ApiError } from "../../src/api.mjs";
import { b64u, hex16 } from "../../src/b64.mjs";
import { cache } from "../../src/store/cache.mjs";
import { outbox } from "../../src/store/outbox.mjs";
import { deleteSetting, getSetting, setSetting } from "../../src/store/settings.mjs";
import { freshStore } from "./idbHelpers.mjs";

/** Waits (real time, in turns of the event loop) until `condition()` is true. */
export async function until(condition, what = "condition") {
  for (let turn = 0; turn < 3000; turn += 1) {
    if (await condition()) return;
    await new Promise((resolve) => setImmediate(resolve));
  }
  throw new Error(`timed out waiting for ${what}`);
}

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

/** A tiny model of the server's item store and changes feed. */
export class Model {
  constructor() {
    this.items = new Map(); // id -> { rev, seq, deleted, blob, tag, tomb } (bytes as base64url)
    this.seq = 0;
    this.minValidSince = 0;
    this.pageSize = 500;
    this.vkEpoch = 1;
    this.restoreEpoch = 0;
    this.latestSeqLie = null;
    this.idems = new Map(); // idem -> { body, result }
    this.writes = []; // every accepted write
  }

  /** The server side of `PUT /api/sync/items/{id}` for the exact body text. */
  put(id, body) {
    const request = JSON.parse(body);
    const seen = this.idems.get(request.idem);
    if (seen) {
      if (seen.body !== body) throw new ApiError(422, "idem_reuse");
      return { ...seen.result, replayed: true };
    }
    const current = this.items.get(id);
    const currentRev = current?.rev ?? 0;
    if (request.base_rev !== currentRev || current?.deleted) {
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
    return {
      changes: page.map(([id, row]) => {
        const change = { id, rev: row.rev, seq: row.seq, deleted: row.deleted };
        if (row.blob !== null) change.blob = row.blob;
        if (row.tag !== null) change.tag = row.tag;
        if (row.tomb !== null) change.tomb = row.tomb;
        return change;
      }),
      latest_seq: this.latestSeqLie ?? this.seq,
      vk_epoch: this.vkEpoch,
      restore_epoch: this.restoreEpoch,
      has_more: all.length > size,
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
    gets: [], // paths of the feed calls
    puts: [], // { id, bytes, text } of every write request, faults included
    failFeed: null, // an ApiError to throw on the next feed calls (count in failFeedTimes)
    failFeedTimes: 0,
    async get(path) {
      api.gets.push(path);
      if (api.failFeed && api.failFeedTimes > 0) {
        api.failFeedTimes -= 1;
        throw api.failFeed;
      }
      const url = new URL(path, "https://vault.invalid");
      return model.changes(Number(url.searchParams.get("since")), Number(url.searchParams.get("limit")));
    },
    async put(path, body) {
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

const rev8 = (rev) => {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(rev));
  return out;
};

/** The worker client for one vault key. Handles are numbers; the body stays inside. */
export function createFakeClient({ key = Buffer.alloc(32, 7), now = () => 1_700_000_000_000 } = {}) {
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
      const { item_type, name, urls = [], favorite = false, modified = 0 } = open.body;
      return {
        item_type, name, fields: [], urls: urls.map((url) => ({ url, matching: "domain" })),
        has_totp: false, passkey: null, has_notes: false, created: modified, modified, favorite,
        device: null, read_only: open.body.read_only === true,
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
  };
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
  const spy = { putRows: [], enqueued: [], settings: [] };
  const service = {
    spy,
    database,
    open: async () => database.store,
    cache: {
      ...cache,
      putRows: async (store, scope, rows) => {
        spy.putRows.push(rows);
        return cache.putRows(store, scope, rows);
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
      enqueue: async (store, scope, entry) => {
        order.push("outbox.enqueue");
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
      spy.settings.push([key, value]);
      return setSetting(store, key, value);
    },
    deleteSetting,
  };
  return service;
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
