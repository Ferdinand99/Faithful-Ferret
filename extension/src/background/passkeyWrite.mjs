// The write of a new passkey (the `passkeys` feature, design document § 8.3, § 9.3 and appendix B): the one path by which a
// passkey that Ferret makes for a website reaches the vault.
//
// The sync (sync.mjs) makes one writer per unlock and hands it the engine, the core client of that unlock, the session's API
// client and the restore epoch this device has accepted. Besides the offer writer it is the only module the engine is handed to;
// it reads the items (`scan`) and, after the write, lets the engine bring the new revision in.
//
// scan   What the vault has for a create request, read in the core with the vault open: the items a new passkey can be added
//        to (a login that matches the frame's address by host or exactly, that has no passkey, that can be written and whose
//        change is not waiting to be sent), whether one of them has the request's user name, the item that already holds a
//        passkey for the same RP ID and user handle, the passkeys of the vault (for `excludeCredentials`) and the folders.
// save   The write itself, and nothing but it decides what the page gets:
//          1. the core makes the passkey and seals it into an item (`passkey_create`), and holds the answer for the page back;
//          2. the sealed item is sent to the server at once, with a key of its own (`idem`). It never goes into the outbox and
//             never reaches the conflict view: a write the server refuses is dropped, not kept as a draft;
//          3. a certain yes (2xx, or a 409 that shows this very write): the core gives the answer (`passkey_create_confirm`);
//             a certain no (409, 4xx, `restore_epoch_changed`, 429, 503): the answer is wiped (`passkey_create_abort`) and the
//             person chooses again; an unknown outcome (no answer, a dropped connection, another 5xx): the same bytes go again
//             under the same key until a certain answer, for at most PASSKEY_SAVE_MS. No certain answer by then counts as a no
//             for the person, and the write is followed up after that (below).
//        The caller holds the request's deadline while this runs (the deadline waits for a started upload) and says, when the
//        outcome is known, whether the page still waits for it.
// Too late. A write the server took after the page stopped waiting (it left, navigated, aborted, or the person cancelled), or
// that it took after the person was told no, is undone at once with an ordinary write through the engine, so nothing is left
// that the website never got: a new item is deleted (a tombstone: it goes to the trash, where an item of the first revision
// with a passkey carries the note that the passkey is not registered at the site); a passkey added to an item is removed from
// it again and the rest of the item stays. A follow-up whose engine stopped (a lock) is kept by the sync and taken up by the
// next unlock of the same account.
//
// Nothing here reads a key: the private key and the PRF seeds are made and sealed in the core, and what passes through here is
// the sealed item, public numbers and the answer for the page.

import { b64u } from "../shared/b64.mjs";
import { encodeWireBytes } from "../shared/wire.mjs";

/** How long the unknown outcome of a write is sent again before the person is told no. */
export const PASSKEY_SAVE_MS = 30_000;
/** The longest wait between two tries of a write whose outcome is unknown (also after PASSKEY_SAVE_MS). */
export const PASSKEY_RETRY_MAX_MS = 60_000;
/** How many follow-ups of writes are kept at most (the oldest goes first). */
export const MAX_LEFTOVERS = 32;

/** How many items are opened at once. */
const BATCH = 64;
/** The most items a create request is offered to add to. */
const MAX_TARGETS = 200;
/** The most folders the window is given. */
const MAX_FOLDERS = 500;
const ITEM_ID = /^[0-9a-f]{32}$/;
const MATCHES = Object.freeze(["exact", "host"]);
/** The core's codes that say the vault or its worker is gone. */
const VAULT_GONE = Object.freeze(["vault_locked", "locked", "worker_failed", "internal", "kdf_out_of_memory", "stopped"]);

/**
 * @typedef {{
 *   id: string, rev: number, type?: string, name: string, username?: string, urls?: string[], folders?: string[],
 *   hasPasskey?: boolean, passkeySite?: string | null, pending?: boolean, readOnly?: boolean, damaged?: boolean,
 *   quarantined?: boolean, blocked?: boolean, conflict?: boolean, missingOnServer?: boolean,
 * }} Summary the part of the engine's item summary read here
 * @typedef {{
 *   list(): Summary[],
 *   open(id: string): Promise<{ handle: number, view: any, close(): Promise<void> }>,
 *   remove(id: string): Promise<void>,
 *   update(id: string, draft: object, expectedRev: number): Promise<void>,
 *   syncNow(): Promise<void>,
 *   health(): { halted: string | null },
 * }} PasskeyEngine the part of the sync engine this module uses
 * @typedef {{ put(path: string, body: Uint8Array, options: { shape: string }): Promise<any> }} PasskeyApi
 * @typedef {{
 *   key: string, scope: string, itemId: string, baseRev: number, rev: number, rpId: string, created: number,
 *   attach: boolean, bytes: Uint8Array, folder: string | null, inflight: Promise<Outcome> | null,
 * }} Leftover a write to follow up: its bytes and key, and what identifies the passkey it made (RP ID and creation time)
 * @typedef {{ kind: "accepted" } | { kind: "refused", reason: string } | { kind: "unknown" }} Outcome
 * @typedef {{ item_id: string, rev: number, name: string, user_name: string, same_user: boolean }} Target
 * @typedef {{
 *   targets: Target[],
 *   existing: { item_id: string, name: string } | null,
 *   stored: Array<{ rp_id: string, id: Uint8Array }>,
 *   folders: string[],
 * }} Scan
 */

/** The error of this module: a short code. */
export class PasskeyWriteError extends Error {
  /** @param {string} code */
  constructor(code) {
    super(code);
    this.name = "PasskeyWriteError";
    this.code = code;
  }
}

/** @param {unknown} error @returns {string} */
const codeOf = (error) => {
  const code = /** @type {{ code?: unknown }} */ (error)?.code;
  return typeof code === "string" ? code : "internal";
};

/** A user name as two of them are compared: NFC, trimmed, lower case. @param {unknown} s */
const fold = (s) => (typeof s === "string" ? s.normalize("NFC").trim().toLowerCase() : "");

/** @param {Uint8Array} a @param {Uint8Array} b */
const sameBytes = (a, b) => a instanceof Uint8Array && b instanceof Uint8Array && a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * The user name of an opened item: its `username` field, or its `email` field when it has no user name.
 * @param {any} view
 */
function userNameOf(view) {
  /** @type {any[]} */
  const fields = Array.isArray(view?.fields) ? view.fields : [];
  for (const id of ["username", "email"]) {
    const value = fields.find((f) => f?.id === id)?.value;
    if (typeof value === "string" && value.trim() !== "") return value;
  }
  return "";
}

/**
 * Whether an item may take a new passkey: a login without one, that can be written, and whose last change is not waiting to be
 * sent (a direct write on top of a queued one would make that one a conflict).
 * @param {Summary} s
 */
export const attachable = (s) =>
  (s.type ?? "login") === "login" && s.hasPasskey !== true && s.readOnly !== true && s.damaged !== true && s.quarantined !== true &&
  s.blocked !== true && s.conflict !== true && s.missingOnServer !== true && s.pending !== true;

/**
 * What the server's answer (or the lack of one) to a write means.
 * @param {any} error an ApiError of the API client @param {{ baseRev: number, blob: string, tag: string }} sent
 * @returns {Outcome}
 */
export function judge(error, sent) {
  if (error === null || typeof error !== "object" || typeof error.status !== "number") return { kind: "unknown" };
  const status = error.status;
  // The server checks the restore epoch before it stores anything: certainly not stored.
  if (error.code === "restore_epoch_changed" || error.body?.error === "restore_epoch_changed") return { kind: "refused", reason: "network" };
  if (status === 409) {
    // A 409 that shows this very write (the key ran out and the row is ours) is a yes.
    const row = error.body;
    if (row && row.deleted !== true && row.current_rev === sent.baseRev + 1 && row.blob === sent.blob && row.tag === sent.tag) return { kind: "accepted" };
    return { kind: "refused", reason: "busy" };
  }
  if (status === 0 || status === 408) return { kind: "unknown" };
  if (status === 429 || status === 503) return { kind: "refused", reason: "network" };
  if (status >= 500) return { kind: "unknown" };
  // A 2xx that did not read as an answer (a proxy's page): the write may have gone through.
  if (status >= 200 && status < 300) return { kind: "unknown" };
  if (status === 401) return { kind: "refused", reason: "network" };
  return { kind: "refused", reason: "internal_error" };
}

/**
 * The writer of new passkeys for one unlock.
 * @param {{
 *   engine: PasskeyEngine,
 *   vault: any,
 *   api: PasskeyApi,
 *   epoch: () => Promise<number | null>,
 *   scope: string,
 *   leftovers: Map<string, Leftover>,
 *   now?: () => number,
 *   timers?: { setTimeout(fn: () => void, ms: number): unknown, clearTimeout(id: unknown): void },
 *   random?: (bytes: Uint8Array) => Uint8Array,
 *   saveMs?: number,
 *   retryMs?: (attempt: number) => number,
 * }} options `vault`: the core client of the open vault (refused after a lock); `epoch`: the restore epoch the writes are
 *   conditional on (null: none yet); `scope`: the server and account the writes go to; `leftovers`: the follow-ups, kept by the
 *   sync across unlocks
 */
export function createPasskeyWrite({
  engine,
  vault,
  api,
  epoch,
  scope,
  leftovers,
  now = Date.now,
  timers = { setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms), clearTimeout: (id) => globalThis.clearTimeout(/** @type {any} */ (id)) },
  random = (bytes) => globalThis.crypto.getRandomValues(/** @type {Uint8Array<ArrayBuffer>} */ (bytes)),
  saveMs = PASSKEY_SAVE_MS,
  retryMs = (attempt) => Math.min(PASSKEY_RETRY_MAX_MS, 1000 * 2 ** Math.min(attempt, 16)),
}) {
  let stopped = false;
  /** @type {Set<unknown>} */
  const waits = new Set();

  /** @param {number} ms @returns {Promise<void>} */
  const sleep = (ms) =>
    new Promise((resolve) => {
      const id = timers.setTimeout(() => {
        waits.delete(id);
        resolve();
      }, Math.max(0, ms));
      waits.add(id);
    });

  /** @param {number} n */
  const hex = (n) => Array.from(random(new Uint8Array(n)), (b) => b.toString(16).padStart(2, "0")).join("");

  /** The engine's items, or none while it is stopped. @returns {Summary[]} */
  const items = () => {
    try {
      const list = engine.list();
      return Array.isArray(list) ? list.filter((s) => typeof s?.id === "string" && ITEM_ID.test(s.id)) : [];
    } catch {
      return [];
    }
  };

  /**
   * Opens the items in batches and gives each opened one to `each`; every handle is closed before this returns or throws.
   * @param {Summary[]} list @param {(opened: Array<{ summary: Summary, handle: number, view: any }>) => Promise<void>} each
   */
  async function inBatches(list, each) {
    for (let at = 0; at < list.length; at += BATCH) {
      const batch = list.slice(at, at + BATCH);
      /** @type {Array<{ summary: Summary, handle: number, view: any, close(): Promise<void> }>} */
      const opened = [];
      try {
        const results = await Promise.allSettled(batch.map((s) => engine.open(s.id)));
        results.forEach((r, i) => {
          if (r.status === "fulfilled") opened.push({ ...r.value, summary: batch[i] });
        });
        const gone = results.find((r) => r.status === "rejected" && VAULT_GONE.includes(codeOf(r.reason)));
        if (gone) throw new PasskeyWriteError("vault_locked");
        if (opened.length > 0) await each(opened);
      } finally {
        await Promise.all(opened.map((o) => o.close().catch(() => {})));
      }
    }
  }

  /**
   * What the vault has for a create request (see the head of the file).
   * @param {{ url: string, rpId: string, userId: Uint8Array, userName: string }} request the frame's address, the RP ID the
   *   core checked, the page's user handle and user name
   * @returns {Promise<Scan>}
   */
  async function scan({ url, rpId, userId, userName }) {
    const all = items();
    /** @type {Target[]} */
    const targets = [];
    /** @type {{ item_id: string, name: string } | null} */
    let existing = null;
    /** @type {Array<{ rp_id: string, id: Uint8Array }>} */
    const stored = [];
    const wanted = fold(userName);
    // The passkeys of the vault: for excludeCredentials (the core compares) and the account that already has one.
    await inBatches(all.filter((s) => s.hasPasskey === true && s.damaged !== true && s.quarantined !== true), async (opened) => {
      for (const o of opened) {
        const p = o.view?.passkey;
        if (!p || typeof p.rp_id !== "string" || !(p.cred_id instanceof Uint8Array)) continue;
        stored.push({ rp_id: p.rp_id, id: p.cred_id });
        if (existing === null && p.rp_id === rpId && sameBytes(p.user_handle, userId)) existing = { item_id: o.summary.id, name: o.summary.name ?? "" };
      }
    });
    // The items a new passkey can go to: those of this address by host or exactly, by the core's own rule.
    await inBatches(all.filter(attachable), async (opened) => {
      if (targets.length >= MAX_TARGETS) return;
      const answer = await vault.match_page(url, opened.map((o) => o.handle));
      if (!Array.isArray(answer)) throw new PasskeyWriteError("internal");
      /** @type {Map<number, string>} */
      const how = new Map();
      for (const hit of answer) if (MATCHES.includes(hit?.how)) how.set(hit.handle, hit.how);
      for (const o of opened) {
        if (!how.has(o.handle) || o.view?.passkey || targets.length >= MAX_TARGETS) continue;
        const user = userNameOf(o.view);
        targets.push({ item_id: o.summary.id, rev: o.summary.rev, name: o.summary.name ?? "", user_name: user, same_user: wanted !== "" && fold(user) === wanted });
      }
    });
    /** @type {Map<string, string>} */
    const folders = new Map();
    for (const s of all) {
      for (const name of Array.isArray(s.folders) ? s.folders : []) {
        if (typeof name === "string" && name !== "" && !folders.has(fold(name))) folders.set(fold(name), name);
      }
    }
    return { targets, existing, stored, folders: [...folders.values()].sort((a, b) => a.localeCompare(b)).slice(0, MAX_FOLDERS) };
  }

  /**
   * One request of the write.
   * @param {string} itemId @param {Uint8Array} bytes @param {{ baseRev: number, blob: string, tag: string }} sent
   * @returns {Promise<Outcome>}
   */
  async function send(itemId, bytes, sent) {
    try {
      await api.put(`/api/sync/items/${itemId}`, bytes, { shape: "put_item_res" });
      return { kind: "accepted" };
    } catch (error) {
      return judge(error, sent);
    }
  }

  /**
   * The answer of `promise`, or null when none came within `ms`.
   * @template T @param {Promise<T>} promise @param {number} ms @returns {Promise<T | null>}
   */
  function within(promise, ms) {
    return new Promise((resolve) => {
      const id = timers.setTimeout(() => {
        waits.delete(id);
        resolve(null);
      }, Math.max(0, ms));
      waits.add(id);
      promise.then((value) => {
        timers.clearTimeout(id);
        waits.delete(id);
        resolve(value);
      });
    });
  }

  /** @param {Leftover} left */
  const keep = (left) => {
    leftovers.delete(left.key);
    leftovers.set(left.key, left);
    while (leftovers.size > MAX_LEFTOVERS) leftovers.delete(/** @type {string} */ (leftovers.keys().next().value));
  };

  /**
   * Waits until the engine has the revision `rev` of the item (or a later one), reading the feed. Null when it did not come
   * (the engine stopped, or the server does not show it yet).
   * @param {string} itemId @param {number} rev @returns {Promise<Summary | null>}
   */
  async function settle(itemId, rev) {
    for (let attempt = 0; attempt < 8 && !stopped; attempt += 1) {
      try {
        await engine.syncNow();
      } catch {
        // The next try reads again.
      }
      const found = items().find((s) => s.id === itemId);
      if (found && found.rev >= rev) return found;
      await sleep(retryMs(attempt));
    }
    return null;
  }

  /**
   * Undoes a write that the server took although nobody wanted it any more: the new item goes (a tombstone), or the passkey
   * leaves the item it was added to. Only the passkey this write made is touched (its RP ID and creation time).
   * @param {Leftover} left
   */
  async function undo(left) {
    const found = await settle(left.itemId, left.rev);
    if (found === null) {
      // Not here yet (or the engine stopped): the next unlock tries again.
      keep({ ...left, inflight: null });
      return;
    }
    /** @type {{ view: any, close(): Promise<void> } | null} */
    let opened = null;
    try {
      opened = await engine.open(left.itemId);
      const p = opened.view?.passkey;
      const ours = p && p.rp_id === left.rpId && p.created === left.created;
      await opened.close();
      opened = null;
      if (ours) {
        if (left.attach) await engine.update(left.itemId, { remove_passkey: true }, found.rev);
        else await engine.remove(left.itemId);
      }
      leftovers.delete(left.key);
    } catch {
      await opened?.close().catch(() => {});
      if (!stopped) leftovers.delete(left.key);
      else keep({ ...left, inflight: null });
    }
  }

  /**
   * Follows a write up whose outcome the person was told no for: the same bytes under the same key until the server answers
   * for certain, then undone when it took it.
   * @param {Leftover} left
   */
  async function followUp(left) {
    keep(left);
    for (let attempt = 0; !stopped; attempt += 1) {
      const sent = sentOf(left.bytes);
      const outcome = left.inflight !== null ? await left.inflight : await send(left.itemId, left.bytes, sent);
      left.inflight = null;
      if (stopped) return;
      if (outcome.kind === "refused") {
        leftovers.delete(left.key);
        return;
      }
      if (outcome.kind === "accepted") {
        await undo(left);
        return;
      }
      await sleep(retryMs(attempt));
    }
  }

  /** What a request's bytes say about the write, to recognise it in a 409. @param {Uint8Array} bytes */
  const sentOf = (bytes) => {
    const body = JSON.parse(new TextDecoder().decode(bytes));
    return { baseRev: body.base_rev, blob: body.blob, tag: body.tag };
  };

  /**
   * Puts a folder on a new item after the server has it (an ordinary write through the engine).
   * @param {string} itemId @param {string} folder
   */
  async function addFolder(itemId, folder) {
    const found = await settle(itemId, 1);
    if (found === null || found.rev !== 1) return;
    await engine.update(itemId, { folders: [folder] }, 1).catch(() => {});
  }

  /**
   * The write of a new passkey (see the head of the file).
   * @param {{
   *   request: object, caller: object, uv: { user_present: boolean, user_verified: boolean }, stored: Array<{ rp_id: string, id: Uint8Array }>,
   *   name: string, folder?: string | null, attach?: { item_id: string, rev: number } | null, rpId: string,
   * }} args `request` is the core's create request; `stored` the vault's passkeys (scan); `rpId` the RP ID the core checked
   * @param {{ started?: () => void, wanted: () => boolean }} hooks `started`: the upload begins (the caller holds the
   *   deadline); `wanted`: whether the page still waits for this answer
   * @returns {Promise<{ kind: "accepted", response: any, undo: () => void } | { kind: "refused", reason: string } | { kind: "late" }>}
   */
  async function save(args, { started = () => {}, wanted }) {
    if (stopped) throw new PasskeyWriteError("vault_locked");
    if (engine.health().halted !== null) return { kind: "refused", reason: "network" };
    const createdAt = now();
    /** @type {{ handle: number, view: any, close(): Promise<void> } | null} */
    let target = null;
    /** @type {number | null} */
    let pending = null;
    /** @type {number | null} */
    let confirmed = null;
    try {
      const attach = args.attach ?? null;
      let itemId;
      let baseRev = 0;
      if (attach !== null) {
        target = await engine.open(attach.item_id);
        const current = items().find((s) => s.id === attach.item_id);
        if (!current || current.rev !== attach.rev || !attachable(current) || target.view?.passkey) return { kind: "refused", reason: "not_found" };
        itemId = attach.item_id;
        baseRev = attach.rev;
      } else {
        itemId = hex(16);
      }
      const made = await vault.passkey_create(
        Uint8Array.from(itemId.match(/../g) ?? [], (h) => parseInt(h, 16)),
        baseRev + 1,
        args.name,
        args.request,
        args.caller,
        args.uv,
        args.stored.length > 0 ? args.stored : "no_existing",
        createdAt,
        target?.handle,
      );
      pending = made.pending;
      const restore = await epoch();
      const sent = { baseRev, blob: b64u.encode(made.item.envelope), tag: b64u.encode(made.item.tag) };
      const idem = hex(16);
      const bytes = encodeWireBytes("put_item_req", { base_rev: baseRev, blob: sent.blob, tag: sent.tag, idem, ...(restore === null ? {} : { restore_epoch: restore }) });
      /** @type {Leftover} */
      const left = {
        key: idem, scope, itemId, baseRev, rev: baseRev + 1, rpId: args.rpId, created: createdAt, attach: attach !== null, bytes,
        folder: attach === null ? (args.folder ?? null) : null, inflight: null,
      };

      // A page that stopped waiting while the passkey was made gets nothing, and nothing is sent.
      if (stopped || !wanted()) return { kind: "late" };
      started();
      const until = now() + saveMs;
      /** @type {Outcome} */
      let outcome = { kind: "unknown" };
      for (let attempt = 0; ; attempt += 1) {
        const left_ms = until - now();
        if (left_ms <= 0) break;
        const flight = send(itemId, bytes, sent);
        const answer = await within(flight, left_ms);
        if (answer === null) {
          left.inflight = flight;
          break;
        }
        outcome = answer;
        if (outcome.kind !== "unknown") break;
        const wait = Math.min(retryMs(attempt), until - now());
        if (wait <= 0) break;
        await sleep(wait);
      }

      if (outcome.kind === "refused") {
        return { kind: "refused", reason: outcome.reason };
      }
      if (outcome.kind === "unknown") {
        // No certain answer in time: a no for the person; the write is followed up.
        void followUp(left);
        return { kind: "refused", reason: "network" };
      }
      if (stopped || !wanted()) {
        void undo(left);
        return { kind: "late" };
      }
      /** @type {any} */
      let done;
      try {
        done = await vault.passkey_create_confirm(pending);
      } catch (error) {
        // The server has it and the page cannot get it: undone like a late one.
        void undo(left);
        throw error;
      }
      pending = null;
      confirmed = attach === null && Number.isSafeInteger(done?.handle) ? done.handle : null;
      // The engine brings the new revision in; a folder the person chose follows as an ordinary write.
      if (left.folder !== null) void addFolder(itemId, left.folder);
      else void Promise.resolve(engine.syncNow()).catch(() => {});
      return { kind: "accepted", response: done.response, undo: () => void undo(left) };
    } finally {
      if (pending !== null) await Promise.resolve(vault.passkey_create_abort(pending)).catch(() => {});
      if (confirmed !== null) await Promise.resolve(vault.close_item(confirmed)).catch(() => {});
      await target?.close().catch(() => {});
    }
  }

  // The follow-ups an earlier unlock of this account left go on now.
  for (const left of [...leftovers.values()]) {
    if (left.scope === scope) void followUp({ ...left, inflight: null });
  }

  return Object.freeze({
    scan,
    save,
    /** Whether a write can be made now: the engine runs and is not stopped by the server's state. */
    ready: () => {
      if (stopped) return false;
      try {
        return engine.health().halted === null;
      } catch {
        return false;
      }
    },
    /** The vault locked or the sync stopped: nothing more is sent from here (the follow-ups stay with the sync). */
    stop() {
      stopped = true;
      for (const id of waits) timers.clearTimeout(id);
      waits.clear();
    },
  });
}
