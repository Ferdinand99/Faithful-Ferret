// The lies of the malicious server in the end-to-end stack. A mode is a pure
// reshaping of the JSON that the real server sent for `/api/sync/changes`,
// `/api/sync/items` and `/api/sync/checkpoint` on the vault host; nothing else
// is touched. The real server's answer is always the starting point, so the lie
// is a lie about what the real server holds.
//
//   mode                  what the proxy does                      what the client should do
//   honest                the bytes, unchanged (the default)       nothing
//   swap_blobs {a, b}     blob and tag swapped between two items   row_damaged
//   replay_old {id}       the first version that was seen          rev_lower_than_local; on a new device
//                                                                  server_shows_older_state
//   hide {id}             the item's rows left out                 with `gone`: missing_on_server,
//                                                                  re-upload, 409 -> server_hid_item
//   gone [{min_valid_since, hide}]
//                         410 for /changes with 0 < since < floor  a full reconciliation; with `hide` the
//                         (see below); with `hide`, that item is     item is also left out of what follows
//                         left out of every answer as in hide      (the K40 order: 410, a listing without
//                                                                  the item, then a 409 with an equal blob)
//   fake_tombstone {id}   live row -> tombstone, rev + 1,          quarantine
//                         40 random bytes
//   seq_lie {latest_seq}  latest_seq rewritten                     lower: rollback_suspected;
//                                                                  higher: a known gap
//   rollback {at}         the state seen at the time `at`          rollback_suspected, nothing to accept
//   fork {sid}            one session gets a frozen state          no warning
//   forge_checkpoint      one byte of mac (or entries) flipped     checkpoint_forged, uploads go on
//   drop_checkpoint_head  `checkpoint` left out of /changes        no warning
//
// The floor of `gone` is fixed when the mode is switched on: `min_valid_since` when it is
// given, else the highest sequence number the proxy has seen (the real server answers
// 410 only when `since != 0 && since < floor`). A client that resumes from the
// `as_of_seq` of its listing therefore settles, unless the floor that was asked for is
// above that `as_of_seq`: then the second 410 ends the pass in `gone`. A client that
// is caught up is only sent into a full reconciliation by a floor above its cursor.
//
// `fork` also keeps the forked session's own `PUT /api/sync/checkpoint` in the session's own
// branch: it is answered 200 (409 `checkpoint_stale` for a lower seq than the branch holds)
// and never sent on to the real server.
//
// `GET /api/sync/checkpoint` is answered 404 in `rollback` and `fork` when the state
// they show holds no checkpoint (a checkpoint that was never seen cannot be shown).
//
// `at` is a time in milliseconds on the proxy's clock (the control port tells
// it: GET /recorded). `sid` is the value of the session cookie
// (`__Host-ferret_sid`) of the session, or its first 8 characters or more.
//
// Test rig only: it lives in the end-to-end stack and in no production image.
import { randomBytes } from "node:crypto";
import { rowOf } from "./recorder.mjs";

export const MODE_NAMES = Object.freeze([
  "honest",
  "swap_blobs",
  "replay_old",
  "hide",
  "gone",
  "fake_tombstone",
  "seq_lie",
  "rollback",
  "fork",
  "forge_checkpoint",
  "drop_checkpoint_head",
]);

/** A mode or a parameter that is not allowed. */
export class ModeError extends Error {}

const ID = /^[0-9a-f]{32}$/;
const SID = /^[A-Za-z0-9_-]{8,200}$/;

/** @param {string} name @param {unknown} value */
function item(name, value) {
  if (typeof value !== "string" || !ID.test(value)) throw new ModeError(`${name} must be an item id (32 lower case hex digits)`);
  return value;
}

/** @param {string} name @param {unknown} value @param {number} min */
function u53(name, value, min = 0) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min) throw new ModeError(`${name} must be an integer of at least ${min}`);
  return value;
}

/** @param {Record<string, unknown>} given @param {string[]} allowed */
function only(given, allowed) {
  for (const key of Object.keys(given)) if (!allowed.includes(key)) throw new ModeError(`unknown parameter ${key}`);
}

/**
 * Checks `{mode, ...params}` and returns the mode with its own parameters.
 * @param {unknown} input
 * @returns {{ mode: string, params: Record<string, any> }}
 */
export function parseMode(input) {
  if (input === null || typeof input !== "object" || Array.isArray(input)) throw new ModeError("the body must be a JSON object with a mode");
  const { mode, ...rest } = /** @type {Record<string, any>} */ (input);
  if (typeof mode !== "string" || !MODE_NAMES.includes(mode)) throw new ModeError(`unknown mode (one of ${MODE_NAMES.join(", ")})`);
  switch (mode) {
    case "swap_blobs": {
      only(rest, ["a", "b"]);
      const a = item("a", rest.a);
      const b = item("b", rest.b);
      if (a === b) throw new ModeError("a and b must be two items");
      return { mode, params: { a, b } };
    }
    case "replay_old":
    case "hide":
    case "fake_tombstone":
      only(rest, ["id"]);
      return { mode, params: { id: item("id", rest.id) } };
    case "gone": {
      only(rest, ["min_valid_since", "hide"]);
      /** @type {Record<string, any>} */
      const params = {};
      if (rest.min_valid_since !== undefined) params.min_valid_since = u53("min_valid_since", rest.min_valid_since, 1);
      if (rest.hide !== undefined) params.hide = item("hide", rest.hide);
      return { mode, params };
    }
    case "seq_lie":
      only(rest, ["latest_seq"]);
      return { mode, params: { latest_seq: u53("latest_seq", rest.latest_seq) } };
    case "rollback":
      only(rest, ["at"]);
      return { mode, params: { at: u53("at", rest.at) } };
    case "fork":
      only(rest, ["sid"]);
      if (typeof rest.sid !== "string" || !SID.test(rest.sid)) throw new ModeError("sid must be the session cookie (8 characters or more)");
      return { mode, params: { sid: rest.sid } };
    case "forge_checkpoint": {
      only(rest, ["field"]);
      const field = rest.field ?? "mac";
      if (field !== "mac" && field !== "entries") throw new ModeError('field must be "mac" or "entries"');
      return { mode, params: { field } };
    }
    default:
      only(rest, []);
      return { mode, params: {} };
  }
}

/**
 * @typedef {{ seq: number, digest: string, mac: string, entries: string }} Branch a checkpoint of a forked session
 * @typedef {{ mode: string, params: Record<string, any>, since: number, floor: number, fakes: Map<string, string>, branch: Branch[] }} Active
 */

/**
 * Makes a parsed mode active: the time it was switched on is kept (the fork
 * freezes the state of that moment), and so is the floor of `gone`.
 * @param {{ mode: string, params: Record<string, any> }} parsed
 * @param {{ now: () => number, top: () => number }} recorder
 * @returns {Active}
 */
export function activate(parsed, recorder) {
  const floor = parsed.mode === "gone" ? (parsed.params.min_valid_since ?? recorder.top()) : 0;
  return { mode: parsed.mode, params: parsed.params, since: recorder.now(), floor, fakes: new Map(), branch: [] };
}

/** The honest mode. */
export const honest = (/** @type {{ now: () => number, top: () => number }} */ recorder) => activate({ mode: "honest", params: {} }, recorder);

/** Whether a session cookie is the one a `sid` parameter names. @param {string | null} cookie @param {string} sid */
export const sessionMatches = (cookie, sid) => cookie !== null && cookie.startsWith(sid);

// ---------------------------------------------------------------- the lies

const rowsKey = (/** @type {string} */ route) => (route === "changes" ? "changes" : "items");

/**
 * The 410 of the mode `gone`, before the real server is asked: for `/changes`
 * with `since != 0 && since < floor`, as the real server does. The floor was fixed
 * when the mode was switched on.
 * @param {Active} active
 * @param {{ route: string, query: URLSearchParams }} req
 * @returns {{ status: number, json: object } | null}
 */
export function preempt(active, req) {
  if (active.mode !== "gone" || req.route !== "changes") return null;
  const raw = req.query.get("since");
  if (raw === null || !/^[0-9]{1,16}$/.test(raw)) return null;
  const since = Number(raw);
  if (since === 0 || since >= active.floor) return null;
  return { status: 410, json: { error: "gone", min_valid_since: active.floor } };
}

/**
 * A `PUT /api/sync/checkpoint` of a forked session: kept in the session's own branch and
 * answered 200, never sent on. `null` means that the request goes on to the real server
 * (another mode, another session, a body that is not a checkpoint).
 * @param {Active} active
 * @param {{ sid: string | null }} req
 * @param {any} body the parsed request body
 * @returns {{ status: number, json: object } | null}
 */
export function interceptCheckpointPut(active, req, body) {
  if (active.mode !== "fork" || !sessionMatches(req.sid, active.params.sid)) return null;
  const text = (/** @type {unknown} */ v) => typeof v === "string" && v.length > 0;
  if (!body || !Number.isSafeInteger(body.seq) || body.seq < 0 || !text(body.digest) || !text(body.mac) || !text(body.entries)) return null;
  const held = active.branch.reduce((m, c) => Math.max(m, c.seq), 0);
  if (body.seq < held) return { status: 409, json: { error: "checkpoint_stale", stored_seq: held } };
  active.branch.push({ seq: body.seq, digest: body.digest, mac: body.mac, entries: body.entries });
  return { status: 200, json: { seq: body.seq } };
}

/**
 * The lie for one answer of the real server (status 200, parsed). `null` means
 * that the answer stays as it is, byte for byte.
 * @param {Active} active
 * @param {ReturnType<typeof import("./recorder.mjs").createRecorder>} recorder
 * @param {{ route: string, query: URLSearchParams, sid: string | null }} req
 * @param {any} up the real answer
 * @param {(n: number) => Uint8Array} [random]
 * @returns {{ status: number, json: object } | null}
 */
export function shape(active, recorder, req, up, random = randomBytes) {
  if (up === null || typeof up !== "object") return null;
  const lie = lieFor(active, recorder, req, up, random);
  if (lie === null) return null;
  return "status" in lie && "json" in lie ? /** @type {any} */ (lie) : { status: 200, json: lie };
}

/** @returns {object | null} the new JSON, or `{ status, json }` for another status */
function lieFor(/** @type {Active} */ active, /** @type {any} */ recorder, /** @type {any} */ req, /** @type {any} */ up, /** @type {any} */ random) {
  const { route } = req;
  switch (active.mode) {
    case "gone":
      // The 410 itself is `preempt`; the item that is hidden stays hidden in everything that follows.
      return active.params.hide ? rewriteRows(route, up, (rows) => withoutItem(rows, active.params.hide)) : null;
    case "swap_blobs":
      return rewriteRows(route, up, (rows) => swapBlobs(rows, active.params.a, active.params.b, recorder));
    case "replay_old":
      return rewriteRows(route, up, (rows) => replayOld(rows, active.params.id, recorder));
    case "hide":
      return rewriteRows(route, up, (rows) => withoutItem(rows, active.params.id));
    case "fake_tombstone":
      return rewriteRows(route, up, (rows) => fakeTombstone(rows, active, random));
    case "seq_lie":
      return route === "changes" && "latest_seq" in up && up.latest_seq !== active.params.latest_seq ? { ...up, latest_seq: active.params.latest_seq } : null;
    case "rollback":
      return viewAnswer(route, req, up, recorder.viewAt(active.params.at));
    case "fork":
      return sessionMatches(req.sid, active.params.sid) ? viewAnswer(route, req, up, recorder.viewAt(active.since, req.sid), active.branch) : null;
    case "forge_checkpoint":
      return forgeCheckpoint(route, up, active.params.field);
    case "drop_checkpoint_head":
      return route === "changes" && "checkpoint" in up ? omit(up, "checkpoint") : null;
    default:
      return null;
  }
}

/** @param {any[]} rows @param {string} id */
function withoutItem(rows, id) {
  const kept = rows.filter((r) => r.id !== id);
  return kept.length === rows.length ? null : kept;
}

/** @param {object} o @param {string} key */
function omit(o, key) {
  const { [key]: _gone, ...rest } = /** @type {Record<string, any>} */ (o);
  return rest;
}

/**
 * Applies `fn` to the rows of a `/changes` or `/items` answer. `fn` returns the
 * new rows, or `null` for no change.
 * @param {string} route @param {any} up @param {(rows: any[]) => any[] | null} fn
 */
function rewriteRows(route, up, fn) {
  if (route !== "changes" && route !== "items") return null;
  const key = rowsKey(route);
  if (!Array.isArray(up[key])) return null;
  const rows = fn(up[key]);
  return rows === null ? null : { ...up, [key]: rows };
}

/** @param {any[]} rows @param {string} a @param {string} b @param {ReturnType<typeof import("./recorder.mjs").createRecorder>} recorder */
function swapBlobs(rows, a, b, recorder) {
  const live = (/** @type {any} */ r) => r && r.deleted === false && typeof r.blob === "string" && typeof r.tag === "string";
  // The other item's body: the row in this very answer, else the newest one seen.
  const bodyOf = (/** @type {string} */ id) => {
    const here = rows.find((r) => r.id === id);
    if (live(here)) return { blob: here.blob, tag: here.tag };
    const seen = here ? null : recorder.latest(id);
    return seen && !seen.deleted ? { blob: seen.blob, tag: seen.tag } : null;
  };
  const bodies = { [a]: bodyOf(a), [b]: bodyOf(b) };
  let changed = false;
  const out = rows.map((r) => {
    if (r.id !== a && r.id !== b) return r;
    const other = bodies[r.id === a ? b : a];
    if (!live(r) || !other || (other.blob === r.blob && other.tag === r.tag)) return r;
    changed = true;
    return { ...r, blob: other.blob, tag: other.tag };
  });
  return changed ? out : null;
}

/** @param {any[]} rows @param {string} id @param {ReturnType<typeof import("./recorder.mjs").createRecorder>} recorder */
function replayOld(rows, id, recorder) {
  const first = recorder.first(id);
  if (!first) return null;
  let changed = false;
  const out = rows.map((r) => {
    if (r.id !== id || (r.rev === first.rev && r.seq === first.seq)) return r;
    changed = true;
    // The old body and revision, at the place in the feed where the real row is.
    return rowOf({ ...first, seq: r.seq });
  });
  return changed ? out : null;
}

/** @param {any[]} rows @param {import("./modes.mjs").Active} active @param {(n: number) => Uint8Array} random */
function fakeTombstone(rows, active, random) {
  let changed = false;
  const out = rows.map((r) => {
    if (r.id !== active.params.id || r.deleted !== false) return r;
    // The same lie for the same row every time it is asked for.
    const key = `${r.id}:${r.rev}`;
    let tomb = active.fakes.get(key);
    if (tomb === undefined) {
      tomb = Buffer.from(random(40)).toString("base64url");
      active.fakes.set(key, tomb);
    }
    changed = true;
    return { id: r.id, rev: r.rev + 1, seq: r.seq, deleted: true, tomb };
  });
  return changed ? out : null;
}

/** @param {string} value one byte flipped @param {number} [index] */
export function flipByte(value, index = 0) {
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length === 0) return value;
  bytes[index % bytes.length] ^= 0xff;
  return bytes.toString("base64url");
}

/** @param {string} route @param {any} up @param {string} field */
function forgeCheckpoint(route, up, field) {
  if (route === "checkpoint") {
    return typeof up[field] === "string" ? { ...up, [field]: flipByte(up[field]) } : null;
  }
  // The head in /changes has no `entries`: the lie there is in the MAC.
  if (route === "changes" && up.checkpoint && typeof up.checkpoint.mac === "string" && field === "mac") {
    return { ...up, checkpoint: { ...up.checkpoint, mac: flipByte(up.checkpoint.mac) } };
  }
  return null;
}

const clampInt = (/** @type {string | null} */ raw, /** @type {number} */ fallback, /** @type {number} */ min, /** @type {number} */ max) => {
  if (raw === null || !/^[0-9]{1,16}$/.test(raw)) return fallback;
  return Math.min(max, Math.max(min, Number(raw)));
};

/**
 * The answer a vault in the recorded state would give: used by `rollback` and
 * `fork`. The epochs are the real ones (a rollback that is not a restore does
 * not change `restore_epoch`).
 * @param {string} route @param {{ query: URLSearchParams }} req @param {any} up
 * @param {ReturnType<ReturnType<typeof import("./recorder.mjs").createRecorder>["viewAt"]>} view
 * @param {Branch[]} [branch] checkpoints that a forked session uploaded itself
 */
function viewAnswer(route, req, up, view, branch = []) {
  const own = branch.reduce((/** @type {Branch | null} */ a, c) => (a === null || c.seq > a.seq ? c : a), null);
  const head = own && (!view.head || own.seq >= view.head.seq) ? own : view.head;
  const full = own && (!view.checkpoint || own.seq >= view.checkpoint.seq) ? own : view.checkpoint;
  if (route === "changes") {
    const since = clampInt(req.query.get("since"), 0, 0, Number.MAX_SAFE_INTEGER);
    const limit = clampInt(req.query.get("limit"), 100, 1, 500);
    const newer = view.rows.filter((v) => v.seq > since).sort((x, y) => x.seq - y.seq);
    /** @type {Record<string, any>} */
    const out = {
      changes: newer.slice(0, limit).map(rowOf),
      latest_seq: view.top,
      vk_epoch: up.vk_epoch,
      restore_epoch: up.restore_epoch,
    };
    if (head) out.checkpoint = { seq: head.seq, digest: head.digest, mac: head.mac };
    out.has_more = newer.length > limit;
    return out;
  }
  if (route === "items") {
    const after = req.query.get("after") ?? "";
    const limit = clampInt(req.query.get("limit"), 100, 1, 500);
    const rest = view.rows.filter((v) => v.id > after);
    const page = rest.slice(0, limit);
    /** @type {Record<string, any>} */
    const out = { items: page.map(rowOf), as_of_seq: view.top, vk_epoch: up.vk_epoch, restore_epoch: up.restore_epoch };
    if (rest.length > limit) out.next_after = page[page.length - 1].id;
    out.has_more = rest.length > limit;
    return out;
  }
  if (route === "checkpoint") {
    // Only a checkpoint whose entries were seen can be shown; a state without one has none (404),
    // and the real server's newer checkpoint is never let through.
    const c = full;
    return c ? { seq: c.seq, digest: c.digest, mac: c.mac, entries: c.entries } : { status: 404, json: { error: "not_found" } };
  }
  return null;
}
