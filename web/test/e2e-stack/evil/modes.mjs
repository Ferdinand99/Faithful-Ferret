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
//   gone                  410 for /changes with since > 0          a full reconciliation
//   fake_tombstone {id}   live row -> tombstone, rev + 1,          quarantine
//                         40 random bytes
//   seq_lie {latest_seq}  latest_seq rewritten                     lower: rollback_suspected;
//                                                                  higher: a known gap
//   rollback {at}         the state seen at the time `at`          rollback_suspected, nothing to accept
//   fork {sid}            one session gets a frozen state          no warning
//   forge_checkpoint      one byte of mac (or entries) flipped     checkpoint_forged, uploads go on
//   drop_checkpoint_head  `checkpoint` left out of /changes        no warning
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
    case "gone":
      only(rest, ["min_valid_since"]);
      return { mode, params: rest.min_valid_since === undefined ? {} : { min_valid_since: u53("min_valid_since", rest.min_valid_since, 1) } };
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
 * @typedef {{ mode: string, params: Record<string, any>, since: number, fakes: Map<string, string> }} Active
 */

/**
 * Makes a parsed mode active: the time it was switched on is kept (the fork
 * freezes the state of that moment).
 * @param {{ mode: string, params: Record<string, any> }} parsed
 * @param {{ now: () => number }} recorder
 * @returns {Active}
 */
export function activate(parsed, recorder) {
  return { mode: parsed.mode, params: parsed.params, since: recorder.now(), fakes: new Map() };
}

/** The honest mode. @param {{ now: () => number }} recorder */
export const honest = (recorder) => activate({ mode: "honest", params: {} }, recorder);

/** Whether a session cookie is the one a `sid` parameter names. @param {string | null} cookie @param {string} sid */
export const sessionMatches = (cookie, sid) => cookie !== null && cookie.startsWith(sid);

// ---------------------------------------------------------------- the lies

const rowsKey = (/** @type {string} */ route) => (route === "changes" ? "changes" : "items");

/**
 * The 410 of the mode `gone`, before the real server is asked. Only for
 * `/changes` with `since` above 0; the floor it names is above `since` (a floor
 * at or below it would make no sense), or `min_valid_since` when that is given.
 * @param {Active} active
 * @param {{ route: string, query: URLSearchParams }} req
 * @param {{ top: () => number }} recorder
 * @returns {{ status: number, json: object } | null}
 */
export function preempt(active, req, recorder) {
  if (active.mode !== "gone" || req.route !== "changes") return null;
  const raw = req.query.get("since");
  if (raw === null || !/^[0-9]{1,16}$/.test(raw)) return null;
  const since = Number(raw);
  if (since === 0) return null;
  const floor = Math.max(active.params.min_valid_since ?? 0, since + 1, recorder.top() + 1);
  return { status: 410, json: { error: "gone", min_valid_since: floor } };
}

/**
 * The lie for one answer of the real server (status 200, parsed). `null` means
 * that the answer stays as it is, byte for byte.
 * @param {Active} active
 * @param {ReturnType<typeof import("./recorder.mjs").createRecorder>} recorder
 * @param {{ route: string, query: URLSearchParams, sid: string | null }} req
 * @param {any} up the real answer
 * @param {(n: number) => Uint8Array} [random]
 * @returns {object | null}
 */
export function shape(active, recorder, req, up, random = randomBytes) {
  if (up === null || typeof up !== "object") return null;
  const { route } = req;
  switch (active.mode) {
    case "swap_blobs":
      return rewriteRows(route, up, (rows) => swapBlobs(rows, active.params.a, active.params.b, recorder));
    case "replay_old":
      return rewriteRows(route, up, (rows) => replayOld(rows, active.params.id, recorder));
    case "hide":
      return rewriteRows(route, up, (rows) => {
        const kept = rows.filter((r) => r.id !== active.params.id);
        return kept.length === rows.length ? null : kept;
      });
    case "fake_tombstone":
      return rewriteRows(route, up, (rows) => fakeTombstone(rows, active, random));
    case "seq_lie":
      return route === "changes" && "latest_seq" in up && up.latest_seq !== active.params.latest_seq ? { ...up, latest_seq: active.params.latest_seq } : null;
    case "rollback":
      return viewAnswer(route, req, up, recorder.viewAt(active.params.at));
    case "fork":
      return sessionMatches(req.sid, active.params.sid) ? viewAnswer(route, req, up, recorder.viewAt(active.since, req.sid)) : null;
    case "forge_checkpoint":
      return forgeCheckpoint(route, up, active.params.field);
    case "drop_checkpoint_head":
      return route === "changes" && "checkpoint" in up ? omit(up, "checkpoint") : null;
    default:
      return null;
  }
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
 */
function viewAnswer(route, req, up, view) {
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
    if (view.head) out.checkpoint = { seq: view.head.seq, digest: view.head.digest, mac: view.head.mac };
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
    // Only a checkpoint whose entries were seen can be replayed; without one the real answer stays.
    const c = view.checkpoint;
    return c ? { seq: c.seq, digest: c.digest, mac: c.mac, entries: c.entries } : null;
  }
  return null;
}
