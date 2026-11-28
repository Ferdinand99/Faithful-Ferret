// The account log as the web vault reads it (`GET /api/account/events`, spec Fase 1 § 11
// "Several accounts"): what was done to the account by an administrator, by a command on the
// server, by the server itself (a restore), and the sign-in codes the account redeemed.
//
// Two places use it. The page "Activity" lists the log, newest first, a page at a time. The
// notice at an unlock tells the events caused by an administrator, the server command or the
// server since this browser last showed "Activity"; a browser that has shown none starts at the
// newest event, so an account's own creation is no notice. What was last shown is a mark of
// this browser and this account (`store/activitySeen.mjs`), and only "Activity" moves it.
//
// The ids of the log can go backwards: the server's table has no AUTOINCREMENT, so after a
// restore from a backup set the new ids continue from the set's newest event, which can be at or
// below an id this browser saw before. `reconcileSeen` starts the mark again when it sees a
// `server_restored` that is newer than the mark (by its id or its time), and when the newest id
// is below the mark with no such restore in sight.
//
// The answer names no account: whose log it is follows from the session of the browser profile,
// and another tab that signs in as another account changes that session under a tab that is open.
// So a page of the log is used only when the session is the unlocked account's both before and
// after it was read (`accountId`); otherwise it is refused as `unauthorized`, and nothing of it is
// shown or kept.
//
// Nothing here is secret: an event is an id, a time, a kind, an actor and an administrator's
// e-mail. No code and no token is ever part of it.
import { ApiError } from "../api.mjs";
import { hex16 } from "../b64.mjs";
import { checkStep, MAX_EVENTS_PAGE } from "../wire.mjs";

/** The address of the account log. */
export const EVENTS_PATH = "/api/account/events";

/** The kinds of delivery 1; any other kind is "Other event" on the page. */
export const EVENT_KINDS = Object.freeze([
  "account_created", "sign_in_code_issued", "sign_in_code_redeemed", "account_disabled", "account_enabled", "signed_out_everywhere", "server_restored",
]);

/** The actors whose events are a notice: everything that the account did not do itself. */
export const NOTICE_ACTORS = Object.freeze(["admin", "server_command", "server"]);

/** The events of one page when the caller names no limit (the server's own default). */
const DEFAULT_PAGE = 50;

/** The session info of the browser. */
const SESSION_PATH = "/api/auth/session";

/**
 * One event of the log, as the server sends it (`account_events_res`).
 * @typedef {{ id: number, at: number, kind: string, actor: "admin" | "server_command" | "server" | "account", actor_name: string }} AccountEvent
 * @typedef {import("../store/activitySeen.mjs").SeenMark} SeenMark
 * @typedef {{ load(): Promise<SeenMark | null>, save(mark: SeenMark): Promise<void> }} SeenStore the mark of this browser and account
 */

/** @param {unknown} value */
const positive = (value) => typeof value === "number" && Number.isSafeInteger(value) && value > 0;

/**
 * The session of the browser is a full session of `accountId`, or `unauthorized`.
 * @param {{ get(path: string, options?: { shape?: string }): Promise<any> }} api
 * @param {string} accountId
 */
async function sessionIs(api, accountId) {
  const info = await api.get(SESSION_PATH, { shape: "session_res" });
  if (info?.account_id !== accountId) throw new ApiError(401, "unauthorized");
}

/**
 * One page of the log: the newest events, or those below `before` (the oldest id shown so far).
 * The answer is checked against the wire shape and must be newest first, every id below `before`.
 * With `accountId` (the unlocked account), the session of the browser must be that account's before and after the page
 * is read (see the top of this file); otherwise it is `unauthorized`.
 * @param {{ get(path: string, options?: { shape?: string }): Promise<any> }} api
 * @param {{ before?: number, limit?: number, accountId?: string }} [options]
 * @returns {Promise<{ events: AccountEvent[], more: boolean }>}
 */
export async function loadEvents(api, { before, limit = DEFAULT_PAGE, accountId } = {}) {
  if (before !== undefined && !positive(before)) throw new TypeError("before is the id of an event");
  if (!positive(limit) || limit > MAX_EVENTS_PAGE) throw new TypeError("a page of the account log has 1 to 100 events");
  if (accountId !== undefined && !hex16.is(accountId)) throw new TypeError("accountId is 32 hexadecimal characters");
  const path = before === undefined ? `${EVENTS_PATH}?limit=${limit}` : `${EVENTS_PATH}?limit=${limit}&before=${before}`;
  if (accountId !== undefined) await sessionIs(api, accountId);
  const answer = await api.get(path, { shape: "account_events_res" });
  if (accountId !== undefined) await sessionIs(api, accountId);
  checkStep("account_events_res", answer);
  /** @type {AccountEvent[]} */
  const events = answer.events;
  let above = before ?? Number.MAX_SAFE_INTEGER + 1;
  for (const event of events) {
    if (event.id >= above) throw new ApiError(200, "bad_response");
    above = event.id;
  }
  return { events, more: answer.more === true };
}

/**
 * The events of a notice: those after `lastSeenId` that an administrator, the server command or the server caused.
 * @param {readonly AccountEvent[]} events newest first
 * @param {number} lastSeenId
 * @returns {AccountEvent[]}
 */
export function unseenAdminEvents(events, lastSeenId) {
  return events.filter((event) => event.id > lastSeenId && NOTICE_ACTORS.includes(event.actor));
}

/**
 * The mark of a page that was shown: its newest event, or 0 and 0 for an empty log.
 * @param {readonly AccountEvent[]} events newest first
 * @returns {SeenMark}
 */
export function markOf(events) {
  const newest = events[0];
  return newest === undefined ? { id: 0, at: 0 } : { id: newest.id, at: newest.at };
}

/**
 * The last-seen id to count a notice from, and the mark to keep when it changed (else null).
 *
 * - No mark: the newest event (a browser that has shown nothing starts there), and that is kept.
 * - A `server_restored` newer than the mark (an id above it, or a time after it): the ids may have gone
 *   backwards, so everything from the oldest such restore on counts, and nothing seen before it.
 * - Otherwise the newest id below the mark: the log was replaced, so the browser starts again at the newest event.
 * @param {readonly AccountEvent[]} events newest first
 * @param {SeenMark | null} stored
 * @returns {{ lastSeenId: number, save: SeenMark | null }}
 */
export function reconcileSeen(events, stored) {
  if (stored === null) {
    const start = markOf(events);
    return { lastSeenId: start.id, save: start };
  }
  const restores = events.filter((event) => event.kind === "server_restored" && (event.id > stored.id || event.at > stored.at));
  if (restores.length > 0) {
    const oldest = Math.min(...restores.map((event) => event.id));
    const lastSeenId = Math.min(stored.id, oldest - 1);
    return { lastSeenId, save: lastSeenId === stored.id ? null : { id: lastSeenId, at: stored.at } };
  }
  const newest = events[0];
  if (newest !== undefined && newest.id < stored.id) return { lastSeenId: newest.id, save: markOf(events) };
  return { lastSeenId: stored.id, save: null };
}

/**
 * The events of the notice at an unlock: the newest page of the log against the mark of this browser. A mark that
 * starts (or starts again) is kept; the notice never moves it otherwise. With `accountId`, the log must be that
 * account's (see `loadEvents`).
 * @param {{ api: Parameters<typeof loadEvents>[0], seen: SeenStore, accountId?: string }} options
 * @returns {Promise<AccountEvent[]>}
 */
export async function noticeEvents({ api, seen, accountId }) {
  const { events } = await loadEvents(api, accountId === undefined ? { limit: MAX_EVENTS_PAGE } : { limit: MAX_EVENTS_PAGE, accountId });
  const { lastSeenId, save } = reconcileSeen(events, await seen.load());
  if (save !== null) await seen.save(save);
  return unseenAdminEvents(events, lastSeenId);
}

/**
 * "Activity" was shown: the mark moves to the newest event of its first page.
 * @param {Pick<SeenStore, "save">} seen
 * @param {readonly AccountEvent[]} events the first page, newest first
 */
export async function markSeen(seen, events) {
  await seen.save(markOf(events));
}

/** The notice of each unlock (each unlock is a new `current()` object): asked once, not on every page. @type {WeakMap<object, Promise<AccountEvent[]>>} */
const perUnlock = new WeakMap();

/**
 * The notice of this unlock, computed once. A check that fails gives no notice and is asked again at the next page.
 * @param {object} open the unlocked session's `current()`
 * @param {() => Promise<AccountEvent[]>} compute
 * @returns {Promise<AccountEvent[]>}
 */
export function noticeOnce(open, compute) {
  const known = perUnlock.get(open);
  if (known !== undefined) return known;
  /** @type {Promise<AccountEvent[]>} */
  const asked = compute().catch(() => {
    if (perUnlock.get(open) === asked) perUnlock.delete(open);
    return [];
  });
  perUnlock.set(open, asked);
  return asked;
}

/**
 * "Activity" is shown: this unlock has no notice any more.
 * @param {object} open the unlocked session's `current()`
 */
export function clearNotice(open) {
  perUnlock.set(open, Promise.resolve([]));
}
