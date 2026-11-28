// The web vault's sync, bound to the account that is unlocked in the tab (spec Fase 1 § 8.8, "Two accounts in one
// browser").
//
// The web vault's session is the cookie of the browser profile, and every tab of the profile shares it. When another tab
// signs in as another account, the server ends the session row the old cookie named and the browser keeps the new
// cookie: a tab that is still open never sees a 401, because its next request carries the other account's cookie. The
// server takes the vault from the session (a write names no vault or account), so a write of that tab would be stored
// in the other account's vault, and the tab would read the other account's feed as its own.
//
// So every request of the tab's sync engine is made only while the session of the profile is the unlocked account's,
// and its answer is used only when the session is still that account's after it: `GET /api/auth/session` must name
// `accountId` before and after the request (requests that start together share the check before them, see
// `REUSE_MS`; the check after a request is always one that started after its answer). When it names another account,
// `onOther` is told once (the caller stops the engine and locks the tab), the request fails as `401 session_other_account`, and every later
// request fails the same way without reaching the server. What waits in the outbox stays there, and goes to the
// account's own vault after its next sign-in. A session that has ended (401) or a network failure is the request's own
// failure, as before.
//
// One short race is left: a sign-in in another tab between the check and the request. The check after the request
// then fails, so the tab does not count the write as delivered: it stays in the outbox and is sent to the account's own
// vault later, and the other account's vault may hold a row that no device of it can open (marked damaged there). Only
// a binding on the server closes that (the client names the vault on each write), which is a wire change for a later
// delivery.
import { ApiError } from "../api.mjs";

/** The session info of the browser. */
export const SESSION_PATH = "/api/auth/session";

/** The code of a request that was not made, or whose answer was not used, because the session is another account's. */
export const SESSION_OTHER_ACCOUNT = "session_other_account";

/** The methods of the API client that make a request the sync engine uses. */
const METHODS = Object.freeze(["get", "put", "post", "delete"]);

/**
 * How old a check that is still on its way may be for a request to wait for it as its check before (ms): requests that
 * start together (the lanes of the outbox) share one. A check that has ended is never reused, and the check after a
 * request is always one that started after its answer.
 */
export const REUSE_MS = 1_000;

/**
 * The API client of a tab's sync engine, bound to the unlocked account.
 * @param {{ get(path: string, options?: { shape?: string }): Promise<any> } & Record<string, any>} api the page's API client
 * @param {string} accountId the unlocked account
 * @param {() => void} onOther told once, the first time the session is found to be another account's
 * @param {{ now?: () => number }} [options] `now` is for tests (a fake clock)
 * @returns {{ api: any, confirm(): Promise<void>, other(): boolean }}
 *   `api` is the client to hand the engine; `confirm` checks the session once (the live channel calls it after each
 *   connection); `other` says whether the session was found to be another account's.
 */
export function sessionBoundApi(api, accountId, onOther, { now = Date.now } = {}) {
  if (typeof accountId !== "string" || accountId === "") throw new TypeError("sessionBoundApi needs the unlocked account");
  let other = false;
  const refused = () => new ApiError(401, SESSION_OTHER_ACCOUNT);
  /** How many checks have started. */
  let started = 0;
  /**
   * The newest check: its number, when it started, its promise, and whether it passed (null while it runs).
   * @type {{ id: number, at: number, done: Promise<void>, ok: boolean | null } | null}
   */
  let newest = null;

  async function ask() {
    if (other) throw refused();
    const info = await api.get(SESSION_PATH, { shape: "session_res" });
    if (other) throw refused();
    if (info?.account_id !== accountId) {
      other = true;
      try {
        onOther();
      } catch {
        // The caller's reaction must not keep the refusal from being thrown.
      }
      throw refused();
    }
  }

  /**
   * A check of the session that started after check number `after` and no earlier than `since` (ms): the newest one when it
   * qualifies and is still on its way, otherwise a new one.
   * @param {number} after
   * @param {number} since
   * @returns {Promise<void>}
   */
  function check(after, since) {
    if (other) return Promise.reject(refused());
    const last = newest;
    if (last !== null && last.ok === null && last.id > after && last.at >= since) return last.done;
    started += 1;
    /** @type {{ id: number, at: number, done: Promise<void>, ok: boolean | null }} */
    const one = { id: started, at: now(), done: Promise.resolve(), ok: null };
    one.done = ask().then(
      () => {
        one.ok = true;
      },
      (error) => {
        one.ok = false;
        throw error;
      },
    );
    newest = one;
    return one.done;
  }

  /** A new check (the live channel's, after a connection). */
  const confirm = () => check(started, Number.NEGATIVE_INFINITY);

  /** @type {Record<string, any>} */
  const bound = Object.create(api);
  for (const method of METHODS) {
    if (typeof api[method] !== "function") continue;
    bound[method] = async (/** @type {unknown[]} */ ...args) => {
      await check(0, now() - REUSE_MS);
      const answer = await api[method](...args);
      // Only a check that starts after the answer says whose session the answer was read in.
      await check(started, Number.NEGATIVE_INFINITY);
      return answer;
    };
  }
  return { api: bound, confirm, other: () => other };
}
