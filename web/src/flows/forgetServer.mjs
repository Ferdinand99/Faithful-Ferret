// "Forget this server": the user's way out when this device no longer trusts a
// server, or when sync is stopped for good (spec Fase 1 section 8.6). It removes
// what this device remembers of the server and the account, and nothing on the
// server. The order matters:
//
//   1. count the writes that were never sent, and whether another address of the
//      server holds the same account (then its records stay), and ask (the
//      caller's `confirm` is given both); a "no" changes nothing;
//   2. tell the other tabs that it is going to happen, so that they lock and stop
//      their engines before anything is removed;
//   3. end the session at the server (best effort: the device is forgotten even
//      if the server cannot be reached), then lock, which stops the engine;
//   4. remove the account's records, inside the Web Lock of the sync memory so
//      that no tab is saving it meanwhile;
//   5. tell the other tabs that it is done (a tab that missed the first message,
//      or that started an engine meanwhile, stops now);
//   6. go to the sign-in page. The next sign-in finds no pinned record: it is a
//      first use again.
//
// What is not closed: a tab whose engine starts a save after the removal and
// before it has read either message would write a sync state again, without a
// pinned record. The two messages make that window a few milliseconds long.
import { hex16 } from "../b64.mjs";
import { serverKey } from "../store/idb.mjs";

/** The message the other tabs hear, first when the forgetting starts and again when it is done. @param {"forgetting" | "forgotten"} type @param {string} server @param {string} accountId */
const messageOf = (type, server, accountId) => ({ type, serverKey: server, accountId });

/**
 * @typedef {object} ForgetResult what the store removed
 * @property {Record<string, number>} removed records removed, by store
 * @property {true} [shared] another address of the server has the same account: the records kept per account stayed
 *
 * @typedef {{ postMessage(message: unknown): void, close?: () => void }} Channel
 */

/**
 * @param {{
 *   api: { post(path: string, body?: unknown): Promise<unknown> },
 *   session: { lock(): Promise<unknown>, forgetSecretKey(accountId: string): Promise<unknown> },
 *   store: {
 *     open(): Promise<any>,
 *     pendingWrites(db: any, accountId: string): Promise<number>,
 *     sharedAccount(db: any, serverUrl: string, accountId: string): Promise<boolean>,
 *     forgetServer(db: any, serverUrl: string, accountId: string): Promise<ForgetResult>,
 *   },
 *   serverUrl: string,
 *   accountId: string,
 *   confirm: (info: { pending: number, shared: boolean }) => Promise<boolean>,
 *   navigate: (hash: string, result: ForgetResult) => void,
 *   channel?: Channel | null,
 *   locks?: { request(name: string, callback: () => Promise<unknown>): Promise<any> },
 * }} options
 *   `channel` is where the other tabs are told; without one the page's `BroadcastChannel("ferret")` is used and closed again.
 *   `locks` is the page's Web Locks.
 * @returns {Promise<"forgotten" | "cancelled">}
 */
export async function forgetServer({
  api, session, store, serverUrl, accountId, confirm, navigate, channel,
  locks = /** @type {any} */ (globalThis).navigator?.locks,
}) {
  const server = serverKey(serverUrl);
  if (!hex16.is(accountId)) throw new TypeError("an account id is 32 lower-case hex characters");
  const db = await store.open();

  // 1. Unsent writes are the one thing this loses that the server does not have, unless another address keeps them.
  const pending = await store.pendingWrites(db, accountId);
  const shared = await store.sharedAccount(db, serverUrl, accountId);
  if ((await confirm({ pending, shared })) !== true) return "cancelled";

  const own = channel === undefined && typeof BroadcastChannel === "function" ? new BroadcastChannel("ferret") : null;
  const out = channel ?? own;
  /** @param {"forgetting" | "forgotten"} type */
  const tell = (type) => {
    try {
      out?.postMessage(messageOf(type, server, accountId));
    } catch {
      // A tab that is not told keeps what it has until its next lock.
    }
  };
  try {
    // 2. The other tabs stop first.
    tell("forgetting");

    // 3. The session at the server ends if it can; the vault locks either way.
    try {
      await api.post("/api/auth/logout");
    } catch {
      // The device is forgotten all the same; the server session ends by itself.
    }
    await session.lock();

    // 4. The same lock as every other write of the sync memory.
    const remove = () => store.forgetServer(db, serverUrl, accountId);
    /** @type {ForgetResult} */
    const result = locks && typeof locks.request === "function"
      ? await locks.request(`ferret-sync-memory:${server}:${accountId}`, remove)
      : await remove();
    // The record of the sealed secret key went with the rest; this is the account session's own way to say so.
    try {
      await session.forgetSecretKey(accountId);
    } catch {
      // Nothing is left to forget: the store has already removed it.
    }
    // 5. The other tabs again: it is done.
    tell("forgotten");

    // 6. Back to the sign-in page.
    navigate("#/login", result);
    return "forgotten";
  } finally {
    own?.close();
  }
}

/**
 * The account the forget page is about, or null when it has to ask. The open vault names
 * its own account; a vault that is locked has only what the server says, and the server
 * is not trusted to name an account: its id counts only when this device holds a record
 * for it, and the e-mail address the dialog shows is the one of that local record.
 * @param {{
 *   session: { current?: () => { accountId?: string } | null, info?: () => Promise<{ accountId: string } | null> },
 *   store: { open(): Promise<any>, loadPinnedAccount(db: any, serverUrl: string, accountId: string): Promise<{ email: string | null } | null> },
 *   serverUrl: string,
 * }} options
 * @returns {Promise<{ accountId: string, email: string | null } | null>}
 */
export async function resolveForgetTarget({ session, store, serverUrl }) {
  /** @type {unknown} */
  let id = session.current?.()?.accountId ?? null;
  if (id === null) {
    try {
      id = (await session.info?.())?.accountId ?? null;
    } catch {
      id = null; // the server cannot be asked: the account is asked for instead
    }
  }
  if (!hex16.is(id)) return null;
  const local = await store.loadPinnedAccount(await store.open(), serverUrl, /** @type {string} */ (id));
  return local === null ? null : { accountId: /** @type {string} */ (id), email: local.email };
}
