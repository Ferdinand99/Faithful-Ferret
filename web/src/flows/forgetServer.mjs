// "Forget this server": the user's way out when this device no longer trusts a
// server, or when sync is stopped for good (spec Fase 1 section 8.6). It removes
// what this device remembers of the server and the account, and nothing on the
// server. The order matters:
//
//   1. count the writes that were never sent, and ask (the caller's `confirm`
//      is given the count); a "no" changes nothing;
//   2. end the session at the server (best effort: the device is forgotten even
//      if the server cannot be reached), then lock, which stops the engine;
//   3. remove the account's records, inside the Web Lock of the sync memory so
//      that no other tab is saving it meanwhile;
//   4. tell the other tabs, so that they lock and stop theirs;
//   5. go to the sign-in page. The next sign-in finds no pinned record: it is a
//      first use again.
import { hex16 } from "../b64.mjs";
import { serverKey } from "../store/idb.mjs";

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
 *   store: { open(): Promise<any>, pendingWrites(db: any, accountId: string): Promise<number>, forgetServer(db: any, serverUrl: string, accountId: string): Promise<ForgetResult> },
 *   serverUrl: string,
 *   accountId: string,
 *   confirm: (info: { pending: number }) => Promise<boolean>,
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

  // 1. Unsent writes are the one thing this loses that the server does not have.
  const pending = await store.pendingWrites(db, accountId);
  if ((await confirm({ pending })) !== true) return "cancelled";

  // 2. The session at the server ends if it can; the vault locks either way.
  try {
    await api.post("/api/auth/logout");
  } catch {
    // The device is forgotten all the same; the server session ends by itself.
  }
  await session.lock();

  // 3. The same lock as every other write of the sync memory.
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

  // 4. The other tabs.
  const own = channel === undefined && typeof BroadcastChannel === "function" ? new BroadcastChannel("ferret") : null;
  const out = channel ?? own;
  try {
    out?.postMessage({ type: "forgotten", serverKey: server, accountId });
  } catch {
    // A tab that is not told keeps what it has until its next lock; the records are gone.
  } finally {
    own?.close();
  }

  // 5. Back to the sign-in page.
  navigate("#/login", result);
  return "forgotten";
}
