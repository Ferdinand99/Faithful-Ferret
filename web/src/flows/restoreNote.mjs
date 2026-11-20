// The two ends of the note about an accepted restore (see `store/restoreNote.mjs`): writing
// it when the user accepts an older server state whose unlock methods went back too, and
// finding it again when a sign-in or an unlock is refused because the server shows an older
// unlock method. Both are best effort: a store that fails never stops the accept, and never
// changes which check refuses what; a note that cannot be read is the same as no note. The
// note also gates "reapply the unlock methods" (`reapplyMethods.mjs`), which reads it itself, so
// a successful unlock or sign-in does not remove it (see `restoreNoteTools`).
import { hex16 } from "../b64.mjs";

/**
 * Keeps the note for an accepted restore, if the restore took the unlock methods back. The restore
 * epoch is read from the sync state the engine has just saved. A note that cannot be kept is not an error
 * for the accept, but it is not silent either: the answer is `"not_kept"` and the page says so.
 * @param {{
 *   store: any,
 *   serverUrl: string,
 *   accountId?: string,
 *   result: { manifestOlder?: boolean },
 *   now?: () => number,
 * }} options `store` is the store service
 * @returns {Promise<"kept" | "none" | "not_kept">} `none`: the restore did not take the unlock methods back, so there is nothing to keep
 */
export async function recordAcceptedRestore({ store, serverUrl, accountId, result, now = Date.now }) {
  if (result?.manifestOlder !== true) return "none";
  if (!hex16.is(accountId)) return "not_kept";
  try {
    const db = await store.open();
    const state = await store.loadSyncState(db, serverUrl, accountId);
    await store.restoreNote.save(db, serverUrl, accountId, { acceptedAt: now(), restoreEpoch: state?.restoreEpoch ?? 0, manifestOlder: true });
    return "kept";
  } catch {
    return "not_kept";
  }
}

/**
 * The account a screen is about: its id, or the one the device has pinned for the typed e-mail.
 * @param {any} store the store service
 * @param {any} db
 * @param {string} serverUrl
 * @param {{ accountId?: string | null, email?: string | null }} who
 * @returns {Promise<string | null>}
 */
async function accountOf(store, db, serverUrl, { accountId = null, email = null }) {
  if (hex16.is(accountId)) return accountId;
  if (typeof email !== "string" || email.trim() === "") return null;
  const pinned = await store.pinHintForEmail(db, serverUrl, email.trim());
  return pinned ? hex16.encode(pinned.account_id) : null;
}

/**
 * A lookup for the screens that show a refusal: the note of an account, found by its id or, when the
 * screen knows only the typed e-mail, by the pinned record that e-mail maps to on this device.
 * Never throws; null is "no note".
 * @param {{ store: any, serverUrl: string, now?: () => number }} options `store` is the store service
 * @returns {(who: { accountId?: string | null, email?: string | null }) => Promise<import("../store/restoreNote.mjs").RestoreNote | null>}
 */
export function restoreNoteFinder({ store, serverUrl, now = Date.now }) {
  return async (who) => {
    try {
      const db = await store.open();
      const account = await accountOf(store, db, serverUrl, who);
      if (account === null) return null;
      return await store.restoreNote.load(db, serverUrl, account, now());
    } catch {
      return null;
    }
  };
}

/**
 * Removes the note of an account. Not handed to the unlock and sign-in screens any more (see `restoreNoteTools`). Best
 * effort, never throws. The account is the id the unlock gave, else the one pinned for the typed e-mail.
 * @param {{ store: any, serverUrl: string }} options `store` is the store service
 * @returns {(who: { accountId?: string | null, email?: string | null }) => Promise<void>}
 */
export function restoreNoteClearer({ store, serverUrl }) {
  return async (who) => {
    try {
      const db = await store.open();
      const account = await accountOf(store, db, serverUrl, who);
      if (account !== null) await store.restoreNote.delete(db, serverUrl, account);
    } catch {
      // The note expires by itself after 30 days.
    }
  };
}

/**
 * What a screen with an unlock or a sign-in needs: the finder, or nothing when there is no store. The clearer is not
 * handed out: a successful unlock does not end the note. When only the recovery key went back with the restore, the
 * password still unlocks, and the note is what lets the vault offer "reapply the unlock methods" afterwards. The note
 * goes when it expires (30 days), when the server is forgotten, when a later accept replaces it, or after a reapply that
 * left no method below its floor (`reapplyMethods.mjs`).
 * @param {{ store?: any, serverUrl: string }} options `store` is the store service
 * @returns {{ restoreNote?: ReturnType<typeof restoreNoteFinder> }}
 */
export function restoreNoteTools({ store, serverUrl }) {
  if (!store) return {};
  return { restoreNote: restoreNoteFinder({ store, serverUrl }) };
}
