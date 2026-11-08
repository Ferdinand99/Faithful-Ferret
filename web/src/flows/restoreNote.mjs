// The two ends of the note about an accepted restore (see `store/restoreNote.mjs`): writing
// it when the user accepts an older server state whose unlock methods went back too, and
// finding it again when a sign-in or an unlock is refused because the server shows an older
// unlock method. Both are best effort: a store that fails never stops the accept, and never
// changes which check refuses what; a note that cannot be read is the same as no note.
import { hex16 } from "../b64.mjs";

/**
 * Keeps the note for an accepted restore, if the restore took the unlock methods back. The restore
 * epoch is read from the sync state the engine has just saved.
 * @param {{
 *   store: any,
 *   serverUrl: string,
 *   accountId?: string,
 *   result: { manifestOlder?: boolean },
 *   now?: () => number,
 * }} options `store` is the store service
 * @returns {Promise<boolean>} whether a note was kept
 */
export async function recordAcceptedRestore({ store, serverUrl, accountId, result, now = Date.now }) {
  if (result?.manifestOlder !== true) return false;
  try {
    const db = await store.open();
    const state = await store.loadSyncState(db, serverUrl, accountId);
    await store.restoreNote.save(db, serverUrl, accountId, { acceptedAt: now(), restoreEpoch: state?.restoreEpoch ?? 0, manifestOlder: true });
    return true;
  } catch {
    return false;
  }
}

/**
 * A lookup for the screens that show a refusal: the note of an account, found by its id or, when the
 * screen knows only the typed e-mail, by the pinned record that e-mail maps to on this device.
 * Never throws; null is "no note".
 * @param {{ store: any, serverUrl: string, now?: () => number }} options `store` is the store service
 * @returns {(who: { accountId?: string | null, email?: string | null }) => Promise<import("../store/restoreNote.mjs").RestoreNote | null>}
 */
export function restoreNoteFinder({ store, serverUrl, now = Date.now }) {
  return async ({ accountId = null, email = null }) => {
    try {
      const db = await store.open();
      let account = accountId;
      if (account === null && typeof email === "string" && email.trim() !== "") {
        const pinned = await store.pinHintForEmail(db, serverUrl, email.trim());
        account = pinned ? hex16.encode(pinned.account_id) : null;
      }
      if (account === null) return null;
      return await store.restoreNote.load(db, serverUrl, account, now());
    } catch {
      return null;
    }
  };
}
