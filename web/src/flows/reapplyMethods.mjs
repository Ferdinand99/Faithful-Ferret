// "Reapply the unlock methods" after a restore (spec Fase 1 § 8.8). The server was restored from a backup older
// than the last change of an unlock method, the user accepted that older state on this device, and the
// recovery wrap the server holds is now below the floor this device pinned. The default renewal refuses
// such a wrap, because anywhere else it is a rollback (`renewRecovery.mjs`). Here, and only here, the
// core's after-restore entry makes the new recovery key over it, with the generation
// max(floor, manifest, server) + 1: the old wrap is never opened, the new one is above every floor, and
// the record this device pins only rises.
//
// This is the one module of the web vault that names the core's after-restore entry. It calls it only
// when all of these hold, checked again after the password check and right before the key is made:
//   - this device keeps a restore note for the account (`store/restoreNote.mjs`) that has not expired,
//     says the unlock methods went back (`manifestOlder`) and is the note the page was given;
//   - the note's restore epoch is the one the sync state stored when the older state was accepted;
//   - the server's recovery wrap is below this device's recovery floor.
// Otherwise nothing is made and nothing is sent. A password wrap below the floor is not renewed here:
// that needs the password itself, and the page sends the user to the password change for it.
//
// Nothing here is secret but the new key, which the renewal handles (`runRenewal`).
import { AccountError } from "../crypto/errors.mjs";
import { accountContext } from "./reauth.mjs";
import { belowFloor, readMethods, runRenewal } from "./renewRecovery.mjs";

/** @typedef {import("../crypto/env.mjs").Env} Env */
/** @typedef {import("../store/restoreNote.mjs").RestoreNote} RestoreNote */

/**
 * The restore note of the account that still applies: kept, not expired, with `manifestOlder`, and for the restore
 * epoch the sync state stored when the older state was accepted. Null otherwise. Never throws.
 *
 * The epoch compared is the one this device accepted, not one the server states now. The server's word cannot raise
 * trust here (it is the party a rollback comes from), and the sync state moves only when the user accepts an older
 * state, so a later restore that this device has not accepted leaves the note on the old epoch until it is accepted
 * too; the accept then writes a new note. A renewal made in between still only raises floors and opens no old wrap.
 * @param {Env} env
 * @param {any} db
 * @param {string} accountId
 * @returns {Promise<RestoreNote | null>}
 */
async function noteThatApplies(env, db, accountId) {
  try {
    const note = await env.store.restoreNote.load(db, env.server, accountId, env.now());
    if (note === null || note.manifestOlder !== true) return null;
    const state = await env.store.loadSyncState(db, env.server, accountId);
    if (!state || !Number.isSafeInteger(state.restoreEpoch) || state.restoreEpoch !== note.restoreEpoch) return null;
    return note;
  } catch {
    return null;
  }
}

/** @param {RestoreNote | null} a @param {unknown} b */
function sameNote(a, b) {
  const other = /** @type {any} */ (b);
  return a !== null && other !== null && typeof other === "object"
    && a.acceptedAt === other.acceptedAt && a.restoreEpoch === other.restoreEpoch && a.manifestOlder === other.manifestOlder;
}

/**
 * What the page may offer: the note that applies and the methods the server holds below this device's floors.
 * `{ note: null, below: [] }` when there is no such note; the server is then not asked. No password check is
 * needed: nothing is made or changed.
 * @param {Env} env
 * @returns {Promise<{ note: RestoreNote | null, below: Array<"password" | "recovery"> }>}
 */
export async function reapplyOffer(env) {
  const { info, db, record } = await accountContext(env);
  const note = await noteThatApplies(env, db, info.accountId);
  if (note === null) return { note: null, below: [] };
  return { note, below: belowFloor(await readMethods(env, record)) };
}

/**
 * Renews the recovery key over a wrap that went below the floor with an accepted restore. Returns the methods
 * that were put back (`["recovery"]`), or `[]` when there was nothing to put back.
 * @param {Env} env
 * @param {{
 *   note: RestoreNote,
 *   confirmNewRk: import("./renewRecovery.mjs").ConfirmNewRk,
 *   reauth: import("./renewRecovery.mjs").Reauth,
 * }} args `note` is the note the page offered this for
 * @returns {Promise<string[]>}
 */
export async function reapplyMethods(env, { note, confirmNewRk, reauth }) {
  if (/** @type {any} */ (note)?.manifestOlder !== true) throw new AccountError("reapply_not_offered");
  let nothing = false;
  /** @type {{ db: any, accountId: string, passwordBelow: boolean } | null} */
  let seen = null;
  try {
    await runRenewal(env, {
      confirmNewRk,
      reauth,
      check: async (methods, context) => {
        // The note is read again: the page's copy decides nothing on its own.
        if (!sameNote(await noteThatApplies(env, context.db, context.info.accountId), note)) throw new AccountError("reapply_not_offered");
        const below = belowFloor(methods);
        if (!below.includes("recovery")) {
          nothing = true;
          throw new AccountError("nothing_to_reapply");
        }
        seen = { db: context.db, accountId: context.info.accountId, passwordBelow: below.includes("password") };
      },
      entry: (vault, pinned, current, manifest) => vault.renew_recovery_after_restore(pinned, current, manifest),
    });
  } catch (error) {
    if (nothing) return [];
    throw error;
  }
  // Done: the note goes, so a later rollback of the same restore gets the plain refusal and its warning, not a second
  // quiet reapply. While the password is still below its floor it stays: the next unlock is refused, and the note is
  // what explains that refusal. Best effort; a note that stays expires after 30 days.
  const done = /** @type {{ db: any, accountId: string, passwordBelow: boolean } | null} */ (seen);
  if (done !== null && !done.passwordBelow) {
    try {
      await env.store.restoreNote.delete(done.db, env.server, done.accountId);
    } catch {
      // as above
    }
  }
  return ["recovery"];
}
