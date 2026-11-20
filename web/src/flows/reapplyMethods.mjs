// "Reapply the unlock methods" after a restore (J25 (i)). The server was restored from a backup older
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
  try {
    await runRenewal(env, {
      confirmNewRk,
      reauth,
      check: async (methods, context) => {
        // The note is read again: the page's copy decides nothing on its own.
        if (!sameNote(await noteThatApplies(env, context.db, context.info.accountId), note)) throw new AccountError("reapply_not_offered");
        if (!belowFloor(methods).includes("recovery")) {
          nothing = true;
          throw new AccountError("nothing_to_reapply");
        }
      },
      entry: (vault, pinned, current, manifest) => vault.renew_recovery_after_restore(pinned, current, manifest),
    });
  } catch (error) {
    if (nothing) return [];
    throw error;
  }
  return ["recovery"];
}
