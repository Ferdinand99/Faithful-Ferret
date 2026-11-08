// The local stores as a service. `open()` opens the database once, when it is
// first needed, and gives every caller the same handle; the other members take
// that handle as their first argument. A sign-in finds its pinned record with
// `pinnedForSignIn` only; the plain lookups by e-mail or account stay inside the
// store, because a miss by e-mail alone looks like a first use. The one exception
// is `pinHintForEmail`, an early guard for the core's `login_finish` (see below).
import { cache } from "../store/cache.mjs";
import { openStore } from "../store/idb.mjs";
import { outbox } from "../store/outbox.mjs";
import { forgetServer, pendingWrites, sharedAccount } from "../store/forget.mjs";
import { forgetPinned, loadPinned, loadPinnedAccount, pinnedForSignIn, savePinned } from "../store/pinned.mjs";
import { loadRestoreNote, saveRestoreNote } from "../store/restoreNote.mjs";
import { deleteSetting, deviceId, deviceSecrets, getSetting, setSetting } from "../store/settings.mjs";
import { loadSyncState, saveSyncState } from "../store/syncState.mjs";
import { trash } from "../store/trash.mjs";

/** @type {import("../app.mjs").ServiceDef} */
export default {
  name: "store",
  deps: [],
  create: () => {
    /** @type {Promise<import("../store/idb.mjs").Store> | null} */
    let opened = null;
    return {
      open: () => {
        opened ??= openStore(undefined, undefined, undefined, () => {
          opened = null; // the browser closed the handle: the next call opens a new one
        }).catch((error) => {
          opened = null; // try again on the next call
          throw error;
        });
        return opened;
      },
      pinnedForSignIn,
      // For the one caller that has to guard the core's `login_finish`, which runs
      // before the server has named the account: the record the typed e-mail maps
      // to, or null. A null is never a first use by itself; the record that opens the
      // vault comes from `pinnedForSignIn`. Accepted residual: if the e-mail was changed on
      // another device, this hint is null, so a KSF downgrade is caught only at
      // `unlock_password`, after Argon2id has run; it is still refused there.
      pinHintForEmail: loadPinned,
      // For the screen that forgets a server: what the device holds for an account the server named.
      loadPinnedAccount,
      savePinned,
      forgetPinned,
      deviceId,
      getSetting,
      setSetting,
      deleteSetting,
      deviceSecrets,
      cache,
      outbox,
      // The sync state holds no lock: the caller takes the Web Lock around every
      // read-modify-write (see store/syncState.mjs).
      loadSyncState,
      saveSyncState,
      trash,
      // The note that an older server state was accepted (not secret; it only picks a text, see store/restoreNote.mjs).
      restoreNote: { save: saveRestoreNote, load: loadRestoreNote },
      forgetServer,
      pendingWrites,
      sharedAccount,
    };
  },
};
