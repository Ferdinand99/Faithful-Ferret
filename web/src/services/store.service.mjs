// The local stores as a service. `open()` opens the database once, when it is
// first needed, and gives every caller the same handle; the other members take
// that handle as their first argument. A sign-in finds its pinned record with
// `pinnedForSignIn` only; the plain lookups by e-mail or account stay inside the
// store, because a miss by e-mail alone looks like a first use.
import { cache } from "../store/cache.mjs";
import { openStore } from "../store/idb.mjs";
import { outbox } from "../store/outbox.mjs";
import { forgetPinned, pinnedForSignIn, savePinned } from "../store/pinned.mjs";
import { deleteSetting, deviceId, deviceSecrets, getSetting, setSetting } from "../store/settings.mjs";

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
      savePinned,
      forgetPinned,
      deviceId,
      getSetting,
      setSetting,
      deleteSetting,
      deviceSecrets,
      cache,
      outbox,
    };
  },
};
