// Arms the idle lock where the vault opens, not where a screen is drawn.
//
// The account session calls `start(scope)` on its sync seam every time it opens
// the vault: after a registration, a sign-in and an unlock, whichever page the
// user is on (the setup page, a sign-in that goes on to the admin pages, the
// sign-in page itself). This service puts the idle lock in front of that call,
// so an unlocked vault always has a timer, and the lock disarms it (the idle
// lock stops itself when the session locks; see `autoLockFor`). Spec: Fase 1
// section 7.1.
import { autoLockFor } from "../lock.mjs";

/** @type {import("../app.mjs").ServiceDef} */
export default {
  name: "vaultLock",
  deps: ["crypto", "sync"],
  create: ({ crypto, sync }) => {
    const seam = {
      /** @param {Parameters<typeof sync.start>[0]} scope */
      start: async (scope) => {
        // First, so that a sync engine that fails to start still leaves the timer running.
        autoLockFor(crypto, sync).start();
        return sync.start(scope);
      },
      stop: () => sync.stop(),
    };
    crypto.attachSync(seam);
    return Object.freeze({ seam });
  },
};
