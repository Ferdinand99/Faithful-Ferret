// What the popup shows, with no DOM (the tests run it as it is). In this
// version the popup has three views:
//
//   signed_out   no device is signed in: a button opens the sign-in tab
//   locked       the server and the account, and the unlock with the master
//                password (and the secret key when this device does not keep it)
//   unlocked     the server and the account, and the lock button in the header
//
// The list of the vault comes in a later version and builds on `unlocked`.

import { shownHost } from "./ui.mjs";
import { unlockWith } from "./signinFlow.mjs";

/**
 * @typedef {{ view: "signed_out" | "locked" | "unlocked", host: string, account: string }} PopupView
 */

/**
 * @param {Record<string, any>} state the answer of `state`
 * @returns {PopupView}
 */
export function viewOf(state) {
  const view = state?.state === "unlocked" ? "unlocked" : state?.state === "locked" ? "locked" : "signed_out";
  return { view, host: shownHost(state ?? {}), account: typeof state?.account === "string" ? state.account : "" };
}

/** @param {import("./ui.mjs").Request} request */
export function createPopupFlow(request) {
  const load = async () => viewOf(await request("state", {}));
  return {
    /** The view for the state the background reports. */
    load,

    /** The lock button: the background locks, and the popup shows the unlock view. */
    async lock() {
      await request("lock", {});
      return load();
    },

    /**
     * @param {{ password: string, secretKey?: string }} fields
     * @returns {Promise<{ result: { ok: boolean, reason?: string }, view: PopupView }>}
     */
    async unlock(fields) {
      const result = await unlockWith(request, fields);
      return { result, view: await load() };
    },
  };
}
