// Ferret's popup and a page's passkey request (the `passkeys` feature, design document § 9.2 and § 9.5): what the popup shows for
// the tab it is about (`passkey_tab`: a modal request that waits without a window, a conditional request, a "click the page again"
// pass; it works locked), the passkeys for that tab (`passkey_tab_list`: a button each for a conditional request, for information
// without one; it needs the open vault) and the popup's click that opens Ferret's window (`passkey_tab_open`: for the waiting
// request, or for the conditional one when the person verifies with Windows Hello). The popup's choice and its verification step
// are `passkey_choose` and `passkey_verify` with a `tab_id` (passkeyWindow.handler.mjs).
//
// Only from the popup itself: a top-level page of this extension at the popup's address. The popup names a tab, never a request:
// the broker finds the tab's request. The list goes back to the popup only; nothing of it reaches a page.
//
// Off in a build without the feature: refused as `not_available` before anything else, as if this handler were not there.

import { FEATURES } from "../../shared/features.mjs";
import { isPopupPage } from "../../shared/origin.mjs";

const notAvailable = () => Object.assign(new Error("not_available"), { code: "not_available" });

/** @param {any} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  if (!FEATURES.passkeys) throw notAvailable();
  if (ctx.channel !== "ui" || ctx.runtime === undefined || typeof ctx.call !== "function" || !isPopupPage(ctx.sender, ctx.runtime)) throw notAvailable();
  if (ctx.type === "passkey_tab_open") return ctx.call("passkey_tab_open", { tab_id: body.tab_id, which: body.which });
  return ctx.call(ctx.type, { tab_id: body.tab_id });
}

export default {
  types: ["passkey_tab", "passkey_tab_list", "passkey_tab_open"],
  channel: /** @type {"ui"} */ ("ui"),
  handle,
};
