// Ferret's chooser window for a page's passkey request (the `passkeys` feature, design document § 9.2 and § 9.4): what the
// window may see of the request (`passkey_pending`), the site as the core checked it (`passkey_site`), the user's cancel
// (`passkey_cancel`) and "use the browser instead" (`passkey_browser`).
//
// Only from the window itself: a top-level page of this extension at `pages/passkey.html` (the router accepted its port
// already; this checks the page). The request is named by the background's own id from the window's address; the window's
// session (its port) is handed on with it, and the first session that names a request owns it. Every decision is the
// broker's (background/passkeyRequests.mjs); the caller the core is given is built there, never here or in the window.
//
// Off in a build without the feature: refused as `not_available` before anything else, as if this handler were not there.

import { isTopLevelExtensionPage } from "../../shared/origin.mjs";
import { FEATURES } from "../../shared/features.mjs";

/** The page of the chooser window, in the package. */
const WINDOW_PAGE = "pages/passkey.html";

const notAvailable = () => Object.assign(new Error("not_available"), { code: "not_available" });

/**
 * True when the sender is the chooser window: a top-level page of this extension whose address is the window's page.
 * @param {import("../router.mjs").HandlerContext} ctx
 */
function fromWindow(ctx) {
  if (ctx.channel !== "ui" || ctx.runtime === undefined || typeof ctx.session !== "string") return false;
  if (!isTopLevelExtensionPage(ctx.sender, ctx.runtime)) return false;
  const page = ctx.runtime.getURL(WINDOW_PAGE);
  const url = ctx.sender?.url;
  return typeof url === "string" && (url === page || url.startsWith(`${page}?`) || url.startsWith(`${page}#`));
}

/** @param {any} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  if (!FEATURES.passkeys) throw notAvailable();
  if (typeof ctx.call !== "function" || !fromWindow(ctx)) throw notAvailable();
  return ctx.call(ctx.type, { request_id: body.request_id, session: ctx.session });
}

export default {
  types: ["passkey_pending", "passkey_site", "passkey_cancel", "passkey_browser"],
  channel: /** @type {"ui"} */ ("ui"),
  handle,
};
