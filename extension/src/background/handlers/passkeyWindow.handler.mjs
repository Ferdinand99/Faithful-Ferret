// Ferret's chooser window for a page's passkey request (the `passkeys` feature, design document § 9.2 and § 9.4): what the
// window may see of the request (`passkey_pending`), the site as the core checked it (`passkey_site`), the user's cancel
// (`passkey_cancel`), "use the browser instead" (`passkey_browser`), "never on this site" (`passkey_never`: the core's RP ID goes on
// the never list, then the browser answers; it needs the open vault), what the vault has for a create request
// (`passkey_create_options`) and the person's choice (`passkey_choose`, background/passkeyFlow.mjs).
//
// Only from the window itself: a top-level page of this extension at `pages/passkey.html?r=<the request's id>` (the router
// accepted its port already; this checks the page), and, where the browser names it, from the browser window the
// background opened for the request. The request is named by the background's own id from the window's address; the window's
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
 * True when the sender is the chooser window of this request: a top-level page of this extension whose address is the
 * window's page with this request's id (`?r=`), the one the background opened it with.
 * @param {import("../router.mjs").HandlerContext} ctx @param {unknown} requestId
 */
function fromWindow(ctx, requestId) {
  if (ctx.channel !== "ui" || ctx.runtime === undefined || typeof ctx.session !== "string") return false;
  if (!isTopLevelExtensionPage(ctx.sender, ctx.runtime)) return false;
  const page = ctx.runtime.getURL(WINDOW_PAGE);
  const url = ctx.sender?.url;
  if (typeof url !== "string" || !url.startsWith(`${page}?`)) return false;
  try {
    return new URL(url).searchParams.get("r") === requestId;
  } catch {
    return false;
  }
}

/** @param {any} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  if (!FEATURES.passkeys) throw notAvailable();
  if (typeof ctx.call !== "function" || !fromWindow(ctx, body?.request_id)) throw notAvailable();
  // The browser window the page is in: the broker checks it against the window it opened for the request.
  const windowId = ctx.sender?.tab?.windowId;
  return ctx.call(ctx.type, {
    request_id: body.request_id,
    session: ctx.session,
    ...(Number.isSafeInteger(windowId) ? { window_id: windowId } : {}),
    // The person's choice (checked by the schema of the type): what was chosen, never a claim of presence or verification.
    ...(ctx.type === "passkey_choose" ? choiceOf(body) : {}),
  });
}

/** The fields of a choice the window sends. @param {any} body */
function choiceOf(body) {
  /** @type {Record<string, unknown>} */
  const out = { kind: body.kind };
  for (const key of ["mode", "name", "folder_id", "item_id"]) if (body[key] !== undefined) out[key] = body[key];
  return out;
}

export default {
  types: ["passkey_pending", "passkey_site", "passkey_cancel", "passkey_browser", "passkey_never", "passkey_create_options", "passkey_choose"],
  channel: /** @type {"ui"} */ ("ui"),
  handle,
};
