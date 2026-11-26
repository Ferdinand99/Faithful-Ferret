// Ferret's chooser window for a page's passkey request (the `passkeys` feature, design document § 9.2 and § 9.4): what the
// window may see of the request (`passkey_pending`), the site as the core checked it (`passkey_site`), the user's cancel
// (`passkey_cancel`), "use the browser instead" (`passkey_browser`), "never on this site" (`passkey_never`: the core's RP ID goes on
// the never list, then the browser answers; it needs the open vault), what the vault has for a create request
// (`passkey_create_options`), the passkeys of the vault that may answer a get (`passkey_candidates`), the person's choice
// (`passkey_choose`: the click is the evidence of presence, so only this window may send it) and the verification step
// (`passkey_verify`: a passkey of the vault, the PIN or the master password; a passkey's 32 bytes come only from this window,
// never the popup).
//
// Only from the window itself: a top-level page of this extension at `pages/passkey.html?r=<the request's id>` (the router
// accepted its port already; this checks the page), and, where the browser names it, from the browser window the
// background opened for the request. The request is named by the background's own id from the window's address; the window's
// session (its port) is handed on with it, and the first session that names a request owns it. Every decision is the
// broker's (background/passkeyRequests.mjs); the caller the core is given is built there, never here or in the window.
//
// Ferret's popup sends `passkey_choose` (a get) and `passkey_verify` (the PIN or the master password) too, with the `tab_id` of the
// tab it is about in place of `request_id`, for that tab's conditional request: from the popup page only (`fromPopup`).
//
// Off in a build without the feature: refused as `not_available` before anything else, as if this handler were not there.

import { isPopupPage, isTopLevelExtensionPage, popupTabOf } from "../../shared/origin.mjs";
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

/** What a type carries beside the request's id (its schema checked it already); nothing else of the body goes on. */
const FIELDS = Object.freeze({
  passkey_choose: Object.freeze(["kind", "item_id", "mode", "name", "folder_id"]),
  passkey_verify: Object.freeze(["method", "pin", "mp", "sk", "credential_id", "prf_output"]),
});

/**
 * The popup's choice and verification step for the tab's conditional request: `tab_id` and no `request_id`, from the popup page
 * only. The click in the popup is the evidence of presence, as the window's is; the popup verifies with the PIN or the master
 * password (a passkey of the vault needs the window), so a passkey's bytes are never taken from it.
 * @param {any} body @param {import("../router.mjs").HandlerContext} ctx
 */
async function fromPopup(body, ctx) {
  if (ctx.channel !== "ui" || ctx.runtime === undefined || typeof ctx.call !== "function" || !isPopupPage(ctx.sender, ctx.runtime)) throw notAvailable();
  // The request the popup listed: its id and origin, sent back so that the broker acts on that request and no other.
  if (typeof body.request_id !== "string" || typeof body.origin !== "string") throw notAvailable();
  const listed = { tab_id: body.tab_id, request_id: body.request_id, origin: body.origin, popup_tab: popupTabOf(ctx) };
  if (ctx.type === "passkey_choose") {
    if (body.kind !== "get" || typeof body.item_id !== "string" || Object.hasOwn(body, "mode") || Object.hasOwn(body, "name") || Object.hasOwn(body, "folder_id")) throw notAvailable();
    return ctx.call("passkey_tab_choose", { ...listed, item_id: body.item_id });
  }
  if (ctx.type === "passkey_verify") {
    if ((body.method !== "pin" && body.method !== "password") || Object.hasOwn(body, "credential_id") || Object.hasOwn(body, "prf_output")) throw notAvailable();
    /** @type {Record<string, unknown>} */
    const extra = {};
    for (const key of ["method", "pin", "mp", "sk"]) if (Object.hasOwn(body, key)) extra[key] = body[key];
    return ctx.call("passkey_tab_verify", { ...extra, ...listed });
  }
  throw notAvailable();
}

/** @param {any} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  if (!FEATURES.passkeys) throw notAvailable();
  // The popup names its tab (with the request it listed); the window names only its request.
  if (Object.hasOwn(body ?? {}, "tab_id")) return fromPopup(body, ctx);
  if (Object.hasOwn(body ?? {}, "origin")) throw notAvailable();
  if (typeof ctx.call !== "function" || !fromWindow(ctx, body?.request_id)) throw notAvailable();
  // The browser window the page is in: the broker checks it against the window it opened for the request.
  const windowId = ctx.sender?.tab?.windowId;
  /** @type {Record<string, unknown>} */
  const extra = {};
  for (const key of /** @type {Record<string, readonly string[]>} */ (FIELDS)[ctx.type] ?? []) if (Object.hasOwn(body, key)) extra[key] = body[key];
  return ctx.call(ctx.type, { ...extra, request_id: body.request_id, session: ctx.session, ...(Number.isSafeInteger(windowId) ? { window_id: windowId } : {}) });
}

export default {
  types: ["passkey_pending", "passkey_site", "passkey_cancel", "passkey_browser", "passkey_never", "passkey_create_options", "passkey_candidates", "passkey_choose", "passkey_verify"],
  channel: /** @type {"ui"} */ ("ui"),
  handle,
};
