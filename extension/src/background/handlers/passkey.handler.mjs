// The passkey bridge's reports (the `passkeys` feature, design document § 9.2 and § 10.8), from the bridge script of a
// page over `runtime.sendMessage`: a call of `create` or `get` (`passkey_request`), the page's abort (`passkey_abort`),
// another provider found in the page (`passkey_foreign`), and the ping while a request waits (`passkey_ping`).
//
// The router decides who may send them (a content script of this extension, in a tab, from a web page) and decodes them
// with the content table; this handler hands the body on with the type and the sender the router checked, and nothing
// else, and says "taken" to a request (the bridge hands a call that was not taken back to the browser). The origin, the frame and the document are the browser's, never the message's; the answer goes back as a push to
// that frame and document. They are taken while the vault is locked (a locked vault is opened in Ferret's own window)
// and never move the auto-lock deadline (they are in LOCK_EXEMPT).
//
// Off in a build without the feature: every report is refused as `not_available` before anything else, as if this
// handler were not there.

import { FEATURES } from "../../shared/features.mjs";

const notAvailable = () => Object.assign(new Error("not_available"), { code: "not_available" });

/** @param {any} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  if (!FEATURES.passkeys) throw notAvailable();
  // Only a content script's report: a message of an extension page never gets here (the content table does not hold these
  // types for a page), and the sender the router checked has a tab.
  if (ctx.channel !== "content" || typeof ctx.passkey !== "function") throw notAvailable();
  await ctx.passkey(body);
  // `passkey_request` is the one with a reply: taken (the answer follows as a push).
  return ctx.type === "passkey_request" ? { accepted: true } : undefined;
}

export default {
  types: ["passkey_request", "passkey_abort", "passkey_foreign", "passkey_ping"],
  channel: /** @type {"content"} */ ("content"),
  handle,
};
