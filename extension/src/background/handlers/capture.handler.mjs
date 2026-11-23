// The capture script's reports (design document, section 10.9), from a content
// script over `runtime.sendMessage`: a form the user submitted (`form_capture`),
// the form of an earlier capture is gone from its page (`form_gone`), and the
// page shows a password field (`page_ready`).
//
// The router decides who may send them (a content script of this extension, in a
// tab, from a web page) and decodes them with the content table; this handler
// hands the body on, and nothing else: the type and the sender are the router's,
// the origin is the browser's (never in the message), and nothing is answered. They
// are taken while the vault is locked and never touch a key or move the
// auto-lock deadline (they are in LOCK_EXEMPT).
//
// Off in a build without the feature: every report is refused as `not_available`
// before anything else, as if this handler were not there.

import { FEATURES } from "../../shared/features.mjs";

/** @param {any} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  if (!FEATURES.save) throw Object.assign(new Error("not_available"), { code: "not_available" });
  // Only a content script's report: a message of an extension page never gets here (the content table does not hold
  // these types for a page), and the sender the router checked has a tab.
  if (ctx.channel !== "content" || typeof ctx.capture !== "function") throw Object.assign(new Error("not_available"), { code: "not_available" });
  await ctx.capture(body);
}

export default {
  types: ["form_capture", "form_gone", "page_ready"],
  channel: /** @type {"content"} */ ("content"),
  handle,
};
