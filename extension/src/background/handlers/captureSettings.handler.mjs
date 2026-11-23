// "Offer to save passwords" and the never list, from the settings page (over
// the UI port), in a build with saving from the extension on. The page asks for
// the permission for https pages in its own click and then says `enable`; the
// background checks the permission itself, registers the capture script and
// keeps the setting. The reply is what is true now: whether capture is on, whether
// the permission is there, and the hosts of the never list. Never a captured value.
//
// Off in a build without the feature: refused as `not_available` before anything
// else. The type needs no key and is exempt from the lock check, so the page works
// on a locked device; it does not move the deadline either.

import { FEATURES } from "../../shared/features.mjs";

/** @param {any} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  if (!FEATURES.save) throw Object.assign(new Error("not_available"), { code: "not_available" });
  const call = /** @type {NonNullable<typeof ctx.call>} */ (ctx.call);
  const reply = /** @type {any} */ (await call("capture_settings", body));
  return {
    ok: reply?.ok === true,
    ...(typeof reply?.reason === "string" && /^[a-z][a-z0-9_]*$/.test(reply.reason) ? { reason: reply.reason } : {}),
    on: reply?.on === true,
    permission: reply?.permission === true,
    never: Array.isArray(reply?.never) ? reply.never.filter((/** @type {unknown} */ h) => typeof h === "string") : [],
  };
}

export default {
  types: ["capture_settings"],
  channel: /** @type {"ui"} */ ("ui"),
  handle,
};
