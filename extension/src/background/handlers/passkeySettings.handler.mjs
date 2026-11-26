// The passkey provider's settings, from the settings page (the `passkeys` feature) over the UI port: "Use Ferret for passkeys", the
// "never" list and "Count an unlock in the last 5 minutes as verification". The page asks for the permission for https pages in its
// own click and then says `enable`; the background checks the permission itself, switches the feature through the registry and
// keeps the setting. The reply is what is true now. Never a vault value.
//
// Off in a build without the feature: refused as `not_available` before anything else. The type needs no key and is exempt from the
// lock check, so the page works on a locked device; it does not move the deadline either (it is in LOCK_EXEMPT).

import { FEATURES } from "../../shared/features.mjs";

/** @param {any} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  if (!FEATURES.passkeys) throw Object.assign(new Error("not_available"), { code: "not_available" });
  const call = /** @type {NonNullable<typeof ctx.call>} */ (ctx.call);
  const reply = /** @type {any} */ (await call("passkey_settings", body));
  return {
    ok: reply?.ok === true,
    ...(typeof reply?.reason === "string" && /^[a-z][a-z0-9_]*$/.test(reply.reason) ? { reason: reply.reason } : {}),
    on: reply?.on === true,
    permission: reply?.permission === true,
    signed_in: reply?.signed_in === true,
    never: Array.isArray(reply?.never) ? reply.never.filter((/** @type {unknown} */ h) => typeof h === "string") : [],
    recent_unlock: reply?.recent_unlock === true,
  };
}

export default {
  types: ["passkey_settings"],
  channel: /** @type {"ui"} */ ("ui"),
  handle,
};
