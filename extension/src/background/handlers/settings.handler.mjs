// The settings page's one setting, "Lock after", over the UI port. A request
// without `lock_seconds` only reads it. A value that is not one of the fixed
// choices is refused (`invalid_input`) and changes nothing; a setting that
// cannot be saved is an `internal_error`. The reply is the setting as it stands.
// Nothing here needs a key, and the type is exempt from the lock check so the
// page works on a locked device; it does not move the deadline either.

import { LOCK_CHOICES } from "../../shared/protocol.mjs";

/** @param {{ lock_seconds?: number }} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  const setSeconds = /** @type {NonNullable<typeof ctx.setSeconds>} */ (ctx.setSeconds);
  const getSeconds = /** @type {NonNullable<typeof ctx.getSeconds>} */ (ctx.getSeconds);
  if (body.lock_seconds !== undefined) {
    if (!LOCK_CHOICES.includes(body.lock_seconds)) throw Object.assign(new Error("invalid_input"), { code: "invalid_input" });
    await setSeconds(body.lock_seconds);
  }
  return { lock_seconds: await getSeconds() };
}

export default {
  types: ["settings"],
  channel: /** @type {"ui"} */ ("ui"),
  handle,
};
