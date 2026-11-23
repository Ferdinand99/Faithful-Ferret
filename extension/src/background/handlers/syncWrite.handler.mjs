// The items whose change waits or was refused, from the popup (over the UI
// port), in a build with saving from the extension on: the list of them, the
// two versions of an item in conflict, "Keep mine" or "Keep the server's", and
// "Discard the draft" of a refused change (design document, section 8.5).
//
// Off in a build without the feature: every type is refused as `not_available`
// before anything else, as if this handler were not there.
//
// An answer names items by a reference good only in the page's session, with a
// name, a user name, a state and the time and device of a change. Never a
// password or another value of an item.

import { FEATURES } from "../../shared/features.mjs";

/** The reasons a page has a text for (`sync.item.error.<reason>`). Every other code becomes `unknown`. */
export const REASONS = Object.freeze([
  "not_offered",
  "not_shown",
  "not_found",
  "in_conflict",
  "conflict_changed",
  "conflict_unsettled",
  "busy",
  "invalid_state",
  "sync_not_running",
  "vault_locked",
  "worker_failed",
  "unknown",
]);

/** @param {unknown} code @returns {string} */
export function reasonOf(code) {
  if (code === "internal" || code === "kdf_out_of_memory") return "worker_failed";
  return typeof code === "string" && REASONS.includes(code) ? code : "unknown";
}

/** @param {any} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  if (!FEATURES.save) throw Object.assign(new Error("not_available"), { code: "not_available" });
  const call = /** @type {NonNullable<typeof ctx.call>} */ (ctx.call);
  const session = ctx.session;
  switch (ctx.type) {
    case "sync_items":
      return call("sync_items", { session });
    case "item_conflict":
    case "item_resolve":
    case "item_discard":
      try {
        const reply = /** @type {any} */ (
          await call(ctx.type, { session, ref: body.ref, ...(ctx.type === "item_resolve" ? { choice: body.choice } : {}) })
        );
        if (reply?.ok !== true) return { ok: false, reason: reasonOf(reply?.reason) };
        return ctx.type === "item_conflict" ? { ok: true, mine: reply.mine, theirs: reply.theirs, differs: Array.isArray(reply.differs) ? reply.differs : [] } : { ok: true };
      } catch (error) {
        return { ok: false, reason: reasonOf(/** @type {any} */ (error)?.code) };
      }
    default:
      throw Object.assign(new Error("not_available"), { code: "not_available" });
  }
}

export default {
  types: ["sync_items", "item_conflict", "item_resolve", "item_discard"],
  channel: /** @type {"ui"} */ ("ui"),
  handle,
};
