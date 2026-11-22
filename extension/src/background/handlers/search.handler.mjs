// The list of the vault in the popup (over the UI port): a search of the whole
// vault, and one item's view. A search gives references for copying only
// ("Fill" takes a reference of the page's candidates), and an answer carries
// names, user names and marks: never a password, a code or another value.

import { reasonOf } from "./copy.handler.mjs";

/** @param {any} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  const call = /** @type {NonNullable<typeof ctx.call>} */ (ctx.call);
  if (ctx.type === "search") {
    return call("search", {
      session: ctx.session,
      query: body.query,
      ...(body.favorites !== undefined ? { favorites: body.favorites } : {}),
      ...(body.type !== undefined ? { type: body.type } : {}),
      ...(body.offset !== undefined ? { offset: body.offset } : {}),
    });
  }
  try {
    return await call("item", { session: ctx.session, ref: body.ref });
  } catch (error) {
    return { ok: false, reason: reasonOf(/** @type {any} */ (error)?.code) };
  }
}

export default {
  types: ["search", "item"],
  channel: /** @type {"ui"} */ ("ui"),
  handle,
};
