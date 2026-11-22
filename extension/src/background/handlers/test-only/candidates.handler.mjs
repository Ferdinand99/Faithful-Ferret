// The test build only: the page's candidates for the popup, from the stand-in
// page matching of the test build (background/test-only/candidates.mjs). The
// release has no handler for `candidates` until the page matching of its own
// is there, so its popup offers nothing to fill.

/** @param {any} body @param {import("../../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  const call = /** @type {NonNullable<typeof ctx.call>} */ (ctx.call);
  return call("fill_offer", { session: ctx.session, tab_id: body.tab_id });
}

export default {
  types: ["candidates"],
  channel: /** @type {"ui"} */ ("ui"),
  handle,
};
