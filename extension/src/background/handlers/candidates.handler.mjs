// The items a page is offered (design document, sections 10.4 and 10.5), from
// the extension's own pages over the UI port: the host the core shows, whether
// the page is plain `http`, each item once with a reference that fills it in
// this popup session only, and the frames of the same site that wait for their
// host permission. The frames come from the browser, the site rules and the
// match from the core (frames.mjs, match.mjs); the references are the fill
// flow's (fillFlow.mjs). `frame_id` keeps one frame (the menu's).

/** @param {any} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  const call = /** @type {NonNullable<typeof ctx.call>} */ (ctx.call);
  return call("fill_offer", {
    session: ctx.session,
    tab_id: body.tab_id,
    ...(body.frame_id !== undefined ? { frame_id: body.frame_id } : {}),
  });
}

export default {
  types: ["candidates"],
  channel: /** @type {"ui"} */ ("ui"),
  handle,
};
