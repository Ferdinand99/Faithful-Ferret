// The lock button of the popup, over the UI port. A lock ends the worker that
// holds the keys (the core host does it, and tells the modules that run beside
// it: the sync stops, the deadline goes). It is never refused, whatever the
// state, and it needs no key.

/** @param {unknown} _body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(_body, ctx) {
  const lock = /** @type {NonNullable<typeof ctx.lock>} */ (ctx.lock);
  await lock("manual");
  return { ok: true };
}

export default {
  types: ["lock"],
  channel: /** @type {"ui"} */ ("ui"),
  handle,
};
