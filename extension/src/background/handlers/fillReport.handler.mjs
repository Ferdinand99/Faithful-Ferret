// The fill script's reports (content scripts, over `runtime.sendMessage`): the
// fields a frame found (`frame_report`) and the answer to one value
// (`fill_result`). They are handed to the pending fill request they name
// (fillFlow.mjs); one that names none, or comes from another frame or
// document, does nothing. A report never gets an answer and never a value.

/** @param {any} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  await ctx.report?.({ kind: ctx.type, body, sender: ctx.sender });
}

export default {
  types: ["frame_report", "fill_result"],
  channel: /** @type {"content"} */ ("content"),
  handle,
};
