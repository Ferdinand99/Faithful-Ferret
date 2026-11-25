// The one-time code of an item for the popup to show (over the UI port). The page names a reference it got in this
// session; the background makes the code in the core from the device's clock (fillFlow.mjs `itemCode`) and answers with
// the code and the seconds it still holds. The secret the code comes from never leaves the core. A locked vault is
// refused by the router before this handler runs. The answer is the code, or a reason from a fixed list.

import { reasonOf } from "./copy.handler.mjs";

/** @param {any} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  const call = /** @type {NonNullable<typeof ctx.call>} */ (ctx.call);
  try {
    const reply = /** @type {{ ok: boolean, reason?: string, code?: string, seconds_left?: number }} */ (
      await call("item_code", { session: ctx.session, ref: body.ref })
    );
    return reply.ok ? { ok: true, code: reply.code, seconds_left: reply.seconds_left } : { ok: false, reason: reasonOf(reply.reason) };
  } catch (error) {
    return { ok: false, reason: reasonOf(/** @type {any} */ (error)?.code) };
  }
}

export default {
  types: ["item_code"],
  channel: /** @type {"ui"} */ ("ui"),
  handle,
};
