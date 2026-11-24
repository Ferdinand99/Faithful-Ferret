// "Fill" from the popup (over the UI port). The page names a reference that the
// page matching gave it in this session, and the tab and frame it was offered
// for; the background does the rest (fillFlow.mjs). The answer is `{ ok }` or a
// reason from a fixed list: never a value, never anything of the item.

import { FRAME_UNCHECKED } from "../../shared/protocol.mjs";

/**
 * The reasons a page has a text for (`popup.error.<reason>`). Every other code becomes `not_filled`, except
 * `frame_unchecked`, whose text is in the frames catalog (`frames.error.frame_unchecked`).
 */
export const REASONS = Object.freeze([
  "not_offered",
  "origin_changed",
  "busy",
  "frame_gone",
  "no_report",
  "no_fields",
  "no_value",
  "no_answer",
  "value_too_long",
  "wrong_kind",
  "covered",
  "frame_hidden",
  "vault_locked",
  "sync_not_running",
  "not_filled",
]);

/** @param {unknown} code @returns {string} */
export function reasonOf(code) {
  if (code === "locked" || code === "worker_failed" || code === "stopped") return "vault_locked";
  // What the fill script answers for a field it refused (content/fill.mjs).
  if (code === "hidden") return "covered";
  if (code === "gone") return "frame_gone";
  if (code === FRAME_UNCHECKED) return FRAME_UNCHECKED;
  return typeof code === "string" && REASONS.includes(code) ? code : "not_filled";
}

/** @param {any} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  const call = /** @type {NonNullable<typeof ctx.call>} */ (ctx.call);
  try {
    const reply = /** @type {{ ok: boolean, reason?: string }} */ (
      await call("fill", { session: ctx.session, ref: body.ref, tab_id: body.tab_id, frame_id: body.frame_id, ...(body.only !== undefined ? { only: body.only } : {}) })
    );
    return reply.ok ? { ok: true } : { ok: false, reason: reasonOf(reply.reason) };
  } catch (error) {
    return { ok: false, reason: reasonOf(/** @type {any} */ (error)?.code) };
  }
}

export default {
  types: ["fill"],
  channel: /** @type {"ui"} */ ("ui"),
  handle,
};
