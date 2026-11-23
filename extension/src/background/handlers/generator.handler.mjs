// The generator of the popup, over the UI port (design document, section 10.2),
// in a build with saving from the extension on: `generate` (a new password or
// passphrase from the core, or the one the background still holds),
// `generate_copy` (the background writes the clipboard itself, and clears it 30
// seconds later) and `fill_generated` (the background fills the new and the
// confirm field of a sign-up, change or reset form of a tab).
//
// Off in a build without the feature: every type is refused as `not_available`
// before anything else, as if this handler were not there.
//
// The reply of `generate` is the only reply that carries a value. The popup
// names a `generation_id` for everything else, so the value never goes from the
// popup to the background, and never to a page but through the fill flow.

import { FEATURES } from "../../shared/features.mjs";
import { FRAME_UNCHECKED } from "../../shared/protocol.mjs";

/**
 * The reasons a page has a text for (`generator.error.<reason>`). Every other code becomes `unknown`, except
 * `frame_unchecked`, whose text is in the frames catalog.
 */
export const REASONS = Object.freeze([
  "not_offered",
  "nothing_kept",
  "invalid_input",
  "origin_changed",
  "busy",
  "frame_gone",
  "no_report",
  "no_fields",
  "no_answer",
  "value_too_long",
  "wrong_kind",
  "covered",
  "frame_hidden",
  "field_too_short",
  "insecure_page",
  "clipboard",
  "not_cleared",
  "vault_locked",
  "unknown",
]);

/** @param {unknown} code @returns {string} */
export function reasonOf(code) {
  if (code === "locked" || code === "worker_failed" || code === "stopped") return "vault_locked";
  // What the fill script answers for a field it refused (content/fill.mjs).
  if (code === "hidden") return "covered";
  if (code === "gone") return "frame_gone";
  if (code === FRAME_UNCHECKED) return FRAME_UNCHECKED;
  return typeof code === "string" && REASONS.includes(code) ? code : "unknown";
}

/** @param {any} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  if (!FEATURES.save) throw Object.assign(new Error("not_available"), { code: "not_available" });
  const call = /** @type {NonNullable<typeof ctx.call>} */ (ctx.call);
  try {
    switch (ctx.type) {
      case "generate": {
        const reply = /** @type {any} */ (await call("generate", body));
        return reply?.ok === true ? reply : { ok: false, reason: reasonOf(reply?.reason) };
      }
      case "generate_copy": {
        const reply = /** @type {any} */ (await call("generate_copy", { generation_id: body.generation_id }));
        return reply?.ok === true ? { ok: true } : { ok: false, reason: reasonOf(reply?.reason) };
      }
      case "fill_generated": {
        const reply = /** @type {any} */ (
          await call("fill_generated", {
            session: ctx.session,
            generation_id: body.generation_id,
            tab_id: body.tab_id,
            ...(body.frame_id !== undefined ? { frame_id: body.frame_id } : {}),
          })
        );
        if (reply?.ok !== true) return { ok: false, reason: reasonOf(reply?.reason) };
        return { ok: true, ...(Number.isSafeInteger(reply.length) ? { length: reply.length } : {}), offer: reply.offer === true };
      }
      default:
        throw Object.assign(new Error("not_available"), { code: "not_available" });
    }
  } catch (error) {
    const code = /** @type {any} */ (error)?.code;
    if (code === "not_available") throw error;
    return { ok: false, reason: reasonOf(code) };
  }
}

export default {
  types: ["generate", "generate_copy", "fill_generated"],
  channel: /** @type {"ui"} */ ("ui"),
  handle,
};
