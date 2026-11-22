// "Copy" and "Open the site" from the popup (over the UI port). The page names
// a reference it got in this session; the background reads the value in the
// core and writes it to the clipboard itself (clipboard.mjs), so a copied
// value never reaches a page. The answer is `{ ok }` or a reason from a fixed
// list.

/** The reasons a page has a text for (`popup.error.<reason>`). Every other code becomes `unknown`. */
export const REASONS = Object.freeze(["not_offered", "no_value", "no_site", "clipboard", "not_found", "vault_locked", "sync_not_running", "busy", "unknown"]);

/** @param {unknown} code @returns {string} */
export function reasonOf(code) {
  if (code === "locked" || code === "worker_failed" || code === "stopped") return "vault_locked";
  return typeof code === "string" && REASONS.includes(code) ? code : "unknown";
}

/** @param {any} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  const call = /** @type {NonNullable<typeof ctx.call>} */ (ctx.call);
  const args = ctx.type === "copy" ? { session: ctx.session, ref: body.ref, field: body.field } : { session: ctx.session, ref: body.ref };
  try {
    const reply = /** @type {{ ok: boolean, reason?: string }} */ (await call(ctx.type, args));
    return reply.ok ? { ok: true } : { ok: false, reason: reasonOf(reply.reason) };
  } catch (error) {
    return { ok: false, reason: reasonOf(/** @type {any} */ (error)?.code) };
  }
}

export default {
  types: ["copy", "open_site"],
  channel: /** @type {"ui"} */ ("ui"),
  handle,
};
