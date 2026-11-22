// The check of the page that asks for a frame's host permission (design
// document, section 10.5), from the grant tab over the UI port. It answers only
// for an origin that a list of candidates named for a grant in the last minutes
// (a frame of the page's site that some item matches), and only for an `https`
// origin exactly as the core writes it; the answer is its host and the pattern.

import { permissionPattern } from "../frames.mjs";

/** @param {any} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  const call = /** @type {NonNullable<typeof ctx.call>} */ (ctx.call);
  // Only an `https` origin exactly as the core writes it: not a page address, not `http`, nothing else.
  const origin = /** @type {string} */ (body.origin);
  let canonical = null;
  try {
    canonical = /** @type {any} */ (await call("page_origin", { url: origin })).origin;
  } catch {
    canonical = null;
  }
  if (canonical !== origin || !origin.startsWith("https://")) return { ok: false, reason: "origin_invalid" };
  // Only an origin the background named for a grant (the grant tab is a page of its own, so the list it came from
  // was answered on another port; the names are kept for a while and forgotten at every lock).
  const listed = /** @type {any} */ (await call("grant_listed", { origin })).listed === true;
  if (!listed) return { ok: false, reason: "origin_invalid" };
  const host = /** @type {import("../frames.mjs").Host} */ (await call("display_host", { url: origin }));
  return { ok: true, origin, host, pattern: permissionPattern(host) };
}

export default {
  types: ["grant_check"],
  channel: /** @type {"ui"} */ ("ui"),
  handle,
};
