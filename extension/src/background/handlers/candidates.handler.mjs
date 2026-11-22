// The items a page is offered, and the check of the page that asks for a
// frame's host permission (design document, sections 10.4 and 10.5), from the
// extension's own pages over the UI port.
//
//   candidates   the list for a tab (or one frame of it): the host the core
//                shows, whether the page is plain `http`, the items with their
//                references, and the frames of the same site that wait for their
//                host permission
//   grant_check  the origin the grant tab was opened for: only one that a list
//                named for a grant in the last minutes (a frame of the page's
//                site that some item matches), and an `https` origin exactly as
//                the core writes it; the answer is its host and the pattern
//
// The frames come from the browser (`webNavigation`), the site rules and the
// match from the core (frames.mjs, match.mjs). The references belong to the
// popup session of the port that asked.

import { candidates, fillableFrames, permissionPattern } from "../frames.mjs";

/** @param {(op: string, args?: unknown) => Promise<unknown>} call @returns {import("../frames.mjs").FrameCore} */
function coreOf(call) {
  return {
    page_origin: async (url) => /** @type {any} */ (await call("page_origin", { url })).origin,
    same_site: async (a, b) => /** @type {any} */ (await call("same_site", { a, b })).same === true,
  };
}

/** The browser's APIs this handler reads (the global of the background page). */
function api() {
  const b = /** @type {any} */ (globalThis).browser;
  return { webNavigation: b?.webNavigation, permissions: b?.permissions };
}

/**
 * The reply on the wire: a user name that is null is left out.
 * @param {import("../frames.mjs").CandidateList} list
 */
function wire(list) {
  return {
    ...(list.host !== null ? { host: list.host } : {}),
    insecure: list.insecure,
    items: list.items.map((item) => ({
      ref: item.ref,
      name: item.name,
      ...(item.username !== null ? { username: item.username } : {}),
      how: item.how,
      frame_id: item.frameId,
    })),
    grant: list.grant.map((g) => ({ origin: g.origin, host: g.host })),
  };
}

/** @param {any} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  const call = /** @type {NonNullable<typeof ctx.call>} */ (ctx.call);
  switch (ctx.type) {
    case "candidates": {
      const { webNavigation, permissions } = api();
      if (!webNavigation) throw Object.assign(new Error("not_available"), { code: "not_available" });
      const core = coreOf(call);
      const list = await candidates(body.tab_id, {
        coreHost: { call },
        frames: (tabId) => fillableFrames(tabId, { webNavigation, core }),
        permissions,
        ...(typeof ctx.session === "string" ? { session: ctx.session } : {}),
        ...(body.frame_id !== undefined ? { frameId: body.frame_id } : {}),
      });
      return wire(list);
    }
    case "grant_check": {
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
    default:
      throw Object.assign(new Error("not_available"), { code: "not_available" });
  }
}

export default {
  types: ["candidates", "grant_check"],
  channel: /** @type {"ui"} */ ("ui"),
  handle,
};
