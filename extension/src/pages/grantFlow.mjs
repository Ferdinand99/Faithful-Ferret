// The steps of the grant tab (design document, section 10.5): a frame of the
// same site as the page, with another origin, is offered nothing until the
// extension may run in it. This tab asks for that one origin's host permission,
// on a click, because a request from the popup would close the popup.
//
// The origin comes from the address of the tab, which only the extension's own
// pages open (no web page can load this page: it is not web-accessible). It is
// still checked by the background with the core before anything is shown or
// asked: only an `https` origin exactly as the core writes it. The host the
// user reads is the core's (`display_host`), with the A-label beside the
// Unicode form when they differ. Plain ESM with no DOM, so the tests run it as
// it is.

/** The longest origin the page reads from its address (the protocol's bound). */
const MAX_ORIGIN = 300;

/**
 * The origin the tab was opened for, or null.
 * @param {string} search `location.search`
 * @returns {string | null}
 */
export function originParam(search) {
  if (typeof search !== "string") return null;
  const params = new URLSearchParams(search);
  const all = params.getAll("origin");
  if (all.length !== 1) return null;
  const origin = all[0];
  return origin !== "" && origin.length <= MAX_ORIGIN ? origin : null;
}

/**
 * @typedef {{ ok: true, origin: string, host: { a_label: string, unicode: string }, pattern: string } | { ok: false, reason: string }} Checked
 */

/**
 * @param {{
 *   request: import("./ui.mjs").Request,
 *   requestPermission: (wanted: { origins: string[] }) => Promise<boolean>,
 * }} deps `requestPermission` is `browser.permissions.request`, called in the click
 */
export function createGrantFlow({ request, requestPermission }) {
  return {
    /**
     * Checks the origin with the background.
     * @param {string | null} origin
     * @returns {Promise<Checked>}
     */
    async check(origin) {
      if (origin === null) return { ok: false, reason: "origin_invalid" };
      try {
        const answer = await request("grant_check", { origin });
        if (answer?.ok === true && answer.origin === origin && typeof answer.pattern === "string") {
          return { ok: true, origin, host: answer.host, pattern: answer.pattern };
        }
        return { ok: false, reason: typeof answer?.reason === "string" ? answer.reason : "origin_invalid" };
      } catch (error) {
        const code = /** @type {{ code?: unknown }} */ (error)?.code;
        return { ok: false, reason: typeof code === "string" ? code : "unknown" };
      }
    },

    /**
     * Asks for the permission of a checked origin. Call it straight from the
     * click: the browser asks only for a request a user made.
     * @param {Checked} checked
     * @returns {Promise<"granted" | "refused">}
     */
    async grant(checked) {
      if (!checked.ok) return "refused";
      try {
        return (await requestPermission({ origins: [checked.pattern] })) === true ? "granted" : "refused";
      } catch {
        return "refused";
      }
    },
  };
}
