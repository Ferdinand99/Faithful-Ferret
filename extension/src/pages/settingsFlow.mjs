// The steps of the settings page, with no DOM (the tests run it as it is). The
// page has one setting, "Lock after": how long the vault stays open with no
// activity in Ferret's own pages. It is one of the fixed choices of the
// protocol, in seconds. The background keeps it and checks it again; the page
// never sends a value that is not one of the choices.

import { LOCK_CHOICES } from "../shared/protocol.mjs";

export { LOCK_CHOICES };

/** The text of a choice (`settings.lock.choice.<seconds>`). @param {number} seconds */
export const choiceKey = (seconds) => `settings.lock.choice.${seconds}`;

/** The text of a reason (`settings.error.<reason>`); one the page has no text for is `unknown`. @param {unknown} reason */
export function errorKey(reason) {
  return `settings.error.${typeof reason === "string" && ["invalid_input", "internal_error", "disconnected"].includes(reason) ? reason : "unknown"}`;
}

/** @param {unknown} error */
const reasonOf = (error) => {
  const code = /** @type {{ code?: unknown }} */ (error)?.code;
  return typeof code === "string" ? code : "unknown";
};

/**
 * @typedef {{ ok: true, seconds: number } | { ok: false, reason: string }} Outcome
 * @param {import("./ui.mjs").Request} request
 */
export function createSettingsFlow(request) {
  /** @param {Record<string, unknown>} body @returns {Promise<Outcome>} */
  async function ask(body) {
    try {
      const reply = await request("settings", body);
      // The background answers with a value of the list; anything else is not shown as a setting.
      if (!LOCK_CHOICES.includes(reply?.lock_seconds)) return { ok: false, reason: "internal_error" };
      return { ok: true, seconds: reply.lock_seconds };
    } catch (error) {
      return { ok: false, reason: reasonOf(error) };
    }
  }
  return {
    /** Reads the setting. */
    load: () => ask({}),
    /**
     * Saves the setting. A value outside the choices is refused here and never sent.
     * @param {unknown} seconds
     * @returns {Promise<Outcome>}
     */
    async setLockSeconds(seconds) {
      if (typeof seconds !== "number" || !LOCK_CHOICES.includes(seconds)) return { ok: false, reason: "invalid_input" };
      return ask({ lock_seconds: seconds });
    },
  };
}
