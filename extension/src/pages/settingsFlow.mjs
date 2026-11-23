// The steps of the settings page, with no DOM (the tests run it as it is). The
// page has one setting, "Lock after": how long the vault stays open with no
// activity in Ferret's own pages. It is one of the fixed choices of the
// protocol, in seconds. The background keeps it and checks it again; the page
// never sends a value that is not one of the choices.

import { CAPTURE_ORIGINS } from "../shared/captureConfig.mjs";
import { LOCK_CHOICES } from "../shared/protocol.mjs";

export { LOCK_CHOICES };

/** The text of a choice (`settings.lock.choice.<seconds>`). @param {number} seconds */
export const choiceKey = (seconds) => `settings.lock.choice.${seconds}`;

/** The text of a reason (`settings.error.<reason>`); one the page has no text for is `unknown`. @param {unknown} reason */
export function errorKey(reason) {
  return `settings.error.${typeof reason === "string" && ["invalid_input", "internal_error", "disconnected"].includes(reason) ? reason : "unknown"}`;
}

/**
 * The text of a reason of the capture setting (`capture.error.<reason>`); one the page has no text for is `unknown`.
 * @param {unknown} reason
 */
export function captureErrorKey(reason) {
  const known = ["disconnected", "not_available", "permission_missing", "permission_refused", "register_failed"];
  return `capture.error.${typeof reason === "string" && known.includes(reason) ? reason : "unknown"}`;
}

/** @param {unknown} error */
const reasonOf = (error) => {
  const code = /** @type {{ code?: unknown }} */ (error)?.code;
  return typeof code === "string" ? code : "unknown";
};

/**
 * @typedef {{ ok: true, seconds: number } | { ok: false, reason: string }} Outcome
 * @typedef {{ on: boolean, permission: boolean, never: string[] }} CaptureState
 * @typedef {({ ok: true } & CaptureState) | ({ ok: false, reason: string } & Partial<CaptureState>)} CaptureOutcome
 * @param {import("./ui.mjs").Request} request
 * @param {{ requestPermission?: ((wanted: { origins: string[] }) => Promise<boolean>) | null }} [options]
 *   `requestPermission` is `browser.permissions.request`, which the browser lets a page call only from a click: the
 *   steps that need it call it first, before anything is awaited
 */
export function createSettingsFlow(request, { requestPermission = null } = {}) {
  /**
   * What the background says about capture: whether it is on, whether the permission for https pages is there, and
   * the hosts of the never list. An answer of another shape is not shown.
   * @param {Record<string, unknown>} body @returns {Promise<CaptureOutcome>}
   */
  async function askCapture(body) {
    try {
      const reply = await request("capture_settings", body);
      if (typeof reply?.on !== "boolean" || typeof reply.permission !== "boolean" || !Array.isArray(reply.never)) return { ok: false, reason: "unknown" };
      const state = { on: reply.on, permission: reply.permission, never: reply.never.filter((/** @type {unknown} */ h) => typeof h === "string") };
      return reply.ok === true ? { ok: true, ...state } : { ok: false, reason: typeof reply.reason === "string" ? reply.reason : "unknown", ...state };
    } catch (error) {
      return { ok: false, reason: reasonOf(error) };
    }
  }

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
    /** What is true of "Offer to save passwords" and the never list. */
    capture: Object.freeze({
      load: () => askCapture({}),
      /**
       * Turns "Offer to save passwords" on. The permission for https pages is asked for first, in the click that
       * called this (a request from anywhere else the browser refuses); the background checks it again before it
       * registers the capture script. Nothing is asked of the background when the user said no.
       * @returns {Promise<CaptureOutcome>}
       */
      async turnOn() {
        const asking = typeof requestPermission === "function" ? requestPermission({ origins: [...CAPTURE_ORIGINS] }) : null;
        /** @type {boolean} */
        let granted = false;
        try {
          granted = asking !== null && (await asking) === true;
        } catch {
          granted = false;
        }
        if (!granted) {
          const state = /** @type {any} */ (await askCapture({}));
          return typeof state.on === "boolean"
            ? { ok: false, reason: "permission_refused", on: state.on, permission: state.permission, never: state.never }
            : { ok: false, reason: "permission_refused" };
        }
        return askCapture({ enable: true });
      },
      /** Turns it off. */
      turnOff: () => askCapture({ enable: false }),
      /** @param {string} host */
      removeNever: (host) => askCapture({ never_remove: host }),
      clearNever: () => askCapture({ never_clear: true }),
    }),
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
