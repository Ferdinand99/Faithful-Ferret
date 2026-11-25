// The steps of the "Unlock" part of the settings view, with no DOM (the tests run it as it is): what the background says
// about the PIN and the passkeys, turning a PIN on or off, and the way to the web vault. The page never keeps a PIN or a
// password: a value goes into one request and nowhere else, and nothing here writes to storage or to a log.
//
// The background answers three requests (a narrow interface; the types are in the protocol of the background):
//
//   unlock_policy {}  ->  { pin: { allowed, after_restart, min_length, set, location, failures_left, wait_ms, offline_ok,
//                                  last_contact_at? }, prf: { enabled, count } }
//   pin_set { mp, sk?, pin, location, acknowledged }  ->  { ok: true } | { ok: false, reason }
//   pin_off {}        ->  { ok: true } | { ok: false, reason }
//
// `location` is "disk" (the default: the PIN works after a restart of the browser) or "session" (memory only, gone when
// the browser closes). `last_contact_at` is the time (milliseconds) of the last successful contact with the server, when the
// background has it. The page also asks `state` (which the popup asks too) for the vault's address and whether it is open.
//
// This module asks no build flag and imports nothing of the background: the section that uses it (unlockSettings.mjs) is
// the one that asks the flag.

/** The smallest PIN the core accepts, whatever the server says (the same floor as the core's). */
export const PIN_FLOOR = 4;
/** The longest PIN, in characters (Unicode scalar values after normalisation), and in UTF-8 bytes. */
export const PIN_MAX_CHARS = 64;
export const PIN_MAX_BYTES = 256;

/** The places a PIN can be kept. */
export const PIN_LOCATIONS = Object.freeze(["disk", "session"]);

/** The reasons of `pin_set` that the page has a text for (`settings.unlock.error.<reason>`). */
export const PIN_SET_REASONS = Object.freeze([
  "wrong_credentials",
  "pin_rule",
  "pin_not_allowed",
  "after_restart_not_allowed",
  "not_acknowledged",
  "out_of_memory",
  "too_slow",
  "network",
]);
/** The reasons that need no request: the dialog says them first. */
export const LOCAL_REASONS = Object.freeze(["too_short", "too_long", "mismatch", "password_missing", "not_acknowledged"]);
/** The reasons of a refusal or of a port that went away. */
export const REFUSAL_REASONS = Object.freeze(["vault_locked", "not_available", "invalid_input", "internal_error", "disconnected"]);

/** The text of a reason (`settings.unlock.error.<reason>`); one the page has no text for is `unknown`. @param {unknown} reason */
export function unlockErrorKey(reason) {
  const known = [...PIN_SET_REASONS, ...LOCAL_REASONS, ...REFUSAL_REASONS];
  return `settings.unlock.error.${typeof reason === "string" && known.includes(reason) ? reason : "unknown"}`;
}

/** @param {unknown} error */
const reasonOf = (error) => {
  const code = /** @type {{ code?: unknown }} */ (error)?.code;
  return typeof code === "string" ? code : "unknown";
};

/**
 * The length of a PIN as the rule counts it: Unicode scalar values after the same normalisation the core uses for the
 * master password (NFKD). The core is the judge; this is what the dialog tells the user before it asks.
 * @param {string} pin
 */
export function pinLength(pin) {
  return [...pin.normalize("NFKD")].length;
}

/**
 * Whether a PIN meets the rule the server set (and the fixed floor and ceiling). Nothing about the PIN is kept or sent.
 * @param {string} pin @param {number} minLength
 * @returns {{ ok: true } | { ok: false, reason: "too_short" | "too_long" }}
 */
export function checkPin(pin, minLength) {
  const length = pinLength(pin);
  if (length < Math.max(PIN_FLOOR, minLength)) return { ok: false, reason: "too_short" };
  if (length > PIN_MAX_CHARS || new TextEncoder().encode(pin.normalize("NFKD")).length > PIN_MAX_BYTES) return { ok: false, reason: "too_long" };
  return { ok: true };
}

/**
 * @typedef {{
 *   allowed: boolean, afterRestart: boolean, minLength: number, set: boolean, location: "disk" | "session" | null,
 *   failuresLeft: number, waitMs: number, offlineOk: boolean, lastContactAt: number | null,
 * }} PinState
 * @typedef {{ pin: PinState, prf: { enabled: boolean, count: number } }} UnlockState
 * @typedef {{ ok: true, state: UnlockState } | { ok: false, reason: string }} LoadOutcome
 * @typedef {{ ok: true } | { ok: false, reason: string }} Outcome
 */

/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
/** @param {unknown} value @param {number} max */
const count = (value, max) => typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= max;

/**
 * What the background said, in the shape the page uses, or null for an answer of another shape (it is not shown).
 * @param {unknown} reply @returns {UnlockState | null}
 */
export function readUnlockState(reply) {
  if (!isRecord(reply) || !isRecord(reply.pin) || !isRecord(reply.prf)) return null;
  const pin = reply.pin;
  const prf = reply.prf;
  if (typeof pin.allowed !== "boolean" || typeof pin.after_restart !== "boolean" || typeof pin.set !== "boolean") return null;
  if (!count(pin.min_length, PIN_MAX_CHARS) || /** @type {number} */ (pin.min_length) < PIN_FLOOR) return null;
  if (typeof prf.enabled !== "boolean" || !count(prf.count, 1000)) return null;
  const location = pin.location === "disk" || pin.location === "session" ? pin.location : null;
  if (pin.set && location === null) return null;
  const contact = pin.last_contact_at;
  return {
    pin: {
      allowed: pin.allowed,
      afterRestart: pin.after_restart,
      minLength: /** @type {number} */ (pin.min_length),
      set: pin.set,
      location: pin.set ? location : null,
      failuresLeft: count(pin.failures_left, 5) ? /** @type {number} */ (pin.failures_left) : 0,
      waitMs: count(pin.wait_ms, 3_600_000) ? /** @type {number} */ (pin.wait_ms) : 0,
      offlineOk: pin.offline_ok === true,
      lastContactAt: typeof contact === "number" && Number.isFinite(contact) && contact > 0 ? contact : null,
    },
    prf: { enabled: prf.enabled, count: /** @type {number} */ (prf.count) },
  };
}

/**
 * The address of the web vault's account page, from the server address the background holds. Only http and https, and
 * nothing of a query or a fragment of the server address is kept.
 * @param {unknown} server @returns {string | null}
 */
export function vaultAccountUrl(server) {
  if (typeof server !== "string") return null;
  let parsed;
  try {
    parsed = new URL(server);
  } catch {
    return null;
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return null;
  if (parsed.username !== "" || parsed.password !== "") return null;
  return `${parsed.origin}${parsed.pathname.replace(/\/+$/, "")}/#/account`;
}

/**
 * @param {import("./ui.mjs").Request} request
 * @param {{ openTab?: ((url: string) => Promise<unknown>) | null }} [options] `openTab` is `browser.tabs.create` with a url
 */
export function createUnlockFlow(request, { openTab = null } = {}) {
  return Object.freeze({
    /** What is true of the PIN and the passkeys. @returns {Promise<LoadOutcome>} */
    async load() {
      try {
        const state = readUnlockState(await request("unlock_policy", {}));
        return state === null ? { ok: false, reason: "unknown" } : { ok: true, state };
      } catch (error) {
        return { ok: false, reason: reasonOf(error) };
      }
    },

    /**
     * Sets or changes the PIN. The master password (and the secret key, when this device does not keep it) go with the
     * PIN in this one request; the core checks them again. A PIN that is kept on disk is refused here when the
     * acknowledgement was not given: nothing is sent.
     * @param {{ password: string, secretKey?: string, pin: string, location: string, acknowledged: boolean }} fields
     * @returns {Promise<Outcome>}
     */
    async setPin({ password, secretKey = "", pin, location, acknowledged }) {
      if (!PIN_LOCATIONS.includes(location)) return { ok: false, reason: "invalid_input" };
      if (typeof password !== "string" || password === "") return { ok: false, reason: "password_missing" };
      if (typeof pin !== "string" || pin === "") return { ok: false, reason: "too_short" };
      if (location === "disk" && acknowledged !== true) return { ok: false, reason: "not_acknowledged" };
      try {
        const reply = await request("pin_set", {
          mp: password,
          ...(secretKey === "" ? {} : { sk: secretKey }),
          pin,
          location,
          acknowledged: acknowledged === true,
        });
        if (reply?.ok === true) return { ok: true };
        return { ok: false, reason: typeof reply?.reason === "string" ? reply.reason : "unknown" };
      } catch (error) {
        return { ok: false, reason: reasonOf(error) };
      }
    },

    /** Turns the PIN off: it needs no password. @returns {Promise<Outcome>} */
    async turnOff() {
      try {
        const reply = await request("pin_off", {});
        return reply?.ok === true ? { ok: true } : { ok: false, reason: typeof reply?.reason === "string" ? reply.reason : "unknown" };
      } catch (error) {
        return { ok: false, reason: reasonOf(error) };
      }
    },

    /**
     * How many passkeys the account has, read from the server now (`prf_options`): a number, or null when that is not known (no
     * network, tokens that ended, a build that cannot say). The policy's own count is not the truth: it is kept at 0.
     * @returns {Promise<number | null>}
     */
    async passkeyCount() {
      try {
        const reply = await request("prf_options", {});
        if (reply?.ok === true && Array.isArray(reply.credentials)) return reply.credentials.length;
        // Only a list can say how many there are: a refusal (`prf_unavailable` among them: no server, a device whose state is not
        // known, a pinned record that is missing) says nothing about the account's passkeys.
        return null;
      } catch {
        return null;
      }
    },

    /** Whether the vault is open (`unlocked`), the dialog must be emptied when it is not. @returns {Promise<"unlocked" | "locked" | "signed_out" | "unknown">} */
    async vaultState() {
      try {
        const reply = await request("state", {});
        return reply?.state === "unlocked" || reply?.state === "locked" || reply?.state === "signed_out" ? reply.state : "unknown";
      } catch {
        return "unknown";
      }
    },

    /** Opens the account page of the web vault in a tab. @returns {Promise<Outcome>} */
    async openVault() {
      if (typeof openTab !== "function") return { ok: false, reason: "not_available" };
      try {
        const url = vaultAccountUrl((await request("state", {}))?.server);
        if (url === null) return { ok: false, reason: "not_available" };
        await openTab(url);
        return { ok: true };
      } catch (error) {
        return { ok: false, reason: reasonOf(error) };
      }
    },
  });
}
