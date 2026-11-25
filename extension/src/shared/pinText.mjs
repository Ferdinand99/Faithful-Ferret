// How the extension counts a PIN, the same way the core does (crates/ferret-core/src/text/pin.rs), so that a PIN the
// popup or the settings accept is never refused later and a typo never costs a counted attempt. Plain ESM, no
// dependencies. The core is the judge; this is the pre-check that tells the user before a request is made.
//
// The minimum (the rule of the server, never below the floor) is counted in Unicode scalar values of the composed form
// of the normalised PIN: NFC of the NFKD form, so a letter with a combining accent or a Hangul syllable written as
// separate jamo counts as one. The maximum is counted in scalar values of the NFKD form, and in UTF-8 bytes of it.

/** The smallest PIN the core accepts, whatever the server says (the same floor as the core's). */
export const PIN_FLOOR = 4;
/** The longest PIN, in Unicode scalar values of the NFKD form, and in UTF-8 bytes of it. */
export const PIN_MAX_CHARS = 64;
export const PIN_MAX_BYTES = 256;

/**
 * The length a rule counts: scalar values of NFC applied to the NFKD form of the PIN (the core's `rule_len`).
 * @param {string} pin
 */
export function pinLength(pin) {
  return [...pin.normalize("NFKD").normalize("NFC")].length;
}

/**
 * Whether a PIN is within the limits of a PIN at all (the core's maximum, which it checks before the rule).
 * @param {string} pin
 */
function withinMaximum(pin) {
  const decomposed = pin.normalize("NFKD");
  return [...decomposed].length <= PIN_MAX_CHARS && new TextEncoder().encode(decomposed).length <= PIN_MAX_BYTES;
}

/**
 * Whether a PIN meets the rule the server set (and the fixed floor and ceiling), in the order of the core: too long
 * first, then too short. Nothing about the PIN is kept or sent.
 * @param {string} pin @param {number} minLength
 * @returns {{ ok: true } | { ok: false, reason: "too_short" | "too_long" }}
 */
export function checkPin(pin, minLength) {
  if (!withinMaximum(pin)) return { ok: false, reason: "too_long" };
  if (pinLength(pin) < Math.max(PIN_FLOOR, minLength)) return { ok: false, reason: "too_short" };
  return { ok: true };
}
