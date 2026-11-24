// The generator's options, and nothing else of it: no DOM, no secret, no randomness.
//
// Nothing here (or anywhere in the web vault) makes a password. The one source of a value is the core's
// `generate_password` / `generate_passphrase` (WASM, the operating system's random numbers, rejection sampling),
// reached through the crypto client, which runs them in the vault worker. This file only holds the options the core takes,
// checks them and hands a value from the generator page to the form of a new item. The options are kept on this device by
// generatorPrefs.mjs.
//
// Where a value lives: in the page that shows it (the generator page, or the password field of the item form), and for the
// length of one click in `createHandoff`. Never in a URL, a store, a log or the storage that holds the options.

/** The bounds of the choices: the core's. */
export const LENGTH_RANGE = Object.freeze({ min: 4, max: 128 });
export const WORDS_RANGE = Object.freeze({ min: 3, max: 20 });
export const MIN_EACH_RANGE = Object.freeze({ min: 0, max: 8 });

/** The separators the core takes for a passphrase, with the i18n key of each one's name. */
export const SEPARATORS = Object.freeze(["-", ".", "_", " "]);
export const SEPARATOR_NAMES = Object.freeze({ "-": "hyphen", ".": "period", "_": "underscore", " ": "space" });

/** The character classes of a password, in the order the page lists them. */
export const CLASSES = Object.freeze(/** @type {const} */ (["upper", "lower", "digits", "symbols"]));

/** The defaults: a password of 20 characters from all four classes, at least one of each; a passphrase of 5 words. */
export const DEFAULT_OPTIONS = Object.freeze({
  kind: /** @type {"password" | "passphrase"} */ ("password"),
  length: 20,
  lower: true,
  upper: true,
  digits: true,
  symbols: true,
  min_each: 1,
  avoid_ambiguous: false,
  words: 5,
  separator: "-",
  capitalize: true,
  number: false,
});

/** @param {unknown} n @param {number} min @param {number} max @param {number} fallback */
const whole = (n, min, max, fallback) => (typeof n === "number" && Number.isInteger(n) && n >= min && n <= max ? n : fallback);
/** @param {unknown} b @param {boolean} fallback */
const flag = (b, fallback) => (typeof b === "boolean" ? b : fallback);

/**
 * The options of a stored value or of a change, with the default for anything missing or out of range (a stored value is
 * never trusted). At least one class of characters is always on.
 * @param {unknown} raw
 */
export function readOptions(raw) {
  const o = typeof raw === "object" && raw !== null && !Array.isArray(raw) ? /** @type {Record<string, unknown>} */ (raw) : {};
  const d = DEFAULT_OPTIONS;
  const classes = { lower: flag(o.lower, d.lower), upper: flag(o.upper, d.upper), digits: flag(o.digits, d.digits), symbols: flag(o.symbols, d.symbols) };
  if (!Object.values(classes).some(Boolean)) Object.assign(classes, { lower: true, upper: true, digits: true, symbols: true });
  return {
    kind: o.kind === "passphrase" ? /** @type {"password" | "passphrase"} */ ("passphrase") : /** @type {"password" | "passphrase"} */ ("password"),
    length: whole(o.length, LENGTH_RANGE.min, LENGTH_RANGE.max, d.length),
    ...classes,
    min_each: whole(o.min_each, MIN_EACH_RANGE.min, MIN_EACH_RANGE.max, d.min_each),
    avoid_ambiguous: flag(o.avoid_ambiguous, d.avoid_ambiguous),
    words: whole(o.words, WORDS_RANGE.min, WORDS_RANGE.max, d.words),
    separator: typeof o.separator === "string" && SEPARATORS.includes(o.separator) ? o.separator : d.separator,
    capitalize: flag(o.capitalize, d.capitalize),
    number: flag(o.number, d.number),
  };
}

/** @typedef {ReturnType<typeof readOptions>} Options */

/**
 * The argument of the core's call for the options: only the keys of the chosen kind, every key given (the core refuses a
 * missing or an unknown one).
 * @param {Options} o
 */
export function requestOf(o) {
  if (o.kind === "passphrase") return { words: o.words, separator: o.separator, capitalize: o.capitalize, number: o.number };
  return {
    length: o.length,
    lower: o.lower,
    upper: o.upper,
    digits: o.digits,
    symbols: o.symbols,
    min_each: o.min_each,
    avoid_ambiguous: o.avoid_ambiguous,
  };
}

/**
 * One new value from the core.
 * @param {{ vault: Record<string, (...args: any[]) => Promise<any>> }} client the crypto client
 * @param {Options} options
 * @returns {Promise<{ value: string, bits: number }>}
 */
export async function makeValue(client, options) {
  const made = await (options.kind === "passphrase"
    ? client.vault.generate_passphrase(requestOf(options))
    : client.vault.generate_password(requestOf(options)));
  if (typeof made?.value !== "string" || made.value === "") throw Object.assign(new Error("unknown"), { code: "unknown" });
  return { value: made.value, bits: Number.isFinite(made.bits) ? Math.max(0, Math.round(made.bits)) : 0 };
}

/**
 * The word for the core's entropy estimate in bits (the estimate is the core's; this only names a range of it).
 * @param {number} bits
 * @returns {"weak" | "fair" | "strong" | "very_strong"}
 */
export function strengthOf(bits) {
  if (bits < 40) return "weak";
  if (bits < 64) return "fair";
  return bits < 100 ? "strong" : "very_strong";
}

/** The codes of a refused generation that have a text of their own (`generator.error.<code>`). */
export const ERROR_CODES = Object.freeze(["generator_options", "invalid_input"]);

/** How long a value waits for the form of the new item: one click and one page change. */
export const HANDOFF_TTL_MS = 60_000;

/**
 * The one place a generated value waits between the generator page and the form of a new item ("Use as new item"): in the
 * memory of the page, for one `take`, never longer than HANDOFF_TTL_MS. `take` and `clear` both empty it, so nothing can read it
 * twice. A reload of the page loses it, as it should.
 * @param {{ now?: () => number, ttlMs?: number }} [options]
 */
export function createHandoff({ now = Date.now, ttlMs = HANDOFF_TTL_MS } = {}) {
  /** @type {{ value: string, until: number } | null} */
  let held = null;
  return {
    /** @param {string} value */
    put(value) {
      held = { value, until: now() + ttlMs };
    },
    /** The value, once; null when there is none or it has waited too long. @returns {string | null} */
    take() {
      const mine = held;
      held = null;
      return mine !== null && now() < mine.until && mine.until - now() <= ttlMs ? mine.value : null;
    },
    clear() {
      held = null;
    },
  };
}

/** The handoff of this page. */
export const generatedHandoff = createHandoff();
