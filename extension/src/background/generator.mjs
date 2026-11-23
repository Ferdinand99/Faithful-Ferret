// The generator of the popup (design document, sections 7.2 and 10.2): what the
// background keeps of a password or passphrase it asked the core for, and the
// operations around it.
//
// Nothing here makes a password. The one source of a value is the core's
// `generate_password` / `generate_passphrase` (WASM, the operating system's
// random numbers, rejection sampling); this module calls them through the
// client the core host gives an operation, and keeps what they answer. It
// imports no randomness: the random name of a generation (`newId`) is given in
// by the entry point, as the fill flow's ids are.
//
// What is kept: the value, under a random `generation_id`, in the memory of the
// background page only, until the vault locks or 15 minutes of wall clock have
// passed (checked on every access: a timer stands still while the computer
// sleeps). Never on disk, never in a log. At most MAX_GENERATIONS are held, the
// oldest goes first. The popup gets the value once, in the reply of `generate`,
// to show it; "Fill" and "Copy" name the `generation_id`, so the value never
// travels from a page of the extension to the background. The popup's options
// (length, classes, words) are the popup's own business in `storage.local`;
// they are sent with each request and are never a value.
//
// Only with the feature `save` on: a build without it refuses every operation
// of this module (`not_available`).

import { FEATURES } from "../shared/features.mjs";

/** How long a generated value is kept: 15 minutes. */
export const GENERATION_TTL_MS = 900_000;

/** The most generations held at once. */
export const MAX_GENERATIONS = 8;

/** The core's limit for a password; the shortest a generated one is made to fit a field is `MIN_FIT`. */
export const MIN_FIT = 8;

const PASSWORD_KEYS = Object.freeze(["length", "lower", "upper", "digits", "symbols", "min_each", "avoid_ambiguous"]);
const PASSPHRASE_KEYS = Object.freeze(["words", "separator", "capitalize", "number"]);

const ID = /^[A-Za-z0-9_-]{1,64}$/;

/** @param {string} code */
const fail = (code) => Object.assign(new Error(code), { code });

/**
 * @typedef {{
 *   id: string, value: string, kind: "password" | "passphrase", bits: number, options: Record<string, unknown>,
 *   expiresAt: number,
 * }} Generation
 */

/**
 * The held generations. Every read checks the wall clock.
 *
 * @param {{ now?: () => number, newId: () => string, ttlMs?: number, max?: number }} options
 */
export function createGenerations({ now = Date.now, newId, ttlMs = GENERATION_TTL_MS, max = MAX_GENERATIONS }) {
  /** @type {Generation[]} */
  let held = [];

  /** Drops what has expired (and anything from a clock that went back). */
  const prune = () => {
    const t = now();
    held = held.filter((g) => t < g.expiresAt && g.expiresAt - t <= ttlMs);
  };

  return {
    /**
     * @param {{ value: string, kind: "password" | "passphrase", bits: number, options: Record<string, unknown> }} made
     * @returns {Generation}
     */
    put({ value, kind, bits, options }) {
      prune();
      const id = newId();
      if (!ID.test(id)) throw fail("internal");
      const entry = Object.freeze({ id, value, kind, bits, options: Object.freeze({ ...options }), expiresAt: now() + ttlMs });
      held.push(entry);
      while (held.length > max) held.shift();
      return entry;
    },

    /** @param {unknown} id @returns {Generation | null} */
    get(id) {
      prune();
      return typeof id === "string" ? (held.find((g) => g.id === id) ?? null) : null;
    },

    /** The newest generation that is still held, or null. @returns {Generation | null} */
    current() {
      prune();
      return held.at(-1) ?? null;
    },

    /**
     * Replaces the value of a generation (a password shortened to fit a field); the lifetime does not restart.
     * @param {string} id @param {{ value: string, bits: number, options: Record<string, unknown> }} next
     * @returns {Generation | null}
     */
    replace(id, { value, bits, options }) {
      prune();
      const at = held.findIndex((g) => g.id === id);
      if (at < 0) return null;
      const entry = Object.freeze({ ...held[at], value, bits, options: Object.freeze({ ...options }) });
      held[at] = entry;
      return entry;
    },

    /** Forgets every generation (every lock). */
    clear() {
      held = [];
    },

    size: () => held.length,
  };
}

/** The options the core takes for a request of the popup, or `invalid_input`. @param {Record<string, any>} args */
function optionsOf(args) {
  const keys = args.kind === "passphrase" ? PASSPHRASE_KEYS : PASSWORD_KEYS;
  /** @type {Record<string, unknown>} */
  const options = {};
  for (const key of keys) {
    if (args[key] === undefined) throw fail("invalid_input");
    options[key] = args[key];
  }
  return options;
}

/** @param {unknown} error @returns {never} */
function refuse(error) {
  const code = /** @type {{ code?: unknown }} */ (error)?.code;
  // The core says `generator_options` for options out of range; to the page that is a bad request.
  throw fail(code === "generator_options" || code === "invalid_input" ? "invalid_input" : typeof code === "string" ? code : "internal");
}

/**
 * Asks the core for one value.
 * @param {any} vault the client's vault side
 * @param {"password" | "passphrase"} kind @param {Record<string, unknown>} options
 * @returns {Promise<{ value: string, bits: number }>}
 */
async function makeValue(vault, kind, options) {
  const made = await (kind === "passphrase" ? vault.generate_passphrase(options) : vault.generate_password(options));
  if (typeof made?.value !== "string" || made.value === "" || !Number.isFinite(made?.bits)) throw fail("internal");
  return { value: made.value, bits: Math.max(0, Math.round(made.bits)) };
}

/**
 * The reply that shows a generation to the popup: the only reply that carries a value.
 * @param {Generation} g
 */
const shown = (g) => ({ ok: true, generation_id: g.id, value: g.value, kind: g.kind, bits: g.bits, expires_at: g.expiresAt });

/**
 * The generator's operations of the core host: `generate` (a new value, or with `current` the one still held) and
 * `generate_copy`. Call `attach` once the core host exists.
 *
 * @param {{
 *   now?: () => number,
 *   newId: () => string,
 *   clipboard: { copy(text: string): Promise<void> },
 *   ttlMs?: number,
 * }} options `newId` makes a random id (16 random bytes as hex); the tests pass their own
 */
export function createGeneratorHost({ now = Date.now, newId, clipboard, ttlMs = GENERATION_TTL_MS }) {
  const generations = createGenerations({ now, newId, ttlMs });
  /** The core host, set by `attach`. @type {any} */
  let host = null;

  const gate = () => {
    if (!FEATURES.save) throw fail("not_available");
  };

  /** @type {import("./coreHost.mjs").CoreOp} */
  const generate = {
    vault: true,
    worker: "vault",
    async run(client, args) {
      gate();
      if (args?.current === true) {
        const held = generations.current();
        return held === null ? { ok: false, reason: "nothing_kept" } : shown(held);
      }
      if (args?.kind !== "password" && args?.kind !== "passphrase") throw fail("invalid_input");
      const options = optionsOf(args);
      const { value, bits } = await makeValue(client.vault, args.kind, options).catch(refuse);
      return shown(generations.put({ value, kind: args.kind, bits, options }));
    },
  };

  /** @type {import("./coreHost.mjs").CoreOp} */
  const generateCopy = {
    vault: true,
    worker: "vault",
    async run(_client, args) {
      gate();
      const held = generations.get(args?.generation_id);
      if (held === null) return { ok: false, reason: "not_offered" };
      try {
        await clipboard.copy(held.value);
      } catch (error) {
        const code = /** @type {{ code?: unknown }} */ (error)?.code;
        return { ok: false, reason: code === "not_cleared" ? "not_cleared" : "clipboard" };
      }
      return { ok: true };
    },
  };

  return {
    ops: Object.freeze({ generate, generate_copy: generateCopy }),
    generations,

    /**
     * Joins the core host: every lock forgets every generation.
     * @param {{ liveClient(options?: { open?: boolean }): any, onLocked(listener: () => void): unknown }} coreHost
     */
    attach(coreHost) {
      host = coreHost;
      coreHost.onLocked(() => generations.clear());
    },

    /** What the fill flow reads: the held generation `id`, or null (it expired, or the vault locked). @param {unknown} id */
    get: (id) => generations.get(id),

    /**
     * Makes the generation `id` fit a field that takes at most `limit` characters: a password is made again by the
     * core at that length (never shorter than MIN_FIT), a passphrase is never cut. The generation keeps its id and its
     * lifetime. `{ ok: false }` when it cannot fit.
     * @param {string} id @param {number} limit
     * @returns {Promise<{ ok: true } | { ok: false }>}
     */
    async fit(id, limit) {
      gate();
      const held = generations.get(id);
      if (held === null || held.kind !== "password" || !Number.isSafeInteger(limit) || limit < MIN_FIT) return { ok: false };
      if (host === null) return { ok: false };
      const options = { ...held.options, length: limit };
      try {
        const { value, bits } = await makeValue(host.liveClient({ open: true }).vault, "password", options);
        return generations.replace(id, { value, bits, options }) === null ? { ok: false } : { ok: true };
      } catch {
        return { ok: false };
      }
    },
  };
}
