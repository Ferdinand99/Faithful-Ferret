// The generator tab of the popup (design document, section 10.2), in a build
// with saving from the extension on: a new password or passphrase from the core,
// its strength, "Copy" and "Fill in the page".
//
// Nothing here makes a password. The page asks the background (`generate`),
// which asks the core, and shows what comes back. The value arrives once, in
// the reply of `generate`; "Copy" and "Fill in the page" name the
// `generation_id`, so the value never goes back to the background and never to
// a page from here. Only the options are kept by the popup, in `storage.local`
// (length, classes, words): never a value. The background keeps the value until
// the vault locks or 15 minutes pass; a popup that is opened again shows it
// again (`generate { current: true }`) instead of making a new one.
//
// The page that is filled is the active tab's, named by the popup (`tabId`). The
// background fills only the new and the confirm field of a sign-up, change or
// reset form of that tab, with the same frame rules as "Fill". After a fill the
// background holds an offer to save the value, and the page is told (`onOffer`)
// so the popup can show the save card at once.

import { el, mount } from "../shared/dom.mjs";
import { FEATURES } from "../shared/features.mjs";
import { UiError } from "./ui.mjs";

/** @typedef {import("./page.mjs").Texts} Texts */

/** The key of the options in `storage.local`. */
export const OPTIONS_KEY = "generator_options";

/** The defaults: a password of 20 characters from all four classes with at least one of each; a passphrase of 5 words. */
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

/** The bounds of the choices (the core's). */
export const LENGTH_RANGE = Object.freeze({ min: 4, max: 128 });
export const WORDS_RANGE = Object.freeze({ min: 3, max: 20 });
export const SEPARATORS = Object.freeze(["-", ".", "_", " "]);

/** The reasons the page has a text for (`generator.error.<reason>`); any other is `unknown`. */
export const ERROR_REASONS = Object.freeze([
  "not_offered",
  "nothing_kept",
  "invalid_input",
  "origin_changed",
  "busy",
  "frame_gone",
  "no_report",
  "no_fields",
  "no_answer",
  "value_too_long",
  "wrong_kind",
  "covered",
  "frame_hidden",
  "frame_unchecked",
  "field_too_short",
  "insecure_page",
  "clipboard",
  "not_cleared",
  "vault_locked",
  "unknown",
]);

/** The i18n key of the text of a refused action. @param {unknown} reason */
export const errorKey = (reason) => `generator.error.${typeof reason === "string" && ERROR_REASONS.includes(reason) ? reason : "unknown"}`;

/**
 * The strength word for an estimate in bits.
 * @param {number} bits
 * @returns {"weak" | "fair" | "strong" | "very_strong"}
 */
export function strengthOf(bits) {
  if (bits < 40) return "weak";
  if (bits < 64) return "fair";
  return bits < 100 ? "strong" : "very_strong";
}

/** @param {unknown} n @param {number} min @param {number} max @param {number} fallback */
const whole = (n, min, max, fallback) => (typeof n === "number" && Number.isInteger(n) && n >= min && n <= max ? n : fallback);
/** @param {unknown} b @param {boolean} fallback */
const flag = (b, fallback) => (typeof b === "boolean" ? b : fallback);

/**
 * The options of a stored value, with the default for anything that is missing or out of range (a stored value is
 * never trusted). At least one class of characters is always on.
 * @param {unknown} raw
 */
export function readOptions(raw) {
  const o = typeof raw === "object" && raw !== null ? /** @type {Record<string, unknown>} */ (raw) : {};
  const d = DEFAULT_OPTIONS;
  const classes = { lower: flag(o.lower, d.lower), upper: flag(o.upper, d.upper), digits: flag(o.digits, d.digits), symbols: flag(o.symbols, d.symbols) };
  if (!Object.values(classes).some(Boolean)) Object.assign(classes, { lower: true, upper: true, digits: true, symbols: true });
  return {
    kind: o.kind === "passphrase" ? /** @type {"password" | "passphrase"} */ ("passphrase") : /** @type {"password" | "passphrase"} */ ("password"),
    length: whole(o.length, LENGTH_RANGE.min, LENGTH_RANGE.max, d.length),
    ...classes,
    // One of each class that is on, as far as the length allows (the core refuses what does not fit).
    min_each: whole(o.min_each, 0, 8, d.min_each),
    avoid_ambiguous: flag(o.avoid_ambiguous, d.avoid_ambiguous),
    words: whole(o.words, WORDS_RANGE.min, WORDS_RANGE.max, d.words),
    separator: typeof o.separator === "string" && SEPARATORS.includes(o.separator) ? o.separator : d.separator,
    capitalize: flag(o.capitalize, d.capitalize),
    number: flag(o.number, d.number),
  };
}

/** @typedef {ReturnType<typeof readOptions>} Options */

/**
 * The body of `generate` for the options: only the keys of the chosen kind.
 * @param {Options} o
 */
export function requestOf(o) {
  if (o.kind === "passphrase") return { kind: o.kind, words: o.words, separator: o.separator, capitalize: o.capitalize, number: o.number };
  return {
    kind: o.kind,
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
 * @typedef {{ generationId: string, value: string, kind: string, bits: number, expiresAt: number }} Generated
 * @typedef {{ ok: true, generated: Generated } | { ok: false, reason: string }} Made
 */

/** @param {any} reply @returns {Made} */
function madeOf(reply) {
  if (reply?.ok !== true || typeof reply.value !== "string" || typeof reply.generation_id !== "string") {
    return { ok: false, reason: typeof reply?.reason === "string" ? reply.reason : "unknown" };
  }
  return { ok: true, generated: { generationId: reply.generation_id, value: reply.value, kind: reply.kind, bits: reply.bits ?? 0, expiresAt: reply.expires_at ?? 0 } };
}

/** @param {unknown} failure */
const reasonOf = (failure) => (failure instanceof UiError ? failure.code : "unknown");

/**
 * The generator's requests, with no DOM.
 * @param {(type: string, body: Record<string, unknown>) => Promise<any>} request
 */
export function createGeneratorFlow(request) {
  return {
    /** A new value with the options. @param {Options} options @returns {Promise<Made>} */
    async generate(options) {
      try {
        return madeOf(await request("generate", requestOf(options)));
      } catch (failure) {
        return { ok: false, reason: reasonOf(failure) };
      }
    },

    /** The value the background still holds (the popup was closed and opened again). @returns {Promise<Made>} */
    async current() {
      try {
        return madeOf(await request("generate", { current: true }));
      } catch (failure) {
        return { ok: false, reason: reasonOf(failure) };
      }
    },

    /**
     * "Fill in the page": the generation, the tab, never the value.
     * @param {string} generationId @param {number} tabId
     * @returns {Promise<{ ok: boolean, reason?: string, length?: number, offer?: boolean }>}
     */
    async fill(generationId, tabId) {
      try {
        const reply = await request("fill_generated", { generation_id: generationId, tab_id: tabId });
        return reply.ok === true ? { ok: true, ...(reply.length !== undefined ? { length: reply.length } : {}), offer: reply.offer === true } : { ok: false, reason: reply.reason };
      } catch (failure) {
        return { ok: false, reason: reasonOf(failure) };
      }
    },

    /** "Copy": the generation, never the value. @param {string} generationId @returns {Promise<{ ok: boolean, reason?: string }>} */
    async copy(generationId) {
      try {
        const reply = await request("generate_copy", { generation_id: generationId });
        return reply.ok === true ? { ok: true } : { ok: false, reason: reply.reason };
      } catch (failure) {
        return { ok: false, reason: reasonOf(failure) };
      }
    },
  };
}

/**
 * The popup's own storage of the options (`storage.local`): never a value.
 * @param {{ get(key: string): Promise<Record<string, unknown>>, set(items: Record<string, unknown>): Promise<void> }} area
 */
export function createOptionsStore(area) {
  return {
    /** @returns {Promise<Options>} */
    async load() {
      try {
        return readOptions((await area.get(OPTIONS_KEY))?.[OPTIONS_KEY]);
      } catch {
        return readOptions(null);
      }
    },
    /** @param {Options} options */
    async save(options) {
      try {
        await area.set({ [OPTIONS_KEY]: options });
      } catch {
        // The options are a convenience: a popup that cannot keep them uses them for this visit.
      }
    },
  };
}

/** @param {unknown} node @returns {any} */
const asAny = (node) => /** @type {any} */ (node);

/**
 * The generator's part of the popup. Null in a build without the feature.
 *
 * @param {{
 *   texts: Texts,
 *   flow: ReturnType<typeof createGeneratorFlow>,
 *   store: ReturnType<typeof createOptionsStore>,
 *   tabId: number | null,
 *   onOffer?: () => void,
 * }} deps `tabId`: the tab whose page is filled (null: the popup is about no page); `onOffer`: the background holds an
 *   offer to save the value that was just filled
 * @returns {{ root: HTMLElement, ready: Promise<void>, shown: () => Generated | null } | null}
 */
export function createGeneratorView({ texts, flow, store, tabId, onOffer = () => {} }) {
  if (!FEATURES.save) return null;
  /** @type {Options} */
  let options = readOptions(null);
  /** @type {Generated | null} */
  let generated = null;
  let busy = false;

  const status = el("p", { class: "ff-gen-status", role: "status", "data-role": "generator-status", hidden: true });
  const valueBox = el("output", { class: "ff-gen-value", dir: "ltr", "data-role": "generated-value" });
  const strength = el("p", { class: "ff-gen-strength ff-hint", "data-role": "generator-strength" });
  const optionsBox = el("div", { class: "ff-gen-options", "data-role": "generator-options" });

  /** @param {string | null} text @param {"info" | "bad"} [tone] */
  function say(text, tone = "info") {
    status.textContent = text ?? "";
    status.hidden = text === null;
    status.setAttribute("data-tone", tone);
  }
  /** @param {unknown} reason */
  const fail = (reason) => {
    const key = reason === "frame_unchecked" ? "generator.error.frame_unchecked" : errorKey(reason);
    say(texts.t(key), "bad");
  };

  function showValue() {
    valueBox.textContent = generated?.value ?? "";
    strength.textContent = generated === null ? "" : texts.t("generator.strength", { strength: texts.t(`generator.strength.${strengthOf(generated.bits)}`), bits: generated.bits });
    for (const [button, off] of /** @type {Array<[HTMLElement, boolean]>} */ ([[fill, generated === null || tabId === null], [copy, generated === null]])) {
      if (off) button.setAttribute("disabled", "");
      else button.removeAttribute("disabled");
    }
  }

  /** @param {() => Promise<void>} job */
  async function exclusive(job) {
    if (busy) return;
    busy = true;
    try {
      await job();
    } finally {
      busy = false;
    }
  }

  async function make() {
    say(null);
    const made = await flow.generate(options);
    if (!made.ok) {
      fail(made.reason);
      return;
    }
    generated = made.generated;
    showValue();
  }

  /** @param {Partial<Options>} change @param {boolean} [again] */
  async function choose(change, again = true) {
    options = readOptions({ ...options, ...change });
    await store.save(options);
    if (again) await exclusive(make);
    renderOptions();
  }

  /**
   * One checkbox of the options.
   * @param {keyof Options} key @param {string} label
   */
  function toggle(key, label) {
    const input = asAny(el("input", { type: "checkbox", "data-role": `option-${key}` }));
    input.checked = options[key] === true;
    input.addEventListener("change", () => void choose({ [key]: input.checked }));
    return el("label", { class: "ff-check ff-gen-check" }, input, el("span", null, label));
  }

  function renderOptions() {
    /** @type {Array<HTMLElement>} */
    const rows = [];
    const kinds = el("div", { class: "ff-gen-kinds", role: "group", "aria-label": texts.t("generator.mode.label") });
    for (const kind of /** @type {const} */ (["password", "passphrase"])) {
      const button = el(
        "button",
        { type: "button", class: "ff-gen-kind", "data-role": `kind-${kind}`, "aria-pressed": options.kind === kind ? "true" : "false" },
        texts.t(`generator.mode.${kind}`),
      );
      button.addEventListener("click", () => void choose({ kind }));
      kinds.append(button);
    }
    rows.push(kinds);
    if (options.kind === "password") {
      const length = asAny(el("input", { id: "gen-length", class: "ff-input", type: "number", min: LENGTH_RANGE.min, max: LENGTH_RANGE.max, "data-role": "option-length" }));
      length.value = String(options.length);
      length.addEventListener("change", () => void choose({ length: Number(length.value) }));
      rows.push(el("div", { class: "ff-field" }, el("label", { for: "gen-length", class: "ff-label" }, texts.t("generator.options.length")), length));
      rows.push(toggle("upper", texts.t("generator.options.upper")), toggle("lower", texts.t("generator.options.lower")), toggle("digits", texts.t("generator.options.digits")), toggle("symbols", texts.t("generator.options.symbols")));
      rows.push(toggle("avoid_ambiguous", texts.t("generator.options.avoid_ambiguous")));
    } else {
      const words = asAny(el("input", { id: "gen-words", class: "ff-input", type: "number", min: WORDS_RANGE.min, max: WORDS_RANGE.max, "data-role": "option-words" }));
      words.value = String(options.words);
      words.addEventListener("change", () => void choose({ words: Number(words.value) }));
      rows.push(el("div", { class: "ff-field" }, el("label", { for: "gen-words", class: "ff-label" }, texts.t("generator.options.words")), words));
      const separator = asAny(el("select", { id: "gen-separator", class: "ff-input", "data-role": "option-separator" }, ...SEPARATORS.map((s) => el("option", { value: s, selected: s === options.separator }, texts.t(`generator.options.separator.${s === " " ? "space" : s === "-" ? "hyphen" : s === "." ? "period" : "underscore"}`)))));
      separator.value = options.separator;
      separator.addEventListener("change", () => void choose({ separator: separator.value }));
      rows.push(el("div", { class: "ff-field" }, el("label", { for: "gen-separator", class: "ff-label" }, texts.t("generator.options.separator")), separator));
      rows.push(toggle("capitalize", texts.t("generator.options.capitalize")), toggle("number", texts.t("generator.options.number")));
    }
    mount(optionsBox, ...rows);
  }

  const regenerate = el("button", { type: "button", class: "ff-button", "data-role": "regenerate" }, texts.t("generator.regenerate"));
  regenerate.addEventListener("click", () => void exclusive(make));

  const copy = el("button", { type: "button", class: "ff-button", "data-role": "copy", disabled: true }, texts.t("generator.copy"));
  copy.addEventListener("click", () =>
    exclusive(async () => {
      if (generated === null) return;
      const done = await flow.copy(generated.generationId);
      if (done.ok) say(texts.t("generator.copied"));
      else if (done.reason === "not_cleared") say(texts.t("generator.error.not_cleared"), "bad");
      else fail(done.reason);
    }),
  );

  const fill = el("button", { type: "button", class: "ff-button ff-primary", "data-role": "fill", disabled: true }, texts.t("generator.fill"));
  fill.addEventListener("click", () =>
    exclusive(async () => {
      if (generated === null || tabId === null) return;
      say(null);
      const done = await flow.fill(generated.generationId, tabId);
      if (!done.ok) {
        fail(done.reason);
        return;
      }
      // A field that takes fewer characters than the value made a shorter one: show what is in the page now.
      if (done.length !== undefined && done.length < generated.value.length) {
        const now = await flow.current();
        if (now.ok) generated = now.generated;
        showValue();
        say(texts.t("generator.filled_short", { length: done.length }));
      } else {
        say(texts.t("generator.filled"));
      }
      if (done.offer === true) onOffer();
    }),
  );

  const root = el(
    "section",
    { class: "ff-gen", "data-role": "generator", "data-feature": "save" },
    el("h2", { class: "ff-gen-title" }, texts.t("generator.title")),
    valueBox,
    strength,
    el("div", { class: "ff-actions ff-gen-actions" }, fill, copy, regenerate),
    tabId === null ? el("p", { class: "ff-hint", "data-role": "generator-no-page" }, texts.t("generator.no_page")) : null,
    status,
    optionsBox,
    el("p", { class: "ff-hint ff-gen-keep", "data-role": "generator-keep" }, texts.t("generator.keep")),
  );

  renderOptions();
  const ready = (async () => {
    options = await store.load();
    renderOptions();
    // The value the background still holds, else a new one.
    const held = await flow.current();
    if (held.ok) {
      generated = held.generated;
      showValue();
      return;
    }
    await exclusive(make);
  })();

  return { root, ready, shown: () => generated };
}
