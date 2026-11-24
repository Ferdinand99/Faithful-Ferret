// `#/generator`: a new password or passphrase.
//
// Nothing here makes a password, and no randomness is imported or called: the value comes from the core's
// `generate_password` / `generate_passphrase`, asked through the crypto client (they run in the vault worker with the
// operating system's random numbers). This page chooses the options, shows what comes back and hands it on.
//
// The options (length, classes, words, separator) are kept on this device (generatorPrefs.mjs), and nothing else: never the value
// (generatorModel.mjs). The value lives in this page only. It is wiped, and a call that is still on its way is dropped, when the
// vault locks (the screen's wipe scope: also a sign-out and another tab taking the vault), when the address leaves this page,
// and when the page is taken off the screen. It is never in an address, a store, a message or a log.
//
// "Copy" is the clipboard path of the item page (`navigator.clipboard.writeText`, with the same text). "Use as new item" puts the
// value in the one-shot handoff (generatorModel.mjs) and opens the form of a new item, which takes it once.
import { el, mount } from "../dom.mjs";
import { describeError, codeOf } from "./common.mjs";
import { createOptionsStore } from "../generatorPrefs.mjs";
import { secretClipboardFor } from "../secretClipboard.mjs";
import {
  CLASSES, ERROR_CODES, LENGTH_RANGE, SEPARATORS, SEPARATOR_NAMES, WORDS_RANGE, generatedHandoff, makeValue, readOptions, strengthOf,
} from "./generatorModel.mjs";

/** The path of this page, as the address holds it. */
export const GENERATOR_PATH = "/generator";

/** @param {unknown} node @returns {any} */
const asAny = (node) => node;

/**
 * @param {{
 *   t: import("./common.mjs").Translate,
 *   client: { vault: Record<string, (...args: any[]) => Promise<any>> },
 *   store?: ReturnType<typeof createOptionsStore>,
 *   handoff?: ReturnType<typeof import("./generatorModel.mjs").createHandoff>,
 *   go?: (path: string) => void,
 *   touch?: () => boolean,
 *   scope?: { add(fn: () => void): () => void },
 *   clipboard?: { writeText(text: string): Promise<void> } | null,
 *   win?: any,
 * }} options `store` keeps the options (the page's own storage by default); `handoff` is where "Use as new item" leaves the value;
 *   `win` is the window whose address is watched
 * @returns {HTMLElement}
 */
export function generatorView({
  t, client, store = createOptionsStore(), handoff = generatedHandoff, go = () => {}, touch = () => true, scope,
  clipboard = globalThis.navigator?.clipboard ?? null, win = globalThis.window ?? globalThis,
}) {
  let options = store.read();
  /** The value on the page, or null. It is held here and in the text of the value box, and nowhere else. @type {string | null} */
  let value = null;
  let bits = 0;
  /** Counts the calls: a reply that is not the newest one is dropped. A wipe counts too, so a reply after it is dropped as well. */
  let token = 0;
  /** The page was wiped: it makes no more values. */
  let dead = false;

  const secrets = secretClipboardFor(clipboard);

  const root = el("section", { class: "generator-page", "data-role": "generator-page" });

  // ---- the value
  const valueBox = el("output", {
    class: "gen-value", dir: "ltr", "aria-live": "polite", "aria-atomic": "true", "aria-label": t("generator.value_label"), "data-role": "generated-value",
  });
  const strength = el("p", { class: "gen-strength", "data-role": "generator-strength" });
  const status = el("p", { class: "status", role: "status", "data-role": "generator-status" });
  const errorBox = el("p", { class: "error", role: "alert", "data-role": "generator-error" });
  errorBox.hidden = true;

  const regenerate = asAny(el("button", { type: "button", class: "btn btn-secondary", "data-role": "regenerate" }, t("generator.regenerate")));
  const copy = asAny(el("button", { type: "button", class: "btn btn-secondary i-copy", "data-role": "copy" }, t("generator.copy")));
  const useAsNew = asAny(el("button", { type: "button", class: "btn btn-primary i-plus", "data-role": "use-as-new" }, t("generator.new_item")));

  /** @param {string | null} text */
  function say(text) {
    mount(status, ...(text === null ? [] : [document.createTextNode(text)]));
  }
  /** @param {string | null} text */
  function problem(text) {
    mount(errorBox, ...(text === null ? [] : [document.createTextNode(text)]));
    errorBox.hidden = text === null;
  }
  /** @param {unknown} error */
  function describe(error) {
    return ERROR_CODES.includes(codeOf(error)) ? t("generator.error.options") : describeError(t, error);
  }

  function showValue() {
    mount(valueBox, ...(value === null ? [] : [document.createTextNode(value)]));
    if (value === null) {
      mount(strength);
      strength.setAttribute("data-level", "none");
    } else {
      const level = strengthOf(bits);
      mount(strength, document.createTextNode(t("generator.strength", { strength: t(`generator.strength.${level}`), bits })));
      strength.setAttribute("data-level", level);
    }
    for (const button of [copy, useAsNew]) button.disabled = value === null;
  }

  /** Forgets the value, drops any call on its way, and leaves nothing to make another. */
  function wipe() {
    dead = true;
    token += 1;
    value = null;
    bits = 0;
    showValue();
    say(null);
    problem(null);
  }

  async function make() {
    if (dead) return;
    token += 1;
    const mine = token;
    problem(null);
    say(null);
    valueBox.setAttribute("aria-busy", "true");
    try {
      const made = await makeValue(client, options);
      if (mine !== token || dead) return;
      value = made.value;
      bits = made.bits;
    } catch (error) {
      if (mine !== token || dead) return;
      value = null;
      bits = 0;
      problem(describe(error));
    } finally {
      if (mine === token) valueBox.setAttribute("aria-busy", "false");
    }
    showValue();
  }

  // ---- the options
  const kindButtons = /** @type {Record<string, any>} */ ({});
  const kinds = el("div", { class: "gen-kinds", role: "group", "aria-label": t("generator.mode.label"), "data-role": "generator-kinds" });
  for (const kind of /** @type {const} */ (["password", "passphrase"])) {
    const button = el("button", { type: "button", class: "gen-kind", "aria-pressed": "false", "data-role": `kind-${kind}` }, t(`generator.mode.${kind}`));
    button.addEventListener("click", () => {
      if (!touch()) return;
      choose({ kind });
    });
    kindButtons[kind] = button;
    kinds.appendChild(button);
  }

  /** A whole number from a box, held to the range; null when the box holds no number. @param {unknown} text @param {{ min: number, max: number }} range */
  function clamped(text, range) {
    const n = Math.round(Number(text));
    return typeof text === "string" && text.trim() !== "" && Number.isFinite(n) ? Math.min(range.max, Math.max(range.min, n)) : null;
  }

  /**
   * A length-like choice: a slider and a box that say the same thing. The slider makes a new value when it is let go (or
   * moved by key), the box when it is left.
   * @param {{ key: "length" | "words", id: string, range: { min: number, max: number }, label: string, sliderLabel: string }} spec
   */
  function amount({ key, id, range, label, sliderLabel }) {
    const slider = asAny(el("input", {
      id: `${id}-range`, type: "range", min: range.min, max: range.max, step: 1, "aria-label": sliderLabel, "data-role": `option-${key}-range`,
    }));
    const box = asAny(el("input", { id, type: "number", class: "gen-number", min: range.min, max: range.max, step: 1, inputmode: "numeric", "data-role": `option-${key}` }));
    slider.addEventListener("input", () => {
      const n = clamped(slider.value, range);
      if (n !== null) box.value = String(n);
    });
    slider.addEventListener("change", () => {
      if (!touch()) return;
      choose({ [key]: clamped(slider.value, range) ?? options[key] });
    });
    box.addEventListener("change", () => {
      if (!touch()) return;
      choose({ [key]: clamped(box.value, range) ?? options[key] });
    });
    return {
      slider, box,
      row: el("div", { class: "field", "data-field": key },
        el("label", { for: id }, label),
        el("div", { class: "gen-amount" }, slider, box)),
    };
  }

  /** @param {string} key @param {string} label @param {(checked: boolean) => Record<string, unknown>} [change] what a click changes (the option of the same name by default) */
  function toggle(key, label, change = (checked) => ({ [key]: checked })) {
    const id = `gen-${key}`;
    const input = asAny(el("input", { id, type: "checkbox", "data-role": `option-${key}` }));
    input.addEventListener("change", () => {
      if (!touch()) return;
      choose(change(input.checked === true));
    });
    return { input, row: el("div", { class: "choice" }, input, el("label", { for: id }, label)) };
  }

  const length = amount({ key: "length", id: "gen-length", range: LENGTH_RANGE, label: t("generator.options.length"), sliderLabel: t("generator.options.length_slider") });
  const classBoxes = Object.fromEntries(CLASSES.map((name) => [name, toggle(name, t(`generator.options.${name}`))]));
  const everyKind = toggle("min_each", t("generator.options.min_each"), (checked) => ({ min_each: checked ? 1 : 0 }));
  const ambiguous = toggle("avoid_ambiguous", t("generator.options.avoid_ambiguous"));
  const passwordPanel = el("div", { class: "stack", "data-role": "options-password" },
    length.row,
    el("div", { class: "gen-classes", role: "group", "aria-label": t("generator.options.classes") }, ...CLASSES.map((name) => classBoxes[name].row)),
    everyKind.row, ambiguous.row);

  const words = amount({ key: "words", id: "gen-words", range: WORDS_RANGE, label: t("generator.options.words"), sliderLabel: t("generator.options.words_slider") });
  const separator = asAny(el("select", { id: "gen-separator", name: "separator", "data-role": "option-separator" },
    ...SEPARATORS.map((s) => el("option", { value: s }, t(`generator.options.separator.${SEPARATOR_NAMES[/** @type {keyof typeof SEPARATOR_NAMES} */ (s)]}`)))));
  separator.addEventListener("change", () => {
    if (!touch()) return;
    choose({ separator: separator.value });
  });
  const capitalize = toggle("capitalize", t("generator.options.capitalize"));
  const number = toggle("number", t("generator.options.number"));
  const passphrasePanel = el("div", { class: "stack", "data-role": "options-passphrase" },
    words.row,
    el("div", { class: "field", "data-field": "separator" }, el("label", { for: "gen-separator" }, t("generator.options.separator")), separator),
    capitalize.row, number.row);

  /** Puts the options on the controls (the page keeps no other copy of them). */
  function showOptions() {
    for (const [kind, button] of Object.entries(kindButtons)) button.setAttribute("aria-pressed", options.kind === kind ? "true" : "false");
    passwordPanel.hidden = options.kind !== "password";
    passphrasePanel.hidden = options.kind !== "passphrase";
    length.slider.value = String(options.length);
    length.box.value = String(options.length);
    words.slider.value = String(options.words);
    words.box.value = String(options.words);
    const on = CLASSES.filter((name) => options[name]);
    for (const name of CLASSES) {
      classBoxes[name].input.checked = options[name];
      // The last class that is on cannot be switched off: a password needs characters from somewhere.
      classBoxes[name].input.disabled = on.length === 1 && on[0] === name;
    }
    everyKind.input.checked = options.min_each > 0;
    ambiguous.input.checked = options.avoid_ambiguous;
    separator.value = options.separator;
    capitalize.input.checked = options.capitalize;
    number.input.checked = options.number;
  }

  /** @param {Record<string, unknown>} change */
  function choose(change) {
    options = readOptions({ ...options, ...change });
    store.save(options);
    showOptions();
    void make();
  }

  // ---- the buttons
  regenerate.addEventListener("click", () => {
    if (!touch()) return;
    void make();
  });

  copy.addEventListener("click", async () => {
    if (!touch() || value === null) return;
    const text = value;
    const label = t(options.kind === "passphrase" ? "generator.mode.passphrase" : "vault.edit.password");
    problem(null);
    try {
      await secrets.copy(text); // cleared again after 30 seconds, and by a lock
      if (!dead) say(t("vault.item.copied_secret", { label }));
    } catch (error) {
      if (!dead) problem(describe(error));
    }
  });

  useAsNew.addEventListener("click", () => {
    if (!touch() || value === null) return;
    handoff.put(value);
    wipe();
    go("/items/new");
  });

  // ---- the page
  mount(root,
    el("h1", null, t("generator.title")),
    el("p", { class: "gen-intro" }, t("generator.intro")),
    el("section", { class: "card stack gen-result", "aria-labelledby": "gen-result-heading", "data-role": "generator-result" },
      el("h2", { id: "gen-result-heading", class: "visually-hidden" }, t("generator.result_heading")),
      valueBox, strength,
      el("div", { class: "actions" }, copy, regenerate, useAsNew),
      status, errorBox,
      el("p", { class: "help", "data-role": "generator-keep" }, t("generator.keep"))),
    el("section", { class: "card stack gen-options", "aria-labelledby": "gen-options-heading", "data-role": "generator-options" },
      el("h2", { id: "gen-options-heading" }, t("generator.options_heading")),
      kinds, passwordPanel, passphrasePanel));
  showOptions();
  showValue();

  // ---- where the value goes when the page does
  // A lock, a sign-out and another tab taking the vault run the wipe scope of the screen.
  const removeWipe = scope?.add(wipe);
  scope?.add(() => void secrets.clearNow());
  /** The address left this page, or the page left the screen: the value goes. */
  const onHash = () => {
    const path = String(win?.location?.hash ?? "").replace(/^#/, "").split("?")[0] || "/";
    if (path === GENERATOR_PATH && asAny(root).isConnected !== false) return;
    wipe();
    win?.removeEventListener?.("hashchange", onHash);
    removeWipe?.();
  };
  win?.addEventListener?.("hashchange", onHash);

  void make();
  return root;
}
