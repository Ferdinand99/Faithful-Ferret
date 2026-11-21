// DOM helpers of the sign-in tab and the popup: the texts in the user's
// language, and the small pieces both pages build with `el()` (no markup from
// strings, ever).

import { el } from "../shared/dom.mjs";
import { SUPPORTED_LANGUAGES, createI18n, negotiate } from "../shared/i18n.mjs";

/** @typedef {{ t(key: string, vars?: Record<string, string | number>): string, lang: string }} Texts */

/** @param {string} lang @returns {Promise<Record<string, string>>} */
async function catalog(lang) {
  const response = await fetch(browser.runtime.getURL(`locales.${lang}.json`));
  if (!response.ok) return {};
  return response.json();
}

/**
 * The texts of the page in the user's language (English as the fallback), and
 * the language set on the document.
 * @returns {Promise<Texts>}
 */
export async function loadTexts() {
  const lang = negotiate(navigator.languages ?? [navigator.language], SUPPORTED_LANGUAGES);
  const [en, own] = await Promise.all([catalog("en"), lang === "en" ? Promise.resolve(null) : catalog(lang)]);
  const texts = createI18n(own === null ? { en } : { en, [lang]: own }, lang);
  document.documentElement.lang = texts.lang;
  return texts;
}

/**
 * Sets the visible text and the accessible names that the static HTML marks
 * with `data-i18n` and `data-i18n-label`.
 * @param {ParentNode} root
 * @param {Texts} texts
 */
export function translateStatic(root, texts) {
  for (const node of root.querySelectorAll("[data-i18n]")) node.textContent = texts.t(node.getAttribute("data-i18n") ?? "");
  for (const node of root.querySelectorAll("[data-i18n-label]")) {
    const label = texts.t(node.getAttribute("data-i18n-label") ?? "");
    node.setAttribute("aria-label", label);
    node.setAttribute("title", label);
  }
}

/**
 * A labelled input. The id ties the label to it.
 * @param {{ id: string, label: string, role: string, type?: string, autocomplete?: string, inputmode?: string, placeholder?: string, hint?: string }} o
 * @returns {{ row: HTMLElement, input: HTMLInputElement }}
 */
export function field({ id, label, role, type = "text", autocomplete = "off", inputmode, placeholder, hint }) {
  const input = /** @type {HTMLInputElement} */ (
    el("input", {
      id,
      type,
      class: "ff-input",
      autocomplete,
      inputmode: inputmode ?? null,
      placeholder: placeholder ?? null,
      "data-role": role,
    })
  );
  const row = el(
    "div",
    { class: "ff-field" },
    el("label", { for: id, class: "ff-label" }, label),
    input,
    hint ? el("p", { class: "ff-hint" }, hint) : null,
  );
  return { row, input };
}

/** The box that shows a reason, read out when it changes. */
export function errorBox() {
  return el("p", { class: "ff-error", role: "alert", "data-role": "error", hidden: true });
}

/**
 * Shows the text of a reason in `box`, or hides it.
 * @param {HTMLElement} box
 * @param {Texts} texts
 * @param {string | null} key the i18n key, or null to hide
 */
export function showError(box, texts, key) {
  box.textContent = key === null ? "" : texts.t(key);
  box.hidden = key === null;
}
