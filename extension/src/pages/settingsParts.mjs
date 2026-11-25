// The small pieces the settings view is built from (settingsView.mjs and the sections it shows): a switch row whose whole row is
// the control, a row that opens a sub-page, the "More about this" disclosure and a page's own heading. No build flag and no
// feature mark live here: a section adds the marks of its feature through `attrs`, so a build without the feature has none.

import { el } from "../shared/dom.mjs";

/** @typedef {import("./page.mjs").Texts} Texts */
/** @typedef {Record<string, string>} Attrs */

let counter = 0;
/** A fresh id for the `aria-labelledby` and `aria-describedby` of a control. @param {string} stem */
const nextId = (stem) => `${stem}-${(counter += 1)}`;

/**
 * A switch: one button that is the whole row (`role="switch"`, `aria-checked`), with a bold title, a one-line description and, on the
 * right, a track with a knob and the words "On" or "Off", so the state never rests on colour alone. A click, Enter or Space on the row
 * turns it; the caller listens to `click` (a permission request must run straight from the click).
 * @param {{ texts: Texts, role: string, title: string, description: string, stateRole?: string, attrs?: Attrs }} spec
 * @returns {{ node: HTMLButtonElement, set: (on: boolean) => void, isOn: () => boolean, stateNode: HTMLElement }}
 */
export function createSwitchRow({ texts, role, title, description, stateRole, attrs = {} }) {
  const titleId = nextId("ff-sw-title");
  const descId = nextId("ff-sw-desc");
  const stateNode = el("span", { class: "ff-switch-text", "aria-hidden": "true", ...(stateRole ? { "data-role": stateRole } : {}), ...attrs }, texts.t("settings.off"));
  const node = /** @type {HTMLButtonElement} */ (
    el(
      "button",
      { type: "button", class: "ff-scard ff-switch-row", role: "switch", "aria-checked": "false", "aria-labelledby": titleId, "aria-describedby": descId, "data-role": role, ...attrs },
      el("span", { class: "ff-scard-text" }, el("span", { class: "ff-scard-title", id: titleId }, title), el("span", { class: "ff-scard-desc", id: descId }, description)),
      el("span", { class: "ff-switch", "aria-hidden": "true" }, stateNode, el("span", { class: "ff-switch-track" }, el("span", { class: "ff-switch-knob" }))),
    )
  );
  node.dataset.on = "0";
  /** @param {boolean} on */
  const set = (on) => {
    node.setAttribute("aria-checked", on ? "true" : "false");
    node.dataset.on = on ? "1" : "0";
    stateNode.textContent = texts.t(on ? "settings.on" : "settings.off");
  };
  return { node, set, isOn: () => node.getAttribute("aria-checked") === "true", stateNode };
}

/**
 * A row of the main screen: an icon, the title, what is true now (the caller keeps `summary` up to date) and a chevron. It opens a sub-page.
 * @param {{ role: string, icon: string, title: string, summary: HTMLElement, attrs?: Attrs }} spec
 * @returns {HTMLButtonElement}
 */
export function createNavRow({ role, icon, title, summary, attrs = {} }) {
  return /** @type {HTMLButtonElement} */ (
    el(
      "button",
      { type: "button", class: "ff-nav-row", "data-role": role, ...attrs },
      el("span", { class: "ff-nav-icon", "aria-hidden": "true" }, el("span", { class: `ff-ico ff-ico-${icon}` })),
      el("span", { class: "ff-nav-title" }, title),
      summary,
      el("span", { class: "ff-ico ff-ico-chevron", "aria-hidden": "true" }),
    )
  );
}

/**
 * The text a row of the main screen shows on its right; the section that owns the page sets it.
 * @param {string} role @param {Attrs} [attrs]
 */
export const createSummary = (role, attrs = {}) => el("span", { class: "ff-nav-summary", "data-role": role, ...attrs });

/**
 * "More about this": the long explanations, one click away and always in the page. A native disclosure, so the keyboard and the
 * screen reader get it for free.
 * @param {Texts} texts @param {Array<HTMLElement | null>} paragraphs @param {Attrs} [attrs]
 * @returns {HTMLElement}
 */
export function createMore(texts, paragraphs, attrs = {}) {
  return el(
    "details",
    { class: "ff-disclosure", "data-role": "more", ...attrs },
    el("summary", { class: "ff-disclosure-summary" }, texts.t("settings.more")),
    el("div", { class: "ff-disclosure-body" }, ...paragraphs),
  );
}

/** One explanation paragraph of a "More about this". @param {string} text @param {string} [role] @param {Attrs} [attrs] */
export const note = (text, role, attrs = {}) => el("p", { class: "ff-hint", ...(role ? { "data-role": role } : {}), ...attrs }, text);
