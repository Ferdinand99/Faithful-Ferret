// The bottom navigation bar of the open popup (the approved layout): the vault, in a build with saving from the
// extension on the generator (design document, section 10.2), and the settings. "Vault" and "Generator" show one part
// each; "Settings" is not a part of the popup: it opens the settings page and the popup closes. The item that shows now
// is marked with `aria-current`. A build without the feature has no generator: the bar is Vault and Settings.
//
// The vault's part stays in the page when the generator is shown (it is only hidden), so its search and open item are as
// they were left. The generator's part is made when its item is first chosen: opening the popup alone never asks the
// core for a password.

import { el } from "../shared/dom.mjs";
import { FEATURES } from "../shared/features.mjs";

/** @typedef {import("./page.mjs").Texts} Texts */
/** @typedef {"vault" | "generator"} Part */

/**
 * @param {{
 *   texts: Texts,
 *   vault: HTMLElement,
 *   makeGenerator: () => HTMLElement | null,
 *   onSettings: () => void,
 * }} deps `vault`: the vault's part; `makeGenerator` makes the generator's part (once, on the first choice of its item);
 *   `onSettings` opens the settings page
 * @returns {{ root: HTMLElement, select: (id: Part) => void, selected: () => Part }}
 */
export function createPopupTabs({ texts, vault, makeGenerator, onSettings }) {
  /** @type {Part} */
  let current = "vault";
  const withGenerator = FEATURES.save;

  const vaultPanel = el("div", { class: "ff-tabpanel", id: "panel-vault", "data-role": "panel-vault" }, vault);
  const generatorPanel = el("div", { class: "ff-tabpanel", id: "panel-generator", "data-role": "panel-generator", hidden: true });
  /** @type {Record<Part, HTMLElement>} */
  const panels = { vault: vaultPanel, generator: generatorPanel };
  let generatorMade = false;

  /**
   * One item of the bar: an icon and a label.
   * @param {{ role: string, icon: string, label: string, feature?: boolean }} spec
   */
  const item = ({ role, icon, label, feature = false }) =>
    el(
      "button",
      { type: "button", class: "ff-tab", "data-role": role, ...(feature ? { "data-feature": "save" } : {}) },
      el("span", { class: `ff-ico ff-ico-${icon}`, "aria-hidden": "true" }),
      label,
    );

  /** @type {Partial<Record<Part, HTMLElement>>} */
  const buttons = { vault: item({ role: "tab-vault", icon: "vault", label: texts.t("generator.tab.vault") }) };
  if (withGenerator) buttons.generator = item({ role: "tab-generator", icon: "generator", label: texts.t("generator.tab.generator"), feature: true });
  const settings = item({ role: "tab-settings", icon: "settings", label: texts.t("session.settings") });

  /** @param {Part} id */
  function select(id) {
    if (id === "generator" && !withGenerator) return;
    if (id === "generator" && !generatorMade) {
      generatorMade = true;
      const made = makeGenerator();
      if (made !== null) generatorPanel.append(made);
    }
    current = id;
    for (const key of /** @type {Part[]} */ (["vault", "generator"])) {
      panels[key].hidden = key !== id;
      const button = buttons[key];
      if (button === undefined) continue;
      if (key === id) button.setAttribute("aria-current", "page");
      else button.removeAttribute("aria-current");
    }
  }

  for (const key of /** @type {Part[]} */ (["vault", "generator"])) buttons[key]?.addEventListener("click", () => select(key));
  settings.addEventListener("click", () => onSettings());

  /** @type {HTMLElement[]} */
  const items = [];
  for (const button of [buttons.vault, buttons.generator, settings]) if (button !== undefined) items.push(button);
  const bar = el("nav", { class: "ff-tabbar", "aria-label": texts.t("generator.tabs.label"), "data-role": "tabs" }, ...items);
  const root = el("div", { class: "ff-tabs", "data-role": "popup-tabs" }, vaultPanel, ...(withGenerator ? [generatorPanel] : []), bar);
  select("vault");
  return { root, select, selected: () => current };
}
