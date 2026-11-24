// The bottom navigation bar of the open popup (the approved layout): the vault, in a build with saving from the
// extension on the generator (design document, section 10.2), and the settings. "Vault", "Generator" and "Settings" show one
// part each, in the popup itself (the settings view is the one of the settings page, settingsView.mjs); "Health" is in the
// layout but has no view yet: it is shown disabled, with a "Coming soon" tag, and a click on it does nothing. The item that
// shows now is marked with `aria-current`. A build without the feature has no generator: the bar is Vault, Health and Settings.
//
// The vault's part stays in the page when another part is shown (it is only hidden), so its search and open item are as
// they were left. The generator's part and the settings' part are made when their item is first chosen: opening the popup
// alone never asks the core for a password or the background for the settings.

import { el } from "../shared/dom.mjs";
import { FEATURES } from "../shared/features.mjs";

/** @typedef {import("./page.mjs").Texts} Texts */
/** @typedef {"vault" | "generator" | "settings"} Part */

/**
 * @param {{
 *   texts: Texts,
 *   vault: HTMLElement,
 *   makeGenerator: () => HTMLElement | null,
 *   makeSettings: () => HTMLElement | null,
 * }} deps `vault`: the vault's part; `makeGenerator` and `makeSettings` make the generator's and the settings' part (once,
 *   on the first choice of their item)
 * @returns {{ root: HTMLElement, select: (id: Part) => void, selected: () => Part }}
 */
export function createPopupTabs({ texts, vault, makeGenerator, makeSettings }) {
  /** @type {Part} */
  let current = "vault";
  const withGenerator = FEATURES.save;

  const vaultPanel = el("div", { class: "ff-tabpanel", id: "panel-vault", "data-role": "panel-vault" }, vault);
  const generatorPanel = el("div", { class: "ff-tabpanel", id: "panel-generator", "data-role": "panel-generator", hidden: true });
  const settingsPanel = el("div", { class: "ff-tabpanel", id: "panel-settings", "data-role": "panel-settings", hidden: true });
  /** @type {Record<Part, HTMLElement>} */
  const panels = { vault: vaultPanel, generator: generatorPanel, settings: settingsPanel };
  let generatorMade = false;
  let settingsMade = false;

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
  const buttons = { vault: item({ role: "tab-vault", icon: "vault", label: texts.t("popup.bar.vault") }) };
  if (withGenerator) buttons.generator = item({ role: "tab-generator", icon: "generator", label: texts.t("generator.tab.generator"), feature: true });
  // Not available yet: no listener, so a click, Enter or Space does nothing. It stays in the tab order with `aria-disabled`
  // (the WAI-ARIA authoring practices keep a disabled item of a bar or menu focusable, so that a keyboard or screen reader user
  // finds it and hears why it does nothing, instead of the bar silently missing an item). Its name is "Health" and the visible
  // tag "Coming soon" is read with it; the space between them keeps the two words apart in the name.
  const health = item({ role: "tab-health", icon: "health", label: texts.t("popup.bar.health") });
  health.setAttribute("aria-disabled", "true");
  health.setAttribute("title", texts.t("popup.bar.soon"));
  health.append(" ", el("span", { class: "ff-tab-soon", "data-role": "tab-soon" }, texts.t("popup.bar.soon")));
  buttons.settings = item({ role: "tab-settings", icon: "settings", label: texts.t("session.settings") });

  /** @param {Part} id */
  function select(id) {
    if (id === "generator" && !withGenerator) return;
    if (id === "generator" && !generatorMade) {
      generatorMade = true;
      const made = makeGenerator();
      if (made !== null) generatorPanel.append(made);
    }
    if (id === "settings" && !settingsMade) {
      settingsMade = true;
      const made = makeSettings();
      if (made !== null) settingsPanel.append(made);
    }
    current = id;
    for (const key of /** @type {Part[]} */ (["vault", "generator", "settings"])) {
      panels[key].hidden = key !== id;
      const button = buttons[key];
      if (button === undefined) continue;
      if (key === id) button.setAttribute("aria-current", "page");
      else button.removeAttribute("aria-current");
    }
  }

  for (const key of /** @type {Part[]} */ (["vault", "generator", "settings"])) buttons[key]?.addEventListener("click", () => select(key));

  /** @type {HTMLElement[]} */
  const items = [];
  for (const button of [buttons.vault, buttons.generator, health, buttons.settings]) if (button !== undefined) items.push(button);
  const bar = el("nav", { class: "ff-tabbar", "aria-label": texts.t("popup.bar.label"), "data-role": "tabs" }, ...items);
  const root = el("div", { class: "ff-tabs", "data-role": "popup-tabs" }, vaultPanel, ...(withGenerator ? [generatorPanel] : []), settingsPanel, bar);
  select("vault");
  return { root, select, selected: () => current };
}
