// The tabs of the open popup: the vault and, in a build with saving from the
// extension on, the generator (design document, section 10.2). A build without
// the feature has no tab bar and no generator: the popup is the vault list as
// it was.
//
// The vault's part stays in the page when the generator is shown (it is only
// hidden), so its search and open item are as they were left. The generator's
// part is made when its tab is first chosen: opening the popup alone never asks
// the core for a password.

import { el } from "../shared/dom.mjs";
import { FEATURES } from "../shared/features.mjs";

/** @typedef {import("./page.mjs").Texts} Texts */

/**
 * @param {{
 *   texts: Texts,
 *   vault: HTMLElement,
 *   makeGenerator: () => HTMLElement | null,
 * }} deps `vault`: the vault's part; `makeGenerator` makes the generator's part (once, on the first choice of its tab)
 * @returns {{ root: HTMLElement, select: (id: "vault" | "generator") => void, selected: () => "vault" | "generator" }}
 */
export function createPopupTabs({ texts, vault, makeGenerator }) {
  /** @type {"vault" | "generator"} */
  let current = "vault";
  if (!FEATURES.save) return { root: vault, select: () => {}, selected: () => current };

  const vaultPanel = el("div", { class: "ff-tabpanel", role: "tabpanel", id: "panel-vault", "aria-labelledby": "tab-vault", "data-role": "panel-vault" }, vault);
  const generatorPanel = el("div", { class: "ff-tabpanel", role: "tabpanel", id: "panel-generator", "aria-labelledby": "tab-generator", "data-role": "panel-generator", hidden: true });
  const panels = { vault: vaultPanel, generator: generatorPanel };
  let generatorMade = false;

  /** @type {Record<"vault" | "generator", HTMLElement>} */
  const buttons = {
    vault: el(
      "button",
      { type: "button", class: "ff-tab", role: "tab", id: "tab-vault", "aria-controls": "panel-vault", "data-role": "tab-vault", "data-feature": "save" },
      el("span", { class: "ff-ico ff-ico-vault", "aria-hidden": "true" }),
      texts.t("generator.tab.vault"),
    ),
    generator: el(
      "button",
      { type: "button", class: "ff-tab", role: "tab", id: "tab-generator", "aria-controls": "panel-generator", "data-role": "tab-generator", "data-feature": "save" },
      el("span", { class: "ff-ico ff-ico-generator", "aria-hidden": "true" }),
      texts.t("generator.tab.generator"),
    ),
  };

  /** @param {"vault" | "generator"} id */
  function select(id) {
    if (id === "generator" && !generatorMade) {
      generatorMade = true;
      const made = makeGenerator();
      if (made !== null) generatorPanel.append(made);
    }
    current = id;
    for (const key of /** @type {const} */ (["vault", "generator"])) {
      panels[key].hidden = key !== id;
      buttons[key].setAttribute("aria-selected", key === id ? "true" : "false");
      buttons[key].setAttribute("tabindex", key === id ? "0" : "-1");
    }
  }

  for (const key of /** @type {const} */ (["vault", "generator"])) {
    buttons[key].addEventListener("click", () => select(key));
    buttons[key].addEventListener("keydown", (/** @type {any} */ event) => {
      // The arrows move between the two tabs, as a tab list does.
      if (event?.key !== "ArrowLeft" && event?.key !== "ArrowRight") return;
      const other = key === "vault" ? "generator" : "vault";
      select(other);
      buttons[other].focus();
    });
  }

  const bar = el("nav", { class: "ff-tabbar", role: "tablist", "aria-label": texts.t("generator.tabs.label"), "data-role": "tabs", "data-feature": "save" }, buttons.vault, buttons.generator);
  const root = el("div", { class: "ff-tabs", "data-role": "popup-tabs" }, vaultPanel, generatorPanel, bar);
  select("vault");
  return { root, select, selected: () => current };
}
