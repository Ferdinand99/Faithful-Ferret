// The credits page of the settings view (its title is the page's own heading), shown in every build: the passphrase
// generator in the core draws its words from the EFF large word list, which is
// in the WASM file of every package. The list is used under CC BY 3.0 US, which
// asks for the author's name, the licence and its address, so all three are
// plain text here.

import { el } from "../shared/dom.mjs";

/** The licence's address, as text. */
export const EFF_LICENSE_URL = "https://creativecommons.org/licenses/by/3.0/us/";

/** Where the list comes from, as text. */
export const EFF_SOURCE_URL = "https://www.eff.org/dice";

/**
 * @param {{ t(key: string, vars?: Record<string, string | number>): string }} texts
 * @returns {HTMLElement}
 */
export function createCredits(texts) {
  return el(
    "div",
    { class: "ff-credits", "data-role": "credits" },
    el("p", { class: "ff-hint", "data-role": "credits-eff" }, texts.t("settings.credits.eff", { license_url: EFF_LICENSE_URL, source_url: EFF_SOURCE_URL })),
  );
}
