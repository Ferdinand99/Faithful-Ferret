// `#/transfer`: where the side menu's "Import and export" entry leads. The two pages are
// different things with their own routes (`#/import`, `#/export`); this page only offers
// the choice, so that neither is out of reach from the menu. It holds nothing secret and
// makes no request.
import { el } from "../dom.mjs";

/** @typedef {import("./form.mjs").Translate} Translate */

/**
 * @param {{ t: Translate }} options
 * @returns {HTMLElement}
 */
export function transferView({ t }) {
  const choice = (/** @type {string} */ role, /** @type {string} */ href, /** @type {string} */ name, /** @type {string} */ help) =>
    el("li", null, el("a", { href, "data-role": role }, el("strong", null, t(name)), el("span", { class: "choice-help" }, t(help))));
  return el("section", { class: "card account transfer-page", "data-role": "transfer-page" },
    el("h1", null, t("transfer.heading")),
    el("p", null, t("transfer.intro")),
    el("ul", { class: "account-menu", "data-role": "transfer-choices" },
      choice("transfer-import", "#/import", "transfer.import", "transfer.import_help"),
      choice("transfer-export", "#/export", "transfer.export", "transfer.export_help")));
}
