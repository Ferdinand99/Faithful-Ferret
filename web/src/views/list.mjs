// The item list. Search is local: it filters the decrypted index that the sync
// engine keeps in memory, by name, address and user name, and the query goes
// nowhere (this file has no way to make a request, and the query is not put in
// the address either). Favourites come first, then the engine's order, which
// is by name.
import { el, mount } from "../dom.mjs";
import { MANIFEST_ID } from "../sync/engine.mjs";
import { listenWhileShown, markBadges } from "./common.mjs";

/** @param {string} text */
const fold = (text) => String(text).normalize("NFKC").toLocaleLowerCase();

/**
 * Whether an item matches a query typed by the user: every word of the query
 * must be in the name, in one of the addresses or in the user name. Case is
 * ignored.
 * @param {{ name: string, urls: readonly string[], username?: string }} item
 * @param {string} query
 */
export function matches(item, query) {
  const words = fold(query).split(/\s+/).filter((w) => w !== "");
  if (words.length === 0) return true;
  const haystack = [item.name, item.username ?? "", ...item.urls].map(fold).join("\n");
  return words.every((word) => haystack.includes(word));
}

/**
 * @param {{
 *   engine: { list(): any[], on(event: string, fn: (payload: any) => void): () => void },
 *   router: { go(path: string): void },
 *   t: import("./common.mjs").Translate,
 * }} options
 * @returns {HTMLElement}
 */
export function listView({ engine, router, t }) {
  const root = el("section", { class: "card list", "data-role": "list" });
  const search = /** @type {HTMLInputElement} */ (el("input", {
    id: "vault-search", name: "search", type: "search", autocomplete: "off", "data-role": "search",
    placeholder: t("vault.list.search_placeholder"),
  }));
  const add = el("button", { type: "button", "data-role": "new-item" }, t("vault.nav.new"));
  add.addEventListener("click", () => router.go("/items/new"));
  const summary = el("p", { class: "count", role: "status", "data-role": "count" });
  const rows = el("ul", { class: "items", "data-role": "items" });

  function render() {
    const query = search.value ?? "";
    // The unlock-method manifest is a row, never an item; the engine does not list it, and this is the second guard.
    const all = engine.list().filter((item) => item.id !== MANIFEST_ID);
    const shown = all.filter((item) => matches(item, query));
    // Favourites first; the engine's order (by name) holds inside each group.
    const ordered = [...shown.filter((i) => i.favorite), ...shown.filter((i) => !i.favorite)];
    mount(summary, document.createTextNode(
      all.length === 0 ? t("vault.list.empty")
        : shown.length === 0 ? t("vault.list.no_match")
          : t("vault.list.count", { shown: shown.length, total: all.length })));
    mount(rows, ...ordered.map((item) => row(item)));
  }

  /** @param {any} item */
  function row(item) {
    const detail = [item.username, item.urls[0]].filter((x) => typeof x === "string" && x !== "").join(" · ");
    return el("li", { class: "item", "data-role": "item", "data-id": item.id },
      el("a", { href: `#/items/${item.id}`, class: "item-link", "data-role": "item-link" },
        item.favorite ? el("span", { class: "star", "aria-label": t("vault.item.favorite"), role: "img" }, "★") : null,
        item.name === "" ? t("vault.item.unnamed") : item.name),
      detail === "" ? null : el("span", { class: "detail" }, detail),
      el("span", { class: "marks" }, ...markBadges(t, item)));
  }

  search.addEventListener("input", render);
  mount(root,
    el("div", { class: "toolbar" },
      el("label", { for: "vault-search", class: "visually-hidden" }, t("vault.list.search")),
      search, add),
    summary,
    rows);
  render();
  listenWhileShown(root, engine, "changed", render);
  return root;
}
