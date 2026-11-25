// The item list: a search field, filter chips, and a table with a menu on every row and a bar for acting on several
// rows at once. Everything here is local. The search runs over the decrypted index that the sync engine keeps in
// memory (name, address and user name) and the text typed goes nowhere: this file has no way to make a request, and
// the search text is not put in the address either. The filters (types, favourites, the order) are kept in the
// address (`#/items?type=login&fav=1`), so back and forward move between them and a link opens the same list; they
// hold no item name and no secret. A long list is drawn as a window of rows (listModel.mjs says which).
//
// The things the user changes here go through the engine like every other change: a favourite is an edit of one item
// (`update` with the one field), a deletion is `remove` (the item goes to the trash of this device), and several rows
// are several writes in the outbox, which the sync sends together.
import { el, mount } from "../dom.mjs";
import { emptyBlock } from "./emptyState.mjs";
import { createListPrefs } from "../listPrefs.mjs";
import { MANIFEST_ID } from "../sync/engine.mjs";
import { folderChips, folderIndex, foldKey, withShownNames } from "../folders.mjs";
import { askConfirm, canChange, describeError, listenWhileShown, markBadges, marksOf } from "./common.mjs";
import { typeLabel } from "./item.mjs";
import { passkeySites } from "./itemModel.mjs";
import {
  OVERSCAN, WINDOW_FROM, applyFilters, countByFolder, countByType, createMatcher, defaultDir, formatListQuery, hasFilters,
  formatExact, inDirection, initialOf, parseListQuery, relativeTime, sameState, sortItems, typesPresent, windowRange,
} from "./listModel.mjs";
import { focusNode, popMenu, within } from "./popMenu.mjs";

export { matches } from "./listModel.mjs";

/** How tall a row is until the first one has been measured. */
const ROW_HEIGHT = 56;

/** Rows drawn when a long list is shown by a page that cannot measure (a test). */
const UNMEASURED_ROWS = 60;

/** About how tall the menu of a row is: it opens upwards when there is less room than this below its button. */
const ROW_MENU_HEIGHT = 224;

/** How wide it is (13 rem): it is set in the style sheet and read here to keep it on the screen. */
const ROW_MENU_WIDTH = 208;

/**
 * @typedef {object} ListNav the address of the list, when the list keeps its filters there
 * @property {string} query the part after `?` now
 * @property {(query: string) => void} set puts a new query in the address (a new entry in the history)
 * @property {(fn: (query: string) => void) => (() => void)} watch told when only the query changes (back, forward, a link)
 */

/**
 * @param {{
 *   engine: { list(): any[], on(event: string, fn: (payload: any) => void): () => void, update?: Function, remove?: Function },
 *   router: { go(path: string): void },
 *   t: import("./common.mjs").Translate,
 *   nav?: ListNav,
 *   locale?: string,
 *   prefs?: ReturnType<typeof createListPrefs>,
 *   touch?: () => boolean,
 *   scope?: { add(fn: () => void): () => void },
 *   now?: () => number,
 *   moveToFolder?: (items: any[], where: { host: HTMLElement, say: (text: string) => void }) => void,
 *   folder?: string,
 *   folderLink?: (name: string) => string,
 *   win?: any,
 * }} options `moveToFolder`: with it a row's menu has "Move to folder", without it the entry is not there. `folder`: the list
 *   is the page of that folder (the folder filter starts with it, and the heading is its name). `folderLink`: where a folder
 *   label of a row leads (none: the label is plain text)
 * @returns {HTMLElement}
 */
export function listView({ engine, router, t, nav, locale, prefs = createListPrefs(), touch = () => true, scope, now = Date.now, moveToFolder, folder, folderLink, win = /** @type {any} */ (globalThis).window }) {
  const doc = /** @type {any} */ (globalThis).document;
  const root = el("section", { class: "list-view", "data-role": "list" });
  const matcher = createMatcher();

  // ------------------------------------------------------------- state
  /** The query the address has now: the list writes it only when it differs. */
  let lastQuery = nav?.query ?? "";
  /** The filters. The folder filter is in memory only: it is not in the address. */
  let state = typeof folder === "string" ? { ...parseListQuery(lastQuery), folders: [folder] } : parseListQuery(lastQuery);
  let query = "";
  /** @type {any[]} every item but the manifest */
  let source = [];
  /** Whether any item has a folder: the folder chip, column and filter exist only then. */
  let haveFolders = false;
  /** @type {Map<string, number>} */
  let folderCounts = new Map();
  /** @type {Record<"name" | "changed", any[]>} the source in each column's up direction, kept until the source changes */
  let ordered = { name: [], changed: [] };
  /** The items shown now: searched, filtered and in order. @type {any[]} */
  let shown = [];
  /** Where each shown item stands, made when it is asked for. @type {Map<string, number> | null} */
  let indexes = null;
  /** @param {string} id @returns {number | undefined} */
  const indexOf = (id) => {
    if (indexes === null) indexes = new Map(shown.map((item, i) => [item.id, i]));
    return indexes.get(id);
  };
  /** @type {Set<string>} */
  const selected = new Set();
  let wiped = false;
  let busy = false;
  let dirty = false;
  let pending = false;
  let drawnOnce = false;
  let framed = false;
  let rowHeight = ROW_HEIGHT;
  /** The rows on the page, by item id. @type {Map<string, { node: HTMLElement, sig: string, check: HTMLInputElement, link: HTMLElement, more: HTMLElement, own: { pop: ReturnType<typeof popMenu> | null } }>} */
  const drawn = new Map();
  /** Menus that can be open: the chips, the column menu, a row's. @type {Set<ReturnType<typeof popMenu>>} */
  const menus = new Set();

  // ----------------------------------------------------------- the bar
  const search = /** @type {HTMLInputElement} */ (el("input", {
    id: "vault-search", name: "search", type: "search", autocomplete: "off", "data-role": "search",
    placeholder: t("vault.list.search_placeholder"),
  }));
  const clearSearch = el("button", { type: "button", class: "list-x", "aria-label": t("list.search_clear"), "data-role": "search-clear" }, el("span", { class: "icon", "data-icon": "close", "aria-hidden": "true" }));
  const searchBox = el("div", { class: "list-search" },
    el("label", { for: "vault-search", class: "visually-hidden" }, t("vault.list.search")), search, clearSearch);

  const customise = el("button", { type: "button", class: "btn btn-secondary", "aria-haspopup": "menu", "aria-expanded": "false", "data-role": "customise" }, t("list.customise"));
  const customiseMenu = el("div", { class: "list-menu", role: "menu", "aria-label": t("list.customise"), "data-role": "customise-menu" });
  const importLink = el("a", { class: "btn btn-secondary", href: "#/import", "data-role": "import" }, t("list.import"));
  const add = el("button", { type: "button", class: "btn btn-primary i-plus", "data-role": "new-item" }, t("list.add"));
  add.addEventListener("click", () => router.go("/items/new"));
  const actions = el("div", { class: "list-actions" }, el("div", { class: "list-pop" }, customise, customiseMenu), importLink, add);
  const searchRow = el("div", { class: "list-search-row" }, searchBox, actions);

  // ---- the chips
  /**
   * A filter chip: the button that opens its menu of values, and a cross that takes the filter off.
   * @param {{ role: string, label: string, toggle(value: string): void, remove(): void }} spec
   */
  function filterChip({ role, label, toggle, remove }) {
    const text = el("span", { class: "chip-text" }, label);
    const caret = el("span", { class: "chip-caret", "aria-hidden": "true" }, "▾");
    const button = el("button", { type: "button", class: "chip-main", "aria-haspopup": "menu", "aria-expanded": "false", "data-role": `${role}-chip` }, text, caret);
    const cross = el("button", { type: "button", class: "chip-x", "aria-label": t("list.chip_remove", { filter: label }), "data-role": `${role}-remove` }, el("span", { class: "icon", "data-icon": "close", "aria-hidden": "true" }));
    cross.hidden = true;
    const menu = el("div", { class: "list-menu", role: "menu", "aria-label": label, "data-role": `${role}-menu` });
    const node = el("div", { class: "chip", "data-role": `chip-${role}`, "data-active": "false" }, button, cross, menu);
    /** @type {{ value: string, node: HTMLElement, count: Text }[]} */
    let entries = [];
    let shape = "";
    const pop = popMenu({ trigger: button, menu, items: () => entries.map((entry) => entry.node), escape: true, onOpen: () => closeMenus(pop) });
    menus.add(pop);
    cross.addEventListener("click", () => {
      pop.close(false);
      remove();
      focusNode(button);
    });
    return {
      node,
      /** @param {{ hidden: boolean, active: boolean, text: string, options: { value: string, label: string, count: number, checked: boolean }[] }} model */
      update(model) {
        node.hidden = model.hidden;
        node.setAttribute("data-active", model.active ? "true" : "false");
        cross.hidden = !model.active;
        mount(text, document.createTextNode(model.text));
        // The entries are built again only when the values change; the numbers and the ticks change in place, so the
        // focus stays where it is while a menu is open.
        const next = model.options.map((option) => `${option.value}\n${option.label}`).join("\n\n");
        if (next !== shape) {
          shape = next;
          entries = model.options.map((option) => {
            const count = document.createTextNode(String(option.count));
            const item = el("button", { type: "button", role: "menuitemcheckbox", tabindex: "-1", class: "menu-check", "aria-checked": "false", "data-value": option.value },
              el("span", { class: "box", "aria-hidden": "true" }), el("span", { class: "menu-label" }, option.label), el("span", { class: "menu-count" }, count));
            item.addEventListener("click", () => toggle(option.value));
            return { value: option.value, node: item, count: /** @type {Text} */ (count) };
          });
          mount(menu, ...entries.map((entry) => entry.node));
        }
        model.options.forEach((option, i) => {
          const entry = entries[i];
          entry.node.setAttribute("aria-checked", option.checked ? "true" : "false");
          if (entry.count.data !== String(option.count)) entry.count.data = String(option.count);
        });
      },
    };
  }

  const typeChip = filterChip({
    role: "type", label: t("list.type"),
    toggle: (value) => change({ ...state, types: state.types.includes(value) ? state.types.filter((v) => v !== value) : [...state.types, value] }),
    remove: () => change({ ...state, types: [] }),
  });
  const folderChip = filterChip({
    role: "folders", label: t("list.folders"),
    toggle: (value) => change({ ...state, folders: state.folders.includes(value) ? state.folders.filter((v) => v !== value) : [...state.folders, value] }),
    remove: () => change({ ...state, folders: [] }),
  });
  const favButton = el("button", { type: "button", class: "chip-main", "aria-pressed": "false", "data-role": "favorites-chip" },
    el("span", { class: "icon chip-star", "data-icon": "star", "aria-hidden": "true" }), el("span", { class: "chip-text" }, t("list.favorites")));
  const favCross = el("button", { type: "button", class: "chip-x", "aria-label": t("list.chip_remove", { filter: t("list.favorites") }), "data-role": "favorites-remove" }, el("span", { class: "icon", "data-icon": "close", "aria-hidden": "true" }));
  favCross.hidden = true;
  const favChip = el("div", { class: "chip", "data-role": "chip-favorites", "data-active": "false" }, favButton, favCross);
  favButton.addEventListener("click", () => change({ ...state, favorite: !state.favorite }));
  favCross.addEventListener("click", () => {
    change({ ...state, favorite: false });
    focusNode(favButton);
  });
  const passkeyButton = el("button", { type: "button", class: "chip-main", "aria-pressed": "false", "data-role": "passkeys-chip" },
    el("span", { class: "chip-text" }, t("passkey.filter")));
  const passkeyCross = el("button", { type: "button", class: "chip-x", "aria-label": t("list.chip_remove", { filter: t("passkey.filter") }), "data-role": "passkeys-remove" }, el("span", { class: "icon", "data-icon": "close", "aria-hidden": "true" }));
  passkeyCross.hidden = true;
  const passkeyChip = el("div", { class: "chip", "data-role": "chip-passkeys", "data-active": "false" }, passkeyButton, passkeyCross);
  passkeyButton.addEventListener("click", () => change({ ...state, passkey: !state.passkey }));
  passkeyCross.addEventListener("click", () => {
    change({ ...state, passkey: false });
    focusNode(passkeyButton);
  });
  const summary = el("p", { class: "count list-count", role: "status", "data-role": "count" });
  const chips = el("div", { class: "list-chips", role: "group", "aria-label": t("list.filters") }, typeChip.node, favChip, passkeyChip, folderChip.node, summary);

  // ---- the bar for several rows
  const bulkCount = el("span", { class: "bulk-count", role: "status", "data-role": "bulk-count" });
  const bulkFavorite = el("button", { type: "button", class: "btn btn-secondary btn-sm", "data-role": "bulk-favorite" });
  const bulkTrash = el("button", { type: "button", class: "btn btn-danger btn-sm i-trash", "data-role": "bulk-trash" }, t("list.bulk_trash"));
  const bulkClear = el("button", { type: "button", class: "btn btn-plain btn-sm", "data-role": "bulk-clear" }, t("list.bulk_clear"));
  const bulk = el("div", { class: "list-bulk", role: "region", "aria-label": t("list.bulk_label"), "data-role": "bulk" }, bulkCount, bulkFavorite, bulkTrash, bulkClear);
  bulk.hidden = true;

  const bar = el("div", { class: "list-bar", "data-role": "list-bar" }, searchRow, chips, bulk);

  // --------------------------------------------------------- the table
  const selectAll = /** @type {HTMLInputElement} */ (el("input", { type: "checkbox", class: "row-check", "aria-label": t("list.select_all"), "data-role": "select-all" }));
  /** @param {"name" | "changed"} key @param {string} label */
  const sortButton = (key, label) => {
    const arrow = el("span", { class: "sort-arrow", "aria-hidden": "true" });
    const button = el("button", { type: "button", class: "sort", "data-role": `sort-${key}` }, label, arrow);
    button.addEventListener("click", () => change(state.sort === key
      ? { ...state, dir: state.dir === "asc" ? "desc" : "asc" }
      : { ...state, sort: key, dir: defaultDir(key) }));
    return { button, arrow };
  };
  const sortName = sortButton("name", t("list.col_name"));
  const sortChanged = sortButton("changed", t("list.col_changed"));
  const headName = el("div", { class: "cell c-name", role: "columnheader", "aria-sort": "ascending" }, sortName.button);
  const headFolders = el("div", { class: "cell c-folders", role: "columnheader" }, t("list.col_folders"));
  const headChanged = el("div", { class: "cell c-changed", role: "columnheader", "aria-sort": "none" }, sortChanged.button);
  const head = el("div", { class: "list-head", role: "row", "aria-rowindex": "1", "data-role": "list-head" },
    el("div", { class: "cell c-check", role: "columnheader" }, selectAll),
    headName, headFolders, headChanged,
    el("div", { class: "cell c-opts", role: "columnheader" }, el("span", { class: "visually-hidden" }, t("list.col_options"))));
  const spacerTop = el("div", { class: "list-spacer", "aria-hidden": "true" });
  const spacerBottom = el("div", { class: "list-spacer", "aria-hidden": "true" });
  const rows = el("div", { class: "list-rows", role: "rowgroup", "data-role": "items" }, spacerTop, spacerBottom);
  const table = el("div", { class: "list-table", role: "table", "aria-label": t("list.table_label"), "data-role": "table", "data-folders": "off", "data-changed": "on" }, head, rows);
  const emptyView = emptyBlock({ role: "list-empty", icon: "items", class: "list-empty" });
  const empty = emptyView.root;
  empty.hidden = true;

  const message = el("p", { class: "message list-message", role: "status", "data-role": "message" });
  const host = el("div", { class: "dialog-host", "data-role": "dialog-host" });
  // Holds the note about conflicts; empty (and so without any box) when there are none.
  const conflicts = el("div", { class: "conflicts", "data-role": "conflicts" });
  const headingText = el("span", { "data-role": "list-title" }, t("shell.nav.items"));
  const heading = el("h1", { class: "list-title" }, el("span", { class: "icon", "data-icon": "items", "aria-hidden": "true" }), headingText);

  // ------------------------------------------------------------ helpers
  /** @param {ReturnType<typeof popMenu> | null} [except] */
  function closeMenus(except = null) {
    for (const menu of menus) if (menu !== except) menu.close(false);
  }

  /** @param {string} text */
  function say(text) {
    if (wiped) return;
    mount(message, document.createTextNode(text));
  }

  const foldersOn = () => haveFolders && prefs.shows("folders");
  const changedOn = () => prefs.shows("changed");

  /** The state the list is drawn from: a folder filter counts only when the vault has folders. */
  const effective = () => (haveFolders ? state : { ...state, folders: [] });

  // -------------------------------------------------------- the filters
  /** @param {import("./listModel.mjs").ListState} next */
  function change(next) {
    if (wiped || !touch()) return;
    const clean = { ...next, types: [...next.types], folders: [...next.folders] };
    if (sameState(clean, state)) return;
    state = clean;
    update();
    // A change that is only of the folder filter (not in the address) is no new entry of the history.
    const query = formatListQuery(state);
    if (query !== lastQuery) {
      lastQuery = query;
      nav?.set(query);
    }
  }

  /** Lets go of the address: the lock ends the screen, and nothing of it may stay reachable through the router. @type {(() => void) | null} */
  let offWatch = null;
  if (nav) {
    const off = nav.watch((next) => {
      if ((/** @type {any} */ (root)).isConnected === false && drawnOnce) {
        off();
        return;
      }
      lastQuery = next;
      const parsed = { ...parseListQuery(next), folders: state.folders };
      if (sameState(parsed, state)) return;
      state = parsed;
      update();
    });
    offWatch = off;
  }

  // ------------------------------------------------------------ reading
  /** A long list has the text of its items folded in the background after it was drawn, a slice at a time, so that the first key of a search is as quick as the next. */
  function warmUp() {
    if (source.length <= WINDOW_FROM) return;
    const list = source;
    let at = 0;
    const slice = () => {
      if (wiped || list !== source) return;
      matcher.warm(list, at, at + 1500);
      at += 1500;
      if (at < list.length) setTimeout(slice, 0);
    };
    setTimeout(slice, 0);
  }

  function readSource() {
    const items = engine.list().filter((item) => item.id !== MANIFEST_ID);
    // One folder is one name here, whatever case each item writes it in (the spelling most items use is shown).
    const index = items.some((item) => Array.isArray(item.folders) && item.folders.length > 0) ? folderIndex(items, locale) : [];
    source = index.length > 0 ? withShownNames(items, index) : items;
    // A folder chosen in the filter follows the spelling the vault shows for it now.
    const shownName = new Map(index.map((entry) => [entry.key, entry.name]));
    const follow = (/** @type {string} */ name) => shownName.get(foldKey(name)) ?? name;
    if (state.folders.some((name) => follow(name) !== name)) state = { ...state, folders: [...new Set(state.folders.map(follow))] };
    if (typeof folder === "string") folder = follow(folder);
    folderCounts = countByFolder(source);
    haveFolders = folderCounts.size > 0;
    ordered = { name: sortItems(source, "name", "asc"), changed: sortItems(source, "changed", "asc") };
    matcher.prune(source);
  }

  function compute() {
    const eff = effective();
    const base = inDirection(ordered[eff.sort], eff.dir);
    // The lists are read, never changed, so a step that has nothing to do hands on the list it was given.
    const searched = matcher.filter(base, query);
    shown = hasFilters(eff) ? applyFilters(searched, eff) : searched;
    indexes = null;
    return { searched, eff };
  }

  // ------------------------------------------------------------- update
  /** Draws everything that depends on the state; `reread` after the engine changed. @param {boolean} [reread] */
  function update(reread = false) {
    if (wiped) return;
    if (reread) readSource();
    const { searched, eff } = compute();
    for (const id of [...selected]) if (indexOf(id) === undefined) selected.delete(id);

    const total = source.length;
    const typeCounts = countByType(eff.favorite || eff.passkey || eff.folders.length > 0 ? applyFilters(searched, eff, "types") : searched);
    typeChip.update({
      hidden: total === 0,
      active: eff.types.length > 0,
      text: chipText("list.type", eff.types.map((type) => typeLabel(t, type))),
      options: typesPresent(source, eff.types).map((type) => ({ value: type, label: typeLabel(t, type), count: typeCounts.get(type) ?? 0, checked: eff.types.includes(type) })),
    });
    const inFolders = haveFolders ? countByFolder(applyFilters(searched, eff, "folders")) : new Map();
    folderChip.update({
      hidden: !haveFolders,
      active: eff.folders.length > 0,
      text: chipText("list.folders", eff.folders),
      options: haveFolders
        ? [...new Set([...folderCounts.keys(), ...eff.folders])].sort((a, b) => a.localeCompare(b)).map((name) => ({ value: name, label: name, count: inFolders.get(name) ?? 0, checked: eff.folders.includes(name) }))
        : [],
    });
    favChip.hidden = total === 0;
    favChip.setAttribute("data-active", eff.favorite ? "true" : "false");
    favButton.setAttribute("aria-pressed", eff.favorite ? "true" : "false");
    favCross.hidden = !eff.favorite;
    // The passkey filter is there only while some item holds a passkey (or while it is on, so it can be taken off).
    const anyPasskey = eff.passkey || source.some((item) => typeof item.passkeySite === "string" && item.passkeySite !== "");
    passkeyChip.hidden = total === 0 || !anyPasskey;
    passkeyChip.setAttribute("data-active", eff.passkey ? "true" : "false");
    passkeyButton.setAttribute("aria-pressed", eff.passkey ? "true" : "false");
    passkeyCross.hidden = !eff.passkey;
    chips.hidden = total === 0;
    searchBox.hidden = total === 0;
    customise.hidden = total === 0;
    clearSearch.hidden = query === "";

    const onlyFavorites = eff.favorite && !eff.passkey && eff.types.length === 0 && eff.folders.length === 0;
    const onlyTheFolder = typeof folder === "string" && eff.folders.length === 1 && eff.folders[0] === folder;
    mount(headingText, document.createTextNode(onlyTheFolder ? /** @type {string} */ (folder) : t(onlyFavorites ? "shell.nav.favorites" : "shell.nav.items")));
    heading.setAttribute("data-folder-page", onlyTheFolder ? "true" : "false");

    mount(summary, document.createTextNode(
      total === 0 ? "" : shown.length === total ? t(total === 1 ? "list.count_one" : "list.count_all", { count: total }) : t("vault.list.count", { shown: shown.length, total })));

    // The empty states, and the table when there is something to show.
    const searching = query.trim() !== "";
    const filtering = hasFilters(eff);
    empty.hidden = shown.length > 0;
    table.hidden = shown.length === 0;
    if (shown.length === 0) {
      if (total === 0) {
        // The one useful thing in an empty vault: make the first item.
        emptyView.fill(t("vault.list.empty"), [{ label: t("list.add"), role: "empty-add", icon: "i-plus", primary: true, onClick: () => router.go("/items/new") }], "items");
      } else {
        /** @type {import("./emptyState.mjs").EmptyAction[]} */
        const ways = [];
        if (searching) ways.push({ label: t("list.search_clear_all"), role: "empty-clear-search", onClick: () => clearTheSearch() });
        if (filtering) ways.push({ label: t("list.clear_filters"), role: "empty-clear-filters", onClick: () => change({ ...state, types: [], favorite: false, passkey: false, folders: [] }) });
        const line = t(searching && filtering ? "list.empty_both" : searching ? "vault.list.no_match" : onlyFavorites ? "shell.favorites.empty" : "list.empty_filters");
        emptyView.fill(line, ways, searching ? "search" : onlyFavorites ? "star" : "items");
      }
    }

    // Every item in conflict is in the list below with its mark; this note says how many and leads to the first.
    const inConflict = source.filter((item) => item.conflict === true && /^[0-9a-f]{32}$/.test(item.id));
    mount(conflicts, ...(inConflict.length === 0 ? [] : [
      el("p", { class: "notice notice-conflict", role: "status", "data-role": "conflict-note" },
        `${t("conflict.list_count", { count: inConflict.length })} `,
        el("a", { href: `#/items/${inConflict[0].id}/conflict`, "data-role": "first-conflict" }, t("conflict.list_open")))]));

    // The columns and the order.
    table.setAttribute("data-folders", foldersOn() ? "on" : "off");
    table.setAttribute("data-changed", changedOn() ? "on" : "off");
    headName.setAttribute("aria-sort", eff.sort === "name" ? (eff.dir === "asc" ? "ascending" : "descending") : "none");
    headChanged.setAttribute("aria-sort", eff.sort === "changed" ? (eff.dir === "asc" ? "ascending" : "descending") : "none");
    mount(sortName.arrow, document.createTextNode(eff.sort === "name" ? (eff.dir === "asc" ? "↓" : "↑") : ""));
    mount(sortChanged.arrow, document.createTextNode(eff.sort === "changed" ? (eff.dir === "asc" ? "↓" : "↑") : ""));
    table.setAttribute("aria-rowcount", String(shown.length + 1));

    renderCustomise();
    renderRows();
    renderBulk();
    drawnOnce = true;
  }

  /** What a chip says: its name alone, with the one value, or with how many. @param {string} key @param {string[]} values */
  function chipText(key, values) {
    if (values.length === 0) return t(key);
    return values.length === 1 ? t("list.chip_value", { filter: t(key), value: values[0] }) : t("list.chip_count", { filter: t(key), count: values.length });
  }

  // ----------------------------------------------------------- the rows
  /** What a row shows, as one text: the row is built again only when this changes. @param {any} item */
  function signature(item) {
    return [item.rev, item.name, item.username ?? "", item.urls?.[0] ?? "", item.favorite === true, item.type, item.modified ?? 0, marksOf(item).join(","), item.passkeySite ?? "", canChange(item),
      foldersOn() ? (item.folders ?? []).join("\u0001") : "", changedOn()].join("\u0000");
  }

  /** @param {any} item @param {number} index */
  function makeRow(item, index) {
    const name = item.name === "" ? t("vault.item.unnamed") : item.name;
    const check = /** @type {HTMLInputElement} */ (el("input", { type: "checkbox", class: "row-check", "aria-label": t("list.select", { name }), "data-role": "select" }));
    check.checked = selected.has(item.id);
    check.addEventListener("change", () => {
      if (!touch()) {
        check.checked = !check.checked;
        return;
      }
      if (check.checked) selected.add(item.id);
      else selected.delete(item.id);
      paintSelection();
    });
    const detail = [item.username, item.urls?.[0]].filter((x) => typeof x === "string" && x !== "").join(" · ");
    const marks = markBadges(t, item);
    // A mark that is cut on a phone still has its word, in the title; the first one (the most serious) is not cut.
    marksOf(item).forEach((mark, i) => marks[i]?.setAttribute("title", t(`vault.mark.${mark}`)));
    // The passkey comes after the marks of the sync state: it says what the item holds, not how it stands with the server.
    if (typeof item.passkeySite === "string" && item.passkeySite !== "") {
      marks.push(el("span", { class: "mark mark-passkey", "data-mark": "passkey", title: t("passkey.mark_title", { site: item.passkeySite }) }, t("passkey.mark")));
    }
    const link = el("a", { href: `#/items/${item.id}`, class: "item-link", "data-role": "item-link" },
      item.favorite ? el("span", { class: "star", "aria-label": t("vault.item.favorite"), role: "img" }, "★") : null,
      name);
    const main = el("div", { class: "main" },
      el("div", { class: "name-line" }, link),
      detail === "" && marks.length === 0 ? null : el("div", { class: "detail-line" },
        detail === "" ? null : el("span", { class: "detail" }, detail),
        marks.length === 0 ? null : el("span", { class: "marks" }, ...marks)));
    const exact = formatExact(item.modified, locale);
    const changed = el("div", { class: "cell c-changed", role: "cell", "data-role": "changed", ...(exact === null ? {} : { title: exact }) }, relativeTime(item.modified, now(), locale) ?? "—");
    const folderCell = el("div", { class: "cell c-folders", role: "cell", "data-role": "folders" });
    if (foldersOn()) {
      // The first folder (in display order) and "+N" for the rest, which are named in its title.
      const { shown: first, more } = folderChips(item.folders, 1, locale);
      const rest = folderChips(item.folders, 20, locale).shown.slice(1);
      const label = first.length === 0 ? null : typeof folderLink === "function"
        ? el("a", { class: "folder-label", href: folderLink(first[0]), "data-role": "folder-link" }, `▭ ${first[0]}`)
        : el("span", { class: "folder-label" }, `▭ ${first[0]}`);
      mount(folderCell,
        ...(label === null ? [el("span", { class: "none" }, "—")] : [label]),
        ...(more > 0 ? [el("span", { class: "folder-label folder-more", title: rest.join(", "), "aria-label": t("folders.more_label", { count: more, names: rest.join(", ") }) }, `+${more}`)] : []));
    }
    const more = el("button", {
      type: "button", class: "row-more", "aria-haspopup": "menu", "aria-expanded": "false", "data-role": "row-menu",
      "aria-label": t("list.options", { name }),
    }, el("span", { class: "icon", "data-icon": "more", "aria-hidden": "true" }));
    const opts = el("div", { class: "cell c-opts", role: "cell" }, more);
    // The menu of a row is made when it is first asked for: a window of rows is built on every key of a search, and most of them are never opened.
    /** @type {ReturnType<typeof popMenu> | null} */
    let pop = null;
    const own = {
      /** @param {"first" | "last"} focus */
      open(focus) {
        if (pop) return;
        const menu = el("div", { class: "list-menu row-menu", role: "menu", "aria-label": name, "data-role": "row-menu-list" });
        opts.appendChild(menu);
        /** @type {HTMLElement[]} */
        let entries = [];
        const made = popMenu({
          trigger: more, menu, items: () => entries, escape: true,
          onOpen: () => {
            closeMenus(made);
            entries = rowMenuItems(item, () => made.close(false));
            mount(menu, ...entries);
            placeMenu(more, menu);
          },
        });
        pop = made;
        menus.add(made);
        made.open(focus);
      },
      get pop() {
        return pop;
      },
    };
    // Until the menu exists these two start it; after that its own listeners take over.
    more.addEventListener("click", () => own.open("first"));
    more.addEventListener("keydown", (/** @type {any} */ event) => {
      if (pop || (event.key !== "ArrowDown" && event.key !== "ArrowUp")) return;
      event.preventDefault?.();
      own.open(event.key === "ArrowUp" ? "last" : "first");
    });
    const node = el("div", { class: "row", role: "row", "data-role": "item", "data-id": item.id, "data-selected": check.checked ? "true" : "false", "aria-rowindex": String(index + 2) },
      el("div", { class: "cell c-check", role: "cell" }, check),
      el("div", { class: "cell c-name", role: "cell" }, el("span", { class: "tile", "data-type": String(item.type ?? ""), "aria-hidden": "true" }, initialOf(item.name)), main),
      folderCell, changed, opts);
    return { node, check, link, more, own };
  }

  /** The entries of the menu of a row. @param {any} item @param {() => void} close @returns {HTMLElement[]} */
  function rowMenuItems(item, close) {
    const editable = canChange(item);
    /** @param {string} role @param {string} icon @param {string} text @param {string | null} href */
    const entry = (role, icon, text, href) => {
      const attrs = { role: "menuitem", tabindex: "-1", class: "side-menuitem", "data-role": role };
      const inner = [el("span", { class: "icon", "data-icon": icon, "aria-hidden": "true" }), text];
      return href === null ? el("button", { type: "button", ...attrs }, ...inner) : el("a", { ...attrs, href }, ...inner);
    };
    /** @type {HTMLElement[]} */
    const out = [];
    const view = entry("row-view", "items", t("list.menu_view"), `#/items/${item.id}`);
    view.addEventListener("click", close);
    out.push(view);
    if (editable) {
      const favorite = entry("row-favorite", "star", t(item.favorite ? "list.menu_unfavorite" : "list.menu_favorite"), null);
      favorite.addEventListener("click", () => {
        close();
        void act(item.favorite ? "unfavorite" : "favorite", [item], item.id);
      });
      out.push(favorite);
      const edit = entry("row-edit", "edit", t("list.menu_edit"), `#/items/${item.id}/edit`);
      edit.addEventListener("click", close);
      out.push(edit);
      if (typeof moveToFolder === "function") {
        const move = entry("row-move", "folder", t("list.menu_move"), null);
        move.addEventListener("click", () => {
          close();
          moveToFolder([item], { host, say: (text) => say(text) });
        });
        out.push(move);
      }
      const del = entry("row-delete", "trash", t("list.menu_delete"), null);
      del.addEventListener("click", () => {
        close();
        void act("trash", [item], item.id);
      });
      out.push(del);
    }
    return out;
  }

  /** Puts the menu of a row next to its button, on the screen, above the button when there is no room below. @param {any} button @param {any} menu */
  function placeMenu(button, menu) {
    if (typeof button.getBoundingClientRect !== "function" || !menu.style) return;
    const at = button.getBoundingClientRect();
    const height = win?.innerHeight ?? 0;
    const width = win?.innerWidth ?? 0;
    const below = height - at.bottom >= ROW_MENU_HEIGHT || at.top < ROW_MENU_HEIGHT;
    menu.style.left = `${Math.max(8, Math.min(width - 8 - ROW_MENU_WIDTH, at.right - ROW_MENU_WIDTH))}px`;
    menu.style.top = below ? `${at.bottom + 4}px` : "auto";
    menu.style.bottom = below ? "auto" : `${height - at.top + 4}px`;
  }

  /** Which rows to draw: all of a short list, the ones that cross the screen of a long one. @param {{ start: number, end: number } | null} [force] */
  function range(force = null) {
    const count = shown.length;
    if (count <= WINDOW_FROM) return { start: 0, end: count };
    if (force) return { start: Math.max(0, Math.min(count, force.start)), end: Math.max(0, Math.min(count, force.end)) };
    if (typeof rows.getBoundingClientRect !== "function" || !(win?.innerHeight > 0)) return { start: 0, end: Math.min(count, UNMEASURED_ROWS) };
    const at = rows.getBoundingClientRect();
    return windowRange({ count, rowHeight, top: -at.top, viewport: win.innerHeight });
  }

  /** @param {{ start: number, end: number } | null} [force] */
  function renderRows(force = null) {
    if (wiped) return;
    const { start, end } = range(force);
    const want = shown.slice(start, end);
    const keep = new Set(want.map((item) => item.id));
    for (const [id, entry] of drawn) {
      if (keep.has(id)) continue;
      if (entry.own.pop) menus.delete(entry.own.pop);
      entry.node.remove();
      drawn.delete(id);
    }
    want.forEach((item, i) => {
      let entry = drawn.get(item.id);
      const sig = signature(item);
      /** The control that had the focus in a row that is built again. @type {string | null} */
      let refocus = null;
      if (entry && entry.sig !== sig) {
        const active = /** @type {any} */ (globalThis.document)?.activeElement;
        if (active && within(active, entry.node)) refocus = active.getAttribute?.("data-role") ?? null;
        if (entry.own.pop) menus.delete(entry.own.pop);
        entry.node.remove();
        entry = undefined;
      }
      if (!entry) {
        const made = makeRow(item, start + i);
        entry = { node: made.node, sig, check: made.check, link: made.link, more: made.more, own: made.own };
        drawn.set(item.id, entry);
      }
      const here = rows.childNodes[1 + i];
      if (here !== entry.node) rows.insertBefore(entry.node, here ?? spacerBottom);
      if (refocus !== null) focusNode(refocus === "select" ? entry.check : refocus === "row-menu" ? entry.more : entry.link);
      const rowIndex = String(start + i + 2);
      if (entry.node.getAttribute("aria-rowindex") !== rowIndex) entry.node.setAttribute("aria-rowindex", rowIndex);
    });
    if (spacerTop.style) {
      spacerTop.style.height = `${start * rowHeight}px`;
      spacerBottom.style.height = `${(shown.length - end) * rowHeight}px`;
    }
    // The first row says how tall they are: a phone's cards are taller than a table's rows.
    const first = want.length > 0 ? drawn.get(want[0].id)?.node : null;
    if (first && typeof first.getBoundingClientRect === "function") {
      const measured = first.getBoundingClientRect().height;
      if (measured > 8 && Math.abs(measured - rowHeight) > 0.5) {
        rowHeight = measured;
        if (shown.length > WINDOW_FROM) renderRows(force);
      }
    }
  }

  /** The page scrolled or was resized: the menu of a row was placed for the page as it was, so it closes; the window of rows follows, once a frame. */
  function onScroll() {
    if (wiped) return;
    for (const entry of drawn.values()) entry.own.pop?.close(false);
    if (shown.length <= WINDOW_FROM || framed) return;
    framed = true;
    const run = () => {
      framed = false;
      renderRows();
    };
    if (typeof win?.requestAnimationFrame === "function") win.requestAnimationFrame(run);
    else run();
  }

  // ---------------------------------------------------------- selection
  function paintSelection() {
    for (const [id, entry] of drawn) {
      const on = selected.has(id);
      if (entry.check.checked !== on) entry.check.checked = on;
      entry.node.setAttribute("data-selected", on ? "true" : "false");
    }
    renderBulk();
  }

  function renderBulk() {
    const n = selected.size;
    selectAll.checked = shown.length > 0 && n === shown.length;
    /** @type {any} */ (selectAll).indeterminate = n > 0 && n < shown.length;
    bulk.hidden = n === 0;
    if (n === 0) return;
    mount(bulkCount, document.createTextNode(t(n === 1 ? "list.bulk_one" : "list.bulk_many", { count: n })));
    const everyFavorite = shown.filter((item) => selected.has(item.id)).every((item) => item.favorite === true);
    mount(bulkFavorite, document.createTextNode(t(everyFavorite ? "list.bulk_unfavorite" : "list.bulk_favorite")));
    bulkFavorite.setAttribute("data-mode", everyFavorite ? "unfavorite" : "favorite");
    /** @type {any} */ (bulkFavorite).disabled = busy;
    /** @type {any} */ (bulkTrash).disabled = busy;
  }

  selectAll.addEventListener("change", () => {
    if (!touch()) {
      selectAll.checked = !selectAll.checked;
      return;
    }
    selected.clear();
    if (selectAll.checked) for (const item of shown) selected.add(item.id);
    paintSelection();
  });
  bulkClear.addEventListener("click", () => {
    selected.clear();
    paintSelection();
  });
  bulkFavorite.addEventListener("click", () => {
    const items = shown.filter((item) => selected.has(item.id));
    void act(bulkFavorite.getAttribute("data-mode") === "unfavorite" ? "unfavorite" : "favorite", items, null);
  });
  bulkTrash.addEventListener("click", () => {
    void act("trash", shown.filter((item) => selected.has(item.id)), null);
  });

  // ------------------------------------------------------------ actions
  /** The item as the engine has it now (the list may have been drawn before a change). @param {any} item */
  const latestOf = (item) => engine.list().find((entry) => entry.id === item.id) ?? item;

  /**
   * A change of one or several items, one write each in the engine's outbox. The list is read again once at the end, not
   * after each write.
   * @param {"favorite" | "unfavorite" | "trash"} kind
   * @param {any[]} items
   * @param {string | null} returnTo the row whose menu button gets the focus back
   */
  async function act(kind, items, returnTo) {
    if (wiped || items.length === 0) return;
    if (busy) {
      say(t("list.busy"));
      return;
    }
    if (!touch()) return;
    busy = true;
    renderBulk();
    mount(message);
    let changedAny = false;
    let text = "";
    try {
      if (kind === "trash") {
        // Items with a passkey: the question names the sites that still hold the public keys and says what happens to the keys here.
        const keys = passkeySites(items.map((item) => latestOf(item)));
        const yes = await askConfirm({
          t, host, title: items.length === 1 ? "list.trash_title_one" : "list.trash_title_many",
          body: keys.passkeys === 0 ? "list.trash_body" : items.length === 1 ? "passkey.delete_body" : "passkey.delete_many_body", confirm: "list.trash_confirm",
          vars: { name: items.length === 1 ? (items[0].name === "" ? t("vault.item.unnamed") : items[0].name) : "", count: items.length, site: keys.sites, sites: keys.sites, passkeys: keys.passkeys },
        });
        if (!yes || wiped) return;
      }
      // The newest revision of each item: a change that came in since the list was drawn.
      const latest = new Map(engine.list().map((item) => [item.id, item]));
      let done = 0;
      let skipped = 0;
      let failed = 0;
      /** @type {unknown} */
      let first = null;
      /** The rows that are settled: changed, already as asked, or not to be changed. A row that failed stays marked, to be tried again. @type {string[]} */
      const settled = [];
      let count = 0;
      for (const picked of items) {
        if (wiped) return;
        // The run is the user's own action: each write counts as activity, so the idle lock does not cut a long run in the middle.
        if (count > 0 && !touch()) return;
        count += 1;
        const item = latest.get(picked.id) ?? picked;
        if (!canChange(item)) {
          skipped += 1;
          settled.push(picked.id);
        } else if (kind !== "trash" && (item.favorite === true) === (kind === "favorite")) {
          done += 1; // it is as asked already
          settled.push(picked.id);
        } else {
          try {
            if (kind === "trash") await /** @type {any} */ (engine).remove(item.id);
            else await /** @type {any} */ (engine).update(item.id, { favorite: kind === "favorite" }, item.rev);
            done += 1;
            changedAny = true;
            settled.push(picked.id);
          } catch (error) {
            failed += 1;
            first ??= error;
          }
        }
        // The line is a status that is read out: not for every item of ten thousand.
        if (items.length > 1 && count % 25 === 0) say(t("list.progress", { done: done + skipped + failed, total: items.length }));
      }
      for (const id of settled) selected.delete(id);
      text = [
        done > 0 ? t(`list.done_${kind}`, { count: done }) : "",
        skipped > 0 ? t("list.done_skipped", { count: skipped }) : "",
        failed > 0 ? `${t("list.done_failed", { count: failed })} ${describeError(t, first)}` : "",
      ].filter((part) => part !== "").join(" ");
    } catch (error) {
      text = describeError(t, error);
    } finally {
      busy = false;
      if (!wiped) {
        update(changedAny || dirty);
        paintSelection();
        dirty = false;
        mount(message, document.createTextNode(text));
        if (returnTo !== null) focusRow(returnTo);
        else if (selected.size === 0) focusNode(shown.length > 0 ? selectAll : add); // the bar that had the focus has gone
      }
    }
  }

  // ---------------------------------------------------------- the focus
  /** The focus goes to the menu button of a row, or to the search field when the row has left the list. @param {string} id */
  function focusRow(id) {
    const entry = drawn.get(id);
    focusNode(entry ? entry.more : search);
  }

  /** The Up and Down keys move between the rows: the same control of the next row (the name, the box or the menu button). */
  rows.addEventListener("keydown", (/** @type {any} */ event) => {
    // On the menu button the arrows open its menu (they are taken there); the rows are moved between from the name and the box.
    if ((event.key !== "ArrowDown" && event.key !== "ArrowUp") || event.defaultPrevented === true) return;
    const role = event.target?.getAttribute?.("data-role");
    if (role !== "item-link" && role !== "select") return;
    let node = event.target;
    while (node && node.getAttribute?.("data-role") !== "item") node = node.parentNode;
    if (!node) return;
    const at = indexOf(node.getAttribute("data-id"));
    if (at === undefined) return;
    const to = at + (event.key === "ArrowDown" ? 1 : -1);
    if (to < 0 || to >= shown.length) return;
    event.preventDefault?.();
    // The next row may be outside the window that is drawn: it is drawn first.
    if (!drawn.has(shown[to].id)) renderRows({ start: to - OVERSCAN, end: to + OVERSCAN + 1 });
    const next = drawn.get(shown[to].id);
    if (next) focusNode(role === "select" ? next.check : next.link);
  });

  // ------------------------------------------------- the menu of columns
  let customiseShape = "";
  function renderCustomise() {
    const columns = [["changed", t("list.col_changed")], ...(haveFolders ? [["folders", t("list.col_folders")]] : [])];
    const shape = columns.map(([column]) => column).join(",");
    if (shape !== customiseShape) {
      customiseShape = shape;
      mount(customiseMenu, ...columns.map(([column, label]) => {
        const item = el("button", {
          type: "button", role: "menuitemcheckbox", tabindex: "-1", class: "menu-check", "aria-checked": "false", "data-value": column, "data-role": `column-${column}`,
        }, el("span", { class: "box", "aria-hidden": "true" }), el("span", { class: "menu-label" }, t("list.show_column", { column: label })));
        item.addEventListener("click", () => {
          prefs.setShown(column, !prefs.shows(column));
          update();
        });
        return item;
      }));
    }
    for (const item of /** @type {any[]} */ ([...customiseMenu.childNodes])) item.setAttribute("aria-checked", prefs.shows(/** @type {any} */ (item).getAttribute("data-value")) ? "true" : "false");
  }
  const customisePop = popMenu({ trigger: customise, menu: customiseMenu, items: () => /** @type {HTMLElement[]} */ ([...customiseMenu.childNodes]), escape: true, onOpen: () => closeMenus(customisePop) });
  menus.add(customisePop);

  // --------------------------------------------------------------- search
  function clearTheSearch() {
    search.value = "";
    query = "";
    update();
    focusNode(search);
  }
  search.addEventListener("input", () => {
    query = search.value ?? "";
    update();
  });
  clearSearch.addEventListener("click", clearTheSearch);
  search.addEventListener("keydown", (/** @type {any} */ event) => {
    if (event.key === "Escape" && query !== "") {
      event.preventDefault?.();
      clearTheSearch();
    }
  });

  // ------------------------------------------------------------- wiring
  const pointerOutside = (/** @type {any} */ event) => {
    if ((/** @type {any} */ (root)).isConnected === false && drawnOnce) {
      doc?.removeEventListener?.("pointerdown", pointerOutside);
      return;
    }
    for (const menu of menus) if (menu.isOpen() && !within(event.target, menu.menu) && !within(event.target, menu.trigger)) menu.close(false);
  };
  doc?.addEventListener?.("pointerdown", pointerOutside);
  win?.addEventListener?.("scroll", onScroll, { passive: true, capture: true });
  win?.addEventListener?.("resize", onScroll);

  /** Lets go of everything the list handed to the page. */
  function dispose() {
    doc?.removeEventListener?.("pointerdown", pointerOutside);
    win?.removeEventListener?.("scroll", onScroll, { capture: true });
    win?.removeEventListener?.("resize", onScroll);
  }

  // The lock wipes the screen: no item name stays in a node of the page.
  scope?.add(() => {
    wiped = true;
    dispose();
    offWatch?.();
    offWatch = null;
    selected.clear();
    drawn.clear();
    menus.clear();
    source = [];
    shown = [];
    ordered = { name: [], changed: [] };
    folderCounts = new Map();
    indexes = null;
    matcher.clear();
    mount(root);
  });

  mount(root,
    heading,
    conflicts,
    el("div", { class: "list-card" }, bar, empty, table),
    message,
    host,
    el("p", { class: "aside" }, el("a", { href: "#/trash", "data-role": "trash-link" }, t("conflict.trash.link"))));
  update(true);
  warmUp();
  const off = listenWhileShown(root, engine, "changed", () => {
    if (wiped) return;
    if (busy) {
      dirty = true;
      return;
    }
    // A short list is drawn at once. A long one (the first sync of a big vault sends many events) is read once for the events of one turn.
    if (source.length <= WINDOW_FROM) {
      update(true);
      return;
    }
    if (pending) return;
    pending = true;
    void Promise.resolve().then(() => {
      pending = false;
      if (wiped) return;
      if (busy) dirty = true;
      else update(true);
    });
  });
  scope?.add(off);
  return root;
}
