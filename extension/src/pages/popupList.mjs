// The list of the vault in the popup's unlocked view (the approved layout):
// the vault and its count, the search and the filter by type, the chip of the
// filter that is on, and the sections "Suggestions for this page" (the
// candidates of the page, with "Fill" and "Copy password"), "Favourites" and
// "All items" (open the site, the copy menu with "Copy user name" or "Copy
// e-mail" and "Copy password", and a menu with "View", "Copy user name", "Copy
// password" and "Open the site"). "View" shows one item.
//
// The popup builds everything with `el()` from what the background answered:
// names, user names, marks and references. A password or a code never reaches
// this page. A copy is written to the clipboard by the background, and a fill
// is done by the background in the page's frame; the popup only learns
// whether it worked.

import { el, mount } from "../shared/dom.mjs";
import { createCopyMenu } from "./copyMenu.mjs";
import { COPY_FIELDS, FILTER_TYPES, actionErrorKey } from "./popupFlow.mjs";

/** @typedef {import("./page.mjs").Texts} Texts */
/** @typedef {import("./popupFlow.mjs").Row} Row */
/** @typedef {ReturnType<typeof import("./popupFlow.mjs").createListFlow>} ListFlow */

/** How long a typed search waits for the next key before it asks. */
const SEARCH_DELAY_MS = 150;
/** How long a note under the list stays. */
const TOAST_MS = 4000;
/** The tints of the item tiles (popup.css, `.ff-tint-<n>`). */
const TINTS = 6;

/** The icons of the layout (popup.css draws each one as a mask in the text colour). */
const ICONS = Object.freeze(["vault", "search", "filter", "copy", "open", "back", "more"]);

/** One icon of the layout: an empty element whose class names the drawing. @param {string} name */
function icon(name) {
  if (!ICONS.includes(name)) throw new TypeError(`popup: no icon ${name}`);
  return el("span", { class: `ff-ico ff-ico-${name}`, "aria-hidden": "true" });
}

/** The tint of an item's tile, the same for the same name. @param {string} name */
function tintOf(name) {
  let n = 0;
  for (const ch of name) n = (n * 31 + (ch.codePointAt(0) ?? 0)) % 9973;
  return `ff-tint-${n % TINTS}`;
}

/** The first letter of a name, for its tile. @param {string} name */
const initialOf = (name) => ([...name.trim()][0] ?? "?").toLocaleUpperCase();

/**
 * @param {{
 *   texts: Texts,
 *   list: ListFlow,
 *   tabId: number | null,
 *   onFilled: () => void,
 *   onGrant: (origin: string) => void,
 * }} options `tabId` is the tab whose page the popup is about (null: none); `onFilled` runs after a fill worked;
 *   `onGrant` opens the tab that asks for a frame's host permission
 */
export function createVaultList({ texts, list, tabId, onFilled, onGrant }) {
  const t = texts.t;
  /** The filter by type that is on, or null. @type {string | null} */
  let type = null;
  let query = "";
  /** Counts the loads: an answer to an older load is dropped. */
  let generation = 0;
  /** @type {ReturnType<typeof setTimeout> | null} */
  let searchTimer = null;
  /** @type {ReturnType<typeof setTimeout> | null} */
  let toastTimer = null;
  /** The row menu that is open: its button and its close. @type {{ button: HTMLElement, close: () => void } | null} */
  let openMenu = null;
  /** How many rows each section showed (after "Show more"), so a reload of the popup's own keeps them. @type {Map<string, number>} */
  const shownOf = new Map();

  const count = el("span", { class: "ff-count", "data-role": "item-count" });
  const picker = el(
    "div",
    { class: "ff-picker-row" },
    el("span", { class: "ff-picker", "data-role": "vault-name" }, icon("vault"), t("popup.vault.all")),
    count,
  );

  const input = /** @type {HTMLInputElement} */ (
    el("input", { type: "search", id: "search", class: "ff-search-input", "data-role": "search", autocomplete: "off", placeholder: t("popup.search.placeholder") })
  );
  const badge = el("span", { class: "ff-badge", "data-role": "filter-badge", hidden: true }, "1");
  const filterButton = el(
    "button",
    { type: "button", class: "ff-filter", "data-role": "filter", "aria-haspopup": "menu", "aria-expanded": "false", "aria-label": t("popup.filter.label"), title: t("popup.filter.label") },
    icon("filter"),
    badge,
  );
  const filterMenu = el("div", { class: "ff-menu ff-filter-menu", role: "menu", "data-role": "filter-menu", hidden: true });
  const searchRow = el(
    "div",
    { class: "ff-search-row" },
    el("label", { class: "ff-search", for: "search" }, icon("search"), el("span", { class: "ff-sr" }, t("popup.search.label")), input),
    el("div", { class: "ff-filter-wrap" }, filterButton, filterMenu),
  );
  const chips = el("div", { class: "ff-chips", "data-role": "filter-chips", hidden: true });
  const body = el("div", { class: "ff-list", "data-role": "list" });
  const toast = el("p", { class: "ff-toast", role: "status", "data-role": "toast", hidden: true });
  const root = el("div", { class: "ff-vault", "data-role": "vault" }, picker, searchRow, chips, body, toast);

  /** @param {string} key @param {Record<string, string | number>} [vars] @param {boolean} [bad] */
  function say(key, vars, bad = false) {
    if (toastTimer !== null) clearTimeout(toastTimer);
    toast.textContent = t(key, vars);
    toast.classList.toggle("ff-toast-bad", bad);
    toast.hidden = false;
    toastTimer = setTimeout(() => {
      toast.hidden = true;
      toastTimer = null;
    }, TOAST_MS);
  }

  function closeMenus() {
    openMenu?.close();
    openMenu = null;
    filterMenu.hidden = true;
    filterButton.setAttribute("aria-expanded", "false");
  }

  // A click outside a menu, or Escape, closes it.
  document.addEventListener("click", (event) => {
    const target = /** @type {Node | null} */ (event.target);
    if (openMenu !== null && target !== null && !openMenu.button.parentElement?.contains(target)) closeMenus();
    if (!filterMenu.hidden && target !== null && !filterMenu.parentElement?.contains(target)) closeMenus();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || (openMenu === null && filterMenu.hidden)) return;
    const back = openMenu?.button ?? filterButton;
    closeMenus();
    event.preventDefault();
    back.focus();
  });

  /**
   * Runs an action of the background and says how it went.
   * @param {() => Promise<{ ok: boolean, reason?: string }>} action @param {string} done the i18n key when it worked
   */
  async function act(action, done) {
    try {
      const result = await action();
      if (result?.ok) {
        say(done);
        return true;
      }
      say(actionErrorKey(result?.reason), undefined, true);
    } catch (error) {
      say(actionErrorKey(/** @type {any} */ (error)?.code), undefined, true);
    }
    return false;
  }

  /** @param {string} ref @param {string} field @param {string} [done] the i18n key of the note when it worked */
  const copy = (ref, field, done = `popup.copied.${field}`) => act(() => list.copy(ref, field), done);
  /** @param {string} ref */
  const openSite = (ref) => act(() => list.openSite(ref), "popup.opened");

  /** An icon button of a row. @param {string} role @param {string} label @param {string} name */
  const iconButton = (role, label, name) =>
    el("button", { type: "button", class: "ff-row-icon", "data-role": role, "aria-label": label, title: label }, icon(name));

  /** The tile and the two lines of a row. @param {Row} row */
  function rowText(row) {
    const name = row.name === "" ? t("popup.item.unnamed") : row.name;
    return [
      el("span", { class: `ff-tile ${tintOf(name)}`, "aria-hidden": "true" }, initialOf(name)),
      el(
        "span",
        { class: "ff-row-text" },
        el("span", { class: "ff-row-name", "data-role": "row-name" }, name, row.favorite ? el("span", { class: "ff-star", role: "img", "aria-label": t("popup.item.favorite") }, " ★") : null),
        row.username !== "" ? el("span", { class: "ff-row-user", "data-role": "row-user" }, row.username) : null,
      ),
    ];
  }

  /**
   * The menu of a row: only what works in this version.
   * @param {Row} row
   */
  function rowMenu(row) {
    const button = iconButton("more", t("popup.row.more"), "more");
    button.setAttribute("aria-haspopup", "menu");
    button.setAttribute("aria-expanded", "false");
    const menu = el("div", { class: "ff-menu ff-row-menu", role: "menu", "data-role": "row-menu", hidden: true });
    /** @param {string} role @param {string} label @param {() => unknown} run */
    const entry = (role, label, run) => {
      const item = el("button", { type: "button", role: "menuitem", class: "ff-menu-item", "data-role": role }, label);
      item.addEventListener("click", () => {
        closeMenus();
        void run();
      });
      return item;
    };
    menu.append(
      entry("menu-view", t("popup.row.view"), () => showItem(row)),
      entry("menu-copy-username", t("popup.row.copy_username"), () => copy(row.ref, "username")),
      entry("menu-copy-password", t("popup.row.copy_password"), () => copy(row.ref, "password")),
    );
    if (row.site) menu.append(entry("menu-open-site", t("popup.row.open_site"), () => openSite(row.ref)));
    button.addEventListener("click", () => {
      const wasOpen = openMenu?.button === button;
      closeMenus();
      if (wasOpen) return;
      menu.hidden = false;
      button.setAttribute("aria-expanded", "true");
      openMenu = {
        button,
        close: () => {
          menu.hidden = true;
          button.setAttribute("aria-expanded", "false");
        },
      };
      /** @type {HTMLElement | null} */ (menu.querySelector('[role="menuitem"]'))?.focus();
    });
    return el("span", { class: "ff-row-more" }, button, menu);
  }

  /**
   * A candidate of the page: "Fill" and the copy menu. An item on an unencrypted page needs one click more.
   * @param {Row} row
   */
  function suggestionRow(row) {
    const fill = el("button", { type: "button", class: "ff-fill", "data-role": "fill" }, t("popup.row.fill"));
    const warning = row.insecure ? el("span", { class: "ff-insecure", "data-role": "insecure" }, t("popup.row.insecure")) : null;
    let confirmed = !row.insecure;
    fill.addEventListener("click", async () => {
      if (tabId === null) return;
      if (!confirmed) {
        confirmed = true;
        fill.textContent = t("popup.row.fill_anyway");
        return;
      }
      fill.setAttribute("disabled", "");
      const ok = await act(() => list.fill(row, /** @type {number} */ (tabId)), "popup.filled");
      fill.removeAttribute("disabled");
      if (ok) onFilled();
    });
    const text = rowText(row);
    if (warning) /** @type {HTMLElement} */ (text[1]).append(warning);
    return el(
      "div",
      { class: "ff-row", "data-role": "suggestion", "data-ref": row.ref },
      ...text,
      fill,
      copyMenu(row),
    );
  }

  /**
   * The copy button of a row: a menu of the values the row's item can be asked to copy. Like the row's other menu,
   * it closes the other menus when it opens, and a click elsewhere or Escape closes it.
   * @param {Row} row
   */
  function copyMenu(row) {
    /** @type {HTMLElement | null} */
    let button = null;
    const menu = createCopyMenu({
      row,
      t,
      copy: (field, done) => copy(row.ref, field, done),
      onOpen: (close) => {
        closeMenus();
        openMenu = { button: /** @type {HTMLElement} */ (button), close };
      },
      onClose: () => {
        if (openMenu?.button === button) openMenu = null;
      },
    });
    button = menu.button;
    return menu.root;
  }

  /**
   * An item of the vault (a favourite, or in all items): open the site, the copy menu and the menu. It is never
   * filled from here.
   * @param {Row} row
   */
  function itemRow(row) {
    /** @type {HTMLElement | null} */
    let site = null;
    if (row.site) {
      site = iconButton("open-site", t("popup.row.open_site"), "open");
      site.addEventListener("click", () => void openSite(row.ref));
    }
    return el("div", { class: "ff-row", "data-role": "item-row", "data-ref": row.ref }, ...rowText(row), site, copyMenu(row), rowMenu(row));
  }

  /** @param {string} title @param {number} total @param {string} role */
  const heading = (title, total, role) =>
    el("div", { class: "ff-section-head" }, el("h2", { class: "ff-section-title" }, title), el("span", { class: "ff-count", "data-role": `${role}-count` }, String(total)));

  /**
   * A section of rows, with "Show more" when the vault holds more than one page.
   * @param {{
   *   role: string,
   *   title: string,
   *   section: import("./popupFlow.mjs").Section,
   *   more?: (offset: number, automatic: boolean) => Promise<import("./popupFlow.mjs").Section>,
   *   keep?: number,
   *   automatic?: boolean,
   * }} o `keep`: the rows to show again (a reload of the popup's own keeps what "Show more" showed)
   * @returns {Promise<HTMLElement>}
   */
  async function section({ role, title, section: part, more, keep = 0, automatic = false }) {
    const rows = el("div", { class: "ff-rows", "data-role": `${role}-rows` }, ...part.rows.map(itemRow));
    const box = el("section", { class: "ff-section", "data-role": role }, heading(title, part.total, role), rows);
    let shown = part.rows.length;
    let total = part.total;
    /** @param {boolean} quiet */
    const next = async (quiet) => {
      if (!more) return false;
      const page = await more(shown, quiet);
      rows.append(...page.rows.map(itemRow));
      shown += page.rows.length;
      total = page.total;
      shownOf.set(role, shown);
      return page.rows.length > 0;
    };
    // The pages the user had opened, read again (a few at most).
    for (let pages = 0; more && shown < Math.min(keep, total) && pages < 10; pages += 1) {
      if (!(await next(automatic).catch(() => false))) break;
    }
    if (more && shown < total) {
      const button = el("button", { type: "button", class: "ff-more", "data-role": `${role}-more` }, t("popup.list.more"));
      button.addEventListener("click", async () => {
        button.setAttribute("disabled", "");
        try {
          await next(false);
          if (shown >= total) button.remove();
        } catch {
          say("popup.error.unknown", undefined, true);
        }
        button.removeAttribute("disabled");
      });
      box.append(button);
    }
    return box;
  }

  /**
   * The frames of the page's site that wait for their host permission: each opens the tab that asks for it.
   * @param {import("./popupFlow.mjs").Grant[]} grants
   */
  function grantSection(grants) {
    return el(
      "section",
      { class: "ff-section", "data-role": "grant" },
      el("div", { class: "ff-section-head" }, el("h2", { class: "ff-section-title" }, t("popup.grant.title"))),
      el("p", { class: "ff-grant-hint" }, t("popup.grant.hint")),
      ...grants.map((g) => {
        const open = el("button", { type: "button", class: "ff-fill", "data-role": "grant-open", "data-origin": g.origin }, t("popup.grant.open"));
        open.addEventListener("click", () => onGrant(g.origin));
        return el("div", { class: "ff-row", "data-role": "grant-row" }, el("span", { class: "ff-row-text" }, el("span", { class: "ff-row-name ff-host", dir: "ltr" }, g.host)), open);
      }),
    );
  }

  /**
   * Builds the list again from the background's answers.
   * @param {{ automatic?: boolean }} [o] `automatic`: the popup reloads by itself (the sync changed something), which is not
   *   activity of the user and must not keep the vault open
   */
  async function reload({ automatic = false } = {}) {
    generation += 1;
    const mine = generation;
    closeMenus();
    const searching = query.trim() !== "";
    const [page, found] = await Promise.all([
      searching ? Promise.resolve(null) : list.page(tabId, { automatic }),
      list.list({ query, type, automatic }),
    ]);
    if (mine !== generation) return;
    count.textContent = t("popup.vault.count", { count: found.count });
    // A reload by the user (a new search, a filter, back from an item) starts from the first page again.
    if (!automatic) shownOf.clear();
    /** @type {HTMLElement[]} */
    const parts = [];
    if (page !== null && page.rows.length > 0) {
      parts.push(
        el(
          "section",
          { class: "ff-section", "data-role": "suggestions" },
          heading(t("popup.section.suggestions"), page.rows.length, "suggestions"),
          page.host !== "" ? el("p", { class: "ff-page-host ff-host", dir: "ltr", "data-role": "page-host" }, page.host) : null,
          el("div", { class: "ff-rows" }, ...page.rows.map(suggestionRow)),
        ),
      );
    }
    if (page !== null && page.grant.length > 0) parts.push(grantSection(page.grant));
    if (found.favorites !== null && found.favorites.rows.length > 0) {
      parts.push(
        await section({
          role: "favorites",
          title: t("popup.section.favorites"),
          section: found.favorites,
          more: (offset, quiet) => list.search({ favorites: true, type, offset, automatic: quiet }),
          keep: shownOf.get("favorites") ?? 0,
          automatic,
        }),
      );
    }
    const role = searching ? "results" : "all";
    parts.push(
      await section({
        role,
        title: t(searching ? "popup.section.results" : "popup.section.all"),
        section: found.all,
        more: (offset, quiet) => list.search({ query, type, offset, automatic: quiet }),
        keep: shownOf.get(role) ?? 0,
        automatic,
      }),
    );
    if (mine !== generation) return;
    if (found.all.rows.length === 0) parts.push(el("p", { class: "ff-empty", "data-role": "empty" }, t(searching || type !== null ? "popup.list.none_found" : "popup.list.empty")));
    mount(body, ...parts);
  }

  /** Shows one item: its name, user name and addresses, and what can be copied. Never a value that is secret. @param {Row} row */
  async function showItem(row) {
    generation += 1;
    const back = el("button", { type: "button", class: "ff-back", "data-role": "back" }, icon("back"), t("popup.item.back"));
    back.addEventListener("click", () => {
      searchRow.hidden = false;
      picker.hidden = false;
      void reload().then(() => input.focus());
    });
    searchRow.hidden = true;
    picker.hidden = true;
    chips.hidden = true;
    mount(body, el("section", { class: "ff-item", "data-role": "item-view" }, back, el("p", { class: "ff-hint" }, t("popup.item.loading"))));
    back.focus();
    /** @type {any} */
    let view;
    try {
      view = await list.item(row.ref);
    } catch {
      view = { ok: false, reason: "unknown" };
    }
    if (!view?.ok) {
      mount(body, el("section", { class: "ff-item", "data-role": "item-view" }, back, el("p", { class: "ff-error", role: "alert" }, t(actionErrorKey(view?.reason)))));
      return;
    }
    const copyable = Array.isArray(view.copyable) ? view.copyable.filter((/** @type {string} */ f) => COPY_FIELDS.includes(f)) : [];
    /** @param {string} field @param {string} shown */
    const valueRow = (field, shown) => {
      const button = el("button", { type: "button", class: "ff-row-icon", "data-role": `copy-${field}`, "aria-label": t(`popup.row.copy_${field}`), title: t(`popup.row.copy_${field}`) }, icon("copy"));
      button.addEventListener("click", () => void copy(row.ref, field));
      return el(
        "div",
        { class: "ff-value-row", "data-role": `value-${field}` },
        el("span", { class: "ff-value-label" }, t(`popup.item.${field}`)),
        el("span", { class: "ff-value" }, shown),
        button,
      );
    };
    const name = typeof view.name === "string" && view.name !== "" ? view.name : t("popup.item.unnamed");
    /** @type {string[]} */
    const urls = Array.isArray(view.urls) ? view.urls : [];
    /** @type {HTMLElement | null} */
    let site = null;
    if (row.site) {
      site = el("button", { type: "button", class: "ff-button", "data-role": "item-open-site" }, t("popup.row.open_site"));
      site.addEventListener("click", () => void openSite(row.ref));
    }
    mount(
      body,
      el(
        "section",
        { class: "ff-item", "data-role": "item-view" },
        back,
        el("div", { class: "ff-item-head" }, el("span", { class: `ff-tile ${tintOf(name)}`, "aria-hidden": "true" }, initialOf(name)), el("h2", { class: "ff-item-name", "data-role": "item-name" }, name, view.favorite ? el("span", { class: "ff-star", role: "img", "aria-label": t("popup.item.favorite") }, " ★") : null)),
        copyable.includes("username") ? valueRow("username", typeof view.username === "string" ? view.username : "") : null,
        // A password and a code are never shown: the popup does not have them.
        copyable.includes("password") ? valueRow("password", "••••••••") : null,
        copyable.includes("totp") ? valueRow("totp", "••• •••") : null,
        urls.length > 0 ? el("ul", { class: "ff-urls", "data-role": "item-urls" }, ...urls.map((u) => el("li", { class: "ff-host", dir: "ltr" }, u))) : null,
        site,
      ),
    );
  }

  /** The chip of the filter that is on, and the badge on the filter button. */
  function showFilter() {
    badge.hidden = type === null;
    filterButton.setAttribute("aria-label", type === null ? t("popup.filter.label") : t("popup.filter.label_on", { count: 1 }));
    if (type === null) {
      mount(chips);
      chips.hidden = true;
      return;
    }
    const chip = el("button", { type: "button", class: "ff-chip", "data-role": "filter-chip", "aria-label": t("popup.filter.clear") }, t("popup.filter.chip", { type: t(`popup.type.${type}`) }), " ✕");
    chip.addEventListener("click", () => {
      type = null;
      showFilter();
      void reload();
      input.focus();
    });
    mount(chips, chip);
    chips.hidden = false;
  }

  for (const choice of [null, ...FILTER_TYPES]) {
    const item = el(
      "button",
      { type: "button", role: "menuitemradio", class: "ff-menu-item", "data-role": "filter-type", "data-type": choice ?? "all" },
      t(choice === null ? "popup.type.all" : `popup.type.${choice}`),
    );
    item.addEventListener("click", () => {
      type = choice;
      for (const other of filterMenu.querySelectorAll('[role="menuitemradio"]')) {
        other.setAttribute("aria-checked", String(other.getAttribute("data-type") === (type ?? "all")));
      }
      closeMenus();
      showFilter();
      void reload();
    });
    item.setAttribute("aria-checked", String(choice === null));
    filterMenu.append(item);
  }
  filterButton.addEventListener("click", () => {
    const wasOpen = !filterMenu.hidden;
    closeMenus();
    if (wasOpen) return;
    filterMenu.hidden = false;
    filterButton.setAttribute("aria-expanded", "true");
    /** @type {HTMLElement | null} */ (filterMenu.querySelector('[aria-checked="true"]'))?.focus();
  });

  input.addEventListener("input", () => {
    if (searchTimer !== null) clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      searchTimer = null;
      query = input.value;
      void reload();
    }, SEARCH_DELAY_MS);
  });

  return {
    root,
    reload,
    focus: () => input.focus(),
    /** Whether the user is in the middle of something the list must not be built again under. */
    busy: () => openMenu !== null || !filterMenu.hidden || body.querySelector('[data-role="item-view"]') !== null,
  };
}
