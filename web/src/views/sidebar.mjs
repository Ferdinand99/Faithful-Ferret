// The side menu of the vault: the mark, the Vault/Admin switch, the entries
// (sidebarModel.mjs says which), the pinned folders, and the account at the foot
// with its menu. On a phone it is a drawer that a button in the top bar opens.
//
// Nothing here holds a secret. The e-mail address is on the page only as text
// and as two letters; folder names are text nodes; the only things kept on the
// device are the folded flag and folder ids (uiPrefs.mjs).
//
// The pieces the frame needs from outside (the sync and live pills, what Lock and
// Sign out do) are handed in; the frame owns the rest of the page.
import { el, mount } from "../dom.mjs";
import { currentEntry, initialsOf, sidebarModel } from "./sidebarModel.mjs";

/** Where Help leads (the project's public documentation). */
export const HELP_URL = "https://github.com/Ferdinand99/Faithful-Ferret/tree/main/docs";

/** A phone: the menu is a drawer. Keep in step with styles/shell.css. */
export const PHONE_QUERY = "(max-width: 767.98px)";

let sequence = 0;

/** @param {any} node */
const focusNode = (node) => {
  if (typeof node?.focus === "function") node.focus();
};

/** Whether `node` is `ancestor` or stands below it. @param {any} node @param {any} ancestor */
function within(node, ancestor) {
  for (let one = node; one; one = one.parentNode) if (one === ancestor) return true;
  return false;
}

/**
 * A menu that opens from a button: `aria-expanded` on the button, arrow keys,
 * Home and End inside, and a way to close it that puts the focus back.
 * @param {{ trigger: HTMLElement, menu: HTMLElement, items: () => HTMLElement[], onOpen?: () => void }} options
 */
function popMenu({ trigger, menu, items, onOpen }) {
  let open = false;
  /** @param {boolean} value */
  const set = (value) => {
    open = value;
    menu.hidden = !value;
    trigger.setAttribute("aria-expanded", value ? "true" : "false");
  };
  /** @param {"first" | "last" | null} focus */
  const show = (focus) => {
    onOpen?.();
    set(true);
    const list = items();
    focusNode(focus === "last" ? list[list.length - 1] : list[0]);
  };
  set(false);
  trigger.addEventListener("click", () => {
    if (open) {
      set(false);
      return;
    }
    show("first");
  });
  trigger.addEventListener("keydown", (/** @type {any} */ event) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault?.();
      if (!open) show(event.key === "ArrowUp" ? "last" : "first");
    }
  });
  menu.addEventListener("keydown", (/** @type {any} */ event) => {
    const list = items();
    const at = list.findIndex((node) => node === event.target || within(event.target, node));
    /** @param {number} to */
    const move = (to) => {
      event.preventDefault?.();
      focusNode(list[(to + list.length) % list.length]);
    };
    if (event.key === "ArrowDown") move(at + 1);
    else if (event.key === "ArrowUp") move(at <= 0 ? list.length - 1 : at - 1);
    else if (event.key === "Home") move(0);
    else if (event.key === "End") move(list.length - 1);
    else if (event.key === "Tab") set(false); // the focus goes on to the next control by itself
  });
  return {
    trigger,
    menu,
    isOpen: () => open,
    /** @param {boolean} [returnFocus] */
    close(returnFocus = false) {
      if (!open) return;
      set(false);
      if (returnFocus) focusNode(trigger);
    },
  };
}

/**
 * @typedef {object} SidebarOptions
 * @property {(key: string, vars?: Record<string, string | number>) => string} t
 * @property {readonly any[]} routes the routes of the page; those with `sidebar` are listed
 * @property {{ all: number, favorites: number }} counts
 * @property {readonly { id: string, name: string, parentId?: string | null }[]} [folders] the folders the vault has (none yet)
 * @property {ReturnType<typeof import("../uiPrefs.mjs").createUiPrefs>} prefs
 * @property {string | null} [email]
 * @property {HTMLElement} status the sync state (a pill)
 * @property {HTMLElement | null} liveStatus the live-update state, or null
 * @property {() => Promise<void> | void} onLock
 * @property {(() => Promise<void> | void) | undefined} [onSignOut]
 * @property {{ check(): Promise<boolean>, go(): void | Promise<void> } | undefined} [admin] the way to the admin pages, for an administrator
 * @property {readonly string[]} [accountPaths] the pages the account page lists
 * @property {string} [helpUrl]
 * @property {any} [win]
 */

/**
 * @param {SidebarOptions} options
 */
export function sidebarView({
  t, routes, counts, folders = [], prefs, email = null, status, liveStatus, onLock, onSignOut, admin, accountPaths = [], helpUrl = HELP_URL, win,
}) {
  sequence += 1;
  const sideId = `vault-side-${sequence}`;
  const accountMenuId = `account-menu-${sequence}`;
  let currentCounts = counts;
  let currentFolders = folders;
  let path = "";
  let drawerOpen = false;

  // ---- the top bar of a phone: the button that opens the drawer, and the name
  const menuButton = el("button", {
    type: "button", class: "side-btn side-menu-open", "aria-label": t("shell.menu.open"), "aria-expanded": "false", "aria-controls": sideId, "data-role": "menu-open",
  }, el("span", { class: "icon", "data-icon": "menu", "aria-hidden": "true" }));
  const top = el("header", { class: "vault-top", "data-role": "top-bar" },
    menuButton,
    el("a", { class: "brand", href: "#/items" }, t("shell.brand")));

  // ---- the head of the menu: the mark, the name, fold and close
  const collapseButton = el("button", { type: "button", class: "side-btn side-collapse", "data-role": "collapse" },
    el("span", { class: "icon", "data-icon": "panel", "aria-hidden": "true" }));
  const closeButton = el("button", { type: "button", class: "side-btn side-close", "aria-label": t("shell.menu.close"), "data-role": "menu-close" },
    el("span", { class: "icon", "data-icon": "close", "aria-hidden": "true" }));
  const head = el("div", { class: "side-head" },
    el("a", { class: "brand", href: "#/items", "data-role": "brand" }, t("shell.brand")), collapseButton, closeButton);

  // ---- the switch to the admin pages: only for an administrator
  const switcher = el("button", { type: "button", class: "side-switch", "aria-label": t("shell.switch.label"), "data-role": "switch-admin" },
    el("span", { class: "icon", "data-icon": "vault", "aria-hidden": "true" }),
    el("span", { class: "side-label", "aria-hidden": "true" }, t("shell.switch.vault")),
    el("span", { class: "side-switch-other", "aria-hidden": "true" }, el("span", { class: "icon", "data-icon": "switch", "aria-hidden": "true" }), t("shell.switch.admin")));
  switcher.hidden = true;
  switcher.addEventListener("click", () => void admin?.go());
  if (admin) {
    void Promise.resolve()
      .then(() => admin.check())
      .then((yes) => {
        switcher.hidden = yes !== true;
      })
      .catch(() => undefined);
  }

  const lists = el("div", { class: "side-sections", "data-role": "side-sections" });
  const nav = el("nav", { class: "side-nav", "aria-label": t("shell.nav.label") }, switcher, lists);

  // ---- the account at the foot
  const avatar = el("span", { class: "avatar", "aria-hidden": "true" }, initialsOf(email));
  const accountButton = el("button", {
    type: "button", class: "side-account-btn", "aria-haspopup": "menu", "aria-expanded": "false", "aria-controls": accountMenuId,
    "aria-label": t("shell.account.menu", { email: email ?? t("security.nav.account") }), "data-role": "account-menu-button",
  }, avatar,
  el("span", { class: "side-email" }, email ?? t("security.nav.account")),
  el("span", { class: "icon side-caret", "data-icon": "switch", "aria-hidden": "true" }));

  /** A menu entry: a button, or a link when it goes to a page of this app. @param {string} role @param {string} icon @param {string} text @param {string | null} href */
  const menuItem = (role, icon, text, href) => {
    const attrs = { role: "menuitem", tabindex: "-1", class: "side-menuitem", "data-role": role };
    const inner = [el("span", { class: "icon", "data-icon": icon, "aria-hidden": "true" }), text];
    return href === null ? el("button", { type: "button", ...attrs }, ...inner) : el("a", { ...attrs, href }, ...inner);
  };
  const settingsItem = menuItem("nav-account", "account", t("shell.account.settings"), "#/account");
  const helpItem = menuItem("help", "help", t("shell.account.help"), null);
  const lockItem = menuItem("lock", "lock", t("shell.account.lock"), null);
  const signOutItem = menuItem("sign-out", "signout", t("shell.account.signout"), null);
  const accountItems = [settingsItem, helpItem, lockItem, ...(onSignOut ? [signOutItem] : [])];
  const accountMenu = el("div", { class: "side-menu", id: accountMenuId, role: "menu", "aria-label": t("security.nav.account"), "data-role": "account-menu" },
    settingsItem, helpItem, el("div", { class: "side-menu-sep", role: "separator" }), lockItem, ...(onSignOut ? [signOutItem] : []));
  const foot = el("div", { class: "side-foot" },
    el("div", { class: "side-account" }, accountButton, accountMenu),
    el("div", { class: "side-sync", "data-role": "side-sync" }, status, ...(liveStatus ? [liveStatus] : [])));

  const side = el("div", { class: "vault-side", id: sideId, "data-open": "false", "data-role": "side" }, head, nav, foot);
  const backdrop = el("div", { class: "side-backdrop", "data-open": "false", "data-role": "drawer-backdrop", "aria-hidden": "true" });

  // ---- menus: one open at a time
  /** @type {ReturnType<typeof popMenu>[]} */
  const menus = [];
  const closeMenus = (/** @type {ReturnType<typeof popMenu> | null} */ except = null) => {
    for (const menu of menus) if (menu !== except) menu.close(false);
  };
  const account = popMenu({ trigger: accountButton, menu: accountMenu, items: () => accountItems, onOpen: () => closeMenus() });
  menus.push(account);
  // A menu is opened by the one control: a second one that opens closes the first (the folder menus do the same).
  accountItems.forEach((item) => item.addEventListener("click", () => account.close(false)));

  settingsItem.addEventListener("click", () => closeDrawer(false));
  helpItem.addEventListener("click", () => {
    const opener = win?.open ?? globalThis.window?.open;
    if (typeof opener === "function") opener.call(win ?? globalThis.window, helpUrl, "_blank", "noopener,noreferrer");
  });
  lockItem.addEventListener("click", () => void onLock());
  signOutItem.addEventListener("click", () => void onSignOut?.());

  // ---- the drawer on a phone
  /** The parts of the page that are out of reach while the drawer is open. @type {any[]} */
  let behind = [];
  /** @param {any[]} nodes */
  function setBehind(nodes) {
    behind = nodes;
  }
  /** @param {boolean} value */
  function setDrawer(value) {
    drawerOpen = value;
    side.setAttribute("data-open", value ? "true" : "false");
    backdrop.setAttribute("data-open", value ? "true" : "false");
    menuButton.setAttribute("aria-expanded", value ? "true" : "false");
    for (const node of [...behind, top]) node.inert = value;
    if (value) closeMenus();
  }
  /** @param {boolean} returnFocus */
  function closeDrawer(returnFocus) {
    if (!drawerOpen) return;
    setDrawer(false);
    if (returnFocus) focusNode(menuButton);
  }
  menuButton.addEventListener("click", () => {
    setDrawer(true);
    focusNode(closeButton);
  });
  closeButton.addEventListener("click", () => closeDrawer(true));
  backdrop.addEventListener("click", () => closeDrawer(true));
  // Resizing to a wide window ends the drawer, so that nothing stays out of reach.
  const matcher = (win ?? globalThis.window)?.matchMedia?.(PHONE_QUERY);
  /** @param {any} event */
  const onResize = (event) => {
    // A menu that has left the page stops listening.
    if (/** @type {any} */ (side).isConnected === false) matcher.removeEventListener("change", onResize);
    else if (event.matches !== true) closeDrawer(false);
  };
  matcher?.addEventListener?.("change", onResize);

  // ---- fold to a rail (a wide window)
  /** @param {boolean} value */
  function paintCollapsed(value) {
    side.setAttribute("data-collapsed", value ? "true" : "false");
    const label = t(value ? "shell.menu.expand" : "shell.menu.collapse");
    collapseButton.setAttribute("aria-label", label);
    collapseButton.setAttribute("title", label);
  }
  paintCollapsed(prefs.collapsed());
  collapseButton.addEventListener("click", () => {
    const next = side.getAttribute("data-collapsed") !== "true";
    prefs.setCollapsed(next);
    paintCollapsed(next);
  });

  // ---- the entries
  /** @param {import("./sidebarModel.mjs").SidebarEntry} entry */
  function linkOf(entry) {
    const label = entry.kind === "folder" ? entry.label : t(entry.label);
    const icon = el("span", { class: "icon", "data-icon": entry.icon, "aria-hidden": "true" });
    if (entry.kind === "soon") {
      return el("span", { class: "side-link side-soon", role: "link", "aria-disabled": "true", "data-role": entry.role, title: t("shell.soon") },
        icon, el("span", { class: "side-label" }, label), el("span", { class: "side-tag" }, t("shell.soon")));
    }
    const link = el("a", { class: "side-link", href: /** @type {string} */ (entry.href), "data-role": entry.role, "data-entry": entry.id, title: label },
      icon, el("span", { class: "side-label" }, label),
      ...(entry.count === null ? [] : [el("span", { class: "side-count" }, String(entry.count))]));
    link.addEventListener("click", () => closeDrawer(false));
    return link;
  }

  /** @param {import("./sidebarModel.mjs").SidebarEntry} entry */
  function folderItem(entry) {
    const link = linkOf(entry);
    const li = el("li", { class: "side-item side-folder", "data-depth": String(entry.depth), "data-folder": entry.folder ?? "" }, link);
    if (entry.folder !== null) {
      const id = entry.folder;
      const more = el("button", {
        type: "button", class: "side-btn side-more", "aria-haspopup": "menu", "aria-expanded": "false", "data-role": "folder-menu-button",
        "aria-label": t("shell.pinned.options", { name: entry.label }),
      }, el("span", { class: "icon", "data-icon": "more", "aria-hidden": "true" }));
      const unpin = el("button", { type: "button", role: "menuitem", tabindex: "-1", class: "side-menuitem", "data-role": "unpin" },
        el("span", { class: "icon", "data-icon": "pin", "aria-hidden": "true" }), t("shell.pinned.unpin"));
      const menu = el("div", { class: "side-menu side-folder-menu", role: "menu", "aria-label": entry.label, "data-role": "folder-menu" }, unpin);
      const pop = popMenu({ trigger: more, menu, items: () => [unpin], onOpen: () => closeMenus(pop) });
      menus.push(pop);
      unpin.addEventListener("click", () => {
        prefs.unpin(id);
        render();
      });
      li.appendChild(more);
      li.appendChild(menu);
    }
    return li;
  }

  function render() {
    // The folder menus built before are gone with their entries; the account menu stays.
    for (let i = menus.length - 1; i >= 1; i -= 1) menus.splice(i, 1);
    const sections = sidebarModel({ routes, counts: currentCounts, folders: currentFolders, pinned: prefs.pinned() });
    mount(lists, ...sections.map((section) => {
      const heading = section.heading === null ? null : el("h2", { class: "side-heading", id: `${sideId}-${section.id}` }, t(section.heading));
      const list = el("ul", {
        class: "side-list", "data-section": section.id, ...(heading === null ? {} : { "aria-labelledby": `${sideId}-${section.id}` }),
      }, ...section.entries.map((entry) => (entry.kind === "folder" ? folderItem(entry) : el("li", { class: "side-item" }, linkOf(entry)))));
      return el("div", { class: "side-section", "data-section": section.id }, ...(heading ? [heading] : []), list);
    }));
    lists.setAttribute("data-current", currentEntry(sections, path) ?? "");
    markCurrent(path, sections);
  }

  /** Marks the entry the page belongs to (aria-current) and the account menu when the page is one of its. @param {string} next @param {import("./sidebarModel.mjs").SidebarSection[]} [sections] */
  function markCurrent(next, sections) {
    path = next;
    const model = sections ?? sidebarModel({ routes, counts: currentCounts, folders: currentFolders, pinned: prefs.pinned() });
    const id = currentEntry(model, next);
    const walk = (/** @type {any} */ node) => {
      if (node?.getAttribute?.("data-entry") !== null && node?.getAttribute?.("data-entry") !== undefined) {
        node.setAttribute("aria-current", node.getAttribute("data-entry") === id ? "page" : "false");
      }
      for (const child of node?.childNodes ?? []) walk(child);
    };
    walk(lists);
    const onAccount = next === "/account" || accountPaths.includes(next);
    settingsItem.setAttribute("aria-current", onAccount ? "page" : "false");
    accountButton.setAttribute("data-current", onAccount ? "true" : "false");
  }

  render();

  return {
    top,
    side,
    backdrop,
    setBehind,
    /** @param {{ all: number, favorites: number }} next */
    setCounts(next) {
      if (next.all === currentCounts.all && next.favorites === currentCounts.favorites) return;
      currentCounts = next;
      render();
    },
    /** @param {readonly { id: string, name: string, parentId?: string | null }[]} next */
    setFolders(next) {
      currentFolders = next;
      render();
    },
    markCurrent: (/** @type {string} */ next) => markCurrent(next),
    refs: { menuButton, closeButton, collapseButton, accountButton, switcher, lockItem, signOutItem, settingsItem, helpItem, accountMenu },
    state: () => ({ drawerOpen, accountOpen: account.isOpen(), collapsed: side.getAttribute("data-collapsed") === "true" }),
    openDrawer: () => {
      setDrawer(true);
      focusNode(closeButton);
    },
    /** Escape: the open menu first, then the drawer; the focus goes back to what opened it. @returns {boolean} whether there was something to close */
    escape() {
      const open = menus.find((menu) => menu.isOpen());
      if (open) {
        open.close(true);
        return true;
      }
      if (drawerOpen) {
        closeDrawer(true);
        return true;
      }
      return false;
    },
    /** A press anywhere: an open menu closes when the press is outside it. @param {any} target */
    press(target) {
      for (const menu of menus) if (menu.isOpen() && !within(target, menu.menu) && !within(target, menu.trigger)) menu.close(false);
    },
    closeMenus: () => closeMenus(),
    closeDrawer: () => closeDrawer(false),
  };
}
