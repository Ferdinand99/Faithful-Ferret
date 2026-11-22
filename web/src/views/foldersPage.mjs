// The Folders page: every folder of the vault (the names its items carry), with how many items are in it, and what can
// be done to a folder as a whole: open it, pin it to the side menu, rename it, delete it.
//
// A folder is not a thing of its own: it is a label inside the encrypted body of each item in it. Renaming a folder is an
// edit of every item that carries it, and deleting one takes the label off those items (the items stay). Each edit is a
// write of one item through the engine's outbox, with a draft that holds the item's new list of folders and nothing else
// (folderActions.mjs). Nothing here is stored or sent apart from those writes; the names are text nodes only.
import { el, mount } from "../dom.mjs";
import { checkFolderName, folderIndex, normalizeFolder, sameFolder } from "../folders.mjs";
import { askConfirm, listenWhileShown } from "./common.mjs";
import { emptyState } from "./emptyState.mjs";
import { deleteFolder, renameFolder, runText } from "./folderActions.mjs";
import { focusNode } from "./popMenu.mjs";

let sequence = 0;

/**
 * The line of a run whose page was wiped before it could say it (the vault locked, or the page was left, in the middle of
 * a rename or delete): the next Folders page shows it once. It holds counts and an error text only, never a folder name,
 * and lives in memory only.
 * @type {string | null}
 */
let heldLine = null;

/**
 * @param {{
 *   engine: any,
 *   t: import("./common.mjs").Translate,
 *   prefs: { isPinned(name: string): boolean, pin(name: string): boolean, unpin(name: string): void, renamePin(from: string, to: string): void },
 *   folderLink: (name: string) => string,
 *   locale?: string,
 *   touch?: () => boolean,
 *   scope?: { add(fn: () => void): () => void },
 * }} options
 * @returns {HTMLElement}
 */
export function foldersPage({ engine, t, prefs, folderLink, locale, touch = () => true, scope }) {
  const root = el("section", { class: "folders-page", "data-role": "folders-page" });
  const list = el("ul", { class: "folders-list", "aria-label": t("folders.title"), "data-role": "folders-list" });
  const message = el("p", { class: "message", role: "status", "data-role": "message" });
  const host = el("div", { class: "dialog-host", "data-role": "dialog-host" });
  const body = el("div", { class: "card folders-card" }, list);
  let busy = false;
  let wiped = false;
  /** The folder whose row is being renamed (its key), or null. @type {string | null} */
  let renaming = null;

  /** @param {string} text */
  function say(text) {
    if (!wiped) mount(message, document.createTextNode(text));
  }

  const folders = () => folderIndex(engine.list(), locale);

  function render() {
    if (wiped) return;
    const all = folders();
    // The row that had the focus gets it back after the rows are built again (a change from another device rebuilds them).
    const active = /** @type {any} */ (globalThis.document)?.activeElement;
    const focusKey = active?.getAttribute?.("data-key") ?? null;
    const focusRole = active?.getAttribute?.("data-role") ?? null;
    if (all.length === 0) {
      mount(body, emptyState({
        role: "folders-empty", icon: "folder", text: t("folders.empty"),
        actions: [{ label: t("folders.empty_action"), role: "folders-empty-items", href: "#/items" }],
      }));
      return;
    }
    mount(body, list);
    mount(list, ...all.map((folder) => (renaming === folder.key ? renameRow(folder) : row(folder))));
    if (focusKey !== null && focusRole !== null) {
      const again = findIn(list, (node) => node.getAttribute?.("data-key") === focusKey && node.getAttribute?.("data-role") === focusRole);
      if (again) focusNode(again);
    }
  }

  /** @param {import("../folders.mjs").FolderInfo} folder */
  function row(folder) {
    const pinned = prefs.isPinned(folder.name);
    const link = el("a", { class: "folder-name", href: folderLink(folder.name), "data-role": "folder-open", "data-key": folder.key },
      el("span", { class: "icon", "data-icon": "folder", "aria-hidden": "true" }), folder.name);
    const count = el("span", { class: "count", "data-role": "folder-count" }, t(folder.ids.length === 1 ? "folders.count_one" : "folders.count_many", { count: folder.ids.length }));
    const pin = el("button", {
      type: "button", class: "btn btn-secondary btn-sm", "aria-pressed": pinned ? "true" : "false", "data-role": "folder-pin", "data-key": folder.key,
      "aria-label": t(pinned ? "folders.unpin_label" : "folders.pin_label", { name: folder.name }),
    }, t(pinned ? "folders.unpin" : "folders.pin"));
    pin.addEventListener("click", () => {
      if (!touch()) return;
      if (prefs.isPinned(folder.name)) prefs.unpin(folder.name);
      else if (!prefs.pin(folder.name)) say(t("folders.pin_full"));
      render();
    });
    const rename = el("button", { type: "button", class: "btn btn-secondary btn-sm", "data-role": "folder-rename", "data-key": folder.key,
      "aria-label": t("folders.rename_label", { name: folder.name }) }, t("folders.rename"));
    rename.addEventListener("click", () => {
      if (busy || !touch()) return;
      renaming = folder.key;
      render();
      const input = findIn(list, (node) => node.getAttribute?.("data-role") === "folder-new-name");
      if (input) focusNode(input);
    });
    const del = el("button", { type: "button", class: "btn btn-danger btn-sm", "data-role": "folder-delete", "data-key": folder.key,
      "aria-label": t("folders.delete_label", { name: folder.name }) }, t("folders.delete"));
    del.addEventListener("click", () => void remove(folder));
    for (const button of [rename, del]) /** @type {any} */ (button).disabled = busy;
    return el("li", { class: "folder-row", "data-role": "folder-row", "data-key": folder.key },
      el("div", { class: "folder-main" }, link, count),
      el("div", { class: "actions folder-actions" }, pin, rename, del));
  }

  /** @param {import("../folders.mjs").FolderInfo} folder */
  function renameRow(folder) {
    sequence += 1;
    const id = `folder-rename-${sequence}`;
    const input = /** @type {HTMLInputElement} */ (el("input", { id, type: "text", autocomplete: "off", maxlength: 256, "data-role": "folder-new-name", "data-key": folder.key }));
    input.spellcheck = false;
    input.value = folder.name;
    const error = el("p", { class: "error", role: "alert", "data-role": "folder-error" });
    error.hidden = true;
    const save = el("button", { type: "submit", class: "btn btn-primary btn-sm", "data-role": "folder-rename-save" }, t("folders.rename_save"));
    const cancel = el("button", { type: "button", class: "btn btn-secondary btn-sm", "data-role": "folder-rename-cancel" }, t("vault.dialog.cancel"));
    const stop = () => {
      renaming = null;
      render();
      const again = findIn(list, (node) => node.getAttribute?.("data-role") === "folder-rename" && node.getAttribute?.("data-key") === folder.key);
      if (again) focusNode(again);
    };
    cancel.addEventListener("click", stop);
    input.addEventListener("keydown", (/** @type {any} */ event) => {
      if (event.key === "Escape") {
        event.preventDefault?.();
        stop();
      }
    });
    const form = el("form", {
      class: "folder-rename", "data-role": "folder-rename-form",
      onsubmit: async (/** @type {Event} */ event) => {
        event.preventDefault();
        if (busy || !touch()) return;
        const wrong = checkFolderName(input.value);
        if (wrong !== null) {
          mount(error, document.createTextNode(t(`folders.error.${wrong}`)));
          error.hidden = false;
          return;
        }
        const to = normalizeFolder(input.value);
        if (to === folder.name) {
          stop();
          return;
        }
        // A name that another folder has already makes the two one folder: say so first.
        const other = folders().find((f) => f.key !== folder.key && sameFolder(f.name, to));
        if (other) {
          const yes = await askConfirm({ t, host, title: "folders.merge_title", body: "folders.merge_body", confirm: "folders.merge_confirm", vars: { from: folder.name, to: other.name } });
          if (!yes || wiped) return;
        }
        renaming = null;
        await run("rename", () => renameFolder({ engine, from: folder.name, to: other ? other.name : to, touch, progress }), () => prefs.renamePin(folder.name, other ? other.name : to));
      },
    }, el("label", { for: id, class: "visually-hidden" }, t("folders.rename_field", { name: folder.name })), input, save, cancel, error);
    return el("li", { class: "folder-row folder-row-edit", "data-role": "folder-row", "data-key": folder.key }, form);
  }

  /** @param {import("../folders.mjs").FolderInfo} folder */
  async function remove(folder) {
    if (busy || !touch()) return;
    const yes = await askConfirm({
      t, host, title: "folders.delete_title", body: folder.ids.length === 1 ? "folders.delete_body_one" : "folders.delete_body_many", confirm: "folders.delete_confirm",
      vars: { name: folder.name, count: folder.ids.length },
    });
    if (!yes || wiped) return;
    await run("delete", () => deleteFolder({ engine, name: folder.name, touch, progress }), () => prefs.unpin(folder.name));
  }

  /** @param {number} done @param {number} total */
  const progress = (done, total) => say(t("folders.progress", { done, total }));

  /**
   * @param {"rename" | "delete"} kind
   * @param {() => Promise<import("./folderActions.mjs").RunResult>} work
   * @param {() => void} after what follows a run that changed every item (the pin follows the folder)
   */
  async function run(kind, work, after) {
    busy = true;
    render();
    say(t("folders.working"));
    let text = "";
    try {
      const result = await work();
      if (result.failed === 0 && result.skipped === 0 && !result.stopped) after();
      text = runText(t, result, kind);
    } catch (error) {
      text = runText(t, { done: 0, skipped: 0, failed: 1, first: error, stopped: false }, kind);
    } finally {
      busy = false;
      render();
      // A page that was wiped meanwhile cannot say it: the next Folders page does.
      if (wiped) heldLine = text;
      else say(text);
    }
  }

  // The lock wipes the page: no folder name stays in a node.
  scope?.add(() => {
    wiped = true;
    renaming = null;
    mount(root);
  });

  mount(root,
    el("h1", { class: "list-title" }, el("span", { class: "icon", "data-icon": "folder", "aria-hidden": "true" }), t("folders.title")),
    el("p", { class: "help" }, t("folders.intro")),
    body, message, host);
  render();
  // What a run that the lock cut short did (see `heldLine`).
  if (heldLine !== null) {
    say(heldLine);
    heldLine = null;
  }
  const off = listenWhileShown(root, engine, "changed", () => {
    if (!busy && renaming === null) render();
  });
  scope?.add(off);
  return root;
}

/**
 * The first node below `root` for which `test` holds.
 * @param {any} root @param {(node: any) => boolean} test
 * @returns {any}
 */
function findIn(root, test) {
  for (const child of root?.childNodes ?? []) {
    if (test(child)) return child;
    const deeper = findIn(child, test);
    if (deeper) return deeper;
  }
  return null;
}

/**
 * The bar above the items of one folder: pin or unpin it, and the way to the list of folders (where it is renamed or
 * deleted).
 * @param {{
 *   t: import("./common.mjs").Translate,
 *   name: string,
 *   prefs: { isPinned(name: string): boolean, pin(name: string): boolean, unpin(name: string): void },
 *   touch?: () => boolean,
 *   scope?: { add(fn: () => void): () => void },
 * }} options
 */
export function folderBar({ t, name, prefs, touch = () => true, scope }) {
  const note = el("span", { class: "message", role: "status", "data-role": "folder-bar-message" });
  const pin = el("button", { type: "button", class: "btn btn-secondary btn-sm", "data-role": "folder-pin" });
  const paint = () => {
    const on = prefs.isPinned(name);
    pin.setAttribute("aria-pressed", on ? "true" : "false");
    mount(pin, el("span", { class: "icon", "data-icon": "pin", "aria-hidden": "true" }), document.createTextNode(t(on ? "folders.unpin" : "folders.pin")));
  };
  paint();
  pin.addEventListener("click", () => {
    if (!touch()) return;
    if (prefs.isPinned(name)) prefs.unpin(name);
    else if (!prefs.pin(name)) mount(note, document.createTextNode(t("folders.pin_full")));
    paint();
  });
  const bar = el("div", { class: "folder-bar actions", "data-role": "folder-bar" },
    pin, el("a", { class: "btn btn-plain btn-sm", href: "#/folders", "data-role": "folders-link" }, t("folders.manage")), note);
  scope?.add(() => mount(bar));
  return bar;
}
