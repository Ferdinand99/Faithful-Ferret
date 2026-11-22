// The copy button of a row in the popup's list: a button with a caret that
// opens a small menu of what can be copied: "Copy user name" (or "Copy e-mail"
// when the user name is an e-mail address) and "Copy password". Each entry asks
// the background to copy one value of the item by the row's reference; the
// value goes from the background to the clipboard and never through the popup,
// and the background clears the clipboard 30 seconds later, whatever was
// copied.
//
// The keyboard follows the menu button pattern: Enter or Space on the button
// opens the menu at its first entry (the browser turns them into a click),
// Arrow Down and Arrow Up open it at the first or the last entry; in the menu
// the arrows move round, Home and End go to the ends, Escape closes it and
// gives the focus back to the button, and Tab closes it and moves on.

import { el } from "../shared/dom.mjs";

/**
 * Whether a row's menu offers the one-time code. Off: the list does not know yet which items hold one, so the entry
 * would be offered for every login. `copyEntries` builds it already; turn it on together with a mark on the handles.
 */
export const ROW_ONE_TIME_CODE = false;

/** An e-mail address, roughly: something, an @, a host with a dot. Only the label depends on it. */
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Whether a user name is an e-mail address (the entry then says "e-mail"). @param {string} text */
export const isEmailAddress = (text) => EMAIL.test(text.trim());

/**
 * @typedef {{ field: "username" | "password" | "totp", label: string, done: string }} CopyEntry
 *   `field`: the value the background is asked to copy; `label` and `done`: the i18n keys of the entry and of the note
 *   after the copy
 */

/**
 * The entries of a row's copy menu, in the order the menu shows them: the user name (when the row has one), the
 * password and, once offered, the one-time code.
 * @param {{ username: string }} row
 * @param {{ oneTimeCode?: boolean }} [options]
 * @returns {CopyEntry[]}
 */
export function copyEntries(row, { oneTimeCode = ROW_ONE_TIME_CODE } = {}) {
  /** @type {CopyEntry[]} */
  const entries = [];
  if (row.username !== "") {
    const email = isEmailAddress(row.username);
    entries.push({
      field: "username",
      label: email ? "popup.row.copy_email" : "popup.row.copy_username",
      done: email ? "popup.copied.email" : "popup.copied.username",
    });
  }
  entries.push({ field: "password", label: "popup.row.copy_password", done: "popup.copied.password" });
  if (oneTimeCode) entries.push({ field: "totp", label: "popup.row.copy_totp", done: "popup.copied.totp" });
  return entries;
}

/**
 * The accessible name of a row's copy button: "Copy from <name>", or "(no name)" for a row without one.
 * @param {{ name?: string }} row
 * @param {(key: string, vars?: Record<string, string | number>) => string} t
 */
export function copyLabel(row, t) {
  const name = typeof row.name === "string" && row.name !== "" ? row.name : t("popup.item.unnamed");
  return t("popup.row.copy_from", { name });
}

/**
 * What a key does to a menu of `count` entries. `at` is the entry that has the focus, -1 for the button.
 * @param {string} key the `key` of the keyboard event
 * @param {{ open: boolean, at: number, count: number }} state
 * @returns {{ open: true, focus: number } | { open: false, focus: "button" | null } | null} null: not the menu's key
 */
export function menuKey(key, { open, at, count }) {
  if (count <= 0) return null;
  if (!open) {
    if (key === "ArrowDown") return { open: true, focus: 0 };
    if (key === "ArrowUp") return { open: true, focus: count - 1 };
    return null;
  }
  switch (key) {
    case "ArrowDown":
      return { open: true, focus: at < 0 ? 0 : (at + 1) % count };
    case "ArrowUp":
      return { open: true, focus: at <= 0 ? count - 1 : at - 1 };
    case "Home":
      return { open: true, focus: 0 };
    case "End":
      return { open: true, focus: count - 1 };
    case "Escape":
      return { open: false, focus: "button" };
    case "Tab":
      return { open: false, focus: null };
    default:
      return null;
  }
}

/**
 * The copy button of a row and its menu. The button and the menu are named after the row ("Copy from <name>"), so a
 * screen reader that lists the buttons of the popup tells one row's from the next; the tooltip stays "Copy".
 * @param {{
 *   row: { ref: string, username: string, name?: string },
 *   t: (key: string, vars?: Record<string, string | number>) => string,
 *   copy: (field: string, done: string) => unknown,
 *   onOpen: (close: () => void) => void,
 *   onClose: () => void,
 *   oneTimeCode?: boolean,
 * }} options `copy` asks the background for the copy and says how it went; `onOpen` runs when the menu opens (the
 *   list closes its other menus and keeps `close` for a click elsewhere), `onClose` when it closes
 */
export function createCopyMenu({ row, t, copy, onOpen, onClose, oneTimeCode = ROW_ONE_TIME_CODE }) {
  const entries = copyEntries(row, { oneTimeCode });
  const label = copyLabel(row, t);
  const button = el(
    "button",
    { type: "button", class: "ff-row-icon ff-copy", "data-role": "copy", "aria-haspopup": "menu", "aria-expanded": "false", "aria-label": label, title: t("popup.row.copy") },
    el("span", { class: "ff-ico ff-ico-copy", "aria-hidden": "true" }),
    el("span", { class: "ff-ico ff-ico-caret", "aria-hidden": "true" }),
  );
  const items = entries.map((entry) =>
    el("button", { type: "button", role: "menuitem", tabindex: "-1", class: "ff-menu-item", "data-role": `copy-${entry.field}`, "data-field": entry.field }, t(entry.label)),
  );
  const menu = el("div", { class: "ff-menu ff-copy-menu", role: "menu", "aria-label": label, "data-role": "copy-menu", hidden: true }, ...items);
  const root = el("span", { class: "ff-row-more", "data-role": "copy-wrap" }, button, menu);
  let isOpen = false;

  /** Opens the menu (once) and moves the focus to an entry. @param {number} focus */
  function open(focus) {
    if (!isOpen) {
      onOpen(() => close(false));
      isOpen = true;
      menu.hidden = false;
      button.setAttribute("aria-expanded", "true");
    }
    items[focus]?.focus();
  }

  /** @param {boolean} focusButton */
  function close(focusButton) {
    if (isOpen) {
      isOpen = false;
      menu.hidden = true;
      button.setAttribute("aria-expanded", "false");
      onClose();
    }
    if (focusButton) button.focus();
  }

  button.addEventListener("click", () => {
    if (isOpen) close(true);
    else open(0);
  });
  items.forEach((item, i) => {
    item.addEventListener("click", () => {
      close(true);
      const entry = entries[i];
      void copy(entry.field, entry.done);
    });
  });
  root.addEventListener("keydown", (/** @type {KeyboardEvent} */ event) => {
    const at = items.indexOf(/** @type {HTMLElement} */ (event.target));
    const step = menuKey(event.key, { open: isOpen, at, count: items.length });
    if (step === null) return;
    // Tab moves on as usual; the other keys are the menu's only.
    if (event.key !== "Tab") event.preventDefault();
    if (step.open) open(step.focus);
    else close(step.focus === "button");
  });

  return {
    root,
    button,
    entries,
    get open() {
      return isOpen;
    },
    close,
  };
}
