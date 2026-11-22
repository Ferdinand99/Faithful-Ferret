// The folder picker of the edit form (and of "Move to folder"): the folders the item is in, as chips that can be
// removed, a field to type a name in, and the folders of the vault that match what is typed, to pick from. A new name
// is a new folder: folders exist only as the labels of items, so a folder is made by putting an item in it.
//
// The names are checked here with the core's rules (folders.mjs) so the user is told at once; the core checks them
// again when the item is sealed, and its refusal (a code) is shown with the same texts. Names are text nodes only.
import { el, mount } from "../dom.mjs";
import { checkFolderList, checkFolderName, foldKey, normalizeFolder, sameFolder, sameList, sortFolders, MAX_FOLDERS } from "../folders.mjs";

/** At most this many suggestions are shown under the field. */
const MAX_SUGGESTIONS = 8;

/** The codes of the core (and of this picker) that have a text under `folders.error.`. */
export const FOLDER_ERRORS = Object.freeze(["folder_empty", "folder_too_long", "folder_bad_character", "folder_too_many", "folder_duplicate"]);

let sequence = 0;

/**
 * @param {{
 *   t: import("./common.mjs").Translate,
 *   initial: readonly string[],
 *   suggestions: () => readonly string[],
 *   locale?: string,
 *   onChange?: () => void,
 * }} options `initial`: the folders the item is in now (in the order stored); `suggestions`: the folders of the vault
 */
export function folderPicker({ t, initial, suggestions, locale, onChange = () => {} }) {
  sequence += 1;
  const id = `folder-input-${sequence}`;
  const start = [...initial];
  /** @type {string[]} */
  let chosen = [...initial];
  let readOnly = false;

  const chips = el("ul", { class: "folder-picker-chips", "aria-label": t("folders.picker.chosen"), "data-role": "folder-picked" });
  const input = /** @type {HTMLInputElement} */ (el("input", {
    id, type: "text", autocomplete: "off", maxlength: 256, "data-role": "folder-input", "aria-describedby": `${id}-help`,
  }));
  input.spellcheck = false;
  const add = el("button", { type: "button", class: "btn btn-secondary btn-sm", "data-role": "folder-add" }, t("folders.picker.add"));
  const help = el("small", { class: "help", id: `${id}-help` }, t("folders.picker.help", { max: MAX_FOLDERS }));
  const error = el("p", { class: "error", role: "alert", "data-role": "folder-error" });
  error.hidden = true;
  const offered = el("div", { class: "folder-picker-offers", role: "group", "aria-label": t("folders.picker.existing"), "data-role": "folder-offers" });
  const root = el("div", { class: "field folder-picker", "data-role": "folder-picker" },
    el("label", { for: id }, t("folders.picker.label")),
    chips,
    el("div", { class: "folder-picker-row" }, input, add),
    help, error, offered);

  /** @param {string | null} code */
  function showError(code) {
    if (code === null) {
      error.hidden = true;
      mount(error);
      return;
    }
    const key = FOLDER_ERRORS.includes(code) ? code : "folder_empty";
    mount(error, document.createTextNode(t(`folders.error.${key}`, key === "folder_too_many" ? { max: MAX_FOLDERS } : undefined)));
    error.hidden = false;
  }

  function render() {
    mount(chips, ...sortFolders(chosen, locale).map((name) => {
      const remove = el("button", {
        type: "button", class: "folder-chip-x", "aria-label": t("folders.picker.remove", { name }), "data-role": "folder-remove", "data-folder": name,
      }, el("span", { class: "icon", "data-icon": "close", "aria-hidden": "true" }));
      /** @type {any} */ (remove).disabled = readOnly;
      remove.addEventListener("click", () => {
        if (readOnly) return;
        chosen = chosen.filter((n) => !sameFolder(n, name));
        showError(null);
        render();
        onChange();
        input.focus?.();
      });
      return el("li", { class: "folder-chip", "data-role": "folder-picked-chip" }, el("span", { class: "folder-chip-text" }, name), remove);
    }));
    chips.hidden = chosen.length === 0;
    renderOffers();
  }

  function renderOffers() {
    const typed = foldKey(input.value ?? "");
    const all = sortFolders([...suggestions()], locale).filter((name) => !chosen.some((n) => sameFolder(n, name)));
    const hits = (typed === "" ? all : all.filter((name) => foldKey(name).includes(typed))).slice(0, MAX_SUGGESTIONS);
    mount(offered, ...hits.map((name) => {
      const pick = el("button", { type: "button", class: "chip-main folder-offer", "data-role": "folder-offer", "data-folder": name },
        el("span", { class: "icon", "data-icon": "folder", "aria-hidden": "true" }), name);
      /** @type {any} */ (pick).disabled = readOnly;
      pick.addEventListener("click", () => {
        addName(name);
        input.focus?.();
      });
      return pick;
    }));
    offered.hidden = hits.length === 0;
  }

  /** @param {string} raw @returns {boolean} */
  function addName(raw) {
    if (readOnly) return false;
    const wrong = checkFolderName(raw);
    if (wrong !== null) {
      showError(wrong);
      return false;
    }
    const name = normalizeFolder(raw);
    // A folder the vault has already is taken in the spelling the vault shows, so one folder is not split in two by case.
    const known = suggestions().find((n) => sameFolder(n, name)) ?? name;
    if (chosen.some((n) => sameFolder(n, known))) {
      showError("folder_duplicate");
      return false;
    }
    if (chosen.length >= MAX_FOLDERS) {
      showError("folder_too_many");
      return false;
    }
    chosen = [...chosen, known];
    input.value = "";
    showError(null);
    render();
    onChange();
    return true;
  }

  add.addEventListener("click", () => {
    addName(input.value ?? "");
    input.focus?.();
  });
  input.addEventListener("keydown", (/** @type {any} */ event) => {
    // Enter adds the name; it never sends the form the picker is in.
    if (event.key === "Enter") {
      event.preventDefault?.();
      addName(input.value ?? "");
    }
  });
  input.addEventListener("input", () => {
    showError(null);
    renderOffers();
  });

  render();

  return {
    root,
    /** The list to save, in the item's order: the old names first where they stay, new ones after. */
    value: () => [...chosen],
    /** Whether the list differs from the one the item has. */
    changed: () => !sameList(chosen, start),
    /** Whether something was typed and not added. */
    typed: () => (input.value ?? "").trim() !== "",
    /** Adds what was typed and not added yet (a save does this first). @returns {boolean} false when the name was refused */
    commitTyped: () => ((input.value ?? "").trim() === "" ? true : addName(input.value ?? "")),
    /** A refusal of the core, by its code. @param {string} code */
    showError,
    /** What the core would say about the list now, or null. */
    check: () => checkFolderList(chosen),
    /** @param {boolean} on */
    setReadOnly(on) {
      readOnly = on;
      input.readOnly = on;
      if (on) input.setAttribute("readonly", "");
      else input.removeAttribute?.("readonly");
      /** @type {any} */ (add).disabled = on;
      render();
    },
    /** Empties what the picker holds (a lock, a save). */
    wipe() {
      chosen = [];
      input.value = "";
      mount(chips);
      mount(offered);
      showError(null);
    },
  };
}
