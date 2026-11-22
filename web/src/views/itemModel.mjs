// What the item screen shows, worked out from what the core hands over, with no DOM and no secret: which fields go
// in which card, the letter and colour of the tile, the folder labels, and the draft that a favourite toggle sends.
// Values never pass through here: a field is described by its id, label and whether the core showed its value, and the
// screen asks the worker for a secret only when the user clicks.
import { checkFolderName, sortFolders } from "../folders.mjs";

/** The item types the tile has a colour for; any other type gets the neutral one. */
const TYPES = Object.freeze(["login", "note", "card", "identity"]);

/** The field ids that belong to the sign-in card, in the order they are shown. */
const LOGIN_FIELDS = Object.freeze(["username", "password"]);

/** More labels than this are not drawn as chips; the rest are one "+N" chip. */
export const MAX_FOLDER_CHIPS = 12;

/**
 * The type of an item as the tile's colour knows it.
 * @param {unknown} type
 * @returns {string} one of the known types, or "other"
 */
export function tileType(type) {
  return TYPES.includes(String(type)) ? String(type) : "other";
}

/**
 * The letter on the tile: the first character of the name, upper case; "?" when the item has no name.
 * @param {unknown} name
 */
export function tileLetter(name) {
  const first = [...String(name ?? "").trim()][0];
  return first === undefined ? "?" : first.toLocaleUpperCase();
}

/**
 * @typedef {object} FieldSpec
 * @property {string} key `f<index>`: the key the screen gives the field's controls
 * @property {number} index the field's place in the item, which the worker is asked for
 * @property {string} id the field's id; a reveal checks it again, so a changed item is not shown as another field
 * @property {string} label the field's label (empty: the screen says "Field")
 * @property {string | null} plain the value when the core shows it, else null (the value is secret)
 */

/**
 * The fields of an item in two groups: the sign-in fields (user name, password) first, and the rest in the order the
 * item has them. A card shows only the groups that have something in them.
 * @param {unknown} fields the `fields` of the core's view
 * @returns {{ login: FieldSpec[], custom: FieldSpec[] }}
 */
export function groupFields(fields) {
  /** @type {FieldSpec[]} */
  const all = [];
  (Array.isArray(fields) ? fields : []).forEach((field, index) => {
    if (field === null || typeof field !== "object") return;
    all.push({
      key: `f${index}`, index, id: String(field.id ?? ""), label: String(field.label ?? ""),
      plain: typeof field.value === "string" ? field.value : null,
    });
  });
  const login = LOGIN_FIELDS.flatMap((id) => all.filter((field) => field.id === id));
  return { login, custom: all.filter((field) => !LOGIN_FIELDS.includes(field.id)) };
}

/**
 * The folder labels an item carries, for the chips in its header, in display order. The view of a core that knows
 * folders lists them in `folders` (checked and in NFC already); one that does not has none, and the chips stay hidden.
 * A name that breaks the rules of a name is dropped here too, and so is a repeat of one (ignoring case).
 * @param {unknown} view
 * @param {string} [locale]
 * @returns {string[]}
 */
export function folderLabels(view, locale) {
  const list = /** @type {any} */ (view)?.folders;
  if (!Array.isArray(list)) return [];
  return sortFolders(list.filter((label) => checkFolderName(label) === null), locale);
}

/**
 * The draft that switches the favourite mark: a patch with that one key, so nothing else of the item is touched.
 * @param {{ favorite?: boolean } | null | undefined} entry
 */
export function favouriteDraft(entry) {
  return { favorite: entry?.favorite !== true };
}
