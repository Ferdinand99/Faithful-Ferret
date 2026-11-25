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

/** The most earlier passwords an item keeps, and so the most the screen lists. */
export const MAX_PASSWORD_HISTORY = 5;

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
 * The earlier passwords an item has, for the list under "Previous passwords": the place of each in the core's list
 * (which a reveal asks for) and the date it stopped being the password, newest first, at most five. Only the dates
 * come from the view; the values never pass through here. An entry whose date is not a number is still listed (its
 * date shows as unknown, `until: null`): it holds a password the user may need. Everything after the fifth is left out.
 * @param {unknown} view
 * @returns {{ index: number, until: number | null }[]}
 */
export function historyEntries(view) {
  const list = /** @type {any} */ (view)?.password_history;
  if (!Array.isArray(list)) return [];
  return list.slice(0, MAX_PASSWORD_HISTORY).map((entry, index) => ({
    index, until: typeof entry?.until === "number" && Number.isFinite(entry.until) ? entry.until : null,
  }));
}

/**
 * The draft that switches the favourite mark: a patch with that one key, so nothing else of the item is touched.
 * @param {{ favorite?: boolean } | null | undefined} entry
 */
export function favouriteDraft(entry) {
  return { favorite: entry?.favorite !== true };
}

/**
 * @typedef {object} PasskeyFacts what the page shows of an item's passkey: public facts only
 * @property {string} site the relying party id the core checked: the identity of the site (never a text the site chose)
 * @property {string} user the user name the site gave, cleaned by the core
 * @property {string | null} siteName what the site calls itself (the site's own text; null when it gave none or it only repeats the id)
 * @property {string | null} displayName the name the site gave the account (the site's own text; null when none or it only repeats the user name)
 * @property {number | null} created when the passkey was made (milliseconds), or null when the view has no usable date
 */

/**
 * The public facts of the passkey in a view, or null for an item without one. The key, the seeds, the credential id and the user
 * handle are not read: the page has no use for them, and the view of the core does not hold the private parts at all. The two texts
 * the site chose are kept apart from the site's identity so the screen can mark them as the site's.
 * @param {unknown} view
 * @returns {PasskeyFacts | null}
 */
export function passkeyOf(view) {
  const pk = /** @type {any} */ (view)?.passkey;
  if (pk === null || typeof pk !== "object" || typeof pk.rp_id !== "string" || pk.rp_id === "") return null;
  const user = typeof pk.user_name === "string" ? pk.user_name : "";
  /** @param {unknown} text @param {string} same */
  const own = (text, same) => (typeof text === "string" && text.trim() !== "" && text.trim().toLowerCase() !== same.toLowerCase() ? text : null);
  return {
    site: pk.rp_id,
    user,
    siteName: own(pk.rp_name, pk.rp_id),
    displayName: own(pk.user_display_name, user),
    created: typeof pk.created === "number" && Number.isSafeInteger(pk.created) && pk.created > 0 ? pk.created : null,
  };
}

/** How many sites the delete question names; the rest are counted. */
const MAX_SITES_NAMED = 5;

/**
 * The sites of the passkeys among some items, each once and in the order first met, for the question before they are deleted.
 * @param {readonly { passkeySite?: string | null }[]} items
 * @returns {{ passkeys: number, sites: string }} how many of the items hold a passkey, and the first few sites as one line
 *   (with "…" after them when more follow)
 */
export function passkeySites(items) {
  const withKey = items.filter((item) => typeof item.passkeySite === "string" && item.passkeySite !== "");
  const sites = [...new Set(withKey.map((item) => /** @type {string} */ (item.passkeySite)))];
  const named = sites.slice(0, MAX_SITES_NAMED).join(", ");
  return { passkeys: withKey.length, sites: sites.length > MAX_SITES_NAMED ? `${named}, …` : named };
}
