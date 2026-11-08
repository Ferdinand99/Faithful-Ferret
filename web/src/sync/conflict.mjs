// What the conflict screen needs to know about two versions of one item, and the
// time the local trash keeps a deleted item. Nothing here holds a secret: it reads
// the views the core gives out (a secret field has no value in a view) and gives
// back only names, kinds and yes or no.

/** How long the local trash keeps a deleted item (Fase 1 section 8.4, "Local trash"): 30 days, in milliseconds. */
export const TRASH_MS = 30 * 86_400_000;

/**
 * @typedef {object} FieldCompare one field of an item, compared across the two versions
 * @property {string} key the id of the field
 * @property {string} label the label of the field (the local one, or the server's when only the server has it)
 * @property {string} kind the kind of the field (`text`, `password`, ...; the local one, or the server's when only the server has it)
 * @property {boolean | null} same true when both versions have the field with the same kind and the same value; false when
 *   it is on one side only, has another kind, or another value; null when it cannot be told: both sides have it and it
 *   is a secret, whose value is not in a view
 */

/**
 * Compares the fields of two item views, field by field. A visible value is compared as it is shown. A field that holds
 * a secret has no value in the view, so two such fields give `null`: the screen reveals them one at a time on the user's
 * request, and nothing here looks at them. A side that has no view (the item is deleted there) has no fields, so every field
 * of the other side is `false`. There is no merge: this only tells what differs.
 * Spec: Fase 1 section 8.5 ("the UI shows both, field by field"; "no automatic merging of fields").
 * @param {any} local the view of the local version, or null
 * @param {any} server the view of the server's version, or null
 * @returns {FieldCompare[]}
 */
export function compareFields(local, server) {
  /** @param {any} view @returns {any[]} */
  const fieldsOf = (view) => (Array.isArray(view?.fields) ? view.fields : []);
  /** @type {Map<string, { mine: any, theirs: any }>} */
  const byKey = new Map();
  for (const field of fieldsOf(local)) {
    const key = String(field?.id ?? "");
    if (!byKey.has(key)) byKey.set(key, { mine: field, theirs: undefined });
  }
  for (const field of fieldsOf(server)) {
    const key = String(field?.id ?? "");
    const have = byKey.get(key);
    if (have === undefined) byKey.set(key, { mine: undefined, theirs: field });
    else if (have.theirs === undefined) have.theirs = field;
  }
  return [...byKey].map(([key, { mine, theirs }]) => {
    const shown = mine ?? theirs;
    /** @type {boolean | null} */
    let same;
    if (mine === undefined || theirs === undefined) same = false;
    else if (String(mine.kind ?? "text") !== String(theirs.kind ?? "text")) same = false;
    else if (typeof mine.value === "string" && typeof theirs.value === "string") same = mine.value === theirs.value;
    else if (typeof mine.value === "string" || typeof theirs.value === "string") same = false; // one side shows a value, the other hides it
    else same = null; // both hidden: no value to compare
    return { key, label: String(shown.label ?? ""), kind: String(shown.kind ?? "text"), same };
  });
}
