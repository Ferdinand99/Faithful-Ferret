// Making and changing an item (a login or a note).
//
// The form never reads a secret back. On an edit the password input starts
// empty: leave it empty and the password stays as it is, because the draft then
// names the field by its id only and the worker keeps its value; type something
// and the draft replaces it. The notes are read into the form only when the
// user asks to edit them. When the item is saved, every input is emptied, and
// the draft object is scrubbed.
//
// A draft is the core's `DraftDto`: only what the user changed, in the core's
// own key names (`item_type`, `matching`).
import { el, mount } from "../dom.mjs";
import { canChange, describeError, markBadges } from "./common.mjs";
import { typeLabel } from "./item.mjs";

const TYPES = Object.freeze(["login", "note"]);

/**
 * @typedef {{ id: string, label?: string, kind?: string, value?: string }} FieldDraft
 * @typedef {{
 *   item_type?: string, name: string, favorite: boolean, fields?: FieldDraft[],
 *   urls?: { url: string, matching: string }[], notes?: string, remove_notes?: boolean,
 * }} Draft
 */

/** @param {Draft} draft Empties what the draft holds, so no reference to a typed secret is left. */
function scrub(draft) {
  for (const field of draft.fields ?? []) if (typeof field.value === "string") field.value = "";
  if (typeof draft.notes === "string") draft.notes = "";
  draft.name = "";
}

/**
 * @param {{
 *   engine: any,
 *   client: { vault: Record<string, (...args: any[]) => Promise<any>> },
 *   id: string | null,
 *   t: import("./common.mjs").Translate,
 *   go?: (path: string) => void,
 *   touch?: () => boolean,
 *   scope?: { add(fn: () => void): () => void },
 * }} options `id` is null for a new item
 * @returns {Promise<HTMLElement>}
 */
export async function editView({ engine, client, id, t, go = () => {}, touch = () => true, scope }) {
  const root = el("section", { class: "card edit", "data-role": "edit" });

  /** @type {any} */
  let view = null;
  /** The revision the form is built from; a save against any other is refused. @type {number | undefined} */
  let baseRev;
  if (id !== null) {
    const entry = engine.list().find((/** @type {any} */ i) => i.id === id);
    baseRev = entry?.rev;
    if (entry && !canChange(entry)) {
      mount(root,
        el("h1", null, entry.name || t("vault.item.unnamed")),
        el("div", { class: "marks" }, ...markBadges(t, entry)),
        el("p", { role: "note", "data-role": "not-editable" }, t(entry.readOnly ? "vault.notice.read_only" : "vault.edit.not_editable")),
        el("p", null, el("a", { href: `#/items/${id}`, "data-role": "back" }, t("vault.edit.back"))));
      return root;
    }
    try {
      const opened = await engine.open(id);
      try {
        view = opened.view;
      } finally {
        await opened.close();
      }
    } catch (error) {
      mount(root,
        el("p", { role: "alert", "data-role": "unavailable" }, describeError(t, error)),
        el("p", null, el("a", { href: "#/items" }, t("vault.item.back"))));
      return root;
    }
    if (view.read_only === true) {
      mount(root,
        el("h1", null, String(view.name ?? "")),
        el("p", { role: "note", "data-role": "not-editable" }, t("vault.notice.read_only")),
        el("p", null, el("a", { href: `#/items/${id}`, "data-role": "back" }, t("vault.edit.back"))));
      return root;
    }
  }

  /** @type {any[]} */
  const oldFields = Array.isArray(view?.fields) ? view.fields : [];
  /** @type {any[]} */
  const oldUrls = Array.isArray(view?.urls) ? view.urls : [];
  const oldUsername = oldFields.find((f) => f.id === "username");
  const oldPassword = oldFields.find((f) => f.id === "password");
  const kind = id === null ? "login" : String(view.item_type);

  /**
   * @param {{ id: string, label: string, type?: string, autocomplete?: string, role: string, help?: string, rows?: number }} spec
   */
  function field({ id: fieldId, label, type = "text", autocomplete = "off", role, help, rows }) {
    const input = /** @type {HTMLInputElement} */ (rows
      ? el("textarea", { id: fieldId, name: fieldId, rows, "data-role": role })
      : el("input", { id: fieldId, name: fieldId, type, autocomplete, "data-role": role }));
    input.spellcheck = false; // what is typed here is not sent to a spelling service
    const row = el("div", { class: "field", "data-field": role },
      el("label", { for: fieldId }, label), input, help ? el("small", { class: "help" }, help) : null);
    return { row, input };
  }

  const name = field({ id: "edit-name", label: t("vault.edit.name"), role: "name" });
  name.input.required = true;
  const username = field({ id: "edit-username", label: t("vault.edit.username"), role: "username", autocomplete: "off" });
  const password = field({
    id: "edit-password", label: t("vault.edit.password"), type: "password", autocomplete: "new-password", role: "password",
    help: oldPassword ? t("vault.edit.password_keep") : undefined,
  });
  const url = field({ id: "edit-url", label: t("vault.edit.url"), role: "url" });
  const notes = field({ id: "edit-notes", label: t("vault.edit.notes"), role: "notes", rows: 6 });
  const favorite = /** @type {HTMLInputElement} */ (el("input", { id: "edit-favorite", type: "checkbox", "data-role": "favorite" }));
  const typeSelect = /** @type {HTMLSelectElement} */ (el("select", { id: "edit-type", name: "type", "data-role": "type" },
    ...TYPES.map((type) => el("option", { value: type }, typeLabel(t, type)))));
  typeSelect.value = "login";

  // Start values. Only values the core shows without a secret go in.
  name.input.value = String(view?.name ?? "");
  username.input.value = typeof oldUsername?.value === "string" ? oldUsername.value : "";
  url.input.value = String(oldUrls[0]?.url ?? "");
  password.input.value = "";
  notes.input.value = "";
  favorite.checked = view?.favorite === true;

  // The notes of an item that has some are read in only on request.
  let notesLoaded = !(view?.has_notes === true);
  const notesSlot = el("div", { "data-role": "notes-slot" });
  const status = el("p", { class: "status", role: "status", "data-role": "status" });
  const errorBox = el("p", { class: "error", role: "alert", "data-role": "error" });
  errorBox.hidden = true;
  const loadNotes = el("button", { type: "button", class: "secondary", "data-role": "load-notes" }, t("vault.edit.notes_load"));
  if (notesLoaded) {
    mount(notesSlot, notes.row);
  } else {
    mount(notesSlot, el("div", { class: "field" }, el("span", { class: "label" }, t("vault.edit.notes")), loadNotes,
      el("small", { class: "help" }, t("vault.edit.notes_help"))));
    loadNotes.addEventListener("click", async () => {
      if (!touch()) return;
      try {
        const opened = await engine.open(/** @type {string} */ (id));
        try {
          notes.input.value = await client.vault.reveal_item_notes(opened.handle);
        } finally {
          await opened.close();
        }
        notesLoaded = true;
        mount(notesSlot, notes.row);
      } catch (error) {
        showError(describeError(t, error));
      }
    });
  }

  /** @param {string} text */
  function showError(text) {
    mount(errorBox, document.createTextNode(text));
    errorBox.hidden = false;
  }

  const loginRows = el("div", { class: "login-fields", "data-role": "login-fields" }, username.row, password.row, url.row);
  const showsLogin = () => (id === null ? typeSelect.value === "login" : kind === "login" || oldUsername !== undefined || oldPassword !== undefined);
  const syncRows = () => {
    loginRows.hidden = !showsLogin();
  };
  typeSelect.addEventListener("change", syncRows);
  syncRows();

  /** Everything the form holds is emptied. */
  function wipeForm() {
    for (const input of [name.input, username.input, password.input, url.input, notes.input]) input.value = "";
    favorite.checked = false;
    notesLoaded = false;
  }

  /** @returns {Draft} */
  function buildDraft() {
    /** @type {Draft} */
    const draft = { name: name.input.value.trim(), favorite: favorite.checked };
    const isLogin = showsLogin();
    if (id === null) draft.item_type = typeSelect.value;
    if (isLogin) {
      /** @type {FieldDraft[]} */
      const fields = oldFields.map((f) => ({ id: String(f.id) })); // by id only: the worker keeps label, kind and value
      /** @param {string} fieldId @param {string} label @param {string} fieldKind @param {string} value */
      const set = (fieldId, label, fieldKind, value) => {
        const entry = fields.find((f) => f.id === fieldId);
        if (entry) entry.value = value;
        else if (value !== "") fields.push({ id: fieldId, label, kind: fieldKind, value });
      };
      const typedName = username.input.value;
      if (oldUsername ? typedName !== (oldUsername.value ?? "") : typedName !== "") {
        set("username", t("vault.edit.username"), "text", typedName);
      }
      if (password.input.value !== "") set("password", t("vault.edit.password"), "password", password.input.value);
      if (fields.length > 0) draft.fields = fields;
      const first = url.input.value.trim();
      const urls = [
        ...(first === "" ? [] : [{ url: first, matching: String(oldUrls[0]?.matching ?? "host") }]),
        ...oldUrls.slice(1).map((u) => ({ url: String(u.url), matching: String(u.matching ?? "host") })),
      ];
      if (id !== null || urls.length > 0) draft.urls = urls;
    }
    if (notesLoaded) {
      const text = notes.input.value;
      if (text !== "") draft.notes = text;
      else if (view?.has_notes === true) draft.remove_notes = true;
    }
    return draft;
  }

  const save = /** @type {HTMLButtonElement} */ (el("button", { type: "submit", "data-role": "save" }, t("vault.edit.save")));
  const cancel = el("a", { class: "button secondary", href: id === null ? "#/items" : `#/items/${id}`, "data-role": "cancel" }, t("vault.edit.cancel"));

  const form = el("form", {
    "data-role": "edit-form",
    onsubmit: async (/** @type {Event} */ event) => {
      event.preventDefault();
      errorBox.hidden = true;
      if (!touch()) return;
      if (name.input.value.trim() === "") {
        showError(describeError(t, { code: "name_required" }));
        return;
      }
      if (id !== null) {
        // The form shows what this device had when it opened. If another device's change has arrived
        // since, saving would replace it without a word: refuse, and let the user look again.
        const now = engine.list().find((/** @type {any} */ i) => i.id === id);
        if (!now || baseRev === undefined || now.rev !== baseRev) {
          showError(describeError(t, { code: "item_changed" }));
          return;
        }
      }
      save.disabled = true;
      mount(status, document.createTextNode(t("vault.edit.saving")));
      const draft = buildDraft();
      try {
        const target = id === null ? await engine.create(draft) : (await engine.update(id, draft, baseRev), id);
        scrub(draft);
        wipeForm();
        mount(status);
        go(`/items/${target}`);
      } catch (error) {
        scrub(draft);
        mount(status);
        save.disabled = false;
        showError(describeError(t, error));
      }
    },
  },
  id === null ? el("div", { class: "field" }, el("label", { for: "edit-type" }, t("vault.edit.type")), typeSelect) : null,
  name.row,
  loginRows,
  notesSlot,
  el("div", { class: "choice" }, favorite, el("label", { for: "edit-favorite" }, t("vault.edit.favorite"))),
  status,
  errorBox,
  el("div", { class: "actions" }, save, cancel));

  mount(root, el("h1", null, t(id === null ? "vault.edit.heading_new" : "vault.edit.heading")), form);
  scope?.add(() => {
    wipeForm();
    mount(root);
  });
  return root;
}
