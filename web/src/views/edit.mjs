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
//
// The password input can be shown, with an eye button beside it, so the user can check what they typed. It is hidden again
// when the form is saved, cancelled, frozen, wiped by a lock or put back in a screen, and a form that is built anew starts
// hidden. Whether it is shown is held in the `type` of the input and nowhere else: never in a URL, a store or a message.
//
// Changes that are not saved live in the form and nowhere else: never in a store, a URL or a message. When
// the vault moves to another tab (`tracker`), the form is kept on screen read-only (`freeze`) and goes on
// when the vault comes back (`thaw`); a lock wipes it as it wipes every screen. The form tells whether it
// has edits (`dirty`) by comparing with what it started with, without holding a copy of any secret.
import { el, mount } from "../dom.mjs";
import { folderIndex } from "../folders.mjs";
import { canChange, codeOf, describeError, listenWhileShown, markBadges } from "./common.mjs";
import { FOLDER_ERRORS, folderPicker } from "./folderPicker.mjs";
import { typeLabel } from "./item.mjs";

const TYPES = Object.freeze(["login", "note"]);

/**
 * @typedef {object} UnsavedForm what the sync service holds about a form with edits that are not saved
 * @property {string} key which form it is: `new`, or `edit:<item id>`
 * @property {string[]} [keys] every key it has answered to (a form that moved to a copy keeps the key of the old id too)
 * @property {HTMLElement} root the form's screen
 * @property {() => boolean} dirty whether it holds edits that are not saved
 * @property {() => void} freeze makes it read-only (the vault moved to another tab); the content stays
 * @property {(next: { engine: any, touch?: () => boolean, scope?: { add(fn: () => void): () => void }, go?: (path: string) => void, tracker?: any }) => void} thaw
 *   the vault is back in this tab: the form is editable again, under the new engine, and the screen it is put in
 */

/**
 * @typedef {{ id: string, label?: string, kind?: string, value?: string }} FieldDraft
 * @typedef {{
 *   item_type?: string, name: string, favorite: boolean, fields?: FieldDraft[],
 *   urls?: { url: string, matching: string }[], notes?: string, remove_notes?: boolean, folders?: string[],
 *   keep_password_history?: boolean,
 * }} Draft
 */

/** @param {Draft} draft Empties what the draft holds, so no reference to a typed secret is left. */
function scrub(draft) {
  for (const field of draft.fields ?? []) if (typeof field.value === "string") field.value = "";
  if (typeof draft.notes === "string") draft.notes = "";
  if (Array.isArray(draft.folders)) draft.folders.length = 0;
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
 *   tracker?: { trackUnsaved(form: UnsavedForm): () => void },
 *   locale?: string,
 * }} options `id` is null for a new item; `tracker` is told about the form's unsaved edits (the sync service)
 * @returns {Promise<HTMLElement>}
 */
export async function editView({ engine, client, id, t, go = () => {}, touch = () => true, scope, tracker, locale }) {
  const root = el("section", { class: "edit-view", "data-role": "edit" });

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
   * @param {{ id: string, label: string, type?: string, autocomplete?: string, role: string, help?: string, rows?: number, toggle?: HTMLElement }} spec
   *   `toggle` is a button that goes inside the frame of the input (the show/hide button of the password)
   */
  function field({ id: fieldId, label, type = "text", autocomplete = "off", role, help, rows, toggle }) {
    const input = /** @type {HTMLInputElement} */ (rows
      ? el("textarea", { id: fieldId, name: fieldId, rows, "data-role": role })
      : el("input", { id: fieldId, name: fieldId, type, autocomplete, "data-role": role }));
    input.spellcheck = false; // what is typed here is not sent to a spelling service
    const row = el("div", { class: "field", "data-field": role },
      el("label", { for: fieldId }, label),
      toggle ? el("div", { class: "secret-input", "data-role": `${role}-box` }, input, toggle) : input,
      help ? el("small", { class: "help" }, help) : null);
    return { row, input };
  }

  const name = field({ id: "edit-name", label: t("vault.edit.name"), role: "name" });
  name.input.required = true;
  const username = field({ id: "edit-username", label: t("vault.edit.username"), role: "username", autocomplete: "off" });
  const reveal = /** @type {HTMLButtonElement} */ (el("button", {
    type: "button", class: "reveal-toggle", "aria-pressed": "false", "aria-label": t("vault.edit.password_show"), "data-role": "password-toggle",
  }, el("span", { class: "icon", "data-icon": "eye", "aria-hidden": "true" })));
  const revealIcon = /** @type {HTMLElement} */ (reveal.firstChild);
  const password = field({
    id: "edit-password", label: t("vault.edit.password"), type: "password", autocomplete: "new-password", role: "password", toggle: reveal,
    help: oldPassword ? `${t("vault.edit.password_keep")} ${t("vault.edit.password_history")}` : undefined,
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
  // What the form started with, for telling whether it has edits. Only values that are shown anyway; no secret is copied.
  const start = { name: name.input.value, username: username.input.value, url: url.input.value, favorite: favorite.checked };

  // The notes of an item that has some are read in only on request.
  let notesLoaded = !(view?.has_notes === true);
  // Typed into the notes of an item that had some (the text itself is not copied to compare with).
  let notesTouched = false;
  notes.input.addEventListener("input", () => {
    notesTouched = true;
  });
  const notesSlot = el("section", { class: "card item-section", "data-role": "notes-slot" });
  // The folders of the item. They are sent only when the user changed them: a draft without `folders` keeps what the
  // item has (also names this screen does not show), and a list replaces them.
  const picker = folderPicker({
    t, locale,
    initial: Array.isArray(view?.folders) ? view.folders.filter((/** @type {unknown} */ n) => typeof n === "string") : [],
    suggestions: () => folderIndex(typeof engine?.list === "function" ? engine.list() : [], locale).map((folder) => folder.name),
  });
  const folderSlot = el("div", { class: "folder-slot", "data-role": "folder-slot" }, picker.root);
  const status = el("p", { class: "status", role: "status", "data-role": "status" });
  const errorBox = el("p", { class: "error", role: "alert", "data-role": "error" });
  errorBox.hidden = true;
  const loadNotes = el("button", { type: "button", class: "btn btn-secondary", "data-role": "load-notes" }, t("vault.edit.notes_load"));
  if (notesLoaded) {
    mount(notesSlot, notes.row);
  } else {
    mount(notesSlot, el("div", { class: "field" }, el("span", { class: "label" }, t("vault.edit.notes")), loadNotes,
      el("small", { class: "help" }, t("vault.edit.notes_help"))));
    loadNotes.addEventListener("click", async () => {
      if (frozen || !touch()) return;
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

  const loginRows = el("section", { class: "card item-section stack", "data-role": "login-fields" },
    el("h2", null, t("vault.item.card_login")), username.row, password.row, url.row);
  const showsLogin = () => (id === null ? typeSelect.value === "login" : kind === "login" || oldUsername !== undefined || oldPassword !== undefined);
  const syncRows = () => {
    loginRows.hidden = !showsLogin();
  };
  typeSelect.addEventListener("change", syncRows);
  syncRows();

  /** Whether the password is on the screen as text. */
  let shown = false;
  /**
   * @param {boolean} on The password input shows its text (`true`) or dots (`false`). The button has one name ("Show password")
   * and `aria-pressed` says whether it is on: a label that also flipped would tell a screen reader the state twice.
   */
  function showPassword(on) {
    shown = on;
    password.input.setAttribute("type", on ? "text" : "password");
    reveal.setAttribute("aria-pressed", on ? "true" : "false");
    revealIcon.setAttribute("data-icon", on ? "eye-off" : "eye");
  }
  reveal.addEventListener("click", () => {
    if (frozen || !touch()) return;
    showPassword(!shown);
  });

  /** The form was saved or wiped: it holds nothing to lose any more. */
  let settled = false;
  /** The form is read-only: the vault is in another tab. */
  let frozen = false;
  /** Removes the form from the list of forms with unsaved edits, and the wipe from the scope of the screen. @type {(() => void)[]} */
  let leave = [];

  /** Everything the form holds is emptied. */
  function wipeForm() {
    for (const input of [name.input, username.input, password.input, url.input, notes.input]) input.value = "";
    favorite.checked = false;
    showPassword(false);
    picker.wipe();
    notesLoaded = false;
    settled = true;
    for (const forget of leave.splice(0)) forget();
  }

  /** Whether the form holds edits that are not saved: a field that differs from the start, a typed password, typed notes. */
  function dirty() {
    if (settled || /** @type {any} */ (root).isConnected === false) return false;
    if (name.input.value !== start.name || username.input.value !== start.username || url.input.value !== start.url) return true;
    if (favorite.checked !== start.favorite || password.input.value !== "") return true;
    if (picker.changed() || picker.typed()) return true;
    if (id === null && typeSelect.value !== "login") return true;
    return notesLoaded && (view?.has_notes === true ? notesTouched : notes.input.value !== "");
  }

  /** @param {boolean} on */
  function setReadOnly(on) {
    frozen = on;
    for (const input of [name.input, username.input, password.input, url.input, notes.input]) {
      input.readOnly = on;
      if (on) input.setAttribute("readonly", "");
      else input.removeAttribute?.("readonly");
    }
    if (on) showPassword(false);
    for (const control of [favorite, typeSelect, save, loadNotes, reveal]) {
      /** @type {any} */ (control).disabled = on;
    }
    picker.setReadOnly(on);
    root.setAttribute("data-state", on ? "frozen" : "open");
    if (on) mount(status);
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
      if (password.input.value !== "") {
        set("password", t("vault.edit.password"), "password", password.input.value);
        // A new password on an item that is being changed: the core moves the old one into the item's previous passwords
        // (it does nothing when the item had none, or when the value is the same). No old value passes through this form.
        if (id !== null) draft.keep_password_history = true;
      }
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
    if (picker.changed()) draft.folders = picker.value();
    return draft;
  }

  const save = /** @type {HTMLButtonElement} */ (el("button", { type: "submit", class: "btn btn-primary", "data-role": "save" }, t("vault.edit.save")));
  const cancel = el("a", { class: "btn btn-secondary", href: id === null ? "#/items" : `#/items/${id}`, "data-role": "cancel" }, t("vault.edit.cancel"));

  cancel.addEventListener("click", () => showPassword(false));

  const form = el("form", {
    class: "stack",
    "data-role": "edit-form",
    onsubmit: async (/** @type {Event} */ event) => {
      event.preventDefault();
      if (frozen) return; // the vault is in another tab: nothing is saved from here
      errorBox.hidden = true;
      if (!touch()) return;
      if (name.input.value.trim() === "") {
        showError(describeError(t, { code: "name_required" }));
        return;
      }
      // A folder name typed and not added yet is added now; one the rules refuse stops the save, with its reason.
      if (!picker.commitTyped()) return;
      const folderProblem = picker.check();
      if (folderProblem !== null) {
        picker.showError(folderProblem);
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
      showPassword(false);
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
        if (FOLDER_ERRORS.includes(codeOf(error))) picker.showError(codeOf(error));
      }
    },
  },
  // The first card: what every item has, with its folders at the foot.
  el("section", { class: "card item-section stack", "data-role": "details-card" },
    el("h2", null, t("vault.edit.card_details")),
    id === null ? el("div", { class: "field" }, el("label", { for: "edit-type" }, t("vault.edit.type")), typeSelect) : null,
    name.row,
    el("div", { class: "choice" }, favorite, el("label", { for: "edit-favorite" }, t("vault.edit.favorite"))),
    folderSlot),
  loginRows,
  notesSlot,
  status,
  errorBox,
  el("div", { class: "actions" }, save, cancel));

  mount(root, el("h1", null, t(id === null ? "vault.edit.heading_new" : "vault.edit.heading")), form);

  /** The wipe for the lock, in the scope of the screen the form is in. @param {{ add(fn: () => void): () => void } | undefined} where */
  const wipeWith = (where) => {
    const removeWipe = where?.add(() => {
      wipeForm();
      mount(root);
    });
    if (removeWipe) leave.push(removeWipe);
  };
  /** @param {{ trackUnsaved(form: UnsavedForm): () => void } | undefined} where */
  const trackWith = (where) => {
    const untrack = where?.trackUnsaved(unsaved);
    if (untrack) leave.push(untrack);
  };
  /** The keys the form has had: the item it was opened on, and the copy it moved to. */
  const names = new Set([id === null ? "new" : `edit:${id}`]);
  /** @type {UnsavedForm} */
  const unsaved = {
    get key() {
      return id === null ? "new" : `edit:${id}`;
    },
    get keys() {
      return [...names];
    },
    root,
    dirty,
    freeze: () => setReadOnly(true),
    // The vault is back in this tab (the form is put in a new screen, under the new engine). The wipe of the old screen no
    // longer reaches it; the wipe and the tracking of the new one do.
    thaw(next) {
      for (const forget of leave.splice(0)) forget();
      engine = next.engine;
      if (next.touch) touch = next.touch;
      if (next.go) go = next.go;
      setReadOnly(false);
      save.disabled = false;
      mount(status);
      watchCopies();
      wipeWith(next.scope);
      trackWith(next.tracker);
    },
  };

  /** @type {(() => void) | null} */
  let stopWatching = null;
  /**
   * A restore over an item the server had purged became a copy under a new id (the engine's `copied`): the form goes on
   * with the copy, and the address says so. The form is not rebuilt, so what was typed stays.
   */
  function watchCopies() {
    stopWatching?.();
    stopWatching = null;
    if (id === null || typeof engine?.on !== "function") return;
    stopWatching = listenWhileShown(root, engine, "copied", (/** @type {any} */ payload) => {
      if (payload?.from !== id || typeof payload?.to !== "string") return;
      const from = id;
      id = payload.to;
      names.add(`edit:${id}`);
      const entry = engine.list().find((/** @type {any} */ i) => i.id === id);
      baseRev = entry?.rev ?? 1;
      cancel.setAttribute("href", `#/items/${id}`);
      try {
        const here = globalThis.location?.hash;
        if (here === `#/items/${from}/edit`) globalThis.history?.replaceState?.(null, "", `#/items/${id}/edit`);
      } catch {
        // The address stays as it is; the form works on the copy either way
      }
    });
  }
  watchCopies();

  wipeWith(scope);
  trackWith(tracker);
  return root;
}
