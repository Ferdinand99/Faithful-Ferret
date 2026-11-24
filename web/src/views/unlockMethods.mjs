// `#/unlock-methods`: the passkeys that open the vault in place of the master password (spec Fase 1 § 4.3, § 9.3).
// The page lists them (the name and the "synced or this device only" label come from the sealed manifest, the AAGUID from the
// server), adds one and removes one. Both changes ask for the master password again first (`flows/unlockMethods.mjs`).
//
// Adding is three steps, and a browser lets a page make one WebAuthn call for each click, so the page asks for a click for
// each call: "Create the passkey" (the name form) makes it, "Use the passkey" uses it once to make the key, and the server
// is told only after that. Nothing the passkey returns is shown or kept here; the page holds the name the user typed
// and the flags the registration reported (synced or not), nothing else.
//
// The page says what a passkey does and does not do before it is added: the master password and the recovery key go on
// working, a passkey opens the vault without the master password and the secret key, a synced passkey is as safe as the
// cloud account it lives in, and the key stays in Windows, iCloud or the phone after it is removed here. A registration that
// fails at once says why that happens (another password manager's passkey provider, or a system with no passkey provider set up).
//
// Every text is set as text; an error is shown by its code, from a fixed list, and its message is never shown.
import { clear, el, mount } from "../dom.mjs";
import { codeOf } from "../crypto/errors.mjs";
import { MAX_NAME_CHARS, MAX_PASSKEYS } from "../flows/unlockMethods.mjs";
import { askConfirm, formatMoment } from "./common.mjs";
import { field, setText } from "./form.mjs";
import { securityErrorText } from "./securityError.mjs";

/** @typedef {import("./form.mjs").Translate} Translate */
/** @typedef {import("../flows/unlockMethods.mjs").PasskeyMethod} PasskeyMethod */
/** @typedef {import("../flows/unlockMethods.mjs").AddingPasskey} AddingPasskey */
/** @typedef {{ add(fn: () => void): () => void }} Scope */

/** The codes with a text of their own under `methods.error.`. */
export const METHODS_ERRORS = Object.freeze([
  "bad_request", "cancelled", "conflict", "method_name_bad_character", "method_name_empty", "method_name_too_long", "method_not_found",
  "method_unconfirmed", "not_a_passkey", "not_found", "passkey_bad_answer", "passkey_bad_output", "passkey_blocked", "passkey_cancelled",
  "passkey_exists", "passkey_failed", "passkey_no_output", "passkey_no_prf", "passkey_not_verified", "passkey_other_credential",
  "passkey_security", "passkey_sequence", "passkey_stored_here", "passkey_unstable", "passkey_unsupported", "quota_exceeded",
  "too_many_passkeys", "unsupported_envelope", "write_conflict",
]);

/** The codes after which the same click can be made again: nothing was made of the passkey. */
const TRY_AGAIN = Object.freeze(["passkey_cancelled", "passkey_blocked"]);

/**
 * The text of an error on this page. Only the code is used.
 * @param {Translate} t
 * @param {unknown} error
 */
export function methodsErrorText(t, error) {
  const code = codeOf(error);
  if (METHODS_ERRORS.includes(code)) return t(`methods.error.${code}`, { max: MAX_PASSKEYS, limit: MAX_NAME_CHARS });
  return securityErrorText(t, error);
}

/**
 * The AAGUID as the usual text of an id: 8-4-4-4-12.
 * @param {string} hex 32 hexadecimal characters
 */
export function formatAaguid(hex) {
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * @param {{
 *   t: Translate,
 *   site: string,
 *   locale?: string,
 *   load: () => Promise<PasskeyMethod[]>,
 *   begin: () => Promise<AddingPasskey>,
 *   remove: (id: string) => Promise<unknown>,
 *   scope?: Scope,
 *   win?: { addEventListener?: Function, removeEventListener?: Function },
 *   host?: HTMLElement,
 * }} options `site` is the exact host of the vault, which a passkey is tied to. `load` reads the list; `begin` starts adding
 * a passkey (the password check and the checks of the server's list; its `create` and `confirm` are the two WebAuthn calls);
 * `remove` removes a method by its id (after the password check). With `scope`, a lock of the vault drops what is half done.
 * `host` is where the dialog of a removal sits (the page by default).
 * @returns {HTMLElement}
 */
export function unlockMethodsView({ t, site, locale, load, begin, remove, scope, win = globalThis, host }) {
  const root = el("section", { class: "card methods-page", "data-role": "methods-page" });
  const dialogHost = host ?? root;
  const status = el("p", { class: "status", role: "status", "data-role": "methods-status" });
  const errorBox = el("div", { class: "error", role: "alert", "data-role": "methods-error" });
  errorBox.hidden = true;
  const done = el("p", { class: "ok", role: "status", "data-role": "methods-done" });
  done.hidden = true;
  const list = el("ul", { class: "methods-list", "data-role": "methods-list" });

  // ------------------------------------------------------------------- adding
  const addButton = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-primary", "data-role": "methods-add" }, t("methods.add.button")));
  const name = field(t, {
    id: "methods-name", role: "methods-name-input", label: "methods.add.name_label", help: "methods.add.name_help", autocomplete: "off",
  });
  name.input.setAttribute("maxlength", String(MAX_NAME_CHARS * 2));
  name.input.setAttribute("spellcheck", "false");
  const createButton = /** @type {HTMLButtonElement} */ (el("button", { type: "submit", class: "btn btn-primary", "data-role": "methods-create" }, t("methods.add.create")));
  const nameCancel = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-secondary", "data-role": "methods-name-cancel" }, t("methods.add.cancel")));
  const nameForm = el("form", { class: "stack methods-form", "data-role": "methods-name-form", "aria-labelledby": "methods-add-heading" },
    el("p", null, t("methods.add.explain_create")),
    name.row,
    el("div", { class: "actions" }, nameCancel, createButton));
  nameForm.hidden = true;

  const confirmButton = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-primary", "data-role": "methods-confirm" }, t("methods.add.confirm")));
  const confirmCancel = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-secondary", "data-role": "methods-confirm-cancel" }, t("methods.add.cancel")));
  const confirmBox = el("div", { class: "stack methods-form", "data-role": "methods-confirm-step" },
    el("h3", { id: "methods-confirm-heading" }, t("methods.add.confirm_heading")),
    el("p", null, t("methods.add.confirm_body")),
    el("div", { class: "actions" }, confirmCancel, confirmButton));
  confirmBox.hidden = true;

  /** @type {"idle" | "preparing" | "naming" | "creating" | "confirming" | "saving"} */
  let phase = "idle";
  /** @type {AddingPasskey | null} */
  let adding = null;
  /** Whether a removal is under way. */
  let removing = false;
  /** @type {HTMLButtonElement[]} */
  let removeButtons = [];

  /** @param {typeof phase} next */
  function setPhase(next) {
    phase = next;
    addButton.hidden = next !== "idle";
    nameForm.hidden = next !== "naming" && next !== "creating";
    confirmBox.hidden = next !== "confirming" && next !== "saving";
    const working = next === "preparing" || next === "creating" || next === "saving";
    name.input.disabled = next === "creating";
    createButton.disabled = next === "creating";
    nameCancel.disabled = next === "creating";
    confirmButton.disabled = next === "saving";
    confirmCancel.disabled = next === "saving";
    addButton.disabled = next === "preparing";
    for (const button of removeButtons) button.disabled = next !== "idle";
    root.setAttribute("aria-busy", working ? "true" : "false");
    /** @type {Record<string, string>} */
    const words = { preparing: "methods.add.preparing", creating: "methods.add.waiting_create", saving: "methods.add.saving" };
    setText(status, words[next] ? t(words[next]) : "");
  }

  function clearMessages() {
    errorBox.hidden = true;
    clear(errorBox);
    done.hidden = true;
  }

  /** @param {unknown} error */
  function showError(error) {
    const code = codeOf(error);
    /** @type {Node[]} */
    const parts = [el("p", null, methodsErrorText(t, error))];
    if (code === "passkey_blocked") {
      // The call was refused before the user could have seen anything: why that happens, and what to check.
      parts.push(el("ul", { "data-role": "methods-blocked-help" },
        el("li", null, t("methods.blocked.other_manager")),
        el("li", null, t("methods.blocked.mac")),
        el("li", null, t("methods.blocked.windows"))));
    }
    mount(errorBox, ...parts);
    errorBox.hidden = false;
  }

  /** @param {string} text */
  function showDone(text) {
    setText(done, text);
    done.hidden = false;
  }

  /** Drops what is half done: the passkey that was made and not yet used, and the name that was typed. */
  function abandon() {
    adding?.cancel();
    adding = null;
    name.input.value = "";
  }

  addButton.addEventListener("click", async () => {
    clearMessages();
    setPhase("preparing");
    try {
      adding = await begin();
    } catch (error) {
      adding = null;
      if (codeOf(error) !== "cancelled") showError(error);
      setPhase("idle");
      addButton.focus?.();
      return;
    }
    setPhase("naming");
    name.input.focus?.();
  });

  nameForm.addEventListener("submit", async (/** @type {Event} */ event) => {
    event.preventDefault();
    if (phase !== "naming" || adding === null) return;
    const typed = name.input.value;
    clearMessages();
    const current = adding;
    // The call to the passkey is the first thing the click does: the browser counts the click as its permission.
    const made = current.create(typed);
    setPhase("creating");
    try {
      await made;
    } catch (error) {
      showError(error);
      // The name can be mended and the click made again; the page stays on the form.
      setPhase("naming");
      name.input.focus?.();
      return;
    }
    setPhase("confirming");
    confirmButton.focus?.();
  });

  nameCancel.addEventListener("click", () => {
    abandon();
    clearMessages();
    setPhase("idle");
    addButton.focus?.();
  });

  confirmButton.addEventListener("click", async () => {
    if (phase !== "confirming" || adding === null) return;
    clearMessages();
    const current = adding;
    const used = current.confirm();
    setPhase("saving");
    try {
      const added = await used;
      adding = null;
      name.input.value = "";
      setPhase("idle");
      showDone(t("methods.add.done", { name: added.name ?? "", kind: t(added.synced ? "methods.kind.synced" : "methods.kind.device") }));
      addButton.focus?.();
    } catch (error) {
      showError(error);
      if (TRY_AGAIN.includes(codeOf(error))) {
        setPhase("confirming");
        confirmButton.focus?.();
        return;
      }
      abandon();
      setPhase("idle");
      addButton.focus?.();
    }
    await refresh();
  });

  confirmCancel.addEventListener("click", () => {
    abandon();
    clearMessages();
    setPhase("idle");
    showDone(t("methods.add.leftover"));
    addButton.focus?.();
  });

  // --------------------------------------------------------------------- list
  /** @param {PasskeyMethod} method */
  function rowView(method) {
    const label = method.name ?? t("methods.list.unnamed");
    const kind = t(method.synced ? "methods.kind.synced" : "methods.kind.device");
    const added = method.addedAt === null ? null : formatMoment(method.addedAt, locale);
    const button = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-secondary", "data-role": "methods-remove" }, t("methods.remove.button")));
    button.setAttribute("aria-label", t("methods.remove.label", { name: label }));
    button.addEventListener("click", async () => {
      if (phase !== "idle" || removing) return;
      clearMessages();
      const sure = await askConfirm({
        t, host: dialogHost, title: "methods.remove.title", body: "methods.remove.body", confirm: "methods.remove.confirm", cancel: "methods.remove.cancel", vars: { name: label },
      });
      if (!sure) {
        button.focus?.();
        return;
      }
      removing = true;
      for (const other of removeButtons) other.disabled = true;
      addButton.disabled = true;
      root.setAttribute("aria-busy", "true");
      try {
        await remove(method.id);
        showDone(t("methods.remove.done", { name: label }));
      } catch (error) {
        showError(error);
      } finally {
        removing = false;
        addButton.disabled = false;
        root.setAttribute("aria-busy", "false");
      }
      await refresh();
    });
    removeButtons.push(button);
    return el("li", { class: "methods-row", "data-role": "methods-row", "data-id": method.id, "data-kind": method.synced ? "synced" : "device" },
      el("div", { class: "methods-name" },
        el("strong", { "data-role": "methods-row-name" }, label),
        el("span", { class: "pill methods-pill", "data-role": "methods-kind", "data-kind": method.synced ? "synced" : "device" }, kind)),
      el("p", { class: "methods-aaguid help", "data-role": "methods-aaguid" },
        method.aaguid === null ? t("methods.aaguid_unknown") : t("methods.aaguid", { aaguid: formatAaguid(method.aaguid) })),
      el("p", { class: "methods-added help", "data-role": "methods-added" }, added === null ? t("methods.added_unknown") : t("methods.added", { time: added })),
      el("div", { class: "actions" }, button));
  }

  async function refresh() {
    setText(status, t("methods.list.loading"));
    /** @type {PasskeyMethod[]} */
    let methods;
    try {
      methods = await load();
    } catch (error) {
      setText(status, "");
      removeButtons = [];
      mount(list);
      showError(error);
      return;
    }
    if (phase === "idle") setText(status, "");
    removeButtons = [];
    mount(list, ...methods.map(rowView));
    if (methods.length === 0) list.appendChild(el("li", { "data-role": "methods-empty" }, t("methods.list.empty")));
    for (const button of removeButtons) button.disabled = phase !== "idle";
    const full = methods.length >= MAX_PASSKEYS;
    addButton.disabled = full || phase === "preparing";
    limit.hidden = !full;
  }

  const limit = el("p", { class: "help", "data-role": "methods-limit" }, t("methods.add.limit", { max: MAX_PASSKEYS }));
  limit.hidden = true;

  // A lock of the vault, or leaving the page, drops what is half done.
  const dropAll = () => {
    abandon();
    clearMessages();
    setPhase("idle");
  };
  scope?.add(dropAll);
  if (typeof win?.addEventListener === "function") {
    const left = () => {
      win.removeEventListener?.("hashchange", left);
      dropAll();
    };
    win.addEventListener("hashchange", left);
  }

  mount(root,
    el("h1", null, t("methods.heading")),
    el("p", { "data-role": "methods-intro" }, t("methods.intro")),
    el("div", { class: "methods-note", "data-role": "methods-what" },
      el("h2", null, t("methods.what.heading")),
      el("p", { "data-role": "methods-what-still" }, t("methods.what.still")),
      el("p", { "data-role": "methods-what-no-password" }, t("methods.what.no_password")),
      el("p", { "data-role": "methods-what-synced" }, t("methods.what.synced")),
      el("p", { "data-role": "methods-what-remove" }, t("methods.what.remove")),
      el("p", { "data-role": "methods-what-suspect" }, t("methods.what.suspect")),
      el("p", { "data-role": "methods-what-host" }, t("methods.what.host", { site }))),
    el("h2", null, t("methods.list.heading")),
    status,
    errorBox,
    done,
    list,
    el("div", { class: "methods-add stack", "data-role": "methods-add-box" },
      el("h2", { id: "methods-add-heading" }, t("methods.add.heading")),
      limit,
      el("div", { class: "actions" }, addButton),
      nameForm,
      confirmBox));
  setPhase("idle");
  void refresh();
  return root;
}
