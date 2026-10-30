// Small pieces the account pages share: labelled fields, the busy state, the
// notice about the web vault's trust boundary and the text of an error. Pages
// are built with `el()` only; text always goes in as a text node.
import { clear, el, mount } from "../dom.mjs";
import { codeOf } from "../crypto/errors.mjs";

/** @typedef {(key: string, vars?: Record<string, string | number>) => string} Translate */

/**
 * Replaces the text of a node.
 * @param {Node} node
 * @param {string} text
 */
export function setText(node, text) {
  mount(node, document.createTextNode(text));
}

/**
 * The notice on the sign-in and setup pages: the web vault trusts the server
 * that delivers its code (spec Fase 1 § 2.4). It is always in the same place,
 * last in the card.
 * @param {Translate} t
 */
export function trustNotice(t) {
  return el("p", { class: "notice trust", role: "note", "data-role": "trust-notice" }, t("account.trust.notice"));
}

/**
 * A labelled input.
 * @param {Translate} t
 * @param {{ id: string, role: string, label: string, type?: string, autocomplete?: string, required?: boolean, help?: string, inputmode?: string }} spec
 * @returns {{ row: HTMLElement, input: HTMLInputElement }}
 */
export function field(t, { id, role, label, type = "text", autocomplete = "off", required = true, help, inputmode }) {
  /** @type {Record<string, string | boolean>} */
  const attrs = { id, name: id, type, autocomplete, "data-role": role };
  if (required) attrs.required = true;
  if (inputmode) attrs.inputmode = inputmode;
  const input = /** @type {HTMLInputElement} */ (el("input", attrs));
  const row = el("div", { class: "field" }, el("label", { for: id }, t(label)), input, help ? el("small", { class: "help" }, t(help)) : null);
  return { row, input };
}

/**
 * A checkbox or radio button with its label.
 * @param {Translate} t
 * @param {{ id: string, role: string, label: string, type?: "checkbox" | "radio", name?: string, value?: string, checked?: boolean }} spec
 * @returns {{ row: HTMLElement, input: HTMLInputElement }}
 */
export function choice(t, { id, role, label, type = "checkbox", name, value, checked = false }) {
  /** @type {Record<string, string | boolean>} */
  const attrs = { id, type, "data-role": role };
  if (name) attrs.name = name;
  if (value) attrs.value = value;
  const input = /** @type {HTMLInputElement} */ (el("input", attrs));
  input.checked = checked;
  const row = el("div", { class: "choice" }, input, el("label", { for: id }, t(label)));
  return { row, input };
}

/**
 * The busy state of a form while Argon2id runs (it takes seconds): the
 * controls are disabled and a status line says so.
 * @param {{ root: HTMLElement, status: HTMLElement, controls: ReadonlyArray<any>, t: Translate, key?: string }} spec
 */
export function busyState({ root, status, controls, t, key = "account.busy" }) {
  return {
    /** @param {boolean} on */
    set(on) {
      for (const control of controls) /** @type {{ disabled: boolean }} */ (control).disabled = on;
      root.setAttribute("aria-busy", on ? "true" : "false");
      if (on) setText(status, t(key));
      else clear(status);
    },
  };
}

/** The codes the pages have a text for (`account.error.<code>`). */
export const KNOWN_ERRORS = Object.freeze([
  "admin_unconfigured", "bad_response", "checksum", "decrypt", "denied", "email_required", "epoch_mismatch",
  "forbidden", "forbidden_origin", "handoff_invalid", "ids_changed", "input_forbidden_character", "input_not_utf8",
  "input_too_long", "input_too_short", "insecure_transport", "kdf_profile_downgrade", "kdf_profile_unknown",
  "malformed_code", "method_list_changed", "method_list_missing", "method_list_unknown", "methods_invalid", "network",
  "non_canonical", "not_confirmed", "password_mismatch", "password_required", "pin_save_failed", "pinned_account_id", "pinned_account_mismatch",
  "pinned_auth_key", "pinned_epoch_downgrade", "pinned_floor_downgrade", "pinned_floor_missing", "pinned_identity_changed",
  "pinned_kek_generation", "pinned_profile_downgrade", "pinned_server_key", "pinned_server_key_changed",
  "pinned_server_url", "pinned_sk_bit", "pinned_vault_id", "pinned_vk_epoch", "profile_rejected",
  "registration_closed", "reauth_not_fresh", "session_ended", "signout_incomplete", "sk_answer_required", "sk_required",
  "throttled", "two_factor_unsupported", "unauthorized", "unknown", "worker_failed",
]);

/**
 * The i18n key of the text for an error. A code the pages have no text for
 * gets the general one; the text never contains anything the user typed.
 * @param {unknown} error
 * @returns {string}
 */
export function errorKey(error) {
  const code = codeOf(error);
  return KNOWN_ERRORS.includes(code) ? `account.error.${code}` : "account.error.unknown";
}

/**
 * @param {Translate} t
 * @param {unknown} error
 * @returns {string}
 */
export function describeError(t, error) {
  const key = errorKey(error);
  let text = t(key);
  const code = codeOf(error);
  if (key === "account.error.unknown" && code !== "unknown") text = `${text} (${code})`;
  const retry = /** @type {any} */ (error)?.retryAfter;
  if (typeof retry === "number" && retry > 0) text = `${text} ${t("account.error.retry_in", { seconds: retry })}`;
  return text;
}
