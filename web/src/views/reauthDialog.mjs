// The dialog that asks for the master password again before a sensitive
// operation (spec Fase 1 § 4.6 (a)). It is a modal card in the page, not a
// browser dialog: the password field and the error stay under the page's own
// control, and a lock of the vault removes it.
//
// It is skipped, and answers "ok" at once, while the freshness the server gave the
// session (`until`, milliseconds since 1970) still covers the next minute: a flow that
// needs a few seconds should not ask again. Past that, the user types the password; the
// field is emptied before the slow call starts (Argon2id takes seconds, and a failed
// attempt leaves nothing on the page), and an error leaves the dialog open for another
// try. The secret key is asked for only when the account has one and this device does not
// hold it. Nothing typed is kept, stored or put in an address.
//
// A caller that needs the one-time grant of a plain export (`reauthenticate` with `wantGrant`) passes
// `needGrant`: the dialog is then never skipped, because a skipped dialog runs nothing and gives no grant.
// While the dialog is open the Tab key stays inside it, and focus goes back to where it was when it closes.
import { el, mount } from "../dom.mjs";
import { codeOf } from "../crypto/errors.mjs";
import { coversNext } from "../flows/reauth.mjs";
import { securityErrorText } from "./securityError.mjs";

/** @typedef {import("./form.mjs").Translate} Translate */

/** Makes the ids of the fields unique when a page opens the dialog more than once. */
let counter = 0;

/**
 * @param {{
 *   t: Translate,
 *   run: (typed: { password: string, skCode?: string }) => Promise<unknown>,
 *   until?: number | null,
 *   now?: () => number,
 *   host?: HTMLElement,
 *   skRequired?: boolean,
 *   needGrant?: boolean,
 *   scope?: { add(fn: () => void): () => void },
 * }} options `run` confirms the password (`session.reauthenticate`); a rejection is shown and keeps the dialog open.
 * `until` is the end of the freshness the session has now, if any. `needGrant`: the caller needs the grant that `run`
 * makes, so the dialog is not skipped whatever `until` says. `host` is where the dialog sits (the page body by
 * default). With `scope`, a lock of the vault removes the dialog and answers "cancelled".
 * @returns {Promise<"ok" | "cancelled">}
 */
export function reauthDialog({ t, run, until = null, now = Date.now, host = document.body, skRequired = false, needGrant = false, scope }) {
  if (!needGrant && coversNext(until, now())) return Promise.resolve("ok");
  return new Promise((resolve) => {
    const before = /** @type {any} */ (globalThis.document)?.activeElement ?? null;
    counter += 1;
    const titleId = `reauth-title-${counter}`;
    const passwordId = `reauth-password-${counter}`;
    const skId = `reauth-sk-${counter}`;
    const password = /** @type {HTMLInputElement} */ (el("input", {
      id: passwordId, name: "password", type: "password", autocomplete: "current-password", required: true, "data-role": "reauth-password",
    }));
    password.value = "";
    const skSlot = el("div", { "data-role": "reauth-sk-slot" });
    /** @type {HTMLInputElement | null} */
    let sk = null;
    const status = el("p", { class: "status", role: "status", "data-role": "reauth-status" });
    const errorBox = el("p", { class: "error", role: "alert", "data-role": "reauth-error" });
    errorBox.hidden = true;
    const confirm = /** @type {HTMLButtonElement} */ (el("button", { type: "submit", class: "btn btn-primary", "data-role": "reauth-confirm" }, t("security.reauth.confirm")));
    const cancel = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-secondary", "data-role": "reauth-cancel" }, t("security.reauth.cancel")));

    function showSecretKeyField() {
      if (sk) return;
      sk = /** @type {HTMLInputElement} */ (el("input", {
        id: skId, name: "secret-key", type: "text", autocomplete: "off", required: true, "data-role": "reauth-secret-key",
      }));
      sk.value = "";
      sk.setAttribute("spellcheck", "false");
      sk.setAttribute("autocapitalize", "off");
      sk.setAttribute("autocorrect", "off");
      mount(skSlot, el("div", { class: "field" }, el("label", { for: skId }, t("security.reauth.secret_key")), sk,
        el("small", { class: "help" }, t("security.reauth.secret_key_help"))));
    }
    if (skRequired) showSecretKeyField();

    /** @param {boolean} on */
    function busy(on) {
      confirm.disabled = on;
      cancel.disabled = on;
      password.disabled = on;
      if (sk) sk.disabled = on;
      dialog.setAttribute("aria-busy", on ? "true" : "false");
      mount(status, document.createTextNode(on ? t("security.reauth.busy") : ""));
    }

    /** @param {string} text */
    function showError(text) {
      mount(errorBox, document.createTextNode(text));
      errorBox.hidden = false;
    }

    /** @type {(() => void) | null} */
    let unscope = null;
    let done = false;
    /** @param {"ok" | "cancelled"} answer */
    function finish(answer) {
      if (done) return;
      done = true;
      password.value = "";
      if (sk) sk.value = "";
      unscope?.();
      dialog.remove();
      // Focus goes back to what had it (the button that opened the dialog).
      if (before !== null && typeof before.focus === "function" && before !== globalThis.document?.body) before.focus();
      resolve(answer);
    }

    const form = el("form", {
      class: "stack",
      "data-role": "reauth-form",
      onsubmit: async (/** @type {Event} */ event) => {
        event.preventDefault();
        if (done || confirm.disabled) return;
        errorBox.hidden = true;
        const typed = password.value;
        const skCode = sk ? sk.value.trim() : "";
        if (typed === "") {
          showError(securityErrorText(t, { code: "password_required" }));
          return;
        }
        if (sk && skCode === "") {
          showError(securityErrorText(t, { code: "sk_required" }));
          return;
        }
        // Out of the inputs before the slow call: a failed attempt leaves nothing on the page.
        password.value = "";
        if (sk) sk.value = "";
        busy(true);
        try {
          await run(skCode === "" ? { password: typed } : { password: typed, skCode });
        } catch (error) {
          if (done) return;
          busy(false);
          if (codeOf(error) === "sk_required") showSecretKeyField();
          showError(securityErrorText(t, error));
          /** @type {any} */ (sk && skCode === "" ? sk : password).focus?.();
          return;
        }
        finish("ok");
      },
    },
    el("div", { class: "field" }, el("label", { for: passwordId }, t("security.reauth.password")), password),
    skSlot,
    status,
    errorBox,
    el("div", { class: "actions" }, cancel, confirm));

    const dialog = el("div", {
      class: "dialog reauth-dialog", role: "dialog", "aria-modal": "true", "aria-labelledby": titleId, "data-role": "reauth-dialog",
    }, el("h2", { id: titleId }, t("security.reauth.title")), el("p", null, t("security.reauth.body")), form);

    cancel.addEventListener("click", () => finish("cancelled"));
    dialog.addEventListener("keydown", (/** @type {any} */ event) => {
      if (event?.key === "Escape" && !confirm.disabled) finish("cancelled");
      if (event?.key === "Tab") trapTab(event);
    });
    // Tab goes round inside the dialog: from the last control to the first, and Shift+Tab the other way. A busy
    // dialog has no enabled control, so Tab is held still.
    /** @param {any} event */
    function trapTab(event) {
      const controls = /** @type {any[]} */ ([password, sk, cancel, confirm]).filter((c) => c && c.disabled !== true);
      if (controls.length === 0) {
        event.preventDefault();
        return;
      }
      const at = controls.indexOf(event.target);
      if (event.shiftKey === true && at <= 0) {
        event.preventDefault();
        controls[controls.length - 1].focus?.();
      } else if (event.shiftKey !== true && (at === controls.length - 1 || at === -1)) {
        event.preventDefault();
        controls[0].focus?.();
      }
    }
    // A lock of the vault removes the dialog with what is typed in it.
    if (scope) unscope = scope.add(() => finish("cancelled"));
    host.appendChild(dialog);
    /** @type {any} */ (sk ?? password).focus?.();
  });
}
