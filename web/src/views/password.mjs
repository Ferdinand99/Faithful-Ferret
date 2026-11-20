// `#/password`: change the master password (spec Fase 1 § 4.6, § 6.3). The
// page is inside the vault frame: the vault is open, and the server session is
// the one the change is made from. The admin pages send people here
// (`/vault/password`).
//
// Three fields: the current password, the new one and the new one again. The
// secret key is asked for only when the account has one and this device does not
// hold it. All typed values leave the fields before the slow call starts (the
// registration runs Argon2id, which takes seconds), so a failed attempt leaves
// nothing on the page, and a lock of the vault empties them too. The page says what
// the change does not do: exports and server backups made before it still open with
// the old password. After it, the page says what it did: every other device is signed
// out and a new backup was asked for.
//
// Nothing typed is kept, logged, stored or put in an address. An error is shown by
// its code, from a fixed list; its message is never shown.
import { el, mount } from "../dom.mjs";
import { busyState, field } from "./form.mjs";
import { securityErrorText } from "./securityError.mjs";

/** @typedef {import("./form.mjs").Translate} Translate */

/**
 * @param {{
 *   t: Translate,
 *   change: (args: { current: string, next: string, nextAgain: string, skCode?: string }) => Promise<{ kekGeneration: number, until?: number }>,
 *   skRequired?: boolean,
 *   skBit?: boolean | null,
 *   scope?: { add(fn: () => void): () => void },
 * }} options `change` is `session.changePassword`. `skRequired`: the account has a secret key that this device does not
 * hold, so the page asks for it. `skBit` (when known) picks the help text for the length of the new password.
 * @returns {HTMLElement}
 */
export function passwordView({ t, change, skRequired = false, skBit = null, scope }) {
  const root = el("section", { class: "card account password-page", "data-role": "password-page" });
  const current = field(t, { id: "password-current", role: "current-password", label: "security.password.current", type: "password", autocomplete: "current-password" });
  const next = field(t, {
    id: "password-new", role: "new-password", label: "security.password.new", type: "password", autocomplete: "new-password",
    help: skBit === true ? "security.password.new_help_sk" : skBit === false ? "security.password.new_help_no_sk" : "security.password.new_help",
  });
  const again = field(t, { id: "password-again", role: "new-password-again", label: "security.password.again", type: "password", autocomplete: "new-password" });
  const sk = field(t, {
    id: "password-sk", role: "secret-key", label: "security.password.secret_key", autocomplete: "off", secret: true, help: "security.password.secret_key_help",
  });
  const skRow = el("div", { "data-role": "sk-slot" });
  if (skRequired) mount(skRow, sk.row);
  const inputs = [current.input, next.input, again.input, sk.input];
  const status = el("p", { class: "status", role: "status", "data-role": "status" });
  const errorBox = el("p", { class: "error", role: "alert", "data-role": "error" });
  errorBox.hidden = true;
  const submit = /** @type {HTMLButtonElement} */ (el("button", { type: "submit", class: "btn btn-primary", "data-role": "submit" }, t("security.password.submit")));
  const busy = busyState({ root, status, controls: [...inputs, submit], t, key: "security.password.busy" });

  /** @param {string} text */
  function showError(text) {
    mount(errorBox, document.createTextNode(text));
    errorBox.hidden = false;
  }
  function wipeFields() {
    for (const input of inputs) input.value = "";
  }
  if (scope) scope.add(wipeFields);

  const notice = el("p", { class: "notice notice-warning", role: "note", "data-role": "old-files-notice" }, t("security.password.old_files"));
  const done = el("div", { class: "stack", "data-role": "password-done" },
    el("h2", null, t("security.password.done_heading")),
    el("p", { "data-role": "done-devices" }, t("security.password.done_devices")),
    el("p", { "data-role": "done-backup" }, t("security.password.done_backup")),
    el("p", { "data-role": "done-old-files" }, t("security.password.done_old_files")),
    el("p", { "data-role": "done-sheet" }, t("security.password.done_sheet")));
  done.hidden = true;

  const form = el("form", {
    class: "stack",
    "data-role": "password-form",
    onsubmit: async (/** @type {Event} */ event) => {
      event.preventDefault();
      errorBox.hidden = true;
      const skTyped = sk.input.value.trim();
      const args = {
        current: current.input.value,
        next: next.input.value,
        nextAgain: again.input.value,
        ...(skTyped === "" ? {} : { skCode: skTyped }),
      };
      // Nothing is sent for what the page can see is wrong, and what was typed stays for another look.
      if (args.current === "" || args.next === "") {
        showError(securityErrorText(t, { code: "password_required" }));
        return;
      }
      if (args.next !== args.nextAgain) {
        showError(securityErrorText(t, { code: "password_mismatch" }));
        return;
      }
      if (args.next === args.current) {
        showError(securityErrorText(t, { code: "password_unchanged" }));
        return;
      }
      if (skRequired && skTyped === "") {
        showError(securityErrorText(t, { code: "sk_required" }));
        return;
      }
      // Out of the fields before the slow call: a failed attempt leaves nothing on the page.
      wipeFields();
      busy.set(true);
      try {
        await change(args);
      } catch (error) {
        busy.set(false);
        const code = /** @type {any} */ (error)?.code;
        if (code === "sk_required" && !skRequired) mount(skRow, sk.row);
        showError(securityErrorText(t, error));
        // The server accepted the change but this device could not save its record: the password is changed.
        if (code === "pin_save_failed") form.hidden = true;
        return;
      }
      busy.set(false);
      form.hidden = true;
      notice.hidden = true;
      done.hidden = false;
    },
  },
  current.row, next.row, again.row, skRow, status, errorBox,
  el("div", { class: "actions" }, submit));

  mount(root,
    el("h1", null, t("security.password.heading")),
    el("p", null, t("security.password.intro")),
    notice,
    form,
    done,
    el("p", { class: "aside" }, el("a", { href: "#/account", "data-role": "back" }, t("security.password.done_back"))));
  return root;
}
