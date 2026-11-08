// The unlock screen: the vault is closed (the page was reloaded, the idle time
// ran out, or the user locked it) but the vault session on the server is still
// valid. The master password opens it again. The secret key is asked for only
// when this device does not hold it (Spec: Fase 1 section 6.2); the screen never
// guesses the answer to "does the account have a secret key".
//
// The password leaves the input before the slow call starts, so a failed
// attempt does not leave it on the page. Argon2id runs in the worker for
// seconds, and the form says so.
import { el, mount } from "../dom.mjs";
import { codeOf } from "./common.mjs";
import { describeError as unlockErrorText, OLDER_METHOD_ERRORS, restoreTextApplies } from "./form.mjs";

/** @typedef {(who: { accountId?: string | null, email?: string | null }) => Promise<import("../store/restoreNote.mjs").RestoreNote | null>} FindRestoreNote */
/** @typedef {(who: { accountId?: string | null, email?: string | null }) => Promise<void>} ClearRestoreNote */

/**
 * What the unlock screen needs to know, found without asking the server for
 * anything but the session.
 * @param {{ info(): Promise<{ accountId: string, email: string } | null>, deviceStatus?(email: string): Promise<{ pinned: boolean, skBit: boolean | null, skStored: boolean }> }} session
 * @returns {Promise<{ signedIn: false } | { signedIn: true, email: string, accountId: string, skRequired: boolean }>}
 */
export async function prepareUnlock(session) {
  const info = await session.info();
  if (!info) return { signedIn: false };
  let skRequired = false;
  try {
    const status = await session.deviceStatus?.(info.email);
    // Only a device that knows the account has a secret key, and does not hold
    // it, has to ask. With no record at all the core says what it needs.
    skRequired = status?.skBit === true && status.skStored !== true;
  } catch {
    skRequired = false;
  }
  return { signedIn: true, email: info.email, accountId: info.accountId, skRequired };
}

/**
 * @param {{
 *   session: { unlock(args: { password: string, skCode?: string }): Promise<unknown> },
 *   t: import("./common.mjs").Translate,
 *   go: (path: string) => void,
 *   email: string,
 *   accountId?: string,
 *   skRequired: boolean,
 *   onUnlocked: () => void,
 *   restoreNote?: FindRestoreNote,
 *   clearRestoreNote?: ClearRestoreNote,
 *   locale?: string,
 * }} options `restoreNote` finds the local note about an accepted restore; it is asked only after the core has refused with
 * an older unlock method, and only picks the text (the refusal stands). `clearRestoreNote` removes the note after a successful unlock.
 */
export function unlockView({ session, t, go, email, accountId, skRequired, onUnlocked, restoreNote: findRestoreNote, clearRestoreNote, locale }) {
  const root = el("section", { class: "auth-card unlock vault-ui", "data-role": "unlock" });
  const password = /** @type {HTMLInputElement} */ (el("input", {
    id: "unlock-password", name: "password", type: "password", autocomplete: "current-password", required: true, "data-role": "password",
  }));
  password.value = "";
  const skSlot = el("div", { "data-role": "sk-slot" });
  /** @type {HTMLInputElement | null} */
  let sk = null;
  const status = el("p", { class: "status", role: "status", "data-role": "status" });
  const errorBox = el("p", { class: "error", role: "alert", "data-role": "error" });
  errorBox.hidden = true;
  const submit = /** @type {HTMLButtonElement} */ (el("button", { type: "submit", class: "btn btn-primary btn-block", "data-role": "submit" }, t("vault.unlock.submit")));

  function showSecretKeyField() {
    if (sk) return;
    sk = /** @type {HTMLInputElement} */ (el("input", {
      id: "unlock-sk", name: "secret-key", type: "text", autocomplete: "off", required: true, "data-role": "secret-key",
    }));
    sk.value = "";
    sk.spellcheck = false;
    mount(skSlot, el("div", { class: "field" },
      el("label", { for: "unlock-sk" }, t("vault.unlock.secret_key")),
      sk,
      el("small", { class: "help" }, t("vault.unlock.secret_key_help"))));
  }
  if (skRequired) showSecretKeyField();

  /** @param {boolean} on */
  function busy(on) {
    submit.disabled = on;
    password.disabled = on;
    if (sk) sk.disabled = on;
    root.setAttribute("aria-busy", on ? "true" : "false");
    mount(status, document.createTextNode(on ? t("vault.unlock.busy") : ""));
  }

  /** @param {string} text */
  function showError(text) {
    mount(errorBox, document.createTextNode(text));
    errorBox.hidden = false;
  }

  // After a restore the way out of the refusal is to forget the server; the link is shown only with the restore text.
  const forgetLink = el("a", { href: "#/forget", "data-role": "forget-link" }, t("syncwarnings.forget.link"));
  const forgetRow = el("p", { class: "aside", "data-role": "forget-row" }, forgetLink);
  forgetRow.hidden = true;

  const form = el("form", {
    class: "stack",
    "data-role": "unlock-form",
    onsubmit: async (/** @type {Event} */ event) => {
      event.preventDefault();
      errorBox.hidden = true;
      forgetRow.hidden = true;
      const typed = password.value;
      const skCode = sk ? sk.value.trim() : "";
      if (typed === "") {
        showError(unlockErrorText(t, { code: "password_required" }));
        return;
      }
      if (sk && skCode === "") {
        showError(unlockErrorText(t, { code: "sk_required" }));
        return;
      }
      // Out of the inputs before the call: a failed attempt leaves nothing on the page.
      password.value = "";
      if (sk) sk.value = "";
      busy(true);
      try {
        await session.unlock(skCode === "" ? { password: typed } : { password: typed, skCode });
      } catch (error) {
        busy(false);
        const code = codeOf(error);
        if (code === "session_ended" || code === "sk_answer_required") {
          go("/login");
          showError(unlockErrorText(t, { code: "session_ended" }));
          return;
        }
        if (code === "sk_required") showSecretKeyField();
        let restoreNote = null;
        if (findRestoreNote && OLDER_METHOD_ERRORS.includes(code)) {
          try {
            restoreNote = await findRestoreNote({ accountId, email });
          } catch {
            restoreNote = null;
          }
        }
        showError(unlockErrorText(t, error, { restoreNote, locale }));
        forgetRow.hidden = !restoreTextApplies(error, restoreNote);
        /** @type {any} */ (sk ?? password).focus?.();
        return;
      }
      busy(false);
      // The unlock worked, so the refusal that the note explains is over; the note goes with it.
      try {
        await clearRestoreNote?.({ accountId, email });
      } catch {
        // The note expires by itself.
      }
      onUnlocked();
    },
  },
  el("div", { class: "field" }, el("label", { for: "unlock-password" }, t("vault.unlock.password")), password),
  skSlot,
  status,
  errorBox,
  forgetRow,
  el("div", { class: "actions" }, submit));

  mount(root,
    el("h1", null, t("vault.unlock.heading")),
    el("p", null, t("vault.unlock.as", { email })),
    form,
    el("p", { class: "aside" }, el("a", { href: "#/login", "data-role": "other-account" }, t("vault.unlock.other"))));
  return root;
}

/**
 * The unlock screen as a place holder that fills itself in: it asks the
 * session who is signed in and whether this device holds the secret key. When
 * nobody is signed in, the page goes to the sign-in page.
 * @param {{
 *   session: Parameters<typeof prepareUnlock>[0] & Parameters<typeof unlockView>[0]["session"],
 *   t: import("./common.mjs").Translate,
 *   go: (path: string) => void,
 *   onUnlocked: () => void,
 *   restoreNote?: FindRestoreNote,
 *   clearRestoreNote?: ClearRestoreNote,
 *   locale?: string,
 * }} options
 */
export function unlockScreen({ session, t, go, onUnlocked, restoreNote, clearRestoreNote, locale }) {
  const box = el("div", { class: "unlock-host vault-ui", "data-role": "unlock-host" },
    el("section", { class: "auth-card", role: "status", "data-role": "unlock-loading" }, el("p", null, t("vault.loading"))));
  prepareUnlock(session).then(
    (found) => {
      if (!found.signedIn) {
        mount(box, el("section", { class: "auth-card unlock vault-ui", "data-role": "unlock" },
          el("h1", null, t("vault.unlock.heading")),
          el("p", { role: "alert" }, t("account.error.session_ended")),
          el("p", null, el("a", { href: "#/login" }, t("vault.unlock.sign_in")))));
        go("/login");
        return;
      }
      mount(box, unlockView({ session, t, go, email: found.email, accountId: found.accountId, skRequired: found.skRequired, onUnlocked, restoreNote, clearRestoreNote, locale }));
    },
    (error) => {
      mount(box, el("section", { class: "auth-card", role: "alert", "data-role": "unlock-error" },
        el("p", null, unlockErrorText(t, error))));
    },
  );
  return box;
}
