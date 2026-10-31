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
import { codeOf, describeError } from "./common.mjs";

/**
 * What the unlock screen needs to know, found without asking the server for
 * anything but the session.
 * @param {{ info(): Promise<{ accountId: string, email: string } | null>, deviceStatus?(email: string): Promise<{ pinned: boolean, skBit: boolean | null, skStored: boolean }> }} session
 * @returns {Promise<{ signedIn: false } | { signedIn: true, email: string, skRequired: boolean }>}
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
  return { signedIn: true, email: info.email, skRequired };
}

/**
 * @param {{
 *   session: { unlock(args: { password: string, skCode?: string }): Promise<unknown> },
 *   t: import("./common.mjs").Translate,
 *   go: (path: string) => void,
 *   email: string,
 *   skRequired: boolean,
 *   onUnlocked: () => void,
 * }} options
 */
export function unlockView({ session, t, go, email, skRequired, onUnlocked }) {
  const root = el("section", { class: "card unlock vault-ui", "data-role": "unlock" });
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
  const submit = /** @type {HTMLButtonElement} */ (el("button", { type: "submit", "data-role": "submit" }, t("vault.unlock.submit")));

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

  const form = el("form", {
    "data-role": "unlock-form",
    onsubmit: async (/** @type {Event} */ event) => {
      event.preventDefault();
      errorBox.hidden = true;
      const typed = password.value;
      const skCode = sk ? sk.value.trim() : "";
      if (typed === "") {
        showError(describeError(t, { code: "password_required" }));
        return;
      }
      if (sk && skCode === "") {
        showError(describeError(t, { code: "sk_required" }));
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
          showError(describeError(t, { code: "session_ended" }));
          return;
        }
        if (code === "sk_required") showSecretKeyField();
        showError(describeError(t, error));
        /** @type {any} */ (sk ?? password).focus?.();
        return;
      }
      busy(false);
      onUnlocked();
    },
  },
  el("div", { class: "field" }, el("label", { for: "unlock-password" }, t("vault.unlock.password")), password),
  skSlot,
  status,
  errorBox,
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
 * }} options
 */
export function unlockScreen({ session, t, go, onUnlocked }) {
  const box = el("div", { class: "unlock-host vault-ui", "data-role": "unlock-host" },
    el("section", { class: "card", role: "status", "data-role": "unlock-loading" }, el("p", null, t("vault.loading"))));
  prepareUnlock(session).then(
    (found) => {
      if (!found.signedIn) {
        mount(box, el("section", { class: "card unlock vault-ui", "data-role": "unlock" },
          el("h1", null, t("vault.unlock.heading")),
          el("p", { role: "alert" }, t("vault.error.session_ended")),
          el("p", null, el("a", { href: "#/login" }, t("vault.unlock.sign_in")))));
        go("/login");
        return;
      }
      mount(box, unlockView({ session, t, go, email: found.email, skRequired: found.skRequired, onUnlocked }));
    },
    (error) => {
      mount(box, el("section", { class: "card", role: "alert", "data-role": "unlock-error" },
        el("p", null, describeError(t, error))));
    },
  );
  return box;
}
