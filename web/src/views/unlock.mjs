// The unlock screen: the vault is closed (the page was reloaded, the idle time
// ran out, or the user locked it). The master password opens it again. Two cases
// (spec Fase 1 § 7.3):
//
//   - the vault session on the server is still valid: the password opens the
//     vault in that session. The secret key is asked for only when this device
//     does not hold it (Spec: Fase 1 section 6.2); the screen never guesses the
//     answer to "does the account have a secret key".
//   - the session has ended, and this browser remembers the account it signed in
//     to (`flows/rememberedAccount.mjs`): the remembered e-mail is shown, read
//     only, with "Not you? Sign out", and the password runs a full sign-in with
//     that e-mail and the secret key this device holds. A refusal of the pinned
//     checks, or a secret key that is not there, gives way to the full sign-in
//     page, which shows the refusal.
//
// With the session valid, a passkey that is one of the account's unlock methods opens the vault too (spec Fase 1 § 7.3):
// a second button, offered only when `session.preparePasskeyUnlock` found a passkey method (see `flows/prfUnlock.mjs`).
// A browser lets a page make one WebAuthn call for each click, so the click itself starts the call and nothing is awaited
// before it. A refusal that comes at once (another password manager's passkey provider has taken over, no provider is set
// up on a Mac, Windows Hello is not set up) says what to check. An ended session has no passkey button: the password is
// asked for, as before.
//
// Anything else goes to the sign-in page.
//
// The password leaves the input before the slow call starts, so a failed
// attempt does not leave it on the page. Argon2id runs in the worker for
// seconds, and the form says so.
import { el, mount } from "../dom.mjs";
import { entryPage, holdRefusal, leavesUnlock } from "../flows/rememberedAccount.mjs";
import { codeOf } from "./common.mjs";
import { describeError as unlockErrorText, OLDER_METHOD_ERRORS, restoreTextApplies } from "./form.mjs";

/** The codes of a passkey unlock that have a text of their own under `vault.unlock.passkey_error.`. */
export const PASSKEY_UNLOCK_ERRORS = Object.freeze([
  "method_changed", "method_removed", "passkey_bad_answer", "passkey_blocked", "passkey_cancelled", "passkey_failed",
  "passkey_not_verified", "passkey_other_credential", "passkey_security", "passkey_sequence", "passkey_unlock_failed",
  "passkey_unsupported",
]);

/** The codes after which the passkey is no longer on offer: the list it was read from is out of date. */
const PASSKEY_GONE = Object.freeze(["method_changed", "method_removed"]);

/**
 * The text of a failed passkey unlock: the passkey's own codes have their texts, every other code is the unlock page's.
 * Only the code is used; the message of an error is never shown.
 * @param {import("./common.mjs").Translate} t
 * @param {unknown} error
 * @param {Parameters<typeof unlockErrorText>[2]} [options]
 */
export function passkeyUnlockErrorText(t, error, options) {
  const code = codeOf(error);
  return PASSKEY_UNLOCK_ERRORS.includes(code) ? t(`vault.unlock.passkey_error.${code}`) : unlockErrorText(t, error, options);
}
/** @typedef {(who: { accountId?: string | null, email?: string | null }) => Promise<import("../store/restoreNote.mjs").RestoreNote | null>} FindRestoreNote */
/** @typedef {(who: { accountId?: string | null, email?: string | null }) => Promise<void>} ClearRestoreNote */

/**
 * @typedef {{ signedIn: false, remembered?: false }
 *   | { signedIn: true, email: string, accountId: string, skRequired: boolean, passkey: import("../flows/prfUnlock.mjs").PasskeyOffer | null }
 *   | { signedIn: false, remembered: true, email: string, accountId: string, skRequired: false }} UnlockFacts
 */

/**
 * What the unlock screen needs to know, found without asking the server for
 * anything but the session: the live session and the secret key question, or,
 * when the session has ended, the account this browser remembers.
 * @param {{
 *   info(): Promise<{ accountId: string, email: string } | null>,
 *   deviceStatus?(email: string): Promise<{ pinned: boolean, skBit: boolean | null, skStored: boolean }>,
 *   remembered?(): Promise<import("../flows/rememberedAccount.mjs").Remembered | null>,
 *   preparePasskeyUnlock?(): Promise<import("../flows/prfUnlock.mjs").PasskeyOffer | null>,
 * }} session
 * @param {{ passkey?: boolean }} [options] `passkey: false` leaves the passkey offer out (the screen asks for it itself, after it
 *   has been drawn, so the three reads do not hold the page back)
 * @returns {Promise<UnlockFacts>}
 */
export async function prepareUnlock(session, { passkey: withPasskey = true } = {}) {
  const info = await session.info();
  if (!info) {
    /** @type {import("../flows/rememberedAccount.mjs").Remembered | null} */
    let remembered = null;
    try {
      remembered = (await session.remembered?.()) ?? null;
    } catch {
      remembered = null;
    }
    if (remembered !== null && entryPage({ info: null, remembered }) === "unlock_remembered") {
      return { signedIn: false, remembered: true, email: remembered.email, accountId: remembered.accountId, skRequired: false };
    }
    return { signedIn: false };
  }
  let skRequired = false;
  try {
    const status = await session.deviceStatus?.(info.email);
    // Only a device that knows the account has a secret key, and does not hold
    // it, has to ask. With no record at all the core says what it needs.
    skRequired = status?.skBit === true && status.skStored !== true;
  } catch {
    skRequired = false;
  }
  // A passkey is offered only while the session is valid and the account has a passkey method; nothing is asked of the
  // passkey now. A failure of the check is "not offered".
  /** @type {import("../flows/prfUnlock.mjs").PasskeyOffer | null} */
  let passkey = null;
  if (withPasskey && typeof session.preparePasskeyUnlock === "function") {
    try {
      passkey = (await session.preparePasskeyUnlock()) ?? null;
    } catch {
      passkey = null;
    }
  }
  return { signedIn: true, email: info.email, accountId: info.accountId, skRequired, passkey };
}

/**
 * @param {{
 *   session: {
 *     unlock(args: { password: string, skCode?: string }): Promise<unknown>,
 *     unlockWithPasskey?(offer: import("../flows/prfUnlock.mjs").PasskeyOffer): Promise<unknown>,
 *     signIn?(args: { email: string, password: string }): Promise<unknown>,
 *     signOut?(): Promise<unknown>,
 *     forgetRemembered?(accountId?: string): Promise<unknown>,
 *   },
 *   t: import("./common.mjs").Translate,
 *   go: (path: string) => void,
 *   email: string,
 *   accountId?: string,
 *   skRequired: boolean,
 *   passkey?: import("../flows/prfUnlock.mjs").PasskeyOffer | null,
 *   remembered?: boolean,
 *   onUnlocked: () => unknown,
 *   onLeave?: (error: unknown) => void,
 *   restoreNote?: FindRestoreNote,
 *   clearRestoreNote?: ClearRestoreNote,
 *   locale?: string,
 * }} options `restoreNote` finds the local note about an accepted restore; it is asked only after the core has refused with
 * an older unlock method, and only picks the text (the refusal stands). `clearRestoreNote` removes the note after a successful unlock.
 * `passkey`: what `preparePasskeyUnlock` found (null: no passkey is offered). `remembered`: the server session has ended and `email` is the one this browser remembers; the password runs a full
 * sign-in. `onLeave` takes such a page to the full sign-in page with a refusal to show (by default it hands the refusal
 * to the sign-in page and goes there). `onUnlocked` may return a promise; a failure of it is shown.
 */
export function unlockView({ session, t, go, email, accountId, skRequired, passkey = null, remembered = false, onUnlocked, onLeave, restoreNote: findRestoreNote, clearRestoreNote, locale }) {
  const root = el("section", { class: "auth-card unlock vault-ui", "data-role": "unlock", "data-mode": remembered ? "remembered" : "session" });
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

  // The remembered e-mail, read only: it is what the sign-in sends, and a browser's password manager finds the account by it.
  /** @type {HTMLInputElement | null} */
  let emailInput = null;
  /** @type {HTMLButtonElement | null} */
  let notYou = null;
  if (remembered) {
    emailInput = /** @type {HTMLInputElement} */ (el("input", {
      id: "unlock-email", name: "email", type: "email", autocomplete: "username", readonly: true, "data-role": "remembered-email",
    }));
    emailInput.value = email;
    notYou = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-plain btn-sm", "data-role": "not-you" }, t("vault.unlock.not_you")));
  }

  function showSecretKeyField() {
    if (sk || remembered) return;
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

  // The passkey button: only with a passkey method and a live session (never on the page of an ended session).
  const passkeyButton = /** @type {HTMLButtonElement} */ (el("button", {
    type: "button", class: "btn btn-secondary btn-block", "data-role": "passkey-unlock",
  }, t("vault.unlock.passkey.button")));
  /** @type {HTMLElement | null} */
  let passkeyBox = null;
  // What to check when the browser refuses the passkey at once, before it has asked the user anything.
  const blockedHelp = el("ul", { class: "help", "data-role": "passkey-blocked-help" },
    el("li", null, t("methods.blocked.other_manager")),
    el("li", null, t("methods.blocked.mac")),
    el("li", null, t("methods.blocked.windows")));
  blockedHelp.hidden = true;

  /**
   * @param {boolean} on
   * @param {string} [text] the key of the text of the status line
   */
  function busy(on, text = "vault.unlock.busy") {
    submit.disabled = on;
    password.disabled = on;
    passkeyButton.disabled = on;
    if (sk) sk.disabled = on;
    if (notYou) notYou.disabled = on;
    root.setAttribute("aria-busy", on ? "true" : "false");
    mount(status, document.createTextNode(on ? t(text) : ""));
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

  // After a refusal of an older password on a server that was restored from a backup: the recovery key (this session stays
  // open for it), or the way out. The same offer as on the sign-in page.
  const offerBox = el("div", { class: "actions", "data-role": "recovery-offer" });
  offerBox.hidden = true;
  /** @param {"recover" | "old_sheet"} offer */
  function showOffer(offer) {
    const action = offer === "recover"
      ? el("button", { type: "button", class: "btn btn-primary", "data-role": "use-recovery-key" }, t("recover.offer.use_key"))
      : el("a", { href: "#/forget", class: "btn btn-secondary", "data-role": "offer-forget" }, t("syncwarnings.forget.link"));
    if (offer === "recover") action.addEventListener("click", () => go("/recover"));
    mount(offerBox, action);
    offerBox.hidden = false;
    showError(t(`recover.offer.${offer}`));
  }

  /**
   * The Unlock page of an ended session gives way to the full sign-in page: this browser forgets the account, and the
   * sign-in page shows the refusal.
   * @param {unknown} error
   */
  async function leave(error) {
    try {
      await session.forgetRemembered?.(accountId);
    } catch {
      // The sign-in page is shown all the same; the marker is checked again there.
    }
    if (onLeave) onLeave(error);
    else {
      holdRefusal(error, { accountId: accountId ?? null, email });
      go("/login");
    }
  }

  // "Not you? Sign out": this browser forgets the account (and its cached rows), and the full sign-in page follows.
  let leaving = false;
  notYou?.addEventListener("click", async () => {
    if (leaving) return;
    leaving = true;
    busy(true);
    try {
      await session.signOut?.();
    } catch {
      // There was no session to end; the device has forgotten the account all the same.
    }
    busy(false);
    go("/login");
  });

  /**
   * The page after a failed unlock: the session has ended (the sign-in page), a field is missing, the way out after a
   * restore of the server, or the text of the refusal (the warning that it can be an attack included).
   * @param {unknown} error
   * @param {string} code
   * @param {{ passkey?: boolean }} [how] `passkey`: the unlock was a passkey's
   */
  async function showFailure(error, code, { passkey: byPasskey = false } = {}) {
    if (code === "session_ended" || code === "sk_answer_required") {
      go("/login");
      showError(unlockErrorText(t, { code: "session_ended" }));
      return;
    }
    if (code === "sk_required") showSecretKeyField();
    const offer = /** @type {any} */ (error)?.recoveryOffer;
    if (code === "pinned_kek_generation" && (offer === "recover" || offer === "old_sheet")) {
      showOffer(offer);
      return;
    }
    let restoreNote = null;
    if (findRestoreNote && OLDER_METHOD_ERRORS.includes(code)) {
      try {
        restoreNote = await findRestoreNote({ accountId, email });
      } catch {
        restoreNote = null;
      }
    }
    showError(byPasskey ? passkeyUnlockErrorText(t, error, { restoreNote, locale }) : unlockErrorText(t, error, { restoreNote, locale }));
    forgetRow.hidden = !restoreTextApplies(error, restoreNote);
    if (byPasskey) {
      // A refusal at once says what to check; a method that is gone is no longer offered.
      blockedHelp.hidden = code !== "passkey_blocked";
      if (PASSKEY_GONE.includes(code) && passkeyBox) passkeyBox.hidden = true;
      /** @type {any} */ (PASSKEY_GONE.includes(code) ? password : passkeyButton).focus?.();
      return;
    }
    /** @type {any} */ (sk ?? password).focus?.();
  }

  // The click on the passkey button. The call of the session is the first thing the handler does: a browser lets a
  // page make one WebAuthn call for each click, and it has to come from the click.
  passkeyButton.addEventListener("click", () => {
    if (leaving || passkeyBox === null || passkey === null || typeof session.unlockWithPasskey !== "function") return;
    const attempt = session.unlockWithPasskey(passkey);
    errorBox.hidden = true;
    blockedHelp.hidden = true;
    forgetRow.hidden = true;
    offerBox.hidden = true;
    busy(true, "vault.unlock.passkey.busy");
    void attempt.then(
      async () => {
        busy(false);
        try {
          await clearRestoreNote?.({ accountId, email });
        } catch {
          // The note expires by itself.
        }
        try {
          await onUnlocked();
        } catch (error) {
          showError(unlockErrorText(t, error, { locale }));
        }
      },
      async (/** @type {unknown} */ error) => {
        busy(false);
        await showFailure(error, codeOf(error), { passkey: true });
      },
    );
  });

  const form = el("form", {
    class: "stack",
    "data-role": "unlock-form",
    onsubmit: async (/** @type {Event} */ event) => {
      event.preventDefault();
      if (leaving) return;
      errorBox.hidden = true;
      forgetRow.hidden = true;
      offerBox.hidden = true;
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
        // An ended session: a full sign-in with the remembered e-mail (the secret key comes from this device). It is a
        // sign-in, never a re-authentication: a session another tab opened meanwhile is not taken over for another account.
        if (remembered) {
          if (typeof session.signIn !== "function") throw new TypeError("the session cannot sign in");
          await session.signIn({ email, password: typed });
        } else {
          await session.unlock(skCode === "" ? { password: typed } : { password: typed, skCode });
        }
      } catch (error) {
        busy(false);
        const code = codeOf(error);
        if (remembered && leavesUnlock(code)) {
          await leave(error);
          return;
        }
        await showFailure(error, code);
        return;
      }
      busy(false);
      // The unlock worked, so the refusal that the note explains is over; the note goes with it.
      try {
        await clearRestoreNote?.({ accountId, email });
      } catch {
        // The note expires by itself.
      }
      try {
        await onUnlocked();
      } catch (error) {
        showError(unlockErrorText(t, error, { locale }));
      }
    },
  },
  emailInput ? el("div", { class: "field" }, el("label", { for: "unlock-email" }, t("account.login.email")), emailInput, el("p", { class: "aside" }, notYou)) : null,
  el("div", { class: "field" }, el("label", { for: "unlock-password" }, t("vault.unlock.password")), password),
  skSlot,
  status,
  errorBox,
  blockedHelp,
  forgetRow,
  offerBox,
  el("div", { class: "actions" }, submit));

  const recoverRow = el("p", { class: "recover-link" }, el("a", { href: "#/recover", "data-role": "recover-link" }, t("recover.link")));

  mount(root,
    el("h1", null, t("vault.unlock.heading")),
    el("p", null, remembered ? t("vault.unlock.ended") : t("vault.unlock.as", { email })),
    form,
    // The way to account recovery from the lock screen: a forgotten master password, or a restore of the server (see above).
    recoverRow,
    // A live session of another account: the sign-in page (with "Sign out"). An ended one has "Not you? Sign out" above.
    ...(remembered ? [] : [el("p", { class: "aside" }, el("a", { href: "#/login", "data-role": "other-account" }, t("vault.unlock.other")))]));
  /**
   * Shows the passkey button for an offer (what `preparePasskeyUnlock` found), below the form. Nothing happens on the page of an
   * ended session, for a second offer or for no offer.
   * @param {import("../flows/prfUnlock.mjs").PasskeyOffer | null} offer
   */
  function offerPasskey(offer) {
    if (offer === null || remembered || passkeyBox !== null) return;
    passkey = offer;
    passkeyBox = el("div", { class: "stack passkey-unlock", "data-role": "passkey-section" },
      el("p", { class: "aside" }, t("vault.unlock.passkey.or")),
      passkeyButton,
      el("small", { class: "help", "data-role": "passkey-help" }, t("vault.unlock.passkey.help")));
    root.insertBefore(passkeyBox, recoverRow);
  }
  offerPasskey(passkey);
  // A screen that learns of the offer after it was drawn (see `unlockScreen`).
  /** @type {any} */ (root).offerPasskey = offerPasskey;
  return root;
}

/**
 * The unlock screen as a place holder that fills itself in: it asks the
 * session who is signed in and whether this device holds the secret key, or,
 * with no session, which account this browser remembers. With neither, the
 * page goes to the sign-in page.
 * @param {{
 *   session: Parameters<typeof prepareUnlock>[0] & Parameters<typeof unlockView>[0]["session"],
 *   t: import("./common.mjs").Translate,
 *   go: (path: string) => void,
 *   onUnlocked: () => unknown,
 *   restoreNote?: FindRestoreNote,
 *   clearRestoreNote?: ClearRestoreNote,
 *   locale?: string,
 * }} options
 */
export function unlockScreen({ session, t, go, onUnlocked, restoreNote, clearRestoreNote, locale }) {
  const box = el("div", { class: "unlock-host vault-ui", "data-role": "unlock-host" },
    el("section", { class: "auth-card", role: "status", "data-role": "unlock-loading" }, el("p", null, t("vault.loading"))));
  prepareUnlock(session, { passkey: false }).then(
    (found) => {
      if (found.signedIn === false && found.remembered !== true) {
        mount(box, el("section", { class: "auth-card unlock vault-ui", "data-role": "unlock" },
          el("h1", null, t("vault.unlock.heading")),
          el("p", { role: "alert" }, t("account.error.session_ended")),
          el("p", null, el("a", { href: "#/login" }, t("vault.unlock.sign_in")))));
        go("/login");
        return;
      }
      const view = unlockView({
        session, t, go, email: found.email, accountId: found.accountId, skRequired: found.skRequired,
        remembered: found.signedIn === false,
        onUnlocked, restoreNote, clearRestoreNote, locale,
      });
      mount(box, view);
      // The page is drawn first; the button comes when the three reads of the offer are done (a failed read is no offer).
      if (found.signedIn === true && typeof session.preparePasskeyUnlock === "function") {
        Promise.resolve().then(() => session.preparePasskeyUnlock?.()).then(
          (offer) => /** @type {any} */ (view).offerPasskey(offer ?? null),
          () => undefined,
        );
      }
    },
    (error) => {
      mount(box, el("section", { class: "auth-card", role: "alert", "data-role": "unlock-error" },
        el("p", null, unlockErrorText(t, error))));
    },
  );
  return box;
}
