// The sign-in page, the unlock form and the panel of a signed-in vault. The
// same page serves `/vault/login` and `/vault/reauth` (the hand-over to the
// admin pages starts there, Spec: Fase 1 § 2.4):
//
//   * not signed in: e-mail, master password and the secret key questions;
//   * signed in but locked (a reload ends the worker): the master password;
//   * signed in and open: what the user can do next.
//
// A hand-over (`?handoff=1&challenge=...`) is only started by a click: the
// click on "Sign in" or "Confirm" that has just checked the password, or the
// click on "Continue to the admin pages" for a session that already exists.
// It is never started because the page was opened.
import { AccountError } from "../crypto/errors.mjs";
import { el, mount } from "../dom.mjs";
import { busyState, choice, describeError, field, setText, trustNotice } from "./form.mjs";

/**
 * @typedef {object} LoginDeps
 * @property {import("./form.mjs").Translate} t
 * @property {any} session the crypto session (`services.crypto`)
 * @property {import("../flows/entry.mjs").Entry} entry how the page was entered
 * @property {string | null} adminUrl the configured admin origin
 * @property {import("../api.mjs").Api} api
 * @property {(path: string) => void} go
 * @property {{ completeHandoff: (options: any) => Promise<void>, goToAdmin: (options: any) => Promise<void> }} handoff
 * @property {{ accountId: string, email: string } | null} info the vault session found when the page was opened
 * @property {boolean} [reauth] the page is `/vault/reauth`
 */

/** @param {LoginDeps} deps */
export function loginView(deps) {
  const { t, session, entry, adminUrl, api, go, handoff, info } = deps;
  const reauthPage = deps.reauth === true;
  const root = el("section", { class: "card account", "data-role": "account-page" });
  const status = el("p", { class: "status", role: "status", "data-role": "status" });
  const errorBox = el("p", { class: "error", role: "alert", "data-role": "error" });
  errorBox.hidden = true;
  const okBox = el("p", { class: "ok", role: "status", "data-role": "done" });
  okBox.hidden = true;
  const trust = trustNotice(t);

  /** @param {unknown} error */
  function showError(error) {
    setText(errorBox, describeError(t, error));
    errorBox.hidden = false;
  }
  function clearError() {
    errorBox.hidden = true;
    setText(errorBox, "");
    okBox.hidden = true;
  }
  /** @param {string} text */
  function showDone(text) {
    setText(okBox, text);
    okBox.hidden = false;
  }

  /**
   * Starts the hand-over for the purpose the page was opened with. Called only
   * from a click handler. A re-authentication hand-over is only started right
   * after a fresh re-authentication.
   */
  async function continueHandoff() {
    const request = entry.handoff;
    if (request === null) throw new AccountError("handoff_invalid");
    if (adminUrl === null) throw new AccountError("admin_unconfigured");
    if (request.purpose === "reauth" && !session.freshReauth()) throw new AccountError("reauth_not_fresh");
    await handoff.completeHandoff({ api, challenge: request.challenge, next: request.next, purpose: request.purpose, adminUrl });
  }

  /** @param {() => Promise<void>} work @param {any[]} controls @param {HTMLElement} form */
  function guarded(work, controls, form) {
    const busy = busyState({ root: form, status, controls, t });
    let running = false;
    return async () => {
      if (running) return;
      running = true;
      clearError();
      busy.set(true);
      try {
        await work();
      } catch (error) {
        showError(error);
      } finally {
        busy.set(false);
        running = false;
      }
    };
  }

  // ------------------------------------------------- the credentials form

  /**
   * @param {{ mode: "signin" | "unlock" }} spec
   */
  function credentialsForm({ mode }) {
    const form = el("form", { class: "stack", "data-role": "credentials" });
    const email = mode === "signin" ? field(t, { id: "email", role: "email", label: "account.login.email", type: "email", autocomplete: "username" }) : null;
    const password = field(t, { id: "password", role: "password", label: "account.login.password", type: "password", autocomplete: "current-password" });

    // The secret key questions: shown according to what this device knows.
    const yes = choice(t, { id: "sk-yes", role: "sk-yes", label: "account.sk.yes", type: "radio", name: "sk-answer", value: "yes" });
    const no = choice(t, { id: "sk-no", role: "sk-no", label: "account.sk.no", type: "radio", name: "sk-answer", value: "no" });
    const question = el("fieldset", { class: "sk-question", "data-role": "sk-question" }, el("legend", null, t("account.sk.question")), yes.row, no.row);
    const code = field(t, { id: "sk-code", role: "sk-code", label: "account.sk.code", autocomplete: "off", required: false, help: "account.sk.needed" });
    const hint = el("p", { class: "notice", role: "note", "data-role": "sk-hint" });
    hint.hidden = true;
    const remembered = el("p", { class: "help", "data-role": "sk-remembered" }, t("account.sk.remembered"));
    remembered.hidden = true;
    const remember = choice(t, { id: "remember", role: "remember", label: "account.remember.label", checked: true });
    const rememberNote = el("small", { class: "help" }, t("account.remember.note"));
    const rememberRow = el("div", { class: "remember", "data-role": "remember-row" }, remember.row, rememberNote);

    /** @type {{ pinned: boolean, skBit: boolean | null, skStored: boolean }} */
    let device = { pinned: false, skBit: null, skStored: false };
    function layout() {
      const unknown = !device.pinned;
      question.hidden = !unknown;
      const answeredYes = yes.input.checked === true;
      code.row.hidden = !(device.pinned ? device.skBit === true && !device.skStored : answeredYes);
      remembered.hidden = !(device.pinned && device.skBit === true && device.skStored);
      // The choice is offered at the first sign-in on a device that does not know the account.
      rememberRow.hidden = !(mode === "signin" && unknown && answeredYes);
    }
    async function refreshDevice() {
      const typed = email ? email.input.value.trim() : (info?.email ?? "");
      try {
        device = typed === "" ? { pinned: false, skBit: null, skStored: false } : await session.deviceStatus(typed);
      } catch {
        device = { pinned: false, skBit: null, skStored: false };
      }
      layout();
    }

    const submit = el("button", { type: "submit", class: "primary", "data-role": "submit" }, t(mode === "signin" ? "account.login.submit" : "account.unlock.submit"));
    yes.input.addEventListener("change", layout);
    no.input.addEventListener("change", layout);
    email?.input.addEventListener("change", () => void refreshDevice());

    const controls = [password.input, yes.input, no.input, code.input, remember.input, submit, ...(email ? [email.input] : [])];
    const run = guarded(async () => {
      // The fields are read and emptied before anything is awaited.
      const typedPassword = password.input.value;
      const typedCode = code.input.value;
      password.input.value = "";
      code.input.value = "";
      if (email) await refreshDevice();
      const answer = yes.input.checked ? true : no.input.checked ? false : undefined;
      const rememberVisible = !rememberRow.hidden;
      /** @type {Record<string, any>} */
      const args = { password: typedPassword, skCode: typedCode, skBit: device.pinned ? undefined : answer };
      if (rememberVisible) args.rememberSk = remember.input.checked;
      try {
        if (email) {
          args.email = email.input.value;
          await session.signIn(args);
        } else {
          await session.unlock(args);
        }
      } catch (error) {
        const skHint = /** @type {any} */ (error)?.skHint;
        if (typeof skHint === "boolean") {
          setText(hint, t(skHint ? "account.sk.hint_yes" : "account.sk.hint_no"));
          hint.hidden = false;
          // A hint only preselects: it never overrides an answer the user gave.
          if (answer === undefined && !device.pinned) (skHint ? yes : no).input.checked = true;
          layout();
        }
        throw error;
      }
      if (entry.handoff !== null) await continueHandoff();
      else go("/");
    }, controls, form);
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      void run();
    });

    mount(form, ...[email?.row, password.row, question, hint, code.row, remembered, rememberRow, submit].filter((n) => n !== undefined && n !== null));
    layout();
    void refreshDevice();
    return form;
  }

  // ---------------------------------------------------- the other panels

  function endedPanel() {
    return el("div", { class: "stack", "data-role": "ended" }, el("p", null, t("account.reauth.ended")), el("p", null, el("a", { href: "#/login" }, t("account.reauth.sign_in"))));
  }

  /** Signed in at the server, vault open or locked: the next steps. */
  function signedInPanel() {
    const open = session.current() !== null;
    const panel = el("div", { class: "stack", "data-role": "signed-in" }, el("p", null, t("account.signedin.as", { email: info?.email ?? "" })));
    /** @type {any[]} */
    const controls = [];
    /**
     * @param {string} label
     * @param {string} role
     * @param {() => Promise<void>} work
     */
    const action = (label, role, work) => {
      const button = el("button", { type: "button", "data-role": role }, t(label));
      controls.push(/** @type {any} */ (button));
      const run = guarded(work, controls, panel);
      button.addEventListener("click", () => void run());
      return button;
    };
    const buttons = [];
    if (open) buttons.push(action("account.signedin.open", "open-vault", async () => go("/")));
    if (entry.handoff !== null) buttons.push(action("account.signedin.continue_admin", "continue-admin", continueHandoff));
    else if (adminUrl !== null) {
      buttons.push(action("account.signedin.admin", "admin", () => handoff.goToAdmin({ adminUrl, next: "/", purpose: "login" })));
    }
    if (open) {
      buttons.push(action("account.signedin.lock", "lock", async () => {
        await session.lock();
        go("/login");
      }));
    }
    buttons.push(action("account.signedin.sign_out", "sign-out", async () => {
      try {
        await session.signOut();
      } finally {
        go("/login");
      }
    }));
    if (info) {
      const accountId = info.accountId;
      buttons.push(action("account.signedin.forget_sk", "forget-sk", async () => {
        await session.forgetSecretKey(accountId);
        showDone(t("account.signedin.forgotten"));
      }));
    }
    mount(panel, panel.firstChild ?? el("span"), el("div", { class: "actions" }, ...buttons));
    return panel;
  }

  // ------------------------------------------------------------ the page

  const reauthTitle = reauthPage ? "account.reauth.heading" : "account.login.heading";
  /** @type {HTMLElement} */
  let body;
  if (reauthPage) {
    body = info ? el("div", { class: "stack" }, el("p", null, t("account.reauth.body")), credentialsForm({ mode: "unlock" })) : endedPanel();
  } else if (info === null) {
    body = credentialsForm({ mode: "signin" });
  } else if (session.current() === null) {
    body = el("div", { class: "stack" }, el("p", null, t("account.unlock.body", { email: info.email })), credentialsForm({ mode: "unlock" }), signedInPanel());
  } else {
    body = signedInPanel();
  }

  const parts = [
    el("h1", null, t(info && !reauthPage ? "account.signedin.heading" : reauthTitle)),
    entry.brokenHandoff ? el("p", { class: "notice", role: "note", "data-role": "handoff-broken" }, t("account.handoff.link_broken")) : null,
    body,
    status,
    okBox,
    errorBox,
    !reauthPage && info === null ? el("p", null, el("a", { href: "#/setup" }, t("account.login.setup_link"))) : null,
    trust,
  ].filter((n) => n !== null);
  mount(root, ...parts);
  return root;
}
