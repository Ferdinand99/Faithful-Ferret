// The sign-in page, the unlock form and the panel of a signed-in vault. The
// same page serves `/vault/login` and `/vault/reauth` (the hand-over to the
// admin pages starts there, Spec: Fase 1 § 2.4):
//
//   * not signed in: e-mail, the text of the sheet's QR code (optional), master password and
//     the secret key questions;
//   * signed in but locked (a reload ends the worker): the master password;
//   * signed in and open: what the user can do next.
//
// A hand-over (`?handoff=1&challenge=...`) is only started by a click: the
// click on "Sign in" or "Confirm" that has just checked the password, or the
// click on "Continue to the admin pages" for a session that already exists.
// It is never started because the page was opened.
//
// The sheet's QR text (spec Fase 1 § 4.2, F-01 point 6): the user pastes it and the page
// reads it, with no request, and shows the host and the port the sheet is for. The sign-in
// does not start before the user has confirmed that address for the text that is in the
// field. The sheet's secret key bit answers the question about the secret key. Without a
// sheet the page says that the first sign-in trusts the server the first time.
import { AccountError, codeOf } from "../crypto/errors.mjs";
import { ADMIN_LANDING } from "../flows/adminUrl.mjs";
import { forgetServer } from "../flows/forgetServer.mjs";
import { checkQrBeforeKe3 } from "../flows/setupQr.mjs";
import { el, mount } from "../dom.mjs";
import { askConfirm } from "./common.mjs";
import { busyState, choice, describeError, field, OLDER_METHOD_ERRORS, setText, trustNotice } from "./form.mjs";

/**
 * @typedef {object} LoginDeps
 * @property {import("./form.mjs").Translate} t
 * @property {any} session the crypto session (`services.crypto`)
 * @property {import("../flows/entry.mjs").Entry} entry how the page was entered
 * @property {string | null} adminUrl the configured admin origin
 * @property {import("../api.mjs").Api} api
 * @property {any} [store] the store service; with it the page offers "Forget the other server" after `pinned_elsewhere`
 * @property {typeof forgetServer} [forget] the flow behind that button (the real one by default)
 * @property {(path: string) => void} go
 * @property {{ completeHandoff: (options: any) => Promise<void>, goToAdmin: (options: any) => Promise<void> }} handoff
 * @property {{ accountId: string, email: string } | null} info the vault session found when the page was opened
 * @property {boolean} [reauth] the page is `/vault/reauth`
 * @property {import("./unlock.mjs").FindRestoreNote} [restoreNote] finds the local note about an accepted restore; asked only after a refusal about an older unlock method, and it only picks the text
 * @property {import("./unlock.mjs").ClearRestoreNote} [clearRestoreNote] removes that note after a successful sign-in or unlock
 * @property {string} [locale] the language, for the date in the restore text
 */

/** @param {LoginDeps} deps */
export function loginView(deps) {
  const { t, session, entry, adminUrl, api, go, handoff, info } = deps;
  const reauthPage = deps.reauth === true;
  const root = el("section", { class: "auth-card account", "data-role": "account-page" });
  const status = el("p", { class: "status", role: "status", "data-role": "status" });
  const errorBox = el("p", { class: "error", role: "alert", "data-role": "error" });
  errorBox.hidden = true;
  const okBox = el("p", { class: "ok", role: "status", "data-role": "done" });
  okBox.hidden = true;
  const trust = trustNotice(t);
  // After `pinned_elsewhere`: the way out is to forget the other server first.
  const otherBox = el("div", { class: "stack", "data-role": "pinned-elsewhere" });
  otherBox.hidden = true;

  /** The e-mail the last sign-in was tried with: after a refusal it names the account whose restore note to look for. @type {string | null} */
  let triedEmail = null;

  /**
   * Offers "Forget the other server" for an account that is pinned under another address. The button asks
   * once more in a dialog; the flow is the one of the forget page, for that address.
   * @param {{ server: string, accountId: string }} other
   */
  function offerForgetOther(other) {
    const button = el("button", { type: "button", class: "btn btn-secondary", "data-role": "forget-other" }, t("account.other.forget"));
    mount(otherBox, button);
    otherBox.hidden = false;
    let running = false;
    button.addEventListener("click", async () => {
      if (running) return;
      running = true;
      errorBox.hidden = true;
      okBox.hidden = true;
      /** @type {any} */ (button).disabled = true;
      try {
        const outcome = await (deps.forget ?? forgetServer)({
          api, session, store: deps.store, serverUrl: other.server, accountId: other.accountId,
          confirm: ({ pending }) => askConfirm({
            t, host: root, title: "account.other.dialog_title",
            body: pending > 0 ? "account.other.dialog_body_pending" : "account.other.dialog_body",
            confirm: "account.other.dialog_confirm", cancel: "account.other.dialog_cancel",
            vars: { server: other.server, count: pending },
          }),
          navigate: () => undefined,
        });
        if (outcome === "forgotten") {
          otherBox.hidden = true;
          showDone(t("account.other.done", { server: other.server }));
        }
      } catch (error) {
        await showError(error);
      } finally {
        /** @type {any} */ (button).disabled = false;
        running = false;
      }
    });
  }

  /** @param {unknown} error */
  async function showError(error) {
    const elsewhere = /** @type {any} */ (error)?.details;
    if (codeOf(error) === "pinned_elsewhere" && deps.store && typeof elsewhere?.server === "string" && typeof elsewhere?.accountId === "string") {
      offerForgetOther({ server: elsewhere.server, accountId: elsewhere.accountId });
    }
    // The core has refused an older unlock method: say so differently when this device accepted a restore lately.
    let restoreNote = null;
    if (deps.restoreNote && OLDER_METHOD_ERRORS.includes(codeOf(error))) {
      try {
        restoreNote = await deps.restoreNote({ accountId: info?.accountId ?? null, email: triedEmail });
      } catch {
        restoreNote = null;
      }
    }
    setText(errorBox, describeError(t, error, { restoreNote, locale: deps.locale }));
    errorBox.hidden = false;
  }
  function clearError() {
    otherBox.hidden = true;
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
        await showError(error);
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

    // The sheet's QR text (a new sign-in only): read with no request, confirmed by the user, then sent along.
    const qrText = mode === "signin" ? field(t, { id: "qr-text", role: "qr-text", label: "account.qr.label", autocomplete: "off", required: false, help: "account.qr.help", secret: true }) : null;
    const qrRead = el("button", { type: "button", class: "btn btn-secondary", "data-role": "qr-read" }, t("account.qr.read"));
    const qrSummary = el("p", { "data-role": "qr-summary" });
    const qrConfirm = choice(t, { id: "qr-confirm", role: "qr-confirm", label: "account.qr.confirm" });
    const qrBox = el("div", { class: "notice", role: "status", "data-role": "qr-shown" }, qrSummary, qrConfirm.row);
    qrBox.hidden = true;
    const tofu = el("p", { class: "notice", role: "note", "data-role": "tofu-notice" }, t("account.qr.tofu"));
    /**
     * The sheet that was read and shown: the text it was read from and what it states. The sign-in is sent only with
     * this very text in the field and the address confirmed.
     * @type {{ text: string, qr: import("../flows/setupQr.mjs").SetupQr } | null}
     */
    let sheet = null;
    /** @param {import("../flows/setupQr.mjs").SetupQr} qr */
    const hostOf = (qr) => (qr.port === null ? qr.host : `${qr.host}:${qr.port}`);
    function forgetSheet() {
      sheet = null;
      qrBox.hidden = true;
      qrConfirm.input.checked = false;
      setText(qrSummary, "");
    }

    // The secret key questions: shown according to what this device knows.
    const yes = choice(t, { id: "sk-yes", role: "sk-yes", label: "account.sk.yes", type: "radio", name: "sk-answer", value: "yes" });
    const no = choice(t, { id: "sk-no", role: "sk-no", label: "account.sk.no", type: "radio", name: "sk-answer", value: "no" });
    const question = el("fieldset", { class: "sk-question", "data-role": "sk-question" }, el("legend", null, t("account.sk.question")), yes.row, no.row);
    const code = field(t, { id: "sk-code", role: "sk-code", label: "account.sk.code", autocomplete: "off", required: false, help: "account.sk.needed", secret: true });
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
      // The sheet answers the question about the secret key, so the page does not ask it.
      question.hidden = !unknown || sheet !== null;
      tofu.hidden = !(qrText !== null && unknown && sheet === null && qrText.input.value.trim() === "");
      const answeredYes = sheet !== null ? sheet.qr.skBit : yes.input.checked === true;
      code.row.hidden = !(device.pinned ? device.skBit === true && !device.skStored : answeredYes);
      // A code typed for another e-mail address must not outlive its field: it would beat the stored key.
      if (code.row.hidden) code.input.value = "";
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

    const submit = el("button", { type: "submit", class: "btn btn-primary btn-block", "data-role": "submit" }, t(mode === "signin" ? "account.login.submit" : "account.unlock.submit"));
    yes.input.addEventListener("change", layout);
    no.input.addEventListener("change", layout);
    email?.input.addEventListener("change", () => void refreshDevice());

    /**
     * Reads the text in the sheet field with the core (no request) and shows what it is for. A sheet for another server
     * is refused here, before the user is asked to confirm anything.
     */
    async function readSheet() {
      if (qrText === null) return;
      clearError();
      forgetSheet();
      const text = qrText.input.value.trim();
      if (text === "") {
        layout();
        return;
      }
      try {
        const qr = await session.readSetupQr(text);
        if (typeof session.serverUrl === "string") checkQrBeforeKe3(qr, { serverUrl: session.serverUrl });
        // The text may have changed while it was read.
        if (qrText.input.value.trim() !== text) return;
        sheet = { text, qr };
        setText(qrSummary, t("account.qr.shown", { host: hostOf(qr), sk: t(qr.skBit ? "account.qr.sk_yes" : "account.qr.sk_no") }));
        qrBox.hidden = false;
      } catch (error) {
        await showError(error);
      }
      layout();
    }
    qrText?.input.addEventListener("input", () => {
      forgetSheet();
      clearError();
      layout();
    });
    qrRead.addEventListener("click", () => void readSheet());

    const controls = [password.input, yes.input, no.input, code.input, remember.input, submit, ...(email ? [email.input] : [])];
    if (qrText) controls.push(qrText.input, qrRead, qrConfirm.input);
    const run = guarded(async () => {
      // The fields are read and emptied before anything is awaited.
      const typedPassword = password.input.value;
      const typedCode = code.input.value;
      const typedSheet = qrText ? qrText.input.value.trim() : "";
      // A text in the sheet field is sent only when this very text was read and its address confirmed. The
      // password stays in its field when it is not: nothing has been used yet.
      const confirmed = sheet !== null && sheet.text === typedSheet && qrConfirm.input.checked === true ? sheet : null;
      if (typedSheet !== "" && confirmed === null) throw new AccountError("qr_not_confirmed");
      password.input.value = "";
      code.input.value = "";
      if (email) await refreshDevice();
      const answer = confirmed ? confirmed.qr.skBit : yes.input.checked ? true : no.input.checked ? false : undefined;
      const rememberVisible = !rememberRow.hidden;
      /** @type {Record<string, any>} */
      const args = { password: typedPassword, skCode: code.row.hidden ? "" : typedCode, skBit: device.pinned && !confirmed ? undefined : answer };
      if (confirmed) args.qr = typedSheet;
      if (rememberVisible) args.rememberSk = remember.input.checked;
      try {
        /** @type {any} */
        let opened;
        if (email) {
          args.email = email.input.value;
          triedEmail = args.email;
          opened = await session.signIn(args);
        } else {
          opened = await session.unlock(args);
        }
        // It worked, so a refusal about an older unlock method no longer stands, and neither does its note.
        try {
          await deps.clearRestoreNote?.({ accountId: opened?.accountId ?? info?.accountId ?? null, email: triedEmail ?? info?.email ?? null });
        } catch {
          // The note expires by itself.
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

    const sheetRows = qrText ? [qrText.row, el("div", { class: "actions" }, qrRead), qrBox, tofu] : [];
    mount(form, ...[email?.row, ...sheetRows, password.row, question, hint, code.row, remembered, rememberRow, submit].filter((n) => n !== undefined && n !== null));
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
      const lead = role === "open-vault" || role === "continue-admin";
      const button = el("button", { type: "button", class: lead ? "btn btn-primary" : "btn btn-secondary", "data-role": role }, t(label));
      controls.push(/** @type {any} */ (button));
      const run = guarded(work, controls, panel);
      button.addEventListener("click", () => void run());
      return button;
    };
    const buttons = [];
    if (open) buttons.push(action("account.signedin.open", "open-vault", async () => go("/")));
    if (entry.handoff !== null) buttons.push(action("account.signedin.continue_admin", "continue-admin", continueHandoff));
    else if (adminUrl !== null) {
      buttons.push(action("account.signedin.admin", "admin", () => handoff.goToAdmin({ adminUrl, next: ADMIN_LANDING, purpose: "login" })));
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
    entry.brokenHandoff ? el("p", { class: "notice notice-warning", role: "note", "data-role": "handoff-broken" }, t("account.handoff.link_broken")) : null,
    body,
    status,
    okBox,
    errorBox,
    otherBox,
    !reauthPage && info === null ? el("p", null, el("a", { href: "#/setup" }, t("account.login.setup_link"))) : null,
    !reauthPage ? el("p", null, el("a", { href: "#/forget", "data-role": "forget-link" }, t("syncwarnings.forget.link"))) : null,
    trust,
  ].filter((n) => n !== null);
  mount(root, ...parts);
  return root;
}
