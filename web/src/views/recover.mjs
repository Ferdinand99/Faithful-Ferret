// The recovery page (`#/recover`, spec Fase 1 § 6.3): a forgotten master password, or a new
// browser, with the recovery key. The admin listener sends the kit's sign-in code page here, so
// a one-time code is only ever typed on this page, and nothing here asks for the old password.
//
//   * No full session: the e-mail and the one-time code from the administrator.
//   * A full session (the vault refused an older password after a restore of the server, or
//     the user is signed in and forgot the password): no code.
//   * On a browser that does not know the account, both pages of the emergency sheet: the QR
//     text and the secret key from page 1, the recovery key from page 2. The QR text is read
//     with no request and its host is shown; the recovery does not start before the user has
//     confirmed that address for the text that is in the field.
//   * Then the new recovery key is shown alone (page 2 of a new sheet) and must be typed back
//     before the request is sent. Page 1 does not change.
//
// The fields that hold a secret are read and emptied before anything is awaited. No secret is
// logged, stored, or put in an address; an error is shown by its code only.
import { el, mount } from "../dom.mjs";
import { AccountError, codeOf } from "../crypto/errors.mjs";
import { checkQrBeforeKe3 } from "../flows/setupQr.mjs";
import { busyState, choice, describeError, field, setText, trustNotice } from "./form.mjs";
import { SECURITY_ERRORS } from "./securityError.mjs";
import { sheetView as realSheetView } from "./sheet.mjs";

/** The codes with a text of their own on this page (`recover.error.<code>`). */
export const RECOVER_ERRORS = Object.freeze([
  "cancelled", "code_refused", "code_required", "decrypt", "denied", "not_confirmed", "qr_required", "recover_unconfirmed",
  "rk_required", "unauthorized",
]);

/**
 * The text of an error on this page: its own, else the security catalog's (a conflict, a stale write), else the
 * sign-in page's. The message of an error is never shown.
 * @param {import("./form.mjs").Translate} t
 * @param {unknown} error
 * @returns {string}
 */
export function recoverErrorText(t, error) {
  const code = codeOf(error);
  if (RECOVER_ERRORS.includes(code)) return t(`recover.error.${code}`);
  if (SECURITY_ERRORS.includes(code)) return t(`security.error.${code}`);
  return describeError(t, error);
}

/**
 * @typedef {object} RecoverDeps
 * @property {import("./form.mjs").Translate} t
 * @property {{ accountId: string, email: string } | null} info the full session found when the page was opened
 * @property {boolean} [resetOpen] a reset session from an earlier code is still open in this browser
 * @property {string} serverUrl this page's server, as one canonical origin
 * @property {(text: string) => Promise<import("../flows/setupQr.mjs").SetupQr>} readSetupQr reads the sheet's QR text (no request)
 * @property {(email: string) => Promise<{ pinned: boolean, skBit: boolean | null, skStored: boolean }>} deviceStatus what this device knows (no request)
 * @property {(args: Record<string, any>) => Promise<"recovered">} recover the flow (`recoverAccount`), bound to the session
 * @property {() => Promise<boolean>} [passkeysOffered] whether the server offers passkeys as unlock methods; when it does, the
 *   page that says the account is recovered asks the user to look at the passkeys (a recovery leaves them as they were)
 * @property {(path: string) => void} go
 * @property {() => void} [print]
 * @property {typeof realSheetView} [sheetView]
 */

/** @param {RecoverDeps} deps */
export function recoverView(deps) {
  const { t, info, go } = deps;
  const makeSheet = deps.sheetView ?? realSheetView;
  const root = el("section", { class: "auth-card account recover-page", "data-role": "recover-page" });
  const status = el("p", { class: "status", role: "status", "data-role": "status" });
  const errorBox = el("p", { class: "error", role: "alert", "data-role": "error" });
  errorBox.hidden = true;
  const doneSlot = el("div", { "data-role": "done-slot" });
  /**
   * The new sheet and its "Stop" button while the new recovery key is shown. The sheet is a card of its own directly
   * inside this one, as on the setup page, so its print styles apply; the rest of the page is left out meanwhile.
   * @type {HTMLElement[]}
   */
  let sheetNodes = [];

  /** @param {unknown} error */
  function showError(error) {
    setText(errorBox, recoverErrorText(t, error));
    errorBox.hidden = false;
  }
  function clearError() {
    errorBox.hidden = true;
    setText(errorBox, "");
  }

  const form = el("form", { class: "stack", "data-role": "recover-form" });
  // The e-mail and the code: asked for unless a full session was found. They are not "required" fields: the flow says
  // what is missing (a reset session that is still open needs no code again).
  let needCode = info === null;
  const email = field(t, { id: "recover-email", role: "email", label: "recover.email", type: "email", autocomplete: "username", required: false });
  const code = field(t, { id: "recover-code", role: "code", label: "recover.code", help: "recover.code_help", secret: true, required: false });
  const resetOpen = el("p", { class: "notice", role: "note", "data-role": "reset-open" }, t("recover.reset_open"));
  const signedIn = info !== null ? el("p", { class: "notice", role: "note", "data-role": "signed-in" }, t("recover.signed_in", { email: info.email })) : null;
  function showCodeFields() {
    email.row.hidden = !needCode;
    code.row.hidden = !needCode;
    resetOpen.hidden = !(needCode && deps.resetOpen === true);
    if (signedIn) signedIn.hidden = needCode;
  }

  // The sheet's QR text: read with no request, confirmed by the user, then used.
  const qrText = field(t, { id: "recover-qr", role: "qr-text", label: "recover.qr_label", required: false, help: "recover.qr_help", secret: true });
  const qrRead = el("button", { type: "button", class: "btn btn-secondary", "data-role": "qr-read" }, t("account.qr.read"));
  const qrSummary = el("p", { "data-role": "qr-summary" });
  const qrConfirm = choice(t, { id: "recover-qr-confirm", role: "qr-confirm", label: "account.qr.confirm" });
  const qrBox = el("div", { class: "notice", role: "status", "data-role": "qr-shown" }, qrSummary, qrConfirm.row);
  qrBox.hidden = true;
  /** @type {{ text: string, qr: import("../flows/setupQr.mjs").SetupQr } | null} */
  let sheet = null;

  const sk = field(t, { id: "recover-sk", role: "sk-code", label: "recover.secret_key", required: false, help: "recover.secret_key_help", secret: true });
  const rk = field(t, { id: "recover-rk", role: "rk-code", label: "recover.rk", help: "recover.rk_help", secret: true });
  const next = field(t, { id: "recover-new", role: "new-password", label: "recover.new_password", type: "password", autocomplete: "new-password", help: "recover.password_help" });
  const again = field(t, { id: "recover-again", role: "new-password-again", label: "recover.new_password_again", type: "password", autocomplete: "new-password" });
  const submit = el("button", { type: "submit", class: "btn btn-primary btn-block", "data-role": "submit" }, t("recover.submit"));

  /** @type {{ pinned: boolean, skBit: boolean | null, skStored: boolean }} */
  let device = { pinned: false, skBit: null, skStored: false };
  function layout() {
    // The secret key field: the sheet says the account has one, or this device knows it has one and does not hold it.
    const needed = sheet !== null ? sheet.qr.skBit && !(device.pinned && device.skStored) : device.pinned && device.skBit === true && !device.skStored;
    sk.row.hidden = !needed;
    if (sk.row.hidden) sk.input.value = "";
  }
  async function refreshDevice() {
    const typed = needCode ? email.input.value.trim() : (info?.email ?? "");
    try {
      device = typed === "" ? { pinned: false, skBit: null, skStored: false } : await deps.deviceStatus(typed);
    } catch {
      device = { pinned: false, skBit: null, skStored: false };
    }
    layout();
  }
  /** @param {import("../flows/setupQr.mjs").SetupQr} qr */
  const hostOf = (qr) => (qr.port === null ? qr.host : `${qr.host}:${qr.port}`);
  function forgetSheet() {
    sheet = null;
    qrBox.hidden = true;
    qrConfirm.input.checked = false;
    setText(qrSummary, "");
  }
  async function readSheet() {
    clearError();
    forgetSheet();
    const text = qrText.input.value.trim();
    if (text !== "") {
      try {
        const qr = await deps.readSetupQr(text);
        checkQrBeforeKe3(qr, { serverUrl: deps.serverUrl });
        // The text may have changed while it was read.
        if (qrText.input.value.trim() !== text) return;
        sheet = { text, qr };
        setText(qrSummary, t("account.qr.shown", { host: hostOf(qr), sk: t(qr.skBit ? "account.qr.sk_yes" : "account.qr.sk_no") }));
        qrBox.hidden = false;
      } catch (error) {
        showError(error);
      }
    }
    layout();
  }
  qrText.input.addEventListener("input", () => {
    forgetSheet();
    clearError();
    layout();
  });
  qrRead.addEventListener("click", () => void readSheet());
  email.input.addEventListener("change", () => void refreshDevice());

  const controls = [qrText.input, qrRead, qrConfirm.input, sk.input, rk.input, next.input, again.input, submit, email.input, code.input];
  const busy = busyState({ root: form, status, controls, t, key: "recover.busy" });

  /**
   * The new recovery key, shown alone; resolves once it has been typed back and checked. The form is out of the way
   * meanwhile; "Stop" ends the recovery before anything is sent.
   * @type {import("../flows/recover.mjs").ConfirmNewRk}
   */
  const confirmNewRk = ({ sheet: newSheet, check }) =>
    new Promise((resolve, reject) => {
      form.hidden = true;
      busy.set(false);
      const cancel = el("button", { type: "button", class: "btn btn-secondary", "data-role": "recover-cancel" }, t("recover.cancel"));
      const view = makeSheet({
        t,
        sheet: newSheet,
        mode: "recover",
        print: deps.print,
        onConfirm: async (typed) => {
          await check(typed);
          // The key checks out: the sheet leaves the page and the request goes out.
          sheetNodes = [];
          render();
          busy.set(true);
          resolve();
        },
      });
      cancel.addEventListener("click", () => {
        view.wipe();
        sheetNodes = [];
        render();
        reject(new AccountError("cancelled"));
      });
      sheetNodes = [view.root, el("div", { class: "actions no-print" }, cancel)];
      render();
    });

  /** @param {boolean} signedIn */
  function showDone(signedIn) {
    sheetNodes = [];
    form.hidden = true;
    const open = el("button", { type: "button", class: "btn btn-primary", "data-role": "open-vault" }, t("recover.done_open"));
    open.addEventListener("click", () => go("/"));
    // A recovery rewrites the password and the recovery key and leaves the passkeys as they were: a passkey someone added
    // before is still there. Where passkeys are offered, the user is asked to look at the list.
    const passkeys = el("p", { "data-role": "done-passkeys" });
    passkeys.hidden = true;
    if (signedIn && deps.passkeysOffered) {
      deps.passkeysOffered().then((offered) => {
        if (!offered) return;
        mount(passkeys, document.createTextNode(`${t("recover.done_passkeys")} `), el("a", { href: "#/unlock-methods", "data-role": "done-passkeys-link" }, t("recover.done_passkeys_link")));
        passkeys.hidden = false;
      }, () => undefined);
    }
    mount(
      doneSlot,
      el(
        "div",
        { class: "stack", "data-role": "recover-done" },
        el("h2", null, t("recover.done_heading")),
        el("p", { "data-role": "done-signed-in" }, t(signedIn ? "recover.done_signed_in" : "recover.done_not_signed_in")),
        el("p", null, t("recover.done_devices")),
        el("p", null, t("recover.done_old_key")),
        el("p", null, t("recover.done_old_files")),
        el("p", null, t("recover.done_sheet")),
        el("p", null, t("recover.done_backup")),
        passkeys,
        // Not signed in: the passkey list cannot be read yet, so the note says where to look once the user is.
        signedIn ? null : el("p", { "data-role": "done-passkeys-later" }, t("recover.done_passkeys_later")),
        signedIn ? el("div", { class: "actions" }, open) : el("p", null, el("a", { href: "#/login" }, t("recover.sign_in_link"))),
      ),
    );
    render();
  }

  let running = false;
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (running) return;
    void (async () => {
      running = true;
      clearError();
      // A text in the sheet field is used only when this very text was read and its address confirmed. Nothing has
      // been emptied yet, so the user can confirm and send again.
      const typedSheet = qrText.input.value.trim();
      const confirmed = sheet !== null && sheet.text === typedSheet && qrConfirm.input.checked === true ? sheet : null;
      if (typedSheet !== "" && confirmed === null) {
        showError(new AccountError("qr_not_confirmed"));
        running = false;
        return;
      }
      // The secrets are read and emptied before anything is awaited.
      const args = {
        email: needCode ? email.input.value : (info?.email ?? ""),
        code: needCode ? code.input.value : "",
        qrText: confirmed ? confirmed.text : null,
        skCode: sk.row.hidden ? "" : sk.input.value,
        rkCode: rk.input.value,
        newPassword: next.input.value,
        newPasswordAgain: again.input.value,
        confirmNewRk,
      };
      for (const input of [sk.input, rk.input, next.input, again.input, code.input]) input.value = "";
      busy.set(true);
      try {
        await deps.recover(args);
        // The sheet text leaves the page too.
        qrText.input.value = "";
        forgetSheet();
        showDone(true);
      } catch (error) {
        sheetNodes = [];
        render();
        if (codeOf(error) === "recovered_not_signed_in") {
          qrText.input.value = "";
          forgetSheet();
          showDone(false);
        } else {
          // The full session the page was opened with has ended meanwhile: the e-mail and a code are needed now.
          if (codeOf(error) === "code_required" && !needCode) {
            needCode = true;
            showCodeFields();
          }
          form.hidden = false;
          showError(error);
        }
      } finally {
        busy.set(false);
        running = false;
      }
    })();
  });

  mount(
    form,
    ...[
      email.row,
      code.row,
      resetOpen,
      qrText.row,
      el("div", { class: "actions" }, qrRead),
      qrBox,
      sk.row,
      rk.row,
      next.row,
      again.row,
      submit,
    ].filter((n) => n !== null && n !== undefined),
  );
  showCodeFields();
  layout();
  void refreshDevice();

  const head = [
    el("h1", null, t("recover.heading")),
    el("p", null, t("recover.intro")),
    el("p", { class: "notice", role: "note", "data-role": "new-browser" }, t("recover.new_browser")),
    ...(signedIn ? [signedIn] : []),
  ];
  const foot = [el("p", { class: "no-print" }, el("a", { href: "#/login", "data-role": "sign-in-link" }, t("recover.sign_in_link"))), trustNotice(t)];
  function render() {
    if (sheetNodes.length > 0) mount(root, ...sheetNodes, status, errorBox);
    else mount(root, ...head, form, doneSlot, status, errorBox, ...foot);
  }
  render();
  return root;
}
