// The sign-in tab (design document, section 7.2): the first sign-in of this
// device, and the unlock when the tab is opened on a locked device. The steps
// are in signinFlow.mjs; this file builds the page with `el()`.
//
// The master password and the secret key are typed only here and in the popup,
// two pages of the extension's own package that no web page can load or frame
// (no `web_accessible_resources`, CSP `frame-ancestors 'none'`). The fields are
// emptied as soon as their value is sent to the background.

import { el, mount } from "../shared/dom.mjs";
import { errorBox, field, loadTexts, showError, translateStatic } from "./page.mjs";
import { createSignInFlow, unlockWith } from "./signinFlow.mjs";
import { UiError, connectUi, reasonKey, shownHost } from "./ui.mjs";

/** @typedef {import("./page.mjs").Texts} Texts */

/** The reason of an error of the port, or of a request the protocol refused. @param {unknown} error */
const reasonOfError = (error) => (error instanceof UiError ? error.code : "unknown");

/**
 * Marks a form busy: its controls are disabled and the status line says so.
 * @param {HTMLElement} form
 * @param {HTMLElement} status
 * @param {Texts} texts
 * @param {boolean} on
 */
function busy(form, status, texts, on) {
  for (const control of form.querySelectorAll("input, button, textarea")) /** @type {HTMLInputElement} */ (control).disabled = on;
  form.setAttribute("aria-busy", on ? "true" : "false");
  status.textContent = on ? texts.t("session.busy") : "";
}

/**
 * @param {HTMLElement} root
 * @param {Texts} texts
 * @param {import("./ui.mjs").Request} request
 */
function start(root, texts, request) {
  const flow = createSignInFlow({ request, requestPermission: (wanted) => browser.permissions.request(wanted) });

  /** Step 1: the server's address. */
  function serverStep() {
    const address = field({
      id: "server",
      label: texts.t("session.server.label"),
      role: "server",
      inputmode: "url",
      autocomplete: "url",
      placeholder: "https://vault.example.com",
      hint: texts.t("session.server.hint"),
    });
    const error = errorBox();
    const status = el("p", { class: "ff-status", "aria-live": "polite" });
    const checked = el("div", { class: "ff-checked", "data-role": "server-checked", hidden: true });
    const form = el(
      "form",
      { class: "ff-form", "data-role": "server-form" },
      address.row,
      el("button", { type: "submit", class: "ff-button ff-primary", "data-role": "server-submit" }, texts.t("session.server.submit")),
      status,
      error,
    );
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      showError(error, texts, null);
      checked.hidden = true;
      busy(form, status, texts, true);
      /** @type {import("./signinFlow.mjs").Checked} */
      let answer;
      try {
        answer = await flow.check(address.input.value);
      } catch (failure) {
        answer = { ok: false, reason: reasonOfError(failure) };
      }
      busy(form, status, texts, false);
      if (!answer.ok) {
        showError(error, texts, reasonKey(answer.reason));
        return;
      }
      grantPanel(checked, answer);
    });
    mount(root, el("h1", null, texts.t("session.signin.title")), el("p", { class: "ff-lead" }, texts.t("session.server.intro")), form, checked);
    address.input.focus();
  }

  /**
   * The checked server and the button that asks for its permission.
   * @param {HTMLElement} panel
   * @param {{ server: string, host?: string, host_a_label?: string }} answer
   */
  function grantPanel(panel, answer) {
    const error = errorBox();
    const button = el("button", { type: "button", class: "ff-button ff-primary", "data-role": "grant" }, texts.t("session.grant.button"));
    button.addEventListener("click", () => {
      showError(error, texts, null);
      // Asked in the turn of the click: the browser grants a request only then.
      const asked = flow.grant();
      asked.then((result) => {
        if (result.ok) credentialsStep(answer);
        else showError(error, texts, reasonKey(result.reason));
      });
    });
    mount(
      panel,
      el("p", null, texts.t("session.grant.server"), " ", el("strong", { class: "ff-host", dir: "ltr", "data-role": "server-host" }, shownHost(answer))),
      el("p", { class: "ff-hint" }, texts.t("session.grant.hint")),
      button,
      error,
    );
    panel.hidden = false;
  }

  /**
   * Step 3: the account.
   * @param {{ server: string, host?: string, host_a_label?: string }} answer
   */
  function credentialsStep(answer) {
    const email = field({ id: "email", label: texts.t("session.email"), role: "email", type: "email", autocomplete: "username" });
    const password = field({ id: "password", label: texts.t("session.password"), role: "password", type: "password", autocomplete: "current-password" });
    const secretKey = field({ id: "sk", label: texts.t("session.sk.code"), role: "sk-code", autocomplete: "off" });
    secretKey.row.hidden = true;
    const yes = /** @type {HTMLInputElement} */ (el("input", { type: "radio", name: "sk-answer", id: "sk-yes", value: "yes", "data-role": "sk-yes" }));
    const no = /** @type {HTMLInputElement} */ (el("input", { type: "radio", name: "sk-answer", id: "sk-no", value: "no", "data-role": "sk-no" }));
    const remember = /** @type {HTMLInputElement} */ (el("input", { type: "checkbox", id: "remember", checked: true, "data-role": "sk-remember" }));
    const rememberRow = el(
      "div",
      { class: "ff-check" },
      remember,
      el("label", { for: "remember" }, texts.t("session.sk.remember")),
      el("p", { class: "ff-hint" }, texts.t("session.sk.remember_hint")),
    );
    const showCode = () => {
      secretKey.row.hidden = !yes.checked;
      rememberRow.hidden = !yes.checked;
    };
    yes.addEventListener("change", showCode);
    no.addEventListener("change", showCode);
    rememberRow.hidden = true;
    const question = el(
      "fieldset",
      { class: "ff-fieldset", "data-role": "sk-question" },
      el("legend", null, texts.t("session.sk.question")),
      el("div", { class: "ff-choice" }, yes, el("label", { for: "sk-yes" }, texts.t("session.sk.yes"))),
      el("div", { class: "ff-choice" }, no, el("label", { for: "sk-no" }, texts.t("session.sk.no"))),
      el("p", { class: "ff-hint" }, texts.t("session.sk.question_hint")),
      secretKey.row,
      rememberRow,
    );
    const qr = /** @type {HTMLTextAreaElement} */ (el("textarea", { id: "qr", class: "ff-input ff-qr", rows: 3, "data-role": "qr-text" }));
    const sheet = el(
      "details",
      { class: "ff-sheet" },
      el("summary", null, texts.t("session.qr.summary")),
      el("label", { for: "qr", class: "ff-label" }, texts.t("session.qr.label")),
      qr,
      el("p", { class: "ff-hint" }, texts.t("session.qr.hint")),
    );
    const tofu = el("p", { class: "ff-notice", "data-role": "tofu-notice" }, texts.t("session.qr.tofu"));
    const error = errorBox();
    const status = el("p", { class: "ff-status", "aria-live": "polite" });
    const form = el(
      "form",
      { class: "ff-form", "data-role": "credentials" },
      email.row,
      password.row,
      question,
      sheet,
      tofu,
      el("button", { type: "submit", class: "ff-button ff-primary", "data-role": "submit" }, texts.t("session.signin.submit")),
      status,
      error,
    );
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      showError(error, texts, null);
      /** @type {import("./signinFlow.mjs").SignInFields} */
      const fields = {
        email: email.input.value,
        password: password.input.value,
        skAnswer: yes.checked ? "yes" : no.checked ? "no" : null,
        secretKey: secretKey.input.value,
        remember: remember.checked,
        qrText: qr.value,
      };
      // What was typed leaves the page once: the fields are emptied before the answer comes.
      password.input.value = "";
      secretKey.input.value = "";
      busy(form, status, texts, true);
      /** @type {{ ok: boolean, reason?: string, account_email?: string, server?: string }} */
      let result;
      try {
        result = await flow.signIn(fields);
      } catch (failure) {
        result = { ok: false, reason: reasonOfError(failure) };
      }
      busy(form, status, texts, false);
      if (result.ok) {
        qr.value = "";
        openView({ account: result.account_email, host: answer.host, host_a_label: answer.host_a_label, server: result.server });
        return;
      }
      showError(error, texts, reasonKey(result.reason));
      password.input.focus();
    });
    mount(
      root,
      el("h1", null, texts.t("session.signin.title")),
      el("p", { class: "ff-lead" }, texts.t("session.signin.at"), " ", el("strong", { class: "ff-host", dir: "ltr", "data-role": "server-host" }, shownHost(answer))),
      form,
    );
    email.input.focus();
  }

  /**
   * The unlock of a signed-in device: only the master password (and the secret key when this device does not keep it).
   * @param {Record<string, any>} state
   */
  function unlockView(state) {
    const password = field({ id: "password", label: texts.t("session.password"), role: "password", type: "password", autocomplete: "current-password" });
    const secretKey = field({ id: "sk", label: texts.t("session.sk.code"), role: "sk-code", autocomplete: "off" });
    secretKey.row.hidden = true;
    const error = errorBox();
    const status = el("p", { class: "ff-status", "aria-live": "polite" });
    const form = el(
      "form",
      { class: "ff-form", "data-role": "unlock-form" },
      password.row,
      secretKey.row,
      el("button", { type: "submit", class: "ff-button ff-primary", "data-role": "unlock" }, texts.t("session.unlock.submit")),
      status,
      error,
    );
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      showError(error, texts, null);
      const fields = { password: password.input.value, secretKey: secretKey.input.value };
      password.input.value = "";
      secretKey.input.value = "";
      busy(form, status, texts, true);
      /** @type {{ ok: boolean, reason?: string }} */
      let result;
      try {
        result = await unlockWith(request, fields);
      } catch (failure) {
        result = { ok: false, reason: reasonOfError(failure) };
      }
      busy(form, status, texts, false);
      if (result.ok) {
        openView(state);
        return;
      }
      if (result.reason === "sk_required") secretKey.row.hidden = false;
      if (result.reason === "signed_out") {
        serverStep();
        return;
      }
      showError(error, texts, reasonKey(result.reason));
      password.input.focus();
    });
    mount(
      root,
      el("h1", null, texts.t("session.unlock.title")),
      accountLine(state),
      form,
    );
    password.input.focus();
  }

  /** @param {Record<string, any>} state */
  function accountLine(state) {
    return el(
      "p",
      { class: "ff-lead", "data-role": "account-line" },
      el("span", { "data-role": "account" }, typeof state.account === "string" ? state.account : ""),
      " · ",
      el("span", { class: "ff-host", dir: "ltr", "data-role": "server-host" }, shownHost(state)),
    );
  }

  /** The vault is open. @param {Record<string, any>} state */
  function openView(state) {
    const lock = el("button", { type: "button", class: "ff-button", "data-role": "lock" }, texts.t("session.lock"));
    lock.addEventListener("click", async () => {
      await request("lock", {}).catch(() => undefined);
      unlockView(state);
    });
    mount(
      root,
      el("h1", { "data-role": "signed-in" }, texts.t("session.open.title")),
      accountLine(state),
      el("p", null, texts.t("session.open.hint")),
      lock,
    );
  }

  return { serverStep, unlockView, openView };
}

async function main() {
  const root = document.getElementById("root");
  if (!root) return;
  const texts = await loadTexts();
  translateStatic(document, texts);
  const ui = connectUi(browser.runtime);
  const views = start(root, texts, ui.request);
  /** @type {Record<string, any>} */
  let state;
  try {
    state = await ui.request("state", {});
  } catch {
    state = { state: "signed_out" };
  }
  if (state.state === "locked") views.unlockView(state);
  else if (state.state === "unlocked") views.openView(state);
  else views.serverStep();
  document.body.dataset.ready = "1";
}

main().catch(() => {
  // The page has nothing to show without the background; it never prints what went wrong.
});
