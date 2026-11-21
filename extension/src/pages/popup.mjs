// The popup (design document, sections 7.2 and 10.3.1). In this version it
// shows whether a device is signed in, unlocks it with the master password,
// and locks it with the button in the header. The views are in popupFlow.mjs;
// this file builds them with `el()`. The list of the vault comes later and
// builds on the unlocked view.
//
// The first sign-in never happens here: Firefox closes the popup when a
// permission is asked for, so it is done in the sign-in tab.

import { el, mount } from "../shared/dom.mjs";
import { errorBox, field, loadTexts, showError, translateStatic } from "./page.mjs";
import { createPopupFlow } from "./popupFlow.mjs";
import { UiError, connectUi, initialsOf, reasonKey } from "./ui.mjs";

/** @typedef {import("./page.mjs").Texts} Texts */
/** @typedef {import("./popupFlow.mjs").PopupView} PopupView */

/** @param {string} id @returns {HTMLElement} */
function byId(id) {
  const node = document.getElementById(id);
  if (!node) throw new Error(`popup: #${id} is missing`);
  return node;
}

async function main() {
  const root = byId("root");
  const lockButton = byId("lock");
  const popOut = byId("popout");
  const avatar = byId("avatar");
  const texts = await loadTexts();
  translateStatic(document, texts);
  const ui = connectUi(browser.runtime);
  const flow = createPopupFlow(ui.request);

  /** @param {PopupView} view */
  function header(view) {
    lockButton.hidden = view.view !== "unlocked";
    avatar.hidden = view.view === "signed_out" || view.account === "";
    avatar.textContent = initialsOf(view.account);
    avatar.setAttribute("title", view.account);
    avatar.setAttribute("aria-label", texts.t("session.account", { account: view.account }));
    document.body.dataset.view = view.view;
  }

  /** @param {PopupView} view */
  function where(view) {
    return el(
      "div",
      { class: "ff-where", "data-role": "account-line" },
      el("span", { class: "ff-where-account", "data-role": "account" }, view.account),
      el("span", { class: "ff-where-host ff-host", dir: "ltr", "data-role": "server-host" }, view.host),
    );
  }

  /** @param {PopupView} view */
  function show(view) {
    header(view);
    if (view.view === "signed_out") return signedOut();
    if (view.view === "locked") return locked(view);
    return unlocked(view);
  }

  function signedOut() {
    const open = el("button", { type: "button", class: "ff-button ff-primary", "data-role": "open-signin" }, texts.t("session.popup.signin"));
    open.addEventListener("click", async () => {
      await browser.tabs.create({ url: browser.runtime.getURL("pages/signin.html") });
      window.close();
    });
    mount(root, el("section", { class: "ff-panel", "data-role": "signed-out-view" }, el("h1", null, texts.t("session.popup.signed_out")), el("p", null, texts.t("session.popup.signed_out_hint")), open));
  }

  /** @param {PopupView} view */
  function locked(view) {
    const password = field({ id: "password", label: texts.t("session.password"), role: "password", type: "password", autocomplete: "current-password" });
    const secretKey = field({ id: "sk", label: texts.t("session.sk.code"), role: "sk-code", autocomplete: "off" });
    secretKey.row.hidden = true;
    const error = errorBox();
    const submit = el("button", { type: "submit", class: "ff-button ff-primary", "data-role": "unlock" }, texts.t("session.unlock.submit"));
    const form = el("form", { class: "ff-form", "data-role": "unlock-form" }, password.row, secretKey.row, submit, error);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      showError(error, texts, null);
      const fields = { password: password.input.value, secretKey: secretKey.input.value };
      password.input.value = "";
      secretKey.input.value = "";
      submit.setAttribute("disabled", "");
      form.setAttribute("aria-busy", "true");
      try {
        const { result, view: next } = await flow.unlock(fields);
        if (result.ok || next.view !== "locked") {
          show(next);
          return;
        }
        if (result.reason === "sk_required") secretKey.row.hidden = false;
        showError(error, texts, reasonKey(result.reason));
      } catch (failure) {
        showError(error, texts, reasonKey(failure instanceof UiError ? failure.code : "unknown"));
      } finally {
        submit.removeAttribute("disabled");
        form.setAttribute("aria-busy", "false");
      }
      password.input.focus();
    });
    mount(
      root,
      el("section", { class: "ff-panel", "data-role": "locked-view" }, el("h1", null, texts.t("session.popup.locked")), where(view), form),
    );
    password.input.focus();
  }

  /** @param {PopupView} view */
  function unlocked(view) {
    mount(
      root,
      el("section", { class: "ff-panel", "data-role": "unlocked-view" }, el("h1", null, texts.t("session.open.title")), where(view), el("p", { class: "ff-hint" }, texts.t("session.popup.open_hint"))),
    );
  }

  lockButton.addEventListener("click", async () => {
    try {
      show(await flow.lock());
    } catch {
      show(await flow.load().catch(() => ({ view: /** @type {const} */ ("signed_out"), host: "", account: "" })));
    }
  });

  popOut.addEventListener("click", async () => {
    await browser.windows.create({ url: browser.runtime.getURL("pages/popup.html"), type: "popup", width: 380, height: 620 });
    window.close();
  });

  try {
    show(await flow.load());
  } catch {
    show({ view: "signed_out", host: "", account: "" });
  }
  document.body.dataset.ready = "1";
}

main().catch(() => {
  // Nothing to show without the background; the popup never prints what went wrong.
});
