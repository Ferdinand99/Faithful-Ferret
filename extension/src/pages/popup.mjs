// The popup (design document, sections 7.2 and 10.3.1). In this version it
// shows whether a device is signed in, unlocks it with the master password,
// locks it with the button in the header, and shows what the sync found: its
// state, a stop with "Try again" and "Forget this server", and the warnings.
// The views are in popupFlow.mjs; this file builds them with `el()`. The list
// of the vault comes later and builds on the unlocked view.
//
// The first sign-in never happens here: Firefox closes the popup when a
// permission is asked for, so it is done in the sign-in tab.

import { el, mount } from "../shared/dom.mjs";
import { errorBox, field, loadTexts, showError, translateStatic } from "./page.mjs";
import { createPopupFlow, statusKey, stopKey, warningKey } from "./popupFlow.mjs";
import { UiError, connectUi, initialsOf, reasonKey } from "./ui.mjs";

/** @typedef {import("./page.mjs").Texts} Texts */
/** @typedef {import("./popupFlow.mjs").PopupView} PopupView */

/** How often an open popup asks for the sync's state again (a poll of it does not move the lock's deadline). */
const SYNC_REFRESH_MS = 1500;

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

  /** The timer that refreshes the sync's part of the unlocked view. @type {ReturnType<typeof setTimeout> | null} */
  let refresh = null;

  /**
   * @param {PopupView} view
   * @param {string | null} [note] the i18n key of a note under a stop of the sync
   */
  function show(view, note = null) {
    if (refresh !== null) clearTimeout(refresh);
    refresh = null;
    header(view);
    if (view.view === "signed_out") return signedOut(view);
    if (view.view === "locked") return locked(view);
    return unlocked(view, note);
  }

  /**
   * "Forget this server": a button, then a question with its two answers. Only the server the popup shows is forgotten.
   * @param {PopupView} view
   */
  function forgetPart(view) {
    const box = el("div", { class: "ff-forget", "data-role": "forget" });
    const start = el("button", { type: "button", class: "ff-button", "data-role": "sync-action", "data-action": "forget" }, texts.t("sync.action.forget"));
    start.addEventListener("click", () => ask());
    mount(box, start);
    function ask() {
      const error = errorBox();
      const confirm = el("button", { type: "button", class: "ff-button ff-danger", "data-role": "forget-confirm" }, texts.t("sync.forget.confirm"));
      const cancel = el("button", { type: "button", class: "ff-button", "data-role": "forget-cancel" }, texts.t("sync.forget.cancel"));
      cancel.addEventListener("click", () => mount(box, start));
      confirm.addEventListener("click", async () => {
        confirm.setAttribute("disabled", "");
        cancel.setAttribute("disabled", "");
        showError(error, texts, null);
        try {
          const { result, view: next } = await flow.forget(view.server);
          if (result.ok) {
            show(next);
            return;
          }
          showError(error, texts, `sync.error.${result.reason ?? "unknown"}`);
        } catch {
          showError(error, texts, "sync.error.unknown");
        }
        confirm.removeAttribute("disabled");
        cancel.removeAttribute("disabled");
      });
      mount(
        box,
        el("h2", null, texts.t("sync.forget.title")),
        el("p", { "data-role": "forget-text" }, texts.t("sync.forget.body")),
        el("div", { class: "ff-actions" }, confirm, cancel),
        error,
      );
      confirm.focus();
    }
    return box;
  }

  /** @param {PopupView} view */
  function signedOut(view) {
    const open = el("button", { type: "button", class: "ff-button ff-primary", "data-role": "open-signin" }, texts.t("session.popup.signin"));
    open.addEventListener("click", async () => {
      await browser.tabs.create({ url: browser.runtime.getURL("pages/signin.html") });
      window.close();
    });
    mount(
      root,
      el(
        "section",
        { class: "ff-panel", "data-role": "signed-out-view" },
        el("h1", null, texts.t("session.popup.signed_out")),
        el("p", null, texts.t("session.popup.signed_out_hint")),
        open,
        view.server !== "" ? forgetPart(view) : null,
      ),
    );
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
      el(
        "section",
        { class: "ff-panel", "data-role": "locked-view" },
        el("h1", null, texts.t("session.popup.locked")),
        where(view),
        form,
        view.server !== "" ? forgetPart(view) : null,
      ),
    );
    password.input.focus();
  }

  /**
   * What the sync shows: its state, a stop with its two ways on, and the warnings. Nothing here names an item.
   * @param {PopupView} view
   * @param {string | null} note the i18n key of a note under the stop (an answer to "Try again"), or null
   */
  function syncPart(view, note) {
    const sync = view.sync;
    const halted = sync?.halted ?? null;
    const box = el("div", { class: "ff-sync", "data-role": "sync", "data-state": halted !== null ? "halted" : (sync?.status ?? "starting"), "data-live": sync?.live ?? "offline" });
    if (sync === null || !sync.running) return box;
    if (halted !== null) {
      const noteBox = errorBox();
      const actions = el("div", { class: "ff-actions", "data-role": "sync-actions" });
      for (const action of sync.actions) {
        if (action === "try_again") {
          const button = el("button", { type: "button", class: "ff-button ff-primary", "data-role": "sync-action", "data-action": "try_again" }, texts.t("sync.action.try_again"));
          button.addEventListener("click", async () => {
            button.setAttribute("disabled", "");
            try {
              const { result, view: next } = await flow.retry();
              show(next, result.ok ? null : `sync.error.${result.reason ?? "unknown"}`);
            } catch {
              show(await flow.load().catch(() => view));
            }
          });
          actions.append(button);
        } else if (action === "forget") {
          actions.append(forgetPart(view));
        }
      }
      box.append(
        el(
          "div",
          { class: "ff-sync-stop", role: "alert", "data-role": "sync-stop", "data-code": halted },
          el("h2", null, texts.t("sync.stop.title")),
          el("p", null, texts.t(stopKey(halted))),
          actions,
          noteBox,
        ),
      );
      showError(noteBox, texts, note);
    } else {
      box.append(el("p", { class: "ff-hint", "data-role": "sync-status" }, texts.t(statusKey(sync.status))));
    }
    if (sync.warnings.length > 0) {
      const list = el("ul", { class: "ff-sync-warnings", "data-role": "sync-warnings" });
      for (const code of sync.warnings) list.append(el("li", { "data-role": "sync-warning", "data-code": code }, texts.t(warningKey(code))));
      box.append(list);
    }
    return box;
  }

  /**
   * @param {PopupView} view
   * @param {string | null} [note] see `syncPart`
   */
  function unlocked(view, note = null) {
    mount(
      root,
      el(
        "section",
        { class: "ff-panel", "data-role": "unlocked-view" },
        el("h1", null, texts.t("session.open.title")),
        where(view),
        syncPart(view, note),
        el("p", { class: "ff-hint" }, texts.t("session.popup.open_hint")),
      ),
    );
    // The sync's part follows the background while the popup is open, unless the user is answering a question in it.
    const mine = setTimeout(async () => {
      if (refresh !== mine) return;
      refresh = null;
      if (root.querySelector('[data-role="forget-confirm"]') !== null) return;
      try {
        const next = await flow.load();
        // Shown only when nothing else was shown meanwhile (an action of the user wins).
        if (refresh === null && document.body.dataset.view === "unlocked") show(next, note);
      } catch {
        // The background is gone for a moment: the next action asks again.
      }
    }, SYNC_REFRESH_MS);
    refresh = mine;
  }

  lockButton.addEventListener("click", async () => {
    try {
      show(await flow.lock());
    } catch {
      show(await flow.load().catch(() => ({ view: /** @type {const} */ ("signed_out"), host: "", account: "", server: "", sync: null })));
    }
  });

  popOut.addEventListener("click", async () => {
    await browser.windows.create({ url: browser.runtime.getURL("pages/popup.html"), type: "popup", width: 380, height: 620 });
    window.close();
  });

  try {
    show(await flow.load());
  } catch {
    show({ view: "signed_out", host: "", account: "", server: "", sync: null });
  }
  document.body.dataset.ready = "1";
}

main().catch(() => {
  // Nothing to show without the background; the popup never prints what went wrong.
});
