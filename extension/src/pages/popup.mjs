// The popup (design document, sections 7.2, 10.3.1 and 10.6). It shows
// whether a device is signed in, unlocks it with the master password, locks it
// with the button in the header, shows what the sync found (its state, a stop
// with "Try again" and "Forget this server", and the warnings), and, while the
// vault is open, the list of the vault (popupList.mjs): the candidates of the
// page with "Fill", the favourites and all items, search, a filter by type,
// copying and one item's view. The views are in popupFlow.mjs; this file builds
// them with `el()`.
//
// The page the popup is about is the active tab of the window it was opened
// from. A popup that was popped out into a window of its own keeps that tab
// (`?tab=<id>` in its address); a popup page opened as a tab of its own has no
// page, so it offers nothing to fill.
//
// The first sign-in never happens here: Firefox closes the popup when a
// permission is asked for, so it is done in the sign-in tab.

import { el, mount } from "../shared/dom.mjs";
import { errorBox, field, loadTexts, showError, translateStatic } from "./page.mjs";
import { createListFlow, createPopupFlow, followStep, statusKey, stopKey, warningKey } from "./popupFlow.mjs";
import { createVaultList } from "./popupList.mjs";
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

/**
 * The tab whose page the popup is about (or null), and whether the popup runs in a tab or a window of its own (popped
 * out, or opened as a page) rather than in the toolbar's panel.
 * @returns {Promise<{ tabId: number | null, windowed: boolean }>}
 */
async function placeOf() {
  const named = new URLSearchParams(location.search).get("tab");
  /** @type {any} */
  let own;
  try {
    // The toolbar's panel is no tab: `getCurrent()` gives nothing there.
    own = await browser.tabs.getCurrent();
  } catch {
    own = undefined;
  }
  const windowed = named !== null || own !== undefined;
  if (named !== null) return { tabId: /^[0-9]{1,10}$/.test(named) ? Number(named) : null, windowed };
  try {
    const [active] = await browser.tabs.query({ active: true, currentWindow: true });
    if (typeof active?.id !== "number") return { tabId: null, windowed };
    // The popup page in a tab of its own is not about a page.
    if (own !== undefined && own?.id === active.id) return { tabId: null, windowed };
    return { tabId: active.id, windowed };
  } catch {
    return { tabId: null, windowed };
  }
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
  const listFlow = createListFlow(ui.request);
  const { tabId, windowed } = await placeOf();
  const poppedOut = new URLSearchParams(location.search).has("tab");
  // The panel is as tall as Firefox lets a popup be; a tab or a window gives the popup its own height (popup.css).
  document.body.classList.toggle("ff-windowed", windowed);

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
      el("span", { class: "ff-where-account", "data-role": "account", title: view.account }, view.account),
      el("span", { class: "ff-where-host ff-host", dir: "ltr", "data-role": "server-host", title: view.host }, view.host),
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
   * The open vault: the sync's part and the list of the vault, and the account and server at the foot.
   * @param {PopupView} view
   * @param {string | null} [note] see `syncPart`
   */
  function unlocked(view, note = null) {
    const syncSlot = el("div", { class: "ff-sync-slot", "data-role": "sync-slot" }, syncPart(view, note));
    const vault = createVaultList({
      texts,
      list: listFlow,
      tabId,
      onFilled: () => {
        // The page has what it needs; a popped-out window stays.
        if (!poppedOut) setTimeout(() => window.close(), 600);
      },
      // The permission is asked for in a tab of its own: a request from the popup would close the popup.
      onGrant: (origin) => {
        const url = `${browser.runtime.getURL("pages/grant.html")}?${new URLSearchParams({ origin }).toString()}`;
        void browser.tabs.create({ url }).then(() => {
          if (!poppedOut) window.close();
        });
      },
    });
    mount(
      root,
      el(
        "section",
        { class: "ff-panel ff-unlocked", "data-role": "unlocked-view" },
        syncSlot,
        vault.root,
        el("footer", { class: "ff-foot" }, where(view)),
      ),
    );
    void vault.reload().then(() => vault.focus(), () => {});
    follow(view, note, syncSlot, vault);
  }

  /**
   * The sync's part follows the background while the popup is open: it is built again only when what the background
   * says has changed, and not while the user answers the question of "Forget this server". The list is read again
   * when the sync's state changes (the vault may hold new items), unless the user is in a menu or an item's view.
   * A change of the view (a lock, another account) builds the popup again, also while that question is open. Reading
   * the state never moves the auto-lock's deadline (`state` and `sync_state` are exempt).
   * @param {PopupView} view what is shown now
   * @param {string | null} note
   * @param {HTMLElement} syncSlot
   * @param {ReturnType<typeof createVaultList>} vault
   */
  function follow(view, note, syncSlot, vault) {
    const mine = setTimeout(async () => {
      if (refresh !== mine) return;
      refresh = null;
      /** @type {PopupView | null} */
      let next = null;
      try {
        next = await flow.load();
      } catch {
        // The background is gone for a moment: look again later.
      }
      // Something else was shown meanwhile (an action of the user wins).
      if (refresh !== null || document.body.dataset.view !== "unlocked") return;
      const step = followStep(view, next, root.querySelector('[data-role="forget-confirm"]') !== null);
      if (step === "same" || next === null) {
        follow(view, note, syncSlot, vault);
        return;
      }
      if (step === "rebuild") {
        show(next, note);
        return;
      }
      mount(syncSlot, syncPart(next, note));
      // Not the user's doing: the reload does not move the auto-lock's deadline.
      if (!vault.busy()) void vault.reload({ automatic: true }).catch(() => {});
      follow(next, note, syncSlot, vault);
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
    // The window keeps the page this popup is about.
    const page = tabId !== null ? `?tab=${tabId}` : "";
    await browser.windows.create({ url: browser.runtime.getURL(`pages/popup.html${page}`), type: "popup", width: 380, height: 620 });
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
