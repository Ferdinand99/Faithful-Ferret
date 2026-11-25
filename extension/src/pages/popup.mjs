// The popup (design document, sections 7.2, 8.5, 8.6, 10.3.1 and 10.6). It
// shows whether a device is signed in, unlocks it with the master password,
// locks it with the button in the header, shows what the sync found (its state,
// a stop with "Try again" and "Forget this server", "Accept the older state"
// for a restored server (olderState.mjs), and the warnings), and, while the
// vault is open, the list of the vault (popupList.mjs): the candidates of the
// page with "Fill", the favourites and all items, search, a filter by type,
// copying and one item's view. In a build with saving from the extension on,
// the sync's part also shows the changes that wait and the items that need the
// user, with their conflict cards (conflictCard.mjs), and the open popup has the
// vault, the generator and the settings as its parts (popupTabs.mjs, generatorView.mjs, settingsView.mjs), and the offers
// to save or update a password that wait for the page above them (offerCards.mjs). The
// views are in popupFlow.mjs; this file builds them with `el()`.
//
// The page the popup is about is the active tab of the window it was opened
// from. A popup that was popped out into a window of its own keeps that tab
// (`?tab=<id>` in its address); a popup page opened as a tab of its own has no
// page, so it offers nothing to fill.
//
// The first sign-in never happens here: Firefox closes the popup when a
// permission is asked for, so it is done in the sign-in tab.
//
// In a build with unlock on, a locked popup of a device that has a PIN (set, and allowed by the administrator) shows the PIN's
// field first (pinUnlockView.mjs), with "Use master password instead" always there; the master password's form is the same
// as in a build without the feature, which asks the background nothing about a PIN.

import { FEATURES } from "../shared/features.mjs";
import { el, mount } from "../shared/dom.mjs";
import { createSyncAttention, createSyncItems } from "./conflictCard.mjs";
import { createGeneratorFlow, createGeneratorView, createOptionsStore } from "./generatorView.mjs";
import { createOfferFlow, createOfferSection } from "./offerCards.mjs";
import { createOlderPanel } from "./olderState.mjs";
import { errorBox, field, loadTexts, showError, translateStatic } from "./page.mjs";
import { createPinUnlockPart } from "./pinUnlockView.mjs";
import {
  createListFlow, createOlderFlow, createPopupFlow, createSyncItemsFlow, followStep, forgetBodyKey, statusKey, stopKey, warningKey,
} from "./popupFlow.mjs";
import { createVaultList } from "./popupList.mjs";
import { createPopupTabs } from "./popupTabs.mjs";
import { createSettingsFlow } from "./settingsFlow.mjs";
import { createSettingsView } from "./settingsView.mjs";
import { UiError, connectUi, initialsOf, reasonKey } from "./ui.mjs";

/** @typedef {import("./page.mjs").Texts} Texts */
/** @typedef {import("./popupFlow.mjs").PopupView} PopupView */

/** How often an open popup asks for the sync's state again (a poll of it does not move the lock's deadline). */
const SYNC_REFRESH_MS = 1500;

/** How often an open popup looks for an offer that arrived after it opened. */
const OFFER_REFRESH_MS = 1000;

/** The feature mark on the controls of the PIN unlock that this page builds (the build's own checks look for it). */
const UNLOCK_MARK = Object.freeze({ "data-feature": "unlock" });

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
  const olderFlow = createOlderFlow(ui.request);
  const itemsFlow = FEATURES.save ? createSyncItemsFlow(ui.request) : null;
  const generatorFlow = FEATURES.save ? createGeneratorFlow(ui.request) : null;
  const generatorStore = FEATURES.save ? createOptionsStore(browser.storage.local) : null;
  const offerFlow = FEATURES.save ? createOfferFlow(ui.request) : null;
  // The settings' part of the popup is the settings page's view. A permission request must come from the click that turns the
  // switch on (the flow calls it first, before it awaits anything). Firefox closes the popup when the prompt opens: the answer
  // then goes nowhere, but a permission that was given stays given, and the switch says so the next time (see captureSettings.mjs).
  const settingsFlow = createSettingsFlow(ui.request, {
    requestPermission: (wanted) => browser.permissions.request(wanted),
    openTab: (url) => browser.tabs.create({ url }),
  });
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
  /** What to empty before the view is built again or the popup closes. @type {(() => void) | null} */
  let teardown = null;
  /** Counts the views shown; a locked view that waits for the answer about the PIN is dropped when another one came. */
  let shown = 0;
  window.addEventListener("pagehide", () => teardown?.());

  /**
   * @param {PopupView} view
   * @param {string | null} [note] the i18n key of a note under a stop of the sync
   */
  function show(view, note = null) {
    shown += 1;
    if (refresh !== null) clearTimeout(refresh);
    refresh = null;
    // Whatever the last view held that must not outlive it (a password the user chose to show on an offer card) is emptied
    // before the next one is built, also when the next one is the locked view.
    teardown?.();
    teardown = null;
    header(view);
    if (view.view === "signed_out") return signedOut(view);
    if (view.view === "locked") return locked(view);
    return unlocked(view, note);
  }

  /**
   * "Forget this server": a button, then a question with its two answers. The question names the changes that were never
   * sent and an account another address of the server keeps, with the web vault's words. Only the server the popup
   * shows is forgotten.
   * @param {PopupView} view
   */
  function forgetPart(view) {
    const box = el("div", { class: "ff-forget", "data-role": "forget" });
    const start = el("button", { type: "button", class: "ff-button", "data-role": "sync-action", "data-action": "forget" }, texts.t("sync.action.forget"));
    start.addEventListener("click", async () => {
      start.setAttribute("disabled", "");
      const preview = await flow.forgetPreview(view.server);
      start.removeAttribute("disabled");
      ask(preview);
    });
    mount(box, start);
    /** @param {{ pending: number, shared: boolean } | null} preview */
    function ask(preview) {
      const error = errorBox();
      const confirm = el("button", { type: "button", class: "ff-button ff-danger", "data-role": "forget-confirm" }, texts.t("sync.forget.confirm"));
      const cancel = el("button", { type: "button", class: "ff-button", "data-role": "forget-cancel" }, texts.t("sync.forget.cancel"));
      cancel.addEventListener("click", () => mount(box, start));
      confirm.addEventListener("click", async () => {
        confirm.setAttribute("disabled", "");
        cancel.setAttribute("disabled", "");
        showError(error, texts, null);
        try {
          const { result, view: next } = await flow.forget(view.server, preview?.pending ?? null);
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
        el("p", { "data-role": "forget-text", "data-body": forgetBodyKey(preview) }, texts.t(forgetBodyKey(preview), { count: preview?.pending ?? 0 })),
        el("div", { class: "ff-actions" }, confirm, cancel),
        error,
      );
      cancel.focus();
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
        view.ended !== undefined ? el("p", { class: "ff-notice", "data-role": "signed-out-reason" }, texts.t(`sync.ended.${view.ended}`)) : null,
        el("p", null, texts.t("session.popup.signed_out_hint")),
        open,
        view.server !== "" ? forgetPart(view) : null,
      ),
    );
  }

  /**
   * The locked view. The master password's form is shown at once. In a build with unlock on the background is also asked
   * whether a PIN is set and allowed; when the answer comes, however late (it may wait for the server), the PIN's field is
   * added. The master password is always one click away. A build with unlock off asks nothing.
   * @param {PopupView} view
   */
  function locked(view) {
    const mounted = mountLocked(view);
    if (!FEATURES.unlock) return;
    const mine = shown;
    void flow.pinPolicy().then((offer) => {
      // Another view was shown meanwhile (a sign-out, a sync that unlocked): the answer is for a view that is gone.
      if (offer !== null && mine === shown) mounted.addPin(offer);
    });
    // The passkey button, when the server offers passkeys and the account has one: the answer needs the network, so it is
    // added when it comes.
    void flow.passkeyOffer().then((offered) => {
      if (offered && mine === shown) mounted.addPasskey();
    });
  }

  /**
   * Builds the locked view and shows it. `addPin` adds the PIN's part to it.
   * @param {PopupView} view
   */
  function mountLocked(view) {
    const password = field({ id: "password", label: texts.t("session.password"), role: "password", type: "password", autocomplete: "current-password" });
    const secretKey = field({ id: "sk", label: texts.t("session.sk.code"), role: "sk-code", autocomplete: "off" });
    secretKey.row.hidden = true;
    const error = errorBox();
    const submit = el("button", { type: "submit", class: "ff-button ff-primary", "data-role": "unlock" }, texts.t("session.unlock.submit"));
    // A build with unlock on keeps the button in a row that "Use PIN instead" joins when a PIN is offered; without it the form is as it was.
    const actions = FEATURES.unlock ? el("div", { class: "ff-actions" }, submit) : null;
    const form = el("form", { class: "ff-form", "data-role": "unlock-form" }, password.row, secretKey.row, actions ?? submit, error);
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
    // What must not outlive the view: a PIN that was typed and not sent (set when the PIN's part is added).
    teardown = null;
    // The passkey button is outside the form (the PIN's part hides the form), and hidden until the background says a passkey can be used.
    const passkeyButton = el("button", { type: "button", class: "ff-button", "data-role": "unlock-passkey", ...UNLOCK_MARK }, texts.t("passkey.button"));
    const passkeyError = errorBox();
    const passkeyRow = el("div", { class: "ff-actions", "data-role": "passkey-actions", hidden: true, ...UNLOCK_MARK }, passkeyButton, passkeyError);
    passkeyButton.addEventListener("click", async () => {
      showError(passkeyError, texts, null);
      // The window opens in its own browser window; the popup closes by itself when that one takes the focus.
      if (!(await flow.openPasskeyWindow())) showError(passkeyError, texts, "passkey.error.prf_unavailable");
    });
    mount(
      root,
      el(
        "section",
        { class: "ff-panel", "data-role": "locked-view" },
        el("h1", null, texts.t("session.popup.locked")),
        where(view),
        form,
        passkeyRow,
        view.server !== "" ? forgetPart(view) : null,
      ),
    );
    password.input.focus();

    /**
     * Adds the PIN's part (a build with unlock on, when the background says a PIN is set and allowed). It takes the place
     * of the master password's form, unless the person has already started typing there: then the form stays and only
     * "Use PIN instead" is added. "Use master password instead" brings the form back, "Use PIN instead" the PIN's part.
     * @param {import("./popupFlow.mjs").PinOffer} offer
     */
    function addPin(offer) {
      if (actions === null || teardown !== null) return;
      const usePin = el("button", { type: "button", class: "ff-button", "data-role": "use-pin", ...UNLOCK_MARK }, texts.t("unlock.pin.use_pin"));
      /** @type {ReturnType<typeof createPinUnlockPart>} */
      const pin = createPinUnlockPart({
        texts,
        flow,
        offer,
        onDone: (next) => show(next),
        onUseMaster: () => {
          pin?.root.setAttribute("hidden", "");
          form.hidden = false;
          password.input.focus();
        },
        // The PIN cannot be tried again (it is gone, or this device cannot check it): the master password stays, with the
        // reason in it, and nothing offers the PIN again in this view.
        onEnded: (message) => {
          pin?.wipe();
          pin?.root.setAttribute("hidden", "");
          usePin.setAttribute("hidden", "");
          form.hidden = false;
          error.textContent = message;
          error.hidden = false;
          password.input.focus();
        },
      });
      if (pin === null) return;
      usePin.addEventListener("click", () => {
        password.input.value = "";
        secretKey.input.value = "";
        form.hidden = true;
        pin.root.removeAttribute("hidden");
        pin.focus();
      });
      actions.append(usePin);
      form.before(pin.root);
      teardown = () => pin.wipe();
      // A submit empties the fields before it awaits the answer, so a form that is busy has been typed in too: a policy
      // answer that lands in the middle of a master password unlock must not hide the form its error is going to be in.
      if (password.input.value !== "" || secretKey.input.value !== "" || form.getAttribute("aria-busy") === "true") {
        // Typing has started in the master password's form: it is not taken away.
        pin.root.setAttribute("hidden", "");
        return;
      }
      form.hidden = true;
      pin.focus();
    }

    /** Shows the passkey button (a build with unlock on, when the background says a passkey can unlock this vault). */
    function addPasskey() {
      if (FEATURES.unlock) passkeyRow.hidden = false;
    }

    return { addPin, addPasskey };
  }

  /**
   * Shows a panel in the sync's part (accepting an older state, the items that need the user), in place of what it
   * shows; closing the panel shows the popup as the background reports it then.
   * @param {HTMLElement} slot
   * @param {(close: () => void) => HTMLElement} make
   */
  function panel(slot, make) {
    const close = () => {
      void flow.load().then(
        (next) => show(next),
        () => {},
      );
    };
    mount(slot, make(close));
  }

  /**
   * What the sync shows: its state, a stop with its ways on, and the warnings; in a build with saving on, also the
   * changes that wait and the items that need the user. Nothing here names an item.
   * @param {PopupView} view
   * @param {string | null} note the i18n key of a note under the stop (an answer to "Try again"), or null
   * @param {HTMLElement} slot where the sync's part is shown (a panel takes its place)
   */
  function syncPart(view, note, slot) {
    const sync = view.sync;
    const halted = sync?.halted ?? null;
    const box = el("div", { class: "ff-sync", "data-role": "sync", "data-state": halted !== null ? "halted" : (sync?.status ?? "starting"), "data-live": sync?.live ?? "offline" });
    if (sync === null || !sync.running) return box;
    if (halted !== null) {
      const noteBox = errorBox();
      const actions = el("div", { class: "ff-actions", "data-role": "sync-actions" });
      for (const action of sync.actions) {
        if (action === "accept_older") {
          const button = el("button", { type: "button", class: "ff-button ff-primary", "data-role": "sync-action", "data-action": "accept_older" }, texts.t("sync.action.accept_older"));
          button.addEventListener("click", () => panel(slot, (close) => createOlderPanel({ texts, flow: olderFlow, onClose: close }).root));
          actions.append(button);
        } else if (action === "try_again") {
          const button = el("button", { type: "button", class: sync.actions[0] === "try_again" ? "ff-button ff-primary" : "ff-button", "data-role": "sync-action", "data-action": "try_again" }, texts.t("sync.action.try_again"));
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
    if (FEATURES.save && itemsFlow !== null) {
      const items = itemsFlow;
      const attention = createSyncAttention({
        texts,
        sync,
        onReview: () => panel(slot, (close) => createSyncItems({ texts, flow: items, onClose: close }).root),
      });
      if (attention !== null) box.append(attention);
    }
    return box;
  }

  /**
   * The open vault: the sync's part and the list of the vault, and the account and server at the foot.
   * @param {PopupView} view
   * @param {string | null} [note] see `syncPart`
   */
  function unlocked(view, note = null) {
    const syncSlot = el("div", { class: "ff-sync-slot", "data-role": "sync-slot" });
    mount(syncSlot, syncPart(view, note, syncSlot));
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
    // The offers to save or update a password that wait for this page, above the vault (a build with saving on). An
    // answered offer may have made a new item: the list is read again.
    const offers =
      offerFlow === null
        ? null
        : createOfferSection({ texts, flow: offerFlow, tabId, onChange: () => void vault.reload({ automatic: true }).catch(() => {}) });
    // An offer that arrives while the popup is open (the browser opens no second popup) is shown here within a moment; the
    // look is not the user's doing, so it does not move the auto-lock's deadline.
    let looking = false;
    const watching =
      offers === null
        ? null
        : setInterval(() => {
            // One look at a time: a slow background does not make them pile up.
            if (looking) return;
            looking = true;
            void offers
              .refresh()
              .then((count) => {
                if (count !== null && count > 0) offers.focus();
              })
              .catch(() => {})
              .finally(() => {
                looking = false;
              });
          }, OFFER_REFRESH_MS);
    /** The settings view, once its part has been made: a lock empties what is typed in it at once. @type {ReturnType<typeof createSettingsView> | null} */
    let settingsView = null;
    teardown = () => {
      if (watching !== null) clearInterval(watching);
      offers?.hide();
      settingsView?.wipe();
    };
    // The bottom bar: the vault, in a build with saving on the generator, and the settings.
    const tabs = createPopupTabs({
      texts,
      vault: vault.root,
      // "Settings" shows the settings view in the popup itself (in every build); no tab is opened.
      makeSettings: () => {
        settingsView = createSettingsView({ texts, flow: settingsFlow });
        return el("div", { class: "ff-settings", "data-role": "settings-view" }, ...settingsView.nodes);
      },
      makeGenerator: () =>
        generatorFlow === null || generatorStore === null
          ? null
          : (createGeneratorView({
              texts,
              flow: generatorFlow,
              store: generatorStore,
              tabId,
              // A generated password that went into the page is offered at once: the card shows now.
              onOffer: () => void offers?.reload().catch(() => {}),
            })?.root ?? null),
    });
    mount(
      root,
      el(
        "section",
        { class: "ff-panel ff-unlocked", "data-role": "unlocked-view" },
        syncSlot,
        ...(offers === null ? [] : [offers.root]),
        tabs.root,
        el("footer", { class: "ff-foot" }, where(view)),
      ),
    );
    // The focus starts on the offer's heading when there is one (never on a button that writes), else on the search.
    void Promise.all([vault.reload().catch(() => {}), offers === null ? Promise.resolve(0) : offers.loaded.catch(() => 0)]).then(([, count]) => {
      if (count > 0) offers?.focus();
      else vault.focus();
    });
    follow(view, note, syncSlot, vault);
  }

  /**
   * The sync's part follows the background while the popup is open: it is built again only when what the background
   * says has changed, and not while the user answers the question of "Forget this server" or is in a panel of the
   * sync (accepting an older state, the items that need the user). The list is read again
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
      // A question or a panel the user is in (forgetting, accepting an older state, the items) is not built again.
      const step = followStep(view, next, root.querySelector('[data-role="forget-confirm"], [data-hold="1"]') !== null);
      if (step === "same" || next === null) {
        follow(view, note, syncSlot, vault);
        return;
      }
      if (step === "rebuild") {
        show(next, note);
        return;
      }
      mount(syncSlot, syncPart(next, note, syncSlot));
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
