// The "Unlock" part of the settings view, as two sub-pages: the PIN (turn it on, change it, turn it off, and what is true of it),
// and the passkeys (how many are set up and the way to the web vault where they are managed). What a PIN is worth, the rule, what a
// synced passkey means and the other long explanations are in a "More about this" on each page. Only a build with unlock on has
// them: this module asks the build flag, and gives nothing in a release. The dialog that sets a PIN is unlockDialog.mjs; the steps
// with the background are unlockFlow.mjs.

import { el } from "../shared/dom.mjs";
import { FEATURES } from "../shared/features.mjs";
import { createMore, createSummary, note } from "./settingsParts.mjs";
import { createPinDialog } from "./unlockDialog.mjs";
import { unlockErrorKey } from "./unlockFlow.mjs";

/** The feature mark on the section and on the controls the tests and the build check look for. */
const FEATURE = Object.freeze({ "data-feature": "unlock" });

/**
 * @typedef {{ id: string, title: string, icon: string, attrs: Record<string, string>, node: HTMLElement, summary: HTMLElement }} SettingsPage
 * @param {ReturnType<typeof import("./unlockFlow.mjs").createUnlockFlow>} flow @param {import("./page.mjs").Texts} texts
 * @param {{ pollMs?: number }} [options]
 * @returns {{ pages: SettingsPage[], refresh: () => Promise<void>, wipe: () => void, checkLock: () => Promise<void>, dialog: ReturnType<typeof createPinDialog> }}
 */
function buildSection(flow, texts, { pollMs } = {}) {
  const t = (/** @type {string} */ key, /** @type {Record<string, string | number>} */ vars = {}) => texts.t(key, vars);
  /** @type {import("./unlockFlow.mjs").UnlockState | null} */
  let state = null;

  const status = el("p", { class: "ff-status", id: "unlock-pin-status", tabindex: "-1", "aria-live": "polite", "data-role": "unlock-pin-status", ...FEATURE });
  const detail = el("div", { class: "ff-hint ff-unlock-detail", "data-role": "unlock-pin-detail", ...FEATURE });
  const moreDetail = el("div", { class: "ff-more-lines", "data-role": "unlock-pin-more-detail", ...FEATURE });
  const ruleLine = el("p", { class: "ff-hint", "data-role": "unlock-pin-rule", ...FEATURE });
  const actions = el("div", { class: "ff-actions", "data-role": "unlock-pin-actions", ...FEATURE });
  const chip = el("span", { class: "ff-chip", "data-role": "unlock-pin-chip", ...FEATURE }, t("settings.off"));
  const failure = el("p", { class: "ff-error", role: "alert", "data-role": "unlock-error", hidden: true });
  const passkeyFailure = el("p", { class: "ff-error", role: "alert", "data-role": "unlock-passkey-error", hidden: true });
  const passkeyCount = el("p", { class: "ff-status", "data-role": "unlock-passkey-count", ...FEATURE });
  const manageSlot = el("div", { class: "ff-actions", "data-role": "unlock-passkey-actions", ...FEATURE });
  const pinSummary = createSummary("unlock-pin-summary", FEATURE);
  const passkeySummary = createSummary("unlock-passkey-summary", FEATURE);

  /** @param {string | null} key */
  const showFailure = (key) => {
    failure.textContent = key === null ? "" : t(key);
    failure.hidden = key === null;
  };

  /** The failure of the passkeys' page. @param {string | null} key */
  const showPasskeyFailure = (key) => {
    passkeyFailure.textContent = key === null ? "" : t(key);
    passkeyFailure.hidden = key === null;
  };

  /** Where the focus goes once a button the user pressed is gone: the first button of the PIN's row, else the status line. */
  const refocus = () => {
    const first = /** @type {HTMLElement | undefined} */ (/** @type {any} */ (actions).childNodes?.[0]);
    if (first && !actions.hidden) first.focus();
    else status.focus();
  };

  const dialog = createPinDialog({
    texts,
    flow,
    pollMs,
    onLate: () => void refresh(),
    onDone: ({ mode }) => {
      status.textContent = t(mode === "change" ? "settings.unlock.pin.done.change" : "settings.unlock.pin.done.set");
      void refresh().then(() => {
        // The line that says what was done stays; the buttons of the new state are rendered, and one of them has the focus.
        status.textContent = t(mode === "change" ? "settings.unlock.pin.done.change" : "settings.unlock.pin.done.set");
        refocus();
      });
    },
    onClosed: (why) => {
      actions.hidden = false;
      if (why === "locked") {
        status.textContent = t("settings.unlock.locked_closed");
        showFailure(null);
      }
      if (why !== "gone") refocus();
    },
  });

  /** @param {number} ms */
  const when = (ms) => {
    try {
      return new Intl.DateTimeFormat(texts.lang, { dateStyle: "medium", timeStyle: "short" }).format(new Date(ms));
    } catch {
      return new Date(ms).toISOString();
    }
  };

  const open = async (/** @type {"set" | "change"} */ mode) => {
    if (state === null || !state.pin.allowed) return;
    showFailure(null);
    // A locked vault (the settings tab can be open while Ferret is locked) cannot set a PIN: say so before a form is offered.
    const vault = await flow.vaultState();
    if (vault === "locked" || vault === "signed_out") {
      showFailure("settings.unlock.error.vault_locked");
      return;
    }
    if (state === null || dialog.isOpen()) return;
    actions.hidden = true;
    dialog.open({ mode, minLength: state.pin.minLength, afterRestart: state.pin.afterRestart, location: state.pin.location });
  };

  const turnOff = async () => {
    showFailure(null);
    for (const button of actions.childNodes) /** @type {HTMLElement} */ (button).setAttribute("disabled", "");
    const outcome = await flow.turnOff();
    for (const pressed of actions.childNodes) /** @type {HTMLElement} */ (pressed).removeAttribute("disabled");
    if (!outcome.ok) {
      await refresh();
      showFailure(unlockErrorKey(outcome.reason));
      return;
    }
    await refresh();
    status.textContent = t("settings.unlock.pin.done.off");
    refocus();
  };

  const button = (/** @type {string} */ role, /** @type {string} */ label, /** @type {boolean} */ primary, /** @type {() => void} */ run) => {
    const node = el("button", { type: "button", class: primary ? "ff-button ff-primary" : "ff-button", "data-role": role, ...FEATURE }, label);
    node.addEventListener("click", run);
    return node;
  };

  /** Draws what is true. */
  const render = () => {
    if (state === null) return;
    const { pin, prf } = state;
    // The PIN: what is set, where, and what is left of it.
    if (!pin.allowed) status.textContent = t("settings.unlock.pin.status.forbidden");
    else if (!pin.set) status.textContent = t("settings.unlock.pin.status.none");
    else status.textContent = t(pin.location === "session" ? "settings.unlock.pin.status.session" : "settings.unlock.pin.status.disk");
    // What the user has to act on stays in sight: the tries that are left, a wait, and a PIN that has to reach the server. The
    // rest (the last contact, what works without a network) is in "More about this".
    /** @type {HTMLElement[]} */
    const lines = [];
    /** @type {HTMLElement[]} */
    const extra = [];
    if (pin.allowed && pin.set) {
      if (pin.failuresLeft > 0 && pin.failuresLeft < 5) lines.push(el("p", { "data-role": "unlock-attempts" }, t("settings.unlock.pin.status.attempts", { count: pin.failuresLeft })));
      if (pin.waitMs > 0) lines.push(el("p", { "data-role": "unlock-wait" }, t("settings.unlock.pin.status.wait", { seconds: Math.ceil(pin.waitMs / 1000) })));
      if (pin.lastContactAt !== null) extra.push(el("p", { "data-role": "unlock-contact" }, t("settings.unlock.pin.status.contact", { when: when(pin.lastContactAt) })));
      const offline = el("p", { "data-role": "unlock-offline" }, t(pin.offlineOk ? "settings.unlock.pin.status.offline_ok" : "settings.unlock.pin.status.offline_expired"));
      (pin.offlineOk ? extra : lines).push(offline);
    }
    detail.replaceChildren(...lines);
    moreDetail.replaceChildren(...extra);
    chip.textContent = t(pin.allowed && pin.set ? "settings.on" : "settings.off");
    chip.dataset.on = pin.allowed && pin.set ? "1" : "0";
    pinSummary.textContent = t(!pin.allowed ? "settings.unlock.pin.summary.forbidden" : pin.set ? "settings.on" : "settings.off");
    ruleLine.textContent = pin.allowed ? t("settings.unlock.pin.rule", { min: pin.minLength }) : "";
    ruleLine.hidden = !pin.allowed;
    actions.replaceChildren(
      ...(!pin.allowed
        ? []
        : pin.set
          ? [button("unlock-pin-change", t("settings.unlock.pin.change"), true, () => void open("change")), button("unlock-pin-off", t("settings.unlock.pin.off"), false, () => void turnOff())]
          : [button("unlock-pin-on", t("settings.unlock.pin.on"), true, () => void open("set"))]),
    );
    // The passkeys.
    manageSlot.replaceChildren();
    if (!prf.enabled) {
      passkeyCount.textContent = t("settings.unlock.passkey.off");
      passkeySummary.textContent = t("settings.off");
    } else {
      // The policy has no count (the background does not read the list for it): the number comes from the server's list,
      // and while it is not known (or cannot be read) the text says only where the passkeys are.
      const total = passkeys;
      passkeyCount.textContent = total === null ? t("settings.unlock.passkey.listed") : total === 0 ? t("settings.unlock.passkey.none") : t("settings.unlock.passkey.count", { count: total });
      passkeySummary.textContent = total === null || total === 0 ? "" : String(total);
      const manage = el("button", { type: "button", class: "ff-button", "data-role": "unlock-manage", ...FEATURE }, t("settings.unlock.passkey.manage"));
      manage.addEventListener("click", async () => {
        showPasskeyFailure(null);
        const outcome = await flow.openVault();
        if (!outcome.ok) showPasskeyFailure(unlockErrorKey(outcome.reason));
      });
      manageSlot.append(manage);
    }
  };

  /** How many passkeys the server lists, or null when that is not known. @type {number | null} */
  let passkeys = null;

  async function refresh() {
    const loaded = await flow.load();
    if (!loaded.ok) {
      showFailure(unlockErrorKey(loaded.reason));
      showPasskeyFailure(unlockErrorKey(loaded.reason));
      return;
    }
    showFailure(null);
    showPasskeyFailure(null);
    state = loaded.state;
    passkeys = null;
    render();
    if (state.prf.enabled) {
      const mine = state;
      const known = await flow.passkeyCount();
      if (state === mine) {
        passkeys = known;
        render();
      }
    }
    // A dialog that is open for a PIN the administrator has meanwhile forbidden is closed.
    if (dialog.isOpen() && !state.pin.allowed) dialog.close("cancel");
  }

  // The page goes away (a tab closed, the popup closed): nothing typed stays in a field.
  if (typeof globalThis.addEventListener === "function") globalThis.addEventListener("pagehide", () => dialog.close("gone"));

  // The PIN's page: one card (the name, the state in words, what is true of it, the buttons), the dialog that takes the card's
  // place while it is open, and the explanations in "More about this".
  const pinCard = el(
    "div",
    { class: "ff-scard ff-scard-col", "data-role": "unlock-pin-card", ...FEATURE },
    el("div", { class: "ff-scard-head", ...FEATURE }, el("span", { class: "ff-scard-title", ...FEATURE }, t("settings.unlock.pin.title")), chip),
    status,
    detail,
    actions,
  );
  const pin = el(
    "div",
    { class: "ff-spage-body ff-unlock", "data-role": "unlock-section", ...FEATURE },
    pinCard,
    dialog.node,
    failure,
    createMore(
      texts,
      [
        note(t("settings.unlock.lead"), "unlock-lead", FEATURE),
        note(t("settings.unlock.pin.about"), "unlock-pin-about", FEATURE),
        ruleLine,
        moreDetail,
      ],
      FEATURE,
    ),
  );
  // The passkeys' page: how many there are, the way to the web vault where they are managed, and what a synced one means.
  const passkeyCard = el(
    "div",
    { class: "ff-scard ff-scard-col", "data-role": "unlock-passkey-card", ...FEATURE },
    el("div", { class: "ff-scard-head", ...FEATURE }, el("span", { class: "ff-scard-title", ...FEATURE }, t("settings.unlock.passkey.title"))),
    passkeyCount,
    manageSlot,
  );
  const passkey = el(
    "div",
    { class: "ff-spage-body ff-unlock", "data-role": "unlock-passkey-section", ...FEATURE },
    passkeyCard,
    passkeyFailure,
    createMore(texts, [note(t("settings.unlock.passkey.about"), "unlock-passkey-about", FEATURE)], FEATURE),
  );
  /** @type {SettingsPage[]} */
  const pages = [
    { id: "pin", title: t("settings.unlock.pin.title"), icon: "pin", attrs: FEATURE, node: pin, summary: pinSummary },
    { id: "passkeys", title: t("settings.unlock.passkey.title"), icon: "passkey", attrs: FEATURE, node: passkey, summary: passkeySummary },
  ];
  return { pages, refresh, wipe: () => dialog.close("gone"), checkLock: () => dialog.checkLock(), dialog };
}

/**
 * The section, or null in a build without the feature (and when the flow has no unlock steps).
 * @param {{ unlock?: ReturnType<typeof import("./unlockFlow.mjs").createUnlockFlow> | null }} flow the settings flow
 * @param {import("./page.mjs").Texts} texts
 * @param {{ pollMs?: number }} [options]
 * @returns {ReturnType<typeof buildSection> | null}
 */
export function createUnlockSection(flow, texts, options) {
  return FEATURES.unlock && flow.unlock ? buildSection(flow.unlock, texts, options) : null;
}
