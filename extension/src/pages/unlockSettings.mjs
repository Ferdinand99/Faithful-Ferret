// The "Unlock" section of the settings view: the PIN (turn it on, change it, turn it off, and what is true of it), and the
// passkeys (how many are set up, what a synced passkey means, and the way to the web vault where they are managed). Only a
// build with unlock on has it: this module asks the build flag, and gives nothing in a release. The dialog that sets a PIN
// is unlockDialog.mjs; the steps with the background are unlockFlow.mjs.

import { el } from "../shared/dom.mjs";
import { FEATURES } from "../shared/features.mjs";
import { createPinDialog } from "./unlockDialog.mjs";
import { unlockErrorKey } from "./unlockFlow.mjs";

/** The feature mark on the section and on the controls the tests and the build check look for. */
const FEATURE = Object.freeze({ "data-feature": "unlock" });

/**
 * @param {ReturnType<typeof import("./unlockFlow.mjs").createUnlockFlow>} flow @param {import("./page.mjs").Texts} texts
 * @param {{ pollMs?: number }} [options]
 * @returns {{ node: HTMLElement, refresh: () => Promise<void>, wipe: () => void, checkLock: () => Promise<void>, dialog: ReturnType<typeof createPinDialog> }}
 */
function buildSection(flow, texts, { pollMs } = {}) {
  const t = (/** @type {string} */ key, /** @type {Record<string, string | number>} */ vars = {}) => texts.t(key, vars);
  /** @type {import("./unlockFlow.mjs").UnlockState | null} */
  let state = null;

  const status = el("p", { class: "ff-status", id: "unlock-pin-status", tabindex: "-1", "aria-live": "polite", "data-role": "unlock-pin-status", ...FEATURE });
  const detail = el("div", { class: "ff-hint ff-unlock-detail", "data-role": "unlock-pin-detail", ...FEATURE });
  const ruleLine = el("p", { class: "ff-hint", "data-role": "unlock-pin-rule", ...FEATURE });
  const actions = el("div", { class: "ff-actions", "data-role": "unlock-pin-actions", ...FEATURE });
  const failure = el("p", { class: "ff-error", role: "alert", "data-role": "unlock-error", hidden: true });
  const passkeyCount = el("p", { class: "ff-status", "data-role": "unlock-passkey-count", ...FEATURE });
  const manageSlot = el("div", { class: "ff-actions", "data-role": "unlock-passkey-actions", ...FEATURE });

  /** @param {string | null} key */
  const showFailure = (key) => {
    failure.textContent = key === null ? "" : t(key);
    failure.hidden = key === null;
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

  const open = (/** @type {"set" | "change"} */ mode) => {
    if (state === null || !state.pin.allowed) return;
    showFailure(null);
    actions.hidden = true;
    dialog.open({ mode, minLength: state.pin.minLength, afterRestart: state.pin.afterRestart });
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
    /** @type {HTMLElement[]} */
    const lines = [];
    if (pin.allowed && pin.set) {
      if (pin.failuresLeft > 0 && pin.failuresLeft < 5) lines.push(el("p", { "data-role": "unlock-attempts" }, t("settings.unlock.pin.status.attempts", { count: pin.failuresLeft })));
      if (pin.waitMs > 0) lines.push(el("p", { "data-role": "unlock-wait" }, t("settings.unlock.pin.status.wait", { seconds: Math.ceil(pin.waitMs / 1000) })));
      if (pin.lastContactAt !== null) lines.push(el("p", { "data-role": "unlock-contact" }, t("settings.unlock.pin.status.contact", { when: when(pin.lastContactAt) })));
      lines.push(el("p", { "data-role": "unlock-offline" }, t(pin.offlineOk ? "settings.unlock.pin.status.offline_ok" : "settings.unlock.pin.status.offline_expired")));
    }
    detail.replaceChildren(...lines);
    ruleLine.textContent = pin.allowed ? t("settings.unlock.pin.rule", { min: pin.minLength }) : "";
    ruleLine.hidden = !pin.allowed;
    actions.replaceChildren(
      ...(!pin.allowed
        ? []
        : pin.set
          ? [button("unlock-pin-change", t("settings.unlock.pin.change"), true, () => open("change")), button("unlock-pin-off", t("settings.unlock.pin.off"), false, () => void turnOff())]
          : [button("unlock-pin-on", t("settings.unlock.pin.on"), true, () => open("set"))]),
    );
    // The passkeys.
    manageSlot.replaceChildren();
    if (!prf.enabled) passkeyCount.textContent = t("settings.unlock.passkey.off");
    else {
      passkeyCount.textContent = prf.count === 0 ? t("settings.unlock.passkey.none") : t("settings.unlock.passkey.count", { count: prf.count });
      const manage = el("button", { type: "button", class: "ff-button", "data-role": "unlock-manage", ...FEATURE }, t("settings.unlock.passkey.manage"));
      manage.addEventListener("click", async () => {
        showFailure(null);
        const outcome = await flow.openVault();
        if (!outcome.ok) showFailure(unlockErrorKey(outcome.reason));
      });
      manageSlot.append(manage);
    }
  };

  async function refresh() {
    const loaded = await flow.load();
    if (!loaded.ok) {
      showFailure(unlockErrorKey(loaded.reason));
      return;
    }
    showFailure(null);
    state = loaded.state;
    render();
    // A dialog that is open for a PIN the administrator has meanwhile forbidden is closed.
    if (dialog.isOpen() && !state.pin.allowed) dialog.close("cancel");
  }

  // The page goes away (a tab closed, the popup closed): nothing typed stays in a field.
  if (typeof globalThis.addEventListener === "function") globalThis.addEventListener("pagehide", () => dialog.close("gone"));

  const node = el(
    "section",
    { class: "ff-form ff-unlock", "data-role": "unlock-section", ...FEATURE },
    el("h2", { ...FEATURE }, t("settings.unlock.title")),
    el("p", { class: "ff-lead", "data-role": "unlock-lead", ...FEATURE }, t("settings.unlock.lead")),
    el("h3", { ...FEATURE }, t("settings.unlock.pin.title")),
    el("p", { class: "ff-hint", ...FEATURE }, t("settings.unlock.pin.about")),
    status,
    detail,
    ruleLine,
    actions,
    dialog.node,
    failure,
    el("h3", { ...FEATURE }, t("settings.unlock.passkey.title")),
    passkeyCount,
    el("p", { class: "ff-hint", "data-role": "unlock-passkey-about", ...FEATURE }, t("settings.unlock.passkey.about")),
    manageSlot,
  );
  return { node, refresh, wipe: () => dialog.close("gone"), checkLock: () => dialog.checkLock(), dialog };
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
