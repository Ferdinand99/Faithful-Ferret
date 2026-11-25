// The "Passkeys on websites" part of the settings view (design document § 9.4), as two sub-pages: the page with the switch "Use Ferret
// for passkeys" and the choice "Count an unlock in the last 5 minutes as verification", and the page with the sites where Ferret
// leaves passkeys to the browser (the "never" list: view, remove one, remove all; a site is added only from Ferret's own window,
// when the person chooses "Never on this site"). Why Ferret asks for access to https pages, what the browser choice does and the
// other long explanations are in a "More about this". Only a build with the passkeys feature on has them: this module asks the build
// flag, and gives nothing in a release without it. (The file is named for what it is, not for the feature: a package without the
// feature keeps it, and it builds nothing there.)

import { el } from "../shared/dom.mjs";
import { FEATURES } from "../shared/features.mjs";
import { errorBox, showError } from "./page.mjs";
import { passkeyErrorKey } from "./settingsFlow.mjs";
import { createMore, createSummary, createSwitchRow, note } from "./settingsParts.mjs";

/** The mark every control of the feature carries, in the pages and in the rows of the main screen that open them. */
const FEATURE = Object.freeze({ "data-feature": "passkeys" });

/**
 * @typedef {{ id: string, title: string, icon: string, attrs: Record<string, string>, node: HTMLElement, summary: HTMLElement }} SettingsPage
 */

/**
 * @param {ReturnType<typeof import("./settingsFlow.mjs").createSettingsFlow>} flow @param {import("./page.mjs").Texts} texts
 * @returns {{ pages: SettingsPage[], refresh: () => Promise<void> }}
 */
function buildSection(flow, texts) {
  const t = (/** @type {string} */ key, /** @type {Record<string, string | number>} */ vars = {}) => texts.t(key, vars);
  const failure = errorBox();
  failure.setAttribute("data-role", "passkeys-error");

  const use = createSwitchRow({ texts, role: "passkeys-switch", stateRole: "passkeys-state", title: t("passkeys.settings.switch"), description: t("passkeys.settings.switch.desc"), attrs: FEATURE });
  use.set(false);
  const recent = createSwitchRow({ texts, role: "passkeys-recent-switch", stateRole: "passkeys-recent-state", title: t("passkeys.settings.recent"), description: t("passkeys.settings.recent.desc"), attrs: FEATURE });
  recent.set(true);
  const accessNote = el("p", { class: "ff-status", "data-role": "passkeys-note", "aria-live": "polite", hidden: true, ...FEATURE });
  const list = el("ul", { class: "ff-never", "data-role": "passkeys-never-list", ...FEATURE });
  const clear = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "ff-button", "data-role": "passkeys-never-clear", ...FEATURE }, t("passkeys.settings.never.clear")));
  const useSummary = createSummary("passkeys-summary", FEATURE);
  const neverSummary = createSummary("passkeys-never-summary", FEATURE);

  /** Shows a note, or hides it when it has no text. @param {HTMLElement} node @param {string} text */
  const say = (node, text) => {
    node.textContent = text;
    node.hidden = text === "";
  };

  /** @param {Awaited<ReturnType<typeof flow.passkeys.load>>} outcome */
  const render = (outcome) => {
    if (outcome.ok === false && !("on" in outcome && typeof outcome.on === "boolean")) {
      showError(failure, texts, passkeyErrorKey(outcome.reason));
      return;
    }
    const known = /** @type {{ on: boolean, permission?: boolean, signedIn?: boolean, never: string[], recentUnlock: boolean }} */ (outcome);
    use.set(known.on);
    useSummary.textContent = t(known.on ? "settings.on" : "settings.off");
    recent.set(known.recentUnlock);
    // On but signed out: the scripts start when Ferret is signed in again. Off with the access already given (a grant that landed
    // while the popup that asked was closed by the prompt): the next press does not ask again.
    say(accessNote, known.on && known.signedIn === false ? t("passkeys.settings.signed_out") : !known.on && known.permission === true ? t("passkeys.settings.off_access_given") : "");
    list.replaceChildren(
      ...known.never.map((rpId) => {
        const remove = el("button", { type: "button", class: "ff-button", "data-role": "passkeys-never-remove", "data-host": rpId, "aria-label": t("passkeys.settings.never.remove.label", { host: rpId }), ...FEATURE }, t("passkeys.settings.never.remove"));
        remove.addEventListener("click", () => {
          flow.passkeys.removeNever(rpId).then(render);
        });
        return el("li", { class: "ff-scard", "data-role": "passkeys-never-host", ...FEATURE }, el("span", { class: "ff-never-host", dir: "ltr" }, rpId), " ", remove);
      }),
    );
    if (known.never.length === 0) list.replaceChildren(el("li", { class: "ff-hint", "data-role": "passkeys-never-empty", ...FEATURE }, t("passkeys.settings.never.empty")));
    neverSummary.textContent = known.never.length === 0 ? "" : String(known.never.length);
    clear.hidden = known.never.length === 0;
    showError(failure, texts, outcome.ok ? null : passkeyErrorKey(outcome.reason));
  };

  /**
   * A switch that is busy while its request runs; the focus stays on it (a button that is disabled loses it in some browsers).
   * @param {HTMLButtonElement} node @param {() => Promise<Awaited<ReturnType<typeof flow.passkeys.load>>>} run
   */
  const busy = (node, run) => {
    const focused = document.activeElement === node;
    node.disabled = true;
    run()
      .then(render)
      .finally(() => {
        node.disabled = false;
        if (focused) node.focus();
      });
  };

  use.node.addEventListener("click", () => {
    const wasOn = use.isOn();
    // The permission request is made inside the click: `turnOn` calls it before it awaits anything.
    busy(use.node, () => (wasOn ? flow.passkeys.turnOff() : flow.passkeys.turnOn()));
  });
  recent.node.addEventListener("click", () => {
    const wasOn = recent.isOn();
    busy(recent.node, () => flow.passkeys.setRecentUnlock(!wasOn));
  });
  clear.addEventListener("click", () => {
    flow.passkeys.clearNever().then(render);
  });

  const main = el(
    "div",
    { class: "ff-spage-body", "data-role": "passkeys-section", ...FEATURE },
    use.node,
    accessNote,
    failure,
    recent.node,
    createMore(
      texts,
      [
        note(t("passkeys.settings.why"), "passkeys-why", FEATURE),
        note(t("passkeys.settings.shared"), "passkeys-shared", FEATURE),
        note(t("passkeys.settings.recent.hint"), "passkeys-recent-hint", FEATURE),
        note(t("passkeys.settings.reload"), "passkeys-reload", FEATURE),
      ],
      FEATURE,
    ),
  );
  const never = el(
    "div",
    { class: "ff-spage-body", "data-role": "passkeys-never-section", ...FEATURE },
    note(t("passkeys.settings.never.short"), "passkeys-never-short", FEATURE),
    list,
    clear,
    createMore(texts, [note(t("passkeys.settings.never.hint"), "passkeys-never-hint", FEATURE)], FEATURE),
  );
  return {
    pages: [
      { id: "provider", title: t("passkeys.settings.title"), icon: "passkey", attrs: FEATURE, node: main, summary: useSummary },
      { id: "provider-never", title: t("passkeys.settings.never.row"), icon: "never", attrs: FEATURE, node: never, summary: neverSummary },
    ],
    refresh: () => flow.passkeys.load().then(render),
  };
}

/**
 * The pages, or null in a build without the feature.
 * @param {ReturnType<typeof import("./settingsFlow.mjs").createSettingsFlow>} flow @param {import("./page.mjs").Texts} texts
 * @returns {{ pages: SettingsPage[], refresh: () => Promise<void> } | null}
 */
export function createProviderSection(flow, texts) {
  return FEATURES.passkeys ? buildSection(flow, texts) : null;
}
