// The "Offer to save passwords" part of the settings view (design document, section 10.9), as two sub-pages: the page with the
// switch for the offers and the switch for the popup that opens by itself, and the page with the never list. Why Ferret asks for
// access to https pages, and the other long explanations, are in a "More about this" on the first page. Only a build with saving
// passwords on has them: this module asks the build flag, and gives nothing in a release.

import { el } from "../shared/dom.mjs";
import { FEATURES } from "../shared/features.mjs";
import { errorBox, showError } from "./page.mjs";
import { captureErrorKey } from "./settingsFlow.mjs";
import { createMore, createSummary, createSwitchRow, note } from "./settingsParts.mjs";

/** The mark every control of the feature carries, in the pages and in the rows of the main screen that open them. */
const FEATURE = Object.freeze({ "data-feature": "save" });

/**
 * @typedef {{ id: string, title: string, icon: string, attrs: Record<string, string>, node: HTMLElement, summary: HTMLElement }} SettingsPage
 */

/**
 * The pages: the switches (a button each, so the permission request runs straight from its click), why Ferret asks for access to
 * https pages, and the never list. Only built in a build with the feature on.
 * @param {ReturnType<typeof import("./settingsFlow.mjs").createSettingsFlow>} flow @param {import("./page.mjs").Texts} texts
 * @returns {{ pages: SettingsPage[], refresh: () => Promise<void> }}
 */
function buildSection(flow, texts) {
  const t = (/** @type {string} */ key, /** @type {Record<string, string | number>} */ vars = {}) => texts.t(key, vars);
  const failure = errorBox();
  failure.setAttribute("data-role", "capture-error");

  const save = createSwitchRow({ texts, role: "capture-switch", stateRole: "capture-state", title: t("capture.switch"), description: t("capture.switch.desc"), attrs: FEATURE });
  const accessNote = el("p", { class: "ff-status", "data-role": "capture-note", "aria-live": "polite", hidden: true, ...FEATURE });
  const autoOpen = createSwitchRow({ texts, role: "auto-open-switch", stateRole: "auto-open-state", title: t("capture.auto_open.switch"), description: t("capture.auto_open.desc"), attrs: FEATURE });
  autoOpen.set(true);
  const autoOpenNote = el("p", { class: "ff-status", "data-role": "auto-open-note", "aria-live": "polite", hidden: true, ...FEATURE });

  const list = el("ul", { class: "ff-never", "data-role": "never-list", ...FEATURE });
  const clear = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "ff-button", "data-role": "never-clear", ...FEATURE }, t("capture.never.clear")));
  const saveSummary = createSummary("capture-summary", FEATURE);
  const neverSummary = createSummary("never-summary", FEATURE);

  /** Shows a note, or hides it when it has no text. @param {HTMLElement} node @param {string} text */
  const say = (node, text) => {
    node.textContent = text;
    node.hidden = text === "";
  };

  /** @param {Awaited<ReturnType<typeof flow.capture.load>>} outcome */
  const render = (outcome) => {
    if (outcome.ok === false && !("on" in outcome && typeof outcome.on === "boolean")) {
      showError(failure, texts, captureErrorKey(outcome.reason));
      return;
    }
    const known = /** @type {{ on: boolean, permission?: boolean, never: string[], autoOpen?: boolean, autoOpenState?: string }} */ (outcome);
    // The popup that opens by itself: the setting, and what the browser has shown about it.
    const wantsOpen = known.autoOpen !== false;
    autoOpen.set(wantsOpen);
    say(autoOpenNote, wantsOpen && known.autoOpenState === "fails" ? t("capture.auto_open.fails") : "");
    save.set(known.on);
    saveSummary.textContent = t(known.on ? "settings.on" : "settings.off");
    // Off with the access already given (the request was answered while the popup that asked closed, as Firefox closes it when
    // the prompt opens): the next press of the switch does not ask again and finishes turning it on.
    say(accessNote, !known.on && known.permission === true ? t("capture.off_access_given") : "");
    list.replaceChildren(
      ...known.never.map((host) =>
        el(
          "li",
          { class: "ff-scard", "data-role": "never-host", ...FEATURE },
          el("span", { class: "ff-never-host", dir: "ltr" }, host),
          " ",
          el("button", { type: "button", class: "ff-button", "data-role": "never-remove", "data-host": host, "aria-label": t("capture.never.remove.label", { host }), ...FEATURE }, t("capture.never.remove")),
        ),
      ),
    );
    if (known.never.length === 0) list.replaceChildren(el("li", { class: "ff-hint", "data-role": "never-empty", ...FEATURE }, t("capture.never.empty")));
    neverSummary.textContent = known.never.length === 0 ? "" : String(known.never.length);
    clear.hidden = known.never.length === 0;
    showError(failure, texts, outcome.ok ? null : captureErrorKey(outcome.reason));
  };

  /**
   * A switch that is busy while its request runs; the focus stays on it (a button that is disabled loses it in some browsers).
   * @param {HTMLButtonElement} node @param {() => Promise<Awaited<ReturnType<typeof flow.capture.load>>>} run
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

  save.node.addEventListener("click", () => {
    const wasOn = save.isOn();
    // The permission request is made inside the click: `turnOn` calls it before it awaits anything.
    busy(save.node, () => (wasOn ? flow.capture.turnOff() : flow.capture.turnOn()));
  });
  autoOpen.node.addEventListener("click", () => {
    const wasOn = autoOpen.isOn();
    busy(autoOpen.node, () => flow.capture.setAutoOpen(!wasOn));
  });
  list.addEventListener("click", (event) => {
    const target = /** @type {HTMLElement | null} */ (/** @type {HTMLElement} */ (event.target)?.closest?.('[data-role="never-remove"]'));
    const host = target?.getAttribute("data-host");
    if (typeof host === "string") flow.capture.removeNever(host).then(render);
  });
  clear.addEventListener("click", () => {
    flow.capture.clearNever().then(render);
  });

  const offers = el(
    "div",
    { class: "ff-spage-body", "data-role": "capture-section", ...FEATURE },
    save.node,
    accessNote,
    failure,
    autoOpen.node,
    autoOpenNote,
    createMore(
      texts,
      [
        note(t("capture.why"), "capture-why", FEATURE),
        note(t("capture.idle"), "capture-idle", FEATURE),
        note(t("capture.reload"), "capture-reload", FEATURE),
        note(t("capture.auto_open.hint"), "auto-open-hint", FEATURE),
      ],
      FEATURE,
    ),
  );
  const never = el("div", { class: "ff-spage-body", "data-role": "never-section", ...FEATURE }, note(t("capture.never.short"), "never-short", FEATURE), list, clear, createMore(texts, [note(t("capture.never.hint"), "never-hint", FEATURE)], FEATURE));
  return {
    pages: [
      { id: "capture", title: t("capture.title"), icon: "save", attrs: FEATURE, node: offers, summary: saveSummary },
      { id: "never", title: t("capture.never.row"), icon: "never", attrs: FEATURE, node: never, summary: neverSummary },
    ],
    refresh: () => flow.capture.load().then(render),
  };
}

/**
 * The pages, or null in a build without the feature.
 * @param {ReturnType<typeof import("./settingsFlow.mjs").createSettingsFlow>} flow @param {import("./page.mjs").Texts} texts
 * @returns {{ pages: SettingsPage[], refresh: () => Promise<void> } | null}
 */
export function createCaptureSection(flow, texts) {
  return FEATURES.save ? buildSection(flow, texts) : null;
}
