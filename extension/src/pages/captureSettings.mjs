// The "Offer to save passwords" section of the settings page (design document, section 10.9): the switch, why Ferret asks
// for access to https pages, and the never list. Only a build with saving passwords on has it: this module asks the
// build flag, and gives nothing in a release.

import { el } from "../shared/dom.mjs";
import { FEATURES } from "../shared/features.mjs";
import { errorBox, showError } from "./page.mjs";
import { captureErrorKey } from "./settingsFlow.mjs";

/**
 * The section: the switch (a button, so the permission request runs straight from its click), why Ferret
 * asks for access to https pages, and the never list. Only built in a build with the feature on.
 * @param {ReturnType<typeof import("./settingsFlow.mjs").createSettingsFlow>} flow @param {import("./page.mjs").Texts} texts
 * @returns {{ node: HTMLElement, refresh: () => Promise<void> }}
 */
function buildSection(flow, texts) {
  const failure = errorBox();
  const toggle = /** @type {HTMLButtonElement} */ (
    el("button", { type: "button", class: "ff-button ff-primary", role: "switch", "aria-checked": "false", "data-role": "capture-switch", "data-feature": "save" }, texts.t("capture.switch"))
  );
  const state = el("p", { class: "ff-status", "data-role": "capture-state", "data-feature": "save", "aria-live": "polite" });
  const list = el("ul", { class: "ff-list", "data-role": "never-list", "data-feature": "save" });
  const clear = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "ff-button", "data-role": "never-clear", "data-feature": "save" }, texts.t("capture.never.clear")));

  /** @param {Awaited<ReturnType<typeof flow.capture.load>>} outcome */
  const render = (outcome) => {
    if (outcome.ok === false && !("on" in outcome && typeof outcome.on === "boolean")) {
      showError(failure, texts, captureErrorKey(outcome.reason));
      return;
    }
    const known = /** @type {{ on: boolean, never: string[] }} */ (outcome);
    toggle.setAttribute("aria-checked", known.on ? "true" : "false");
    toggle.dataset.on = known.on ? "1" : "0";
    state.textContent = texts.t(known.on ? "capture.on" : "capture.off");
    list.replaceChildren(
      ...known.never.map((host) =>
        el(
          "li",
          { "data-role": "never-host" },
          el("span", { dir: "ltr" }, host),
          " ",
          el("button", { type: "button", class: "ff-button", "data-role": "never-remove", "data-host": host, "aria-label": texts.t("capture.never.remove.label", { host }) }, texts.t("capture.never.remove")),
        ),
      ),
    );
    if (known.never.length === 0) list.replaceChildren(el("li", { class: "ff-hint", "data-role": "never-empty" }, texts.t("capture.never.empty")));
    clear.hidden = known.never.length === 0;
    showError(failure, texts, outcome.ok ? null : captureErrorKey(outcome.reason));
  };

  toggle.addEventListener("click", () => {
    const wasOn = toggle.getAttribute("aria-checked") === "true";
    toggle.disabled = true;
    // The permission request is made inside the click: `turnOn` calls it before it awaits anything.
    (wasOn ? flow.capture.turnOff() : flow.capture.turnOn()).then(render).finally(() => {
      toggle.disabled = false;
    });
  });
  list.addEventListener("click", (event) => {
    const target = /** @type {HTMLElement | null} */ (/** @type {HTMLElement} */ (event.target)?.closest?.('[data-role="never-remove"]'));
    const host = target?.getAttribute("data-host");
    if (typeof host === "string") flow.capture.removeNever(host).then(render);
  });
  clear.addEventListener("click", () => {
    flow.capture.clearNever().then(render);
  });

  const node = el(
    "section",
    { class: "ff-form", "data-role": "capture-section", "data-feature": "save" },
    el("h2", { "data-feature": "save" }, texts.t("capture.title")),
    el("p", { class: "ff-lead", "data-role": "capture-why", "data-feature": "save" }, texts.t("capture.why")),
    toggle,
    state,
    el("p", { class: "ff-hint", "data-role": "capture-reload", "data-feature": "save" }, texts.t("capture.reload")),
    failure,
    el("h3", { "data-feature": "save" }, texts.t("capture.never.title")),
    el("p", { class: "ff-hint", "data-feature": "save" }, texts.t("capture.never.hint")),
    list,
    clear,
  );
  return { node, refresh: () => flow.capture.load().then(render) };
}


/**
 * The section, or null in a build without the feature.
 * @param {ReturnType<typeof import("./settingsFlow.mjs").createSettingsFlow>} flow @param {import("./page.mjs").Texts} texts
 * @returns {{ node: HTMLElement, refresh: () => Promise<void> } | null}
 */
export function createCaptureSection(flow, texts) {
  return FEATURES.save ? buildSection(flow, texts) : null;
}
