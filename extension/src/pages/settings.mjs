// The settings page (design document, section 7.2): opened in a tab by the
// browser's "Preferences" button of the add-on. "Lock after", a select with the
// fixed choices, and, in a build with saving passwords on, "Offer to save
// passwords" with its never list (section 10.9). It talks to the background over
// the UI port like the other pages; it never sees a key or a captured value.

import { el, mount } from "../shared/dom.mjs";
import { FEATURES } from "../shared/features.mjs";
import { errorBox, loadTexts, showError, translateStatic } from "./page.mjs";
import { LOCK_CHOICES, captureErrorKey, choiceKey, createSettingsFlow, errorKey } from "./settingsFlow.mjs";
import { connectUi } from "./ui.mjs";

async function main() {
  const root = document.getElementById("root");
  if (!root) return;
  const texts = await loadTexts();
  translateStatic(document, texts);
  const ui = connectUi(browser.runtime);
  const flow = createSettingsFlow(ui.request, { requestPermission: (wanted) => browser.permissions.request(wanted) });

  const select = el(
    "select",
    { id: "lock-after", class: "ff-input", "data-role": "lock-after" },
    ...LOCK_CHOICES.map((seconds) => el("option", { value: String(seconds), "data-seconds": String(seconds) }, texts.t(choiceKey(seconds)))),
  );
  const status = el("p", { class: "ff-status", "data-role": "saved", "aria-live": "polite" });
  const error = errorBox();
  const shown = /** @type {HTMLSelectElement} */ (select);

  /** @param {number} seconds */
  const show = (seconds) => {
    shown.value = String(seconds);
  };

  const first = await flow.load();
  if (first.ok) show(first.seconds);
  else showError(error, texts, errorKey(first.reason));

  shown.addEventListener("change", async () => {
    status.textContent = "";
    showError(error, texts, null);
    shown.disabled = true;
    const outcome = await flow.setLockSeconds(Number(shown.value));
    shown.disabled = false;
    if (outcome.ok) {
      show(outcome.seconds);
      status.textContent = texts.t("settings.saved");
    } else {
      // The setting did not change: show the one the background keeps.
      const now = await flow.load();
      if (now.ok) show(now.seconds);
      showError(error, texts, errorKey(outcome.reason));
    }
  });

  // Only a build with saving passwords on has the section.
  const capture = FEATURES.save ? captureSection(flow, texts) : null;

  mount(
    root,
    el("h1", { "data-role": "settings-title" }, texts.t("settings.title")),
    el(
      "form",
      { class: "ff-form", "data-role": "settings-form" },
      el(
        "div",
        { class: "ff-field" },
        el("label", { for: "lock-after", class: "ff-label" }, texts.t("settings.lock.label")),
        select,
        el("p", { class: "ff-hint" }, texts.t("settings.lock.hint")),
      ),
      status,
      error,
    ),
    ...(capture === null ? [] : [capture.node]),
  );
  if (capture !== null) await capture.refresh();
  document.body.dataset.ready = "1";
}

/**
 * "Offer to save passwords": the switch (a button, so the permission request runs straight from its click), why Ferret
 * asks for access to https pages, and the never list. Only built in a build with the feature on.
 * @param {ReturnType<typeof createSettingsFlow>} flow @param {import("./page.mjs").Texts} texts
 * @returns {{ node: HTMLElement, refresh: () => Promise<void> }}
 */
function captureSection(flow, texts) {
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

main().catch(() => {
  // The page has nothing to show without the background; it never prints what went wrong.
});
