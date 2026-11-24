// The settings view: "Lock after", in a build with saving passwords on "Offer to save passwords" with its never list and the
// popup that opens by itself (design document, sections 7.2 and 10.9), and the credits. One module builds it for both
// places that show it, so there is one source of the logic and of the texts: the settings page (the add-on's options page,
// pages/settings.html) and the "Settings" part of the open popup (popupTabs.mjs). It talks to the background through the
// flow it is given (settingsFlow.mjs) and never sees a key or a captured value.

import { el } from "../shared/dom.mjs";
import { createCaptureSection } from "./captureSettings.mjs";
import { createCredits } from "./credits.mjs";
import { errorBox, showError } from "./page.mjs";
import { LOCK_CHOICES, choiceKey, errorKey } from "./settingsFlow.mjs";

/**
 * Builds the view and starts reading what is true. The nodes are returned for the caller to put in its own container; the
 * values are filled in as the background answers, and `ready` settles when the first read is done.
 * @param {{ texts: import("./page.mjs").Texts, flow: ReturnType<typeof import("./settingsFlow.mjs").createSettingsFlow> }} deps
 * @returns {{ nodes: HTMLElement[], ready: Promise<void>, refresh: () => Promise<void> }}
 */
export function createSettingsView({ texts, flow }) {
  const select = /** @type {HTMLSelectElement} */ (
    el(
      "select",
      { id: "lock-after", class: "ff-input", "data-role": "lock-after" },
      ...LOCK_CHOICES.map((seconds) => el("option", { value: String(seconds), "data-seconds": String(seconds) }, texts.t(choiceKey(seconds)))),
    )
  );
  const status = el("p", { class: "ff-status", "data-role": "saved", "aria-live": "polite" });
  const error = errorBox();

  /** @param {number} seconds */
  const show = (seconds) => {
    select.value = String(seconds);
  };

  select.addEventListener("change", async () => {
    status.textContent = "";
    showError(error, texts, null);
    select.disabled = true;
    const outcome = await flow.setLockSeconds(Number(select.value));
    select.disabled = false;
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

  // Only a build with saving passwords on has the section (the module asks the build flag).
  const capture = createCaptureSection(flow, texts);

  const nodes = [
    el("h1", { class: "ff-settings-title", "data-role": "settings-title" }, texts.t("settings.title")),
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
    createCredits(texts),
  ];

  const refresh = async () => {
    const first = await flow.load();
    if (first.ok) show(first.seconds);
    else showError(error, texts, errorKey(first.reason));
    if (capture !== null) await capture.refresh();
  };
  return { nodes, ready: refresh(), refresh };
}
