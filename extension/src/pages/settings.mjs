// The settings page (design document, section 7.2): opened in a tab by the
// browser's "Preferences" button of the add-on. One setting for now, "Lock
// after", a select with the fixed choices. It talks to the background over the
// UI port like the other pages; it never sees a key.

import { el, mount } from "../shared/dom.mjs";
import { createCredits } from "./credits.mjs";
import { errorBox, loadTexts, showError, translateStatic } from "./page.mjs";
import { LOCK_CHOICES, choiceKey, createSettingsFlow, errorKey } from "./settingsFlow.mjs";
import { connectUi } from "./ui.mjs";

async function main() {
  const root = document.getElementById("root");
  if (!root) return;
  const texts = await loadTexts();
  translateStatic(document, texts);
  const ui = connectUi(browser.runtime);
  const flow = createSettingsFlow(ui.request);

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
    createCredits(texts),
  );
  document.body.dataset.ready = "1";
}

main().catch(() => {
  // The page has nothing to show without the background; it never prints what went wrong.
});
