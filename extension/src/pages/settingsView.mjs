// The settings view (design document, sections 7.2 and 10.9): a main screen of groups, each row an icon, a title, what is true now
// and a chevron, and a sub-page for each row with a back button at its top. The groups are "Filling and saving" (in a build with
// saving passwords on: the offers and the never list), "Unlocking" (in a build with unlock on: the PIN and the passkeys), "Passkeys on
// websites" (in a build with the passkeys feature on: the switch, and the sites that use the browser), "Security" (the lock) and "About" (the credits). A group with no row is not built, so a flag that is off leaves no trace. One module builds
// the view for both places that show it, so there is one source of the logic and of the texts: the settings page (the add-on's
// options page, pages/settings.html) and the "Settings" part of the open popup (popupTabs.mjs). It talks to the background through
// the flow it is given (settingsFlow.mjs) and never sees a key or a captured value.

import { el } from "../shared/dom.mjs";
import { createCaptureSection } from "./captureSettings.mjs";
import { createCredits } from "./credits.mjs";
import { errorBox, showError } from "./page.mjs";
import { createProviderSection } from "./providerSettings.mjs";
import { LOCK_CHOICES, choiceKey, errorKey } from "./settingsFlow.mjs";
import { createMore, createNavRow, createSummary, note } from "./settingsParts.mjs";
import { createUnlockSection } from "./unlockSettings.mjs";

/** @typedef {{ id: string, title: string, icon: string, attrs?: Record<string, string>, node: HTMLElement, summary: HTMLElement }} Page */

/**
 * Builds the view and starts reading what is true. The nodes are returned for the caller to put in its own container; the
 * values are filled in as the background answers, and `ready` settles when the first read is done.
 * @param {{ texts: import("./page.mjs").Texts, flow: ReturnType<typeof import("./settingsFlow.mjs").createSettingsFlow> }} deps
 * @returns {{ nodes: HTMLElement[], ready: Promise<void>, refresh: () => Promise<void>, wipe: () => void, open: (id: string | null) => void, current: () => string | null }}
 */
export function createSettingsView({ texts, flow }) {
  const t = (/** @type {string} */ key) => texts.t(key);

  // ---- Security: the lock.
  const select = /** @type {HTMLSelectElement} */ (
    el(
      "select",
      { id: "lock-after", class: "ff-input ff-select", "aria-describedby": "lock-after-desc", "data-role": "lock-after" },
      ...LOCK_CHOICES.map((seconds) => el("option", { value: String(seconds), "data-seconds": String(seconds) }, texts.t(choiceKey(seconds)))),
    )
  );
  const status = el("p", { class: "ff-status", "data-role": "saved", "aria-live": "polite" });
  const error = errorBox();
  error.setAttribute("data-role", "lock-error");
  const lockSummary = createSummary("lock-summary");

  /** @param {number} seconds */
  const show = (seconds) => {
    select.value = String(seconds);
    lockSummary.textContent = texts.t(choiceKey(seconds));
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

  const lockPage = el(
    "div",
    { class: "ff-spage-body", "data-role": "lock-section" },
    el(
      "div",
      { class: "ff-scard", "data-role": "lock-card" },
      el("span", { class: "ff-scard-text" }, el("label", { for: "lock-after", class: "ff-scard-title" }, t("settings.lock.label")), el("span", { class: "ff-scard-desc", id: "lock-after-desc" }, t("settings.lock.short"))),
      select,
    ),
    status,
    error,
    createMore(texts, [note(t("settings.lock.hint"), "lock-hint")]),
  );

  // Only a build with saving passwords on has these pages (the module asks the build flag).
  const capture = createCaptureSection(flow, texts);

  // Only a build with unlock on has these pages (the module asks the build flag).
  const unlock = createUnlockSection(flow, texts);

  // Only a build with the passkeys feature on has these pages (the module asks the build flag).
  const provider = createProviderSection(flow, texts);

  /** @type {Array<{ id: string, title: string, pages: Page[] }>} */
  const groups = [
    { id: "fill", title: t("settings.group.fill"), pages: capture?.pages ?? [] },
    { id: "unlock", title: t("settings.group.unlock"), pages: unlock?.pages ?? [] },
    { id: "passkeys", title: t("passkeys.settings.group"), pages: provider?.pages ?? [] },
    { id: "security", title: t("settings.group.security"), pages: [{ id: "lock", title: t("settings.lock.title"), icon: "clock", node: lockPage, summary: lockSummary }] },
    { id: "about", title: t("settings.group.about"), pages: [{ id: "credits", title: t("settings.credits.title"), icon: "info", node: createCredits(texts), summary: createSummary("credits-summary") }] },
  ].filter((group) => group.pages.length > 0);

  // ---- The screens: the main one and a page for each row. Exactly one is shown; the others stay built, so what is typed or
  // chosen in a page is as it was left when the user comes back to it (and a switch to another part of the popup keeps the page).
  /** @type {string | null} */
  let current = null;
  /** @type {Array<{ id: string, shell: HTMLElement, heading: HTMLElement, row: HTMLElement }>} */
  const screens = [];

  const main = el("div", { class: "ff-smain", "data-role": "settings-main" }, el("h1", { class: "ff-settings-title", "data-role": "settings-title" }, t("settings.title")));
  /** @type {HTMLElement[]} */
  const shells = [];

  for (const group of groups) {
    const headingId = `ff-sgroup-${group.id}`;
    const list = el("div", { class: "ff-nav-list" });
    for (const page of group.pages) {
      const row = createNavRow({ role: `settings-row-${page.id}`, icon: page.icon, title: page.title, summary: page.summary, attrs: page.attrs });
      const back = el(
        "button",
        { type: "button", class: "ff-sback", "data-role": "settings-back", "aria-label": t("settings.back") },
        el("span", { class: "ff-ico ff-ico-back", "aria-hidden": "true" }),
        t("settings.title"),
      );
      const heading = el("h2", { class: "ff-spage-title", id: `ff-spage-${page.id}`, tabindex: "-1", "data-role": "settings-page-title" }, page.title);
      const shell = el(
        "section",
        { class: "ff-spage", "aria-labelledby": `ff-spage-${page.id}`, "data-role": "settings-page", "data-page": page.id, hidden: true, ...page.attrs },
        back,
        heading,
        page.node,
      );
      row.addEventListener("click", () => open(page.id));
      back.addEventListener("click", () => open(null));
      screens.push({ id: page.id, shell, heading, row });
      shells.push(shell);
      list.append(row);
    }
    main.append(el("section", { class: "ff-sgroup", "aria-labelledby": headingId }, el("h2", { class: "ff-sgroup-title", id: headingId }, group.title), list));
  }

  /**
   * Shows a page, or the main screen (null). The focus goes to the page's heading, and back to the row that opened the page.
   * @param {string | null} id
   */
  function open(id) {
    const target = id === null ? null : (screens.find((screen) => screen.id === id) ?? null);
    const leaving = current === null ? null : (screens.find((screen) => screen.id === current) ?? null);
    current = target === null ? null : target.id;
    main.hidden = target !== null;
    for (const screen of screens) screen.shell.hidden = screen !== target;
    if (target !== null) target.heading.focus();
    else leaving?.row.focus();
  }

  const root = el("div", { class: "ff-sview", "data-role": "settings-root" }, main, ...shells);

  const refresh = async () => {
    const first = await flow.load();
    if (first.ok) show(first.seconds);
    else showError(error, texts, errorKey(first.reason));
    if (capture !== null) await capture.refresh();
    if (unlock !== null) await unlock.refresh();
    if (provider !== null) await provider.refresh();
  };
  return { nodes: [root], ready: refresh(), refresh, wipe: () => unlock?.wipe(), open, current: () => current };
}
