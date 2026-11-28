// `#/activity`: the account log (spec Fase 1 § 11, "Several accounts"). What was done to the
// account, newest first: by an administrator (with the administrator's e-mail), by a command on
// the server, by the server itself (a restore), and the sign-in codes the account redeemed. Each
// row says what happened, who did it and when; a kind this version does not know is "Other
// event". "Show older" asks for the page before the oldest row.
//
// Showing the first page is what clears the notice at an unlock: the page tells its route
// (`onShown`), which moves this browser's mark (flows/accountEvents.mjs).
//
// Nothing here is secret, and the page holds no code and no token. An administrator's e-mail
// comes from the server, checked only for its length, so every text is set with `textContent`
// and a name is shown as it is, never read as markup. An administrator whose account is gone
// has an empty name, and the row says so in words.
import { el, mount } from "../dom.mjs";
import { EVENT_KINDS } from "../flows/accountEvents.mjs";
import { codeOf, formatMoment } from "./common.mjs";
import { emptyState } from "./emptyState.mjs";

/** @typedef {import("./form.mjs").Translate} Translate */
/** @typedef {import("../flows/accountEvents.mjs").AccountEvent} AccountEvent */

/** The error codes with a text under `activity.error.`. */
const ERRORS = Object.freeze(["bad_response", "busy", "forbidden", "network", "throttled", "unauthorized"]);

/**
 * The text of an error. Only the code is used; the message of an error is never shown.
 * @param {Translate} t
 * @param {unknown} error
 */
export function activityErrorText(t, error) {
  const code = codeOf(error);
  return t(ERRORS.includes(code) ? `activity.error.${code}` : "activity.error.unknown");
}

/**
 * Who caused an event, in words.
 * @param {Translate} t
 * @param {AccountEvent} event
 */
export function actorText(t, event) {
  if (event.actor === "admin") return event.actor_name === "" ? t("activity.who.admin_gone") : t("activity.who.admin", { name: event.actor_name });
  if (event.actor === "server_command") return t("activity.who.server_command");
  if (event.actor === "account") return t("activity.who.account");
  return t("activity.who.server");
}

/**
 * @param {{
 *   t: Translate,
 *   load: (before?: number) => Promise<{ events: AccountEvent[], more: boolean }>,
 *   onShown?: (events: AccountEvent[]) => Promise<void> | void,
 *   locale?: string,
 * }} options `load` reads a page (the newest, or the one before an id); `onShown` is told the first page once it is
 *   on screen
 * @returns {HTMLElement}
 */
export function activityView({ t, load, onShown, locale }) {
  const root = el("section", { class: "card activity-page", "data-role": "activity-page" });
  const status = el("p", { class: "status", role: "status", "data-role": "activity-status" });
  const errorBox = el("p", { class: "error", role: "alert", "data-role": "activity-error" });
  errorBox.hidden = true;
  const retryBox = el("div", { class: "actions" });
  const list = el("ul", { class: "activity-list", "data-role": "activity-list" });
  const moreBox = el("div", { class: "actions" });
  /** The oldest id on the page, for the next page. @type {number | null} */
  let oldest = null;
  let shown = false;

  /** @param {unknown} error */
  function showError(error) {
    mount(errorBox, document.createTextNode(activityErrorText(t, error)));
    errorBox.hidden = false;
  }

  /** @param {AccountEvent} event */
  function rowView(event) {
    const kind = EVENT_KINDS.includes(event.kind) ? event.kind : "other";
    const when = formatMoment(event.at * 1000, locale);
    return el("li", { class: "activity-row", "data-role": "activity-row", "data-kind": kind },
      el("strong", { "data-role": "activity-what" }, t(`activity.kind.${kind}`)),
      el("p", { class: "activity-who", "data-role": "activity-who" }, actorText(t, event)),
      el("p", { class: "activity-when", "data-role": "activity-when" }, when ?? t("activity.when_unknown")));
  }

  /** @param {boolean} more */
  function showMore(more) {
    if (!more || oldest === null) {
      mount(moreBox);
      return;
    }
    const button = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-secondary", "data-role": "activity-more" }, t("activity.more")));
    button.addEventListener("click", async () => {
      button.disabled = true;
      errorBox.hidden = true;
      try {
        const page = await load(/** @type {number} */ (oldest));
        for (const event of page.events) list.appendChild(rowView(event));
        oldest = page.events.at(-1)?.id ?? oldest;
        showMore(page.more && page.events.length > 0);
      } catch (error) {
        showError(error);
        button.disabled = false;
      }
    });
    mount(moreBox, button);
  }

  async function first() {
    errorBox.hidden = true;
    mount(retryBox);
    mount(status, document.createTextNode(t("activity.loading")));
    /** @type {{ events: AccountEvent[], more: boolean }} */
    let page;
    try {
      page = await load();
    } catch (error) {
      mount(status);
      showError(error);
      const retry = el("button", { type: "button", class: "btn btn-secondary", "data-role": "activity-retry" }, t("activity.retry"));
      retry.addEventListener("click", () => first());
      mount(retryBox, retry);
      return;
    }
    mount(status);
    mount(list, ...page.events.map(rowView));
    if (page.events.length === 0) {
      list.appendChild(el("li", { "data-role": "activity-empty" }, emptyState({ role: "activity-empty-state", icon: "account", text: t("activity.empty") })));
    }
    oldest = page.events.at(-1)?.id ?? null;
    showMore(page.more);
    if (!shown) {
      shown = true;
      try {
        await onShown?.(page.events);
      } catch {
        // Not kept: the notice comes back at the next unlock, which is the safe way to fail.
      }
    }
  }

  mount(root,
    el("h1", null, t("activity.heading")),
    el("p", { "data-role": "activity-intro" }, t("activity.intro")),
    el("p", { class: "help", "data-role": "activity-notice-help" }, t("activity.notice_help")),
    status,
    errorBox,
    retryBox,
    list,
    moreBox);
  void first();
  return root;
}
