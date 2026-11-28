// The notice at an unlock: what an administrator, a command on the server or the server did to
// the account since this browser last showed "Activity" (flows/accountEvents.mjs decides which
// events). It names the newest of them, with its time, says how many more there are, and leads
// to "Activity", which clears it. "Dismiss" hides it until the next unlock (`onDismiss`) and
// moves nothing, so the next unlock shows it again.
//
// The notice names who did it in general words ("An administrator") and never the e-mail the log
// holds: the page "Activity" shows that, as text. Every text is set with `textContent`.
import { el } from "../dom.mjs";
import { EVENT_KINDS } from "../flows/accountEvents.mjs";

/** @typedef {import("./form.mjs").Translate} Translate */
/** @typedef {import("../flows/accountEvents.mjs").AccountEvent} AccountEvent */

/** The actors with a subject of their own in a notice. */
const ACTORS = Object.freeze(["admin", "server_command", "server", "account"]);

/**
 * The day and the time of an event, short: "27.11. kl. 14:02". An event of another year names the year.
 * @param {Translate} t
 * @param {number} at seconds since 1970
 * @param {string | undefined} locale
 * @param {number} now ms since 1970
 * @returns {string}
 */
export function noticeMoment(t, at, locale, now) {
  const date = new Date(at * 1000);
  const thisYear = new Date(now).getFullYear() === date.getFullYear();
  // Norwegian writes the day and the month as numbers ("27.11."), other languages name the month.
  const numeric = typeof locale === "string" && /^(?:nb|nn|no)\b/.test(locale);
  /** @type {Intl.DateTimeFormatOptions} */
  const day = { day: "numeric", month: numeric ? "numeric" : "short", ...(thisYear ? {} : { year: "numeric" }) };
  try {
    return t("activity.notice.moment", {
      date: new Intl.DateTimeFormat(locale, day).format(date),
      clock: new Intl.DateTimeFormat(locale, { timeStyle: "short" }).format(date),
    });
  } catch {
    return t("activity.notice.moment", { date: date.toISOString().slice(0, 10), clock: date.toISOString().slice(11, 16) });
  }
}

/**
 * The sentence of one event: who did what, and when.
 * @param {Translate} t
 * @param {AccountEvent} event
 * @param {string | undefined} locale
 * @param {number} now
 */
export function noticeSentence(t, event, locale, now) {
  const kind = EVENT_KINDS.includes(event.kind) ? event.kind : "other";
  const actor = t(`activity.notice.actor.${ACTORS.includes(event.actor) ? event.actor : "server"}`);
  return t(`activity.notice.${kind}`, { actor, time: noticeMoment(t, event.at, locale, now) });
}

/**
 * The notice, or null when there is nothing to tell.
 * @param {{ t: Translate, events: readonly AccountEvent[], locale?: string, now?: number, onDismiss?: () => void }} options
 *   `events` newest first, as `unseenAdminEvents` gives them; `onDismiss` is told when "Dismiss" was pressed
 * @returns {HTMLElement | null}
 */
export function accountNoticeView({ t, events, locale, now = Date.now(), onDismiss }) {
  const newest = events[0];
  if (newest === undefined) return null;
  const sentence = noticeSentence(t, newest, locale, now);
  const text = events.length > 1 ? t("activity.notice.more", { text: sentence, count: events.length - 1 }) : sentence;
  const node = el("p", { class: "banner banner-info account-notice", role: "status", "data-role": "account-notice" },
    el("span", { "data-role": "account-notice-text" }, text), " – ",
    el("a", { href: "#/activity", "data-role": "account-notice-link" }, t("activity.notice.link")), " ");
  const dismiss = el("button", { type: "button", class: "btn btn-secondary btn-sm", "data-role": "account-notice-dismiss" }, t("activity.notice.dismiss"));
  dismiss.addEventListener("click", () => {
    node.remove();
    onDismiss?.();
  });
  node.appendChild(dismiss);
  return node;
}
