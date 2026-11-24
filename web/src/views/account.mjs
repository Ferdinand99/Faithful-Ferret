// `#/account`: the page every account setting hangs under. It holds no setting
// of its own. It lists the pages that say `menu: "account"` in their route (the
// routes of the build, `routes.gen.mjs`), so a page for a new setting appears here
// by adding its route file, and this file never changes for it. It also says whether
// the master password was confirmed lately, and lets the user confirm it now: a
// sensitive change asks for the password again unless that is still fresh (spec
// Fase 1 § 4.6 (a)).
//
// Nothing here is secret. The dialog that asks for the password is `reauthDialog`.
import { el, mount } from "../dom.mjs";
import { formatMoment } from "./common.mjs";

/** @typedef {import("./form.mjs").Translate} Translate */

/** The menu the pages of an account belong to. */
export const ACCOUNT_MENU = "account";

/**
 * The routes of the page that this server offers: a page that says what it `requires` (the passkeys the server has
 * to offer) is left out when the server does not have it.
 * @template {{ requires?: string }} R
 * @param {ReadonlyArray<R>} routes
 * @param {{ prf: boolean }} offered what the server offers
 * @returns {R[]}
 */
export function offeredRoutes(routes, { prf }) {
  return routes.filter((route) => route.requires === undefined || (route.requires === "prf" && prf));
}

/**
 * The routes that belong in the account menu, in the order they say (`menuOrder`, then by path). A route
 * with a parameter or a catch-all has no address a link can name, so it is left out.
 * @param {ReadonlyArray<{ path: string, title: string, menu?: string, menuOrder?: number }>} routes
 */
export function menuRoutes(routes) {
  return routes
    .filter((route) => route.menu === ACCOUNT_MENU && typeof route.path === "string" && /^\/[A-Za-z0-9_./-]*$/.test(route.path) && typeof route.title === "string")
    .sort((a, b) => (a.menuOrder ?? 100) - (b.menuOrder ?? 100) || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

/**
 * @param {{
 *   t: Translate,
 *   routes: ReadonlyArray<{ path: string, title: string, menu?: string, menuOrder?: number }>,
 *   email?: string | null,
 *   fresh?: () => number | null,
 *   reauth?: () => Promise<"ok" | "cancelled">,
 *   locale?: string,
 *   toAdmin?: () => void | Promise<void>,
 * }} options `fresh` says when the freshness of the password check ends (ms since 1970), or null. `reauth` opens the
 * dialog (`reauthDialog`) and answers how it ended; without it the page has no button. `toAdmin` starts the hand-over
 * to the admin pages; the page has a link for it only when it is given (the route gives it to an administrator of a
 * vault that has an admin address).
 * @returns {HTMLElement}
 */
export function accountView({ t, routes, email = null, fresh = () => null, reauth, locale, toAdmin }) {
  const root = el("section", { class: "card account account-page", "data-role": "account-page" });
  const status = el("p", { class: "status", role: "status", "data-role": "reauth-state" });
  const note = el("p", { class: "ok", role: "status", "data-role": "reauth-done" });
  note.hidden = true;

  function showState() {
    const until = fresh();
    const time = until === null ? null : formatMoment(until, locale);
    mount(status, document.createTextNode(time === null ? t("security.account.reauth_stale") : t("security.account.reauth_fresh", { time })));
    status.setAttribute("data-fresh", time === null ? "false" : "true");
  }
  showState();

  const pages = menuRoutes(routes);
  const list = el("ul", { class: "account-menu", "data-role": "account-menu" },
    ...pages.map((route) => el("li", null, el("a", { href: `#${route.path}`, "data-role": "account-link", "data-path": route.path }, t(route.title)))));
  const reauthRow = el("div", { class: "stack", "data-role": "reauth-row" }, el("h2", null, t("security.account.reauth_heading")), status, note);
  if (reauth) {
    const button = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-secondary", "data-role": "reauth-button" }, t("security.account.reauth_button")));
    button.addEventListener("click", async () => {
      note.hidden = true;
      button.disabled = true;
      try {
        const answer = await reauth();
        showState();
        if (answer === "ok") {
          mount(note, document.createTextNode(t("security.account.reauth_done")));
          note.hidden = false;
        }
      } finally {
        button.disabled = false;
      }
    });
    reauthRow.appendChild(el("div", { class: "actions" }, button));
  }

  /** The way to the admin pages, for an administrator. */
  let adminRow = null;
  if (toAdmin) {
    const failed = el("p", { class: "error", role: "alert", "data-role": "admin-error" }, t("account.error.admin_unconfigured"));
    failed.hidden = true;
    const link = el("button", { type: "button", class: "btn btn-secondary", "data-role": "admin" }, t("account.signedin.admin"));
    link.addEventListener("click", async () => {
      failed.hidden = true;
      try {
        await toAdmin();
      } catch {
        failed.hidden = false;
      }
    });
    adminRow = el("div", { class: "stack", "data-role": "admin-row" }, el("div", { class: "actions" }, link), failed);
  }

  // What this vault uses that others made and asked to be named for (the addresses are text: the page makes no link off this origin).
  const credits = el("div", { class: "stack", "data-role": "credits" },
    el("h2", null, t("security.account.credits_heading")),
    el("p", { "data-role": "credit-eff" }, t("security.account.credits_eff")),
    el("p", { class: "aside", "data-role": "credit-eff-source" }, t("security.account.credits_eff_source")),
    el("p", { class: "aside", "data-role": "credit-eff-licence" }, t("security.account.credits_eff_licence")));

  mount(root, ...[
    el("h1", null, t("security.account.heading")),
    email ? el("p", { "data-role": "account-email" }, t("security.account.signed_in", { email })) : null,
    el("p", null, t("security.account.intro")),
    el("h2", null, t("security.account.menu_heading")),
    pages.length > 0 ? list : el("p", { "data-role": "account-menu-empty" }, t("security.account.menu_empty")),
    reauthRow,
    adminRow,
    credits,
  ].filter((node) => node !== null));
  return root;
}
