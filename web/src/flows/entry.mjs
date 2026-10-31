// How the page was entered. The admin pages and the setup message send people
// to `/vault/login`, `/vault/reauth`, `/vault/setup` and `/vault/password`, with
//
//   ?handoff=1&challenge=<43 chars>&next=<path>   a hand-over to the admin pages
//   #token=<setup token>                          the first-administrator token
//
// The app routes by the address fragment, so this runs once before the router
// starts: it reads what the address carried, keeps it in memory, and rewrites
// the address to `/vault/#/<page>` with `history.replaceState`, so neither the
// challenge nor the token stays in the address bar, the history or a bookmark.
// The token comes from the fragment only (never from the query string, where a
// server log or a `Referer` could show it).

const PAGES = Object.freeze(/** @type {Record<string, string>} */ ({
  "/vault/login": "login",
  "/vault/reauth": "reauth",
  "/vault/setup": "setup",
  "/vault/password": "password",
}));
const CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
const TOKEN = /^[A-Za-z0-9._~-]{1,128}$/;

/**
 * @typedef {object} Entry
 * @property {string | null} page `login`, `reauth`, `setup`, `password`, or null for any other address
 * @property {{ challenge: string, next: string, purpose: "login" | "reauth" } | null} handoff a well formed hand-over request
 * @property {boolean} brokenHandoff `handoff=1` came without a usable challenge
 * @property {string | null} setupToken
 */

/**
 * A `next` that is a path on the admin origin, else `/`. The server cleans it
 * again; this only keeps an obviously foreign value from being used at all.
 * @param {unknown} next
 * @returns {string}
 */
export function plainNext(next) {
  if (typeof next !== "string") return "/";
  if (!next.startsWith("/") || next.startsWith("//") || /[\\\s\u0000-\u001f\u007f]/.test(next)) return "/";
  if (next.length > 512) return "/";
  return next;
}

/**
 * @param {{ pathname: string, search: string, hash: string }} location
 * @returns {Entry}
 */
export function readEntry(location) {
  const path = location.pathname.length > 1 ? location.pathname.replace(/\/+$/, "") : location.pathname;
  const page = Object.hasOwn(PAGES, path) ? PAGES[path] : null;
  /** @type {Entry} */
  const entry = { page, handoff: null, brokenHandoff: false, setupToken: null };
  if (page === "login" || page === "reauth") {
    const params = new URLSearchParams(location.search);
    if (params.get("handoff") === "1") {
      const challenge = params.get("challenge");
      if (challenge !== null && CHALLENGE.test(challenge)) {
        entry.handoff = { challenge, next: plainNext(params.get("next")), purpose: page };
      } else {
        entry.brokenHandoff = true;
      }
    }
  }
  if (page === "setup") {
    const match = /^#token=([^&]*)$/.exec(location.hash);
    if (match && TOKEN.test(match[1])) entry.setupToken = match[1];
  }
  return entry;
}

/** @type {Entry} */
const NONE = Object.freeze({ page: null, handoff: null, brokenHandoff: false, setupToken: null });
/** @type {Entry} */
let current = NONE;

/** The entry that was read at start (or none). */
export function getEntry() {
  return current;
}

/** Forgets the setup token once it has been used. */
export function clearSetupToken() {
  current = { ...current, setupToken: null };
}

/**
 * Reads the address, keeps what it carried and rewrites the address.
 * @param {{ location: { pathname: string, search: string, hash: string }, history: { replaceState(state: any, title: string, url: string): void } }} win
 * @returns {Entry}
 */
export function consumeEntry(win) {
  current = readEntry(win.location);
  if (current.page !== null) win.history.replaceState(null, "", `/vault/#/${current.page}`);
  return current;
}
