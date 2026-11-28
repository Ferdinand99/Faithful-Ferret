// How the page was entered. The admin pages and the setup message send people
// to `/vault/login`, `/vault/reauth`, `/vault/setup` and `/vault/password`, with
//
//   ?handoff=1&challenge=<43 chars>&next=<path>   a hand-over to the admin pages
//   #token=<setup token>                          the first-administrator token
//   #invite=<43 characters of base62>             an invitation link (`/vault/setup` only)
//
// The app routes by the address fragment, so this runs once before the router
// starts: it reads what the address carried, keeps it in memory, and rewrites
// the address to `/vault/#/<page>` with `history.replaceState`, so neither the
// challenge nor a token stays in the address bar, the history or a bookmark.
// A token comes from the fragment only (never from the query string, where a
// server log or a `Referer` could show it).
//
// The rewrite of an invitation link marks the history entry with
// `JOIN_STATE` (`{ ferretJoin: true }`, nothing of the token). A reload of that
// entry, or a tab the browser discarded and brought back, then knows that it
// came from an invitation whose token is gone, and the setup page says so
// before it asks for anything (`joinLost`), instead of showing the first
// administrator's form.

const PAGES = Object.freeze(/** @type {Record<string, string>} */ ({
  "/vault/login": "login",
  "/vault/reauth": "reauth",
  "/vault/setup": "setup",
  "/vault/password": "password",
}));
const CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
const TOKEN = /^[A-Za-z0-9._~-]{1,128}$/;
/** The kit's invitation token: 43 characters of base62 (`wire.mjs` `INVITE_CHARS`). */
const INVITE = /^[0-9A-Za-z]{43}$/;
/** The mark of a history entry that held an invitation link. It holds no part of the token. */
export const JOIN_STATE = Object.freeze({ ferretJoin: true });

/**
 * @typedef {object} Entry
 * @property {string | null} page `login`, `reauth`, `setup`, `password`, or null for any other address
 * @property {{ challenge: string, next: string, purpose: "login" | "reauth" } | null} handoff a well formed hand-over request
 * @property {boolean} brokenHandoff `handoff=1` came without a usable challenge
 * @property {string | null} setupToken
 * @property {string | null} invite the token of an invitation link
 * @property {boolean} joinLost the page came from an invitation link but has no usable token: the link was not
 *   complete, or this is a reload of the page after its token was read and taken out of the address
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
  const entry = { page, handoff: null, brokenHandoff: false, setupToken: null, invite: null, joinLost: false };
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
    const invite = /^#invite=(.*)$/s.exec(location.hash);
    if (invite && INVITE.test(invite[1])) entry.invite = invite[1];
    else if (invite) entry.joinLost = true;
  }
  return entry;
}

/** @type {Entry} */
const NONE = Object.freeze({ page: null, handoff: null, brokenHandoff: false, setupToken: null, invite: null, joinLost: false });
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

/** @typedef {{ location: { pathname: string, search: string, hash: string }, history: { state?: unknown, replaceState(state: any, title: string, url: string): void } }} EntryWindow */

/** The window the entry was read from, so that the mark can be taken off again. @type {EntryWindow | null} */
let marked = null;

/** Whether a history state is the mark of an invitation link. @param {unknown} state */
const isJoinState = (state) => typeof state === "object" && state !== null && /** @type {any} */ (state).ferretJoin === true;

/** Forgets the invitation once the account it made exists, and takes the mark off the history entry. */
export function clearInvite() {
  current = { ...current, invite: null, joinLost: false };
  if (marked !== null && isJoinState(marked.history.state)) {
    const { pathname, search, hash } = marked.location;
    marked.history.replaceState(null, "", `${pathname}${search}${hash}`);
  }
  marked = null;
}

/**
 * Reads the address, keeps what it carried and rewrites the address. An
 * invitation link leaves the mark `JOIN_STATE` on the entry; the setup page of
 * a marked entry without a token is `joinLost`.
 * @param {EntryWindow} win
 * @returns {Entry}
 */
export function consumeEntry(win) {
  current = readEntry(win.location);
  const fromInvite = current.page === "setup" && (current.invite !== null || current.joinLost);
  if (current.page !== null) win.history.replaceState(fromInvite ? JOIN_STATE : null, "", `/vault/#/${current.page}`);
  else if (win.location.hash === "#/setup" && isJoinState(win.history.state)) current = { ...current, joinLost: true };
  marked = fromInvite || current.joinLost ? win : null;
  return current;
}
