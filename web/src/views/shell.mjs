// The frame around every vault screen: the sync status line, the banners for
// warnings and refused changes, the lock button, and `enterVault`, which every
// vault route calls first (it decides between the screen asked for and the
// unlock screen).
//
// Nothing in this file holds a secret. What a screen wants wiped when the vault
// locks is registered in a wipe scope, and the shell runs the scope before it
// puts the unlock screen in place of everything else.
import { el, mount } from "../dom.mjs";
import { autoLockFor } from "../lock.mjs";
import { createWipeScope, describeError, listenWhileShown } from "./common.mjs";
import { isBannerCode, syncBanner } from "./syncBanner.mjs";
import { unlockScreen } from "./unlock.mjs";

/** @typedef {import("./common.mjs").Translate} Translate */

// ------------------------------------------------------------------- frame

/**
 * @typedef {object} ShellOptions
 * @property {Translate} t
 * @property {any} engine the sync engine (`on`, `list`)
 * @property {any} session the account session (`onLock`)
 * @property {HTMLElement} content the screen
 * @property {() => Promise<unknown>} lock locks the vault (the idle lock's `lock`)
 * @property {() => boolean} touch marks activity; false when the vault just locked
 * @property {{ add(fn: () => void): () => void, run(): void }} scope what to wipe on lock
 * @property {() => HTMLElement} onLocked makes the unlock screen
 * @property {{ location?: { hash?: string }, addEventListener?: Function, removeEventListener?: Function }} [win] the page, for the link of the current screen
 * @property {LiveSource} [live] the live-update channel (`state`, `on`); without it the frame has no live field
 * @property {{ go(path: string): void }} [router] where the actions of the sync banner lead
 *
 * @typedef {object} LiveSource
 * @property {() => string} state
 * @property {(event: "state", fn: (state: string) => void) => () => void} on
 */

/** More conflicts than this are shown as one banner with the count. */
const MAX_CONFLICT_BANNERS = 3;

/** The states of the live-update channel that the frame has a text for. */
const LIVE_STATES = Object.freeze(["connecting", "live", "fallback", "offline", "unauthorized"]);

/**
 * @typedef {object} LiveScreen a frame (or a notice) that is built and may still be on the page
 * @property {HTMLElement} root
 * @property {{ run(): void } | null} scope
 * @property {() => void} wipe what a lock does to it
 * @property {boolean} seen it was on the page at some point
 */

/** The screens of each session that a lock must wipe. @type {WeakMap<object, Set<LiveScreen>>} */
const live = new WeakMap();

/** More screens than this cannot be on the page; the oldest are wiped and forgotten. */
const MAX_LIVE = 16;

/**
 * Remembers a screen so that a lock wipes it. Every screen that was built is
 * kept, not only the newest: a route that finishes late (two quick
 * navigations) builds its frame after a newer one, and the frame on the page
 * may be either of them. A screen that was shown and has left the page is
 * wiped and dropped here, when the next one is built.
 * @param {any} session @param {LiveScreen} screen
 */
function trackLock(session, screen) {
  let set = live.get(session);
  if (!set) {
    const made = /** @type {Set<LiveScreen>} */ (new Set());
    set = made;
    live.set(session, made);
    session.onLock?.(() => {
      const all = [...made];
      made.clear();
      for (const one of all) one.wipe();
    });
  }
  for (const one of [...set]) {
    if (/** @type {any} */ (one.root).isConnected === true) one.seen = true;
    else if (one.seen) {
      set.delete(one);
      one.scope?.run();
    }
  }
  while (set.size >= MAX_LIVE) {
    // The oldest frame that is not on the page. A frame that is on it is never dropped: a lock must reach it.
    const oldest = [...set].find((one) => /** @type {any} */ (one.root).isConnected !== true);
    if (!oldest) break;
    set.delete(oldest);
    oldest.scope?.run();
  }
  set.add(screen);
}

/**
 * The frame: a bar with the navigation, the sync status and the lock button,
 * the banners, and the screen. When the vault locks, the screen and the
 * banners are cleared and the unlock screen takes the whole frame.
 * @param {ShellOptions} options
 */
export function shellView({ t, engine, session, content, lock, touch, scope, onLocked, live, router = { go() {} }, win = /** @type {any} */ (globalThis).window }) {
  const root = el("div", { class: "vault-ui vault-shell", "data-role": "shell" });
  const status = el("span", { class: "pill sync-status", role: "status", "data-role": "sync-status" }, t("sync.state.syncing"));
  const banners = el("div", { class: "banners", "data-role": "banners" });
  const lockButton = el("button", { type: "button", class: "btn btn-secondary btn-sm i-lock", "data-role": "lock" }, t("vault.lock"));
  const navItems = el("a", { href: "#/items", "data-role": "nav-items" }, t("vault.nav.items"));
  const navNew = el("a", { href: "#/items/new", "data-role": "nav-new" }, t("vault.nav.new"));
  const nav = el("nav", { "aria-label": t("vault.nav.label") }, navItems, navNew);
  // The live-update field: a second pill beside the sync state, only when the page has the channel.
  const liveStatus = live ? el("span", { class: "pill live-status", role: "status", "data-role": "live-status" }) : null;
  const bar = el("header", { class: "vault-bar" },
    el("a", { class: "brand", href: "#/items" }, t("app.name")),
    nav,
    // With the live field, the two states share one group, so that on a phone they stack in the second row of the bar.
    liveStatus ? el("span", { class: "vault-status", "data-role": "status-group" }, status, liveStatus) : status,
    lockButton);
  const main = el("main", { class: "vault-main", "data-role": "content" }, content);
  // What the engine has found out about the server (warnings and stops) has its own banner, which follows the engine's
  // table of warnings. An engine without `health` (a stand-in in a test) has none.
  const warnings = typeof engine.health === "function" ? syncBanner({ engine, router, t }) : null;
  mount(root, ...[bar, warnings, banners, main].filter((node) => node !== null));

  /** @type {Map<string, HTMLElement>} */
  const shown = new Map();
  /** @param {string} key @param {string} kind @param {string} text */
  function banner(key, kind, text) {
    const node = el("p", { class: `banner banner-${kind}`, role: kind === "error" ? "alert" : "status", "data-role": "banner", "data-banner": key }, text);
    const dismiss = el("button", { type: "button", class: "btn btn-secondary btn-sm", "data-role": "banner-dismiss" }, t("vault.banner.dismiss"));
    dismiss.addEventListener("click", () => {
      node.remove();
      shown.delete(key);
    });
    node.appendChild(dismiss);
    shown.get(key)?.remove();
    shown.set(key, node);
    banners.appendChild(node);
  }

  /** @param {any} payload */
  function onState(payload) {
    if (payload?.kind === "warning") {
      const code = String(payload.code ?? "");
      if (warnings !== null && isBannerCode(code)) return; // the sync banner shows it
      if (/^[a-z_]{1,64}$/.test(code)) banner(`warning:${code}`, "warning", t(`sync.warning.${code}`));
      return;
    }
    const kind = String(payload?.kind ?? "");
    if (/^(?:failed|halted|idle|offline|retrying|syncing|unauthorized)$/.test(kind)) {
      mount(status, document.createTextNode(t(kind === "halted" ? "syncwarnings.pill.halted" : `sync.state.${kind}`)));
      status.setAttribute("data-state", kind);
      if (kind === "unauthorized") banner("unauthorized", "error", t("vault.banner.sign_in_again"));
    }
  }

  /** The items a conflict was reported for, so that many of them become one banner. @type {Set<string>} */
  const conflictIds = new Set();
  /** @param {any} payload */
  function onError(payload) {
    const code = String(payload?.code ?? "");
    if (warnings !== null && code === "bad_feed") return; // the sync banner shows it, with a way to try again
    // After an older state is accepted, every item that exists on the server is a conflict: there can be hundreds. The
    // first few are shown by name as before; past that they are one banner with the count, and no names.
    if (code === "restore_item_unreadable") {
      banner("error:restore_item_unreadable", "warning", t("syncwarnings.error.restore_item_unreadable"));
      return;
    }
    if (code === "conflict" && typeof payload?.id === "string") {
      conflictIds.add(payload.id);
      if (conflictIds.size > MAX_CONFLICT_BANNERS) {
        for (const [key, node] of [...shown]) {
          if (key.startsWith("error:conflict:")) {
            node.remove();
            shown.delete(key);
          }
        }
        banner("error:conflicts", "warning", t("syncwarnings.error.conflicts_many", { count: conflictIds.size }));
        return;
      }
    }
    const named = typeof payload?.id === "string" ? engine.list().find((/** @type {any} */ i) => i.id === payload.id) : null;
    const text = describeError(t, { code, reason: payload?.reason });
    banner(`error:${code}:${payload?.id ?? ""}`, "error", named ? t("vault.banner.item", { name: named.name, message: text }) : text);
  }

  // The link of the screen that is open says so (aria-current), and follows the address.
  function markCurrent() {
    const path = String(win?.location?.hash ?? "").replace(/^#/, "");
    const onNew = path === "/items/new";
    const onItems = !onNew && (path === "/items" || path.startsWith("/items/"));
    navItems.setAttribute("aria-current", onItems ? "page" : "false");
    navNew.setAttribute("aria-current", onNew ? "page" : "false");
  }
  markCurrent();
  if (typeof win?.addEventListener === "function") {
    const onHash = () => {
      // A frame that has left the page stops listening.
      if (/** @type {any} */ (root).isConnected === false) win.removeEventListener?.("hashchange", onHash);
      else markCurrent();
    };
    win.addEventListener("hashchange", onHash);
  }

  /** @param {unknown} state */
  function onLive(state) {
    if (!liveStatus) return;
    const name = typeof state === "string" && LIVE_STATES.includes(state) ? state : "offline";
    const text = t(`live.state.${name}`);
    mount(liveStatus, document.createTextNode(text));
    liveStatus.setAttribute("aria-label", t("live.label", { state: text })); // the short word needs its subject
    liveStatus.setAttribute("data-state", name);
  }
  if (live && liveStatus) {
    onLive(live.state());
    // Removed with the screen: a frame that was never put on the page (a route that finished late) must not stay
    // listening, since the listener keeps the frame, and the list it holds, alive.
    scope.add(listenWhileShown(root, live, "state", onLive));
  }

  // A frame built while the engine is stopped says so from the start.
  if (warnings !== null && engine.health().halted !== null) onState({ kind: "halted", code: engine.health().halted });
  listenWhileShown(root, engine, "state", onState);
  listenWhileShown(root, engine, "error", onError);

  // Activity: a click or a key press moves the idle time on. When the lock time
  // has passed, `touch` locks instead and the event is dropped.
  const activity = () => void touch();
  root.addEventListener("pointerdown", activity);
  root.addEventListener("keydown", activity);

  function wipe() {
    scope.run();
    shown.clear();
    // A frame that has left the page only needs to be emptied; the one on it gets the unlock screen.
    if (/** @type {any} */ (root).isConnected === false) mount(root);
    else mount(root, onLocked());
  }
  trackLock(session, { root, scope, wipe, seen: false });

  lockButton.addEventListener("click", async () => {
    await lock();
  });
  return root;
}

// ---------------------------------------------------------------- entering

/**
 * The scope of a sync engine from the open session.
 * @param {{ accountId: string, vaultId: string, vkEpoch: number }} open
 */
const scopeOf = ({ accountId, vaultId, vkEpoch }) => ({ accountId, vaultId, vkEpoch });

/**
 * What every vault route does first. It finds the account session and the sync
 * service in the container, starts the idle lock, and answers one of two ways:
 *
 * - `{ locked }`: the vault is not open. `locked` is the unlock screen (or a
 *   notice while the page goes to the sign-in page).
 * - `{ engine, sync, client, session, scope, touch, page(content) }`: the vault
 *   is open. `page` puts a screen in the frame.
 *
 * @param {import("../app.mjs").RouteContext} ctx
 */
export async function enterVault(ctx) {
  const { services, i18n, go, path } = ctx;
  const t = i18n.t;
  const session = services.crypto;
  const sync = services.sync;
  if (!session || !sync) throw new Error("vault: the account session or the sync service is missing");
  const autoLock = autoLockFor(session, sync);

  const open = session.current?.() ?? null;
  const onUnlocked = () => go(path);
  const lockedScreen = () => unlockScreen({ session, t, go, onUnlocked });
  if (!open) return { locked: lockedScreen() };

  // An open vault always has an idle lock, whatever else fails below (Spec: Fase 1 section 7.1).
  if (!autoLock.running()) autoLock.start();

  let engine = sync.current();
  if (!engine) {
    try {
      engine = await sync.start(scopeOf(open));
    } catch {
      engine = null;
    }
  }
  if (!engine) {
    // The vault stays open and the idle lock is running; the card says sync is down and offers the lock.
    const lockButton = el("button", { type: "button", class: "btn btn-secondary i-lock", "data-role": "lock" }, t("vault.lock"));
    lockButton.addEventListener("click", () => void autoLock.lock());
    const card = el("section", { class: "auth-card vault-ui", role: "alert", "data-role": "sync-unavailable" },
      el("p", null, t("vault.error.sync_unavailable")), lockButton);
    trackLock(session, { root: card, scope: null, seen: false, wipe: () => mount(card, lockedScreen()) });
    return { locked: card };
  }

  const scope = createWipeScope();
  const touch = () => autoLock.touch();
  return {
    engine,
    sync,
    client: ctx.client,
    session,
    scope,
    touch,
    /** @param {HTMLElement} content */
    page: (content) => {
      // A route that was still loading when the vault locked must not put a frame over the unlock screen.
      if (!session.current?.()) return lockedScreen();
      return shellView({ t, engine, session, content, lock: () => autoLock.lock(), touch, scope, onLocked: lockedScreen, live: services.liveSync, router: { go: ctx.go } });
    },
  };
}

/** A card with a message, for a screen that cannot be shown. @param {Translate} t @param {string} key */
export function messageCard(t, key) {
  return el("section", { class: "card", "data-role": "message" }, el("p", null, t(key)),
    el("p", null, el("a", { href: "#/items" }, t("vault.nav.items"))));
}
