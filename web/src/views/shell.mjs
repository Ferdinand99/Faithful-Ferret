// The frame around every vault screen: the side menu (with the sync status, the
// account menu and Lock now), the banners for warnings and refused changes, and
// `enterVault`, which every
// vault route calls first (it decides between the screen asked for and the
// unlock screen).
//
// Nothing in this file holds a secret. What a screen wants wiped when the vault
// locks is registered in a wipe scope, and the shell runs the scope before it
// puts the unlock screen in place of everything else.
import { el, mount } from "../dom.mjs";
import { ADMIN_LANDING, configuredAdminUrl } from "../flows/adminUrl.mjs";
import { goToAdmin } from "../flows/handoff.mjs";
import { restoreNoteTools } from "../flows/restoreNote.mjs";
import { autoLockFor } from "../lock.mjs";
import { MANIFEST_ID } from "../sync/engine.mjs";
import { createWipeScope, describeError, formatMoment, listenWhileShown } from "./common.mjs";
import { menuRoutes } from "./account.mjs";
import { sidebarView } from "./sidebar.mjs";
import { countItems } from "./sidebarModel.mjs";
import { standbyView } from "./standby.mjs";
import { isBannerCode, syncBanner } from "./syncBanner.mjs";
import { unlockScreen } from "./unlock.mjs";
import { createUiPrefs } from "../uiPrefs.mjs";

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
 * @property {readonly string[]} [accountPaths] the addresses of the pages the account page lists (routes that say `menu: "account"`); the account link is marked on them and on `/account`
 * @property {StandbySource} [standby] where the tab is told that another tab took the vault; without it the frame never shows the standby notice
 * @property {ExportReminder | null} [reminder] the reminder to take a new encrypted export; without it the frame never shows one
 * @property {readonly any[]} [routes] the routes of the page; the side menu lists those that say `sidebar`
 * @property {string | null} [email] the signed-in account, for the foot of the side menu
 * @property {{ check(): Promise<boolean>, go(): void | Promise<void> }} [admin] the way to the admin pages; the switch shows only when `check` answers true
 * @property {() => Promise<void> | void} [signOut] what "Sign out" does (it leaves for the sign-in page itself, and rejects when the server could not be asked); without it the menu has no such item
 * @property {ReturnType<typeof createUiPrefs>} [prefs] what this device remembers about the menu
 * @property {readonly { id: string, name: string, parentId?: string | null }[]} [folders] the folders of the vault, for the pinned ones (the vault has none yet)
 *
 * @typedef {object} LiveSource
 * @property {() => string} state
 * @property {(event: "state", fn: (state: string) => void) => () => void} on
 *
 * @typedef {object} ExportReminder
 * @property {() => Promise<{ due: boolean, lastExportAt: number | null }>} check whether the reminder is due now
 * @property {() => Promise<void>} snooze keeps it away for a while ("Remind me later")
 *
 * @typedef {object} StandbySource
 * @property {(fn: (standby: boolean) => void) => () => void} onStandby
 * @property {(options?: { unsaved?: boolean }) => ReturnType<typeof standbyView>} card makes the notice; `unsaved` when a form is kept below it
 * @property {() => boolean} [freeze] makes the forms with edits that are not saved read-only and keeps them; answers whether there was one
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
 * The frame: the side menu (a drawer on a phone) with the navigation, the sync
 * status, the account menu and Lock now; the banners; and the screen. When the
 * vault locks, the screen and the banners are cleared and the unlock screen
 * takes the whole frame.
 * @param {ShellOptions} options
 */
export function shellView({ t, engine, session, content, lock, touch, scope, onLocked, live, standby, accountPaths = [], router = { go() {} }, reminder, routes = [], email = null, admin, signOut, prefs = createUiPrefs(), folders = [], win = /** @type {any} */ (globalThis).window }) {
  const root = el("div", { class: "vault-ui vault-shell", "data-role": "shell" });
  const status = el("span", { class: "pill sync-status", role: "status", "data-role": "sync-status" }, el("span", { class: "pill-text" }, t("sync.state.syncing")));
  const banners = el("div", { class: "banners", "data-role": "banners" });
  // The live-update field: a second pill beside the sync state, only when the page has the channel.
  const liveStatus = live ? el("span", { class: "pill live-status", role: "status", "data-role": "live-status" }) : null;
  const items = () => (typeof engine.list === "function" ? engine.list() : []);
  const chrome = sidebarView({
    t, routes, counts: countItems(items(), MANIFEST_ID), folders, prefs, email, status, liveStatus, admin, accountPaths,
    onLock: async () => {
      await lock();
    },
    onSignOut: signOut
      ? async () => {
        try {
          await signOut();
        } catch {
          // The device is signed out, but the server could not be asked to end its session: say so, in place of the page.
          mount(root, el("section", { class: "auth-card vault-ui", role: "alert", "data-role": "signout-incomplete" },
            el("p", null, t("account.error.signout_incomplete")),
            el("p", null, el("a", { href: "#/login" }, t("shell.signout.login")))));
        }
      }
      : undefined,
    win,
  });
  const main = el("main", { class: "vault-main", id: "vault-content", tabindex: "-1", "data-role": "content" }, content);
  // What the engine has found out about the server (warnings and stops) has its own banner, which follows the engine's
  // table of warnings. An engine without `health` (a stand-in in a test) has none.
  const warnings = typeof engine.health === "function" ? syncBanner({ engine, router, t }) : null;
  const body = el("div", { class: "vault-body" }, ...[warnings, banners, main].filter((node) => node !== null));
  // For a keyboard: the way past the menu, straight to the screen.
  const skip = el("button", { type: "button", class: "skip-link", "data-role": "skip" }, t("shell.skip"));
  skip.addEventListener("click", () => {
    if (typeof main.focus === "function") main.focus();
  });
  // Out of reach while the drawer is open: the screen, the skip link, and the page's own footer (outside the frame).
  const pageFoot = globalThis.document?.getElementById?.("foot") ?? null;
  chrome.setBehind([skip, body, ...(pageFoot === null ? [] : [pageFoot])]);
  // What the frame hands to the page (the window's media query, the parts it holds) is let go when the frame leaves the page or the vault locks.
  scope.add(() => chrome.dispose());
  mount(root, skip, chrome.top, el("div", { class: "vault-layout" }, chrome.side, chrome.backdrop, body));

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
    if (payload?.kind === "warning_cleared" && payload.code === "checkpoint_upload_failed") {
      // A later upload went through: the notice that it failed is withdrawn.
      shown.get("error:checkpoint_upload_failed")?.remove();
      shown.delete("error:checkpoint_upload_failed");
      return;
    }
    if (payload?.kind === "warning") {
      const code = String(payload.code ?? "");
      if (warnings !== null && isBannerCode(code)) return; // the sync banner shows it
      if (/^[a-z_]{1,64}$/.test(code)) banner(`warning:${code}`, "warning", t(`sync.warning.${code}`));
      return;
    }
    const kind = String(payload?.kind ?? "");
    if (/^(?:failed|halted|idle|offline|retrying|syncing|unauthorized)$/.test(kind)) {
      mount(status, el("span", { class: "pill-text" }, t(kind === "halted" ? "syncwarnings.pill.halted" : `sync.state.${kind}`)));
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
    // A pass found that the older state of a restored server does not check out; the engine has stopped again.
    if (code === "restore_not_verified") {
      const extra = payload?.reason === "no_checkpoint" ? ` ${t("syncwarnings.restored.not_verified_no_checkpoint")}` : "";
      banner("error:restore_not_verified", "error", `${t("syncwarnings.restored.not_verified")}${extra}`);
      return;
    }
    if (code === "restore_item_unreadable") {
      banner("error:restore_item_unreadable", "warning", t("syncwarnings.error.restore_item_unreadable"));
      return;
    }
    if (code === "checkpoint_upload_failed") {
      // Harmless: the upload is tried again later. A calm notice, one for all failures, and no code or reason on screen.
      banner("error:checkpoint_upload_failed", "warning", describeError(t, { code }));
      return;
    }
    if (code === "restore_epoch_refused") {
      // One banner however many items are waiting, and no item name: the text is about the server, not about an item.
      banner("error:restore_epoch_refused", "error", describeError(t, { code }));
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

  // The entry of the screen that is open says so (aria-current), and follows the address.
  const pathNow = () => String(win?.location?.hash ?? "").replace(/^#/, "");
  chrome.markCurrent(pathNow());
  if (typeof win?.addEventListener === "function") {
    const onHash = () => {
      // A frame that has left the page stops listening.
      if (/** @type {any} */ (root).isConnected === false) win.removeEventListener?.("hashchange", onHash);
      else chrome.markCurrent(pathNow());
    };
    win.addEventListener("hashchange", onHash);
    scope.add(() => win.removeEventListener?.("hashchange", onHash));
  }
  // The numbers beside "All items" and "Favourites" follow the items.
  scope.add(listenWhileShown(root, engine, "changed", () => chrome.setCounts(countItems(items(), MANIFEST_ID))));

  /** @param {unknown} state */
  function onLive(state) {
    if (!liveStatus) return;
    const name = typeof state === "string" && LIVE_STATES.includes(state) ? state : "offline";
    const text = t(`live.state.${name}`);
    mount(liveStatus, el("span", { class: "pill-text" }, text));
    liveStatus.setAttribute("aria-label", t("live.label", { state: text })); // the short word needs its subject
    liveStatus.setAttribute("data-state", name);
  }
  if (live && liveStatus) {
    onLive(live.state());
    // Removed with the screen: a frame that was never put on the page (a route that finished late) must not stay
    // listening, since the listener keeps the frame, and the list it holds, alive.
    scope.add(listenWhileShown(root, live, "state", onLive));
  }

  // The reminder to take a new encrypted export (spec Fase 1 § 6.4: every 30 days): one notice, with the way to the export page.
  // It is a date check and nothing else; a store that cannot answer shows no reminder.
  if (reminder) {
    let alive = true;
    scope.add(() => {
      alive = false;
    });
    void (async () => {
      try {
        const { due, lastExportAt } = await reminder.check();
        const onExport = String(win?.location?.hash ?? "").replace(/^#/, "") === "/export";
        if (!alive || !due || onExport) return;
        const date = lastExportAt === null ? null : formatMoment(lastExportAt, undefined);
        const node = el("p", { class: "banner banner-info", role: "status", "aria-label": t("export.reminder.label"), "data-role": "export-reminder" },
          date === null ? t("export.reminder.never") : t("export.reminder.text", { date }), " ",
          el("a", { href: "#/export", "data-role": "export-reminder-link" }, t("export.reminder.link")), " ");
        const later = el("button", { type: "button", class: "btn btn-secondary btn-sm", "data-role": "export-reminder-later" }, t("export.reminder.later"));
        later.addEventListener("click", async () => {
          node.remove();
          try {
            await reminder.snooze();
          } catch {
            // Not kept: the reminder comes back at the next page, which is the safe way to fail.
          }
        });
        node.appendChild(later);
        banners.appendChild(node);
      } catch {
        // No answer from the store: no reminder.
      }
    })();
  }

  // A frame built while the engine is stopped says so from the start.
  if (warnings !== null && engine.health().halted !== null) onState({ kind: "halted", code: engine.health().halted });
  // A state that the engine announced before this screen was built (a write that was refused while the page changed screens) is
  // said now: the announcement is made once, and a screen that missed it would show "Syncing" for good.
  const stood = typeof engine.status === "function" ? engine.status() : "";
  if (stood === "unauthorized" || stood === "offline" || stood === "failed") onState({ kind: stood });
  scope.add(listenWhileShown(root, engine, "state", onState));
  scope.add(listenWhileShown(root, engine, "error", onError));

  // Activity: a click or a key press moves the idle time on. When the lock time
  // has passed, `touch` locks instead and the event is dropped.
  const activity = () => void touch();
  root.addEventListener("pointerdown", activity);
  root.addEventListener("keydown", activity);
  // Escape closes the open menu or the drawer and puts the focus back on what opened it; a press elsewhere closes a menu.
  root.addEventListener("keydown", (/** @type {any} */ event) => {
    chrome.trap(event);
    if (event.key === "Escape" && chrome.escape()) event.preventDefault?.();
  });
  root.addEventListener("pointerdown", (/** @type {any} */ event) => chrome.press(event.target));

  function wipe() {
    scope.run();
    shown.clear();
    // A frame that has left the page only needs to be emptied; the one on it gets the unlock screen.
    if (/** @type {any} */ (root).isConnected === false) mount(root);
    else mount(root, onLocked());
  }
  trackLock(session, { root, scope, wipe, seen: false });

  // Another tab took the vault: this one stops showing it. The engine has stopped already (the items and the open handles are gone);
  // what is on the screen goes too, and the notice takes the whole frame.
  if (standby) {
    scope.add(listenWhileShown(root, { on: (_event, fn) => standby.onStandby(fn) }, "standby", (/** @type {boolean} */ on) => {
      if (on !== true) return;
      // A form with edits that are not saved stays on screen, read-only, under the notice (with "Take back"); the lock wipes it.
      // Anything else on the screen goes, as before.
      if (standby.freeze?.() === true) {
        const card = standby.card({ unsaved: true });
        const kept = [...main.childNodes];
        mount(main, card.root, ...kept);
        card.focus();
        return;
      }
      scope.run();
      shown.clear();
      const card = standby.card();
      mount(root, card.root);
      card.focus();
    }));
  }

  // An item that was restored over one the server had purged is a copy under a new id now (the engine's `copied`): the screen of
  // the old one moves to the copy, and the user is told once. An edit screen follows by itself (it keeps what was typed).
  scope.add(listenWhileShown(root, engine, "copied", (/** @type {any} */ payload) => {
    const from = payload?.from;
    const to = payload?.to;
    if (typeof from !== "string" || typeof to !== "string") return;
    if (String(win?.location?.hash ?? "").replace(/^#/, "") === `/items/${from}`) router.go(`/items/${to}`);
    banner(`copied:${to}`, "info", t("vault.banner.copied"));
  }));

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
  const noteTools = restoreNoteTools({ store: services.store, serverUrl: session.serverUrl });
  const lockedScreen = () => unlockScreen({ session, t, go, onUnlocked, ...noteTools, locale: i18n.lang });
  if (!open) return { locked: lockedScreen() };

  // An open vault always has an idle lock, whatever else fails below (Spec: Fase 1 section 7.1).
  if (!autoLock.running()) autoLock.start();

  // Another tab holds the vault: this tab has no engine and shows nothing from it, only the way to move it here.
  const standbyCard = (/** @type {{ unsaved?: boolean }} */ options = {}) => standbyView({
    t, sync, onTaken: () => go(path), lock: () => autoLock.lock(), touch: () => autoLock.touch(), unsaved: options.unsaved === true,
  });
  const standbyScreen = () => {
    const card = standbyCard();
    trackLock(session, { root: card.root, scope: null, seen: false, wipe: () => mount(card.root, lockedScreen()) });
    return card.root;
  };
  if (typeof sync.standby === "function" && sync.standby()) return { locked: standbyScreen() };

  let engine = sync.current();
  if (!engine) {
    try {
      engine = await sync.start(scopeOf(open));
    } catch {
      engine = null;
    }
  }
  if (!engine && typeof sync.standby === "function" && sync.standby()) return { locked: standbyScreen() };
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
      return shellView({ t, engine, session, content, lock: () => autoLock.lock(), touch, scope, onLocked: lockedScreen, live: services.liveSync, router: { go: ctx.go },
        routes: ctx.routes ?? [], email: typeof open.email === "string" ? open.email : null,
        admin: adminWay(session, open.accountId),
        signOut: typeof session.signOut === "function" ? () => signOutAndLeave(session, go) : undefined,
        accountPaths: menuRoutes(ctx.routes ?? []).map((route) => route.path),
        reminder: reminderOf(services.store, session.serverUrl, open.accountId),
        standby: typeof sync.onStandby === "function"
          ? { onStandby: (/** @type {any} */ fn) => sync.onStandby(fn), card: standbyCard, freeze: typeof sync.freezeUnsaved === "function" ? () => sync.freezeUnsaved() : undefined }
          : undefined,
      });
    },
  };
}

/** What the admin check found, per session and account: asked once, not on every page. @type {WeakMap<object, { accountId: string, admin: boolean }>} */
const adminSeen = new WeakMap();

/**
 * The way to the admin pages for the switch in the side menu: only where this vault has an admin address, and
 * the switch shows only when the server says the account is an administrator. A failed check shows no switch
 * and is asked again at the next page.
 * @param {any} session
 * @param {string} accountId
 * @returns {{ check(): Promise<boolean>, go(): Promise<void> } | undefined}
 */
function adminWay(session, accountId) {
  const adminUrl = configuredAdminUrl();
  if (adminUrl === null || typeof session?.info !== "function") return undefined;
  return {
    async check() {
      const seen = adminSeen.get(session);
      if (seen && seen.accountId === accountId) return seen.admin;
      try {
        const admin = (await session.info())?.admin === true;
        adminSeen.set(session, { accountId, admin });
        return admin;
      } catch {
        return false;
      }
    },
    go: async () => goToAdmin({ adminUrl, next: ADMIN_LANDING, purpose: "login" }),
  };
}

/**
 * Sign out, then the sign-in page. The device is wiped whatever happens. When the server could not be asked to end its
 * session (`signout_incomplete`) this rejects instead of leaving, so that the frame can say so; any other failure
 * still leaves for the sign-in page, as the sign-in page's own button does.
 * @param {any} session
 * @param {(path: string) => void} go
 */
async function signOutAndLeave(session, go) {
  /** @type {unknown} */
  let failure = null;
  try {
    await session.signOut();
  } catch (error) {
    failure = error;
  }
  if (/** @type {any} */ (failure)?.code === "signout_incomplete") throw failure;
  go("/login");
}

/**
 * The sync service as the edit screen's tracker of unsaved edits, or undefined where it has none (a stand-in).
 * @param {any} sync
 * @returns {{ trackUnsaved(form: import("./edit.mjs").UnsavedForm): () => void, takeFrozen(key: string): import("./edit.mjs").UnsavedForm | null } | undefined}
 */
export function trackerOf(sync) {
  return typeof sync?.trackUnsaved === "function" && typeof sync?.takeFrozen === "function" ? sync : undefined;
}

/**
 * The export reminder of an account, over the store service; null where the store has none (a stand-in).
 * @param {any} store the store service
 * @param {string} serverUrl
 * @param {string} accountId
 * @returns {ExportReminder | null}
 */
function reminderOf(store, serverUrl, accountId) {
  const tools = store?.exportReminder;
  if (!tools || typeof store.open !== "function") return null;
  return {
    check: async () => tools.status(await store.open(), serverUrl, accountId, Date.now()),
    snooze: async () => tools.snooze(await store.open(), serverUrl, accountId, Date.now()),
  };
}

/** A card with a message, for a screen that cannot be shown. @param {Translate} t @param {string} key */
export function messageCard(t, key) {
  return el("section", { class: "card", "data-role": "message" }, el("p", null, t(key)),
    el("p", null, el("a", { href: "#/items" }, t("vault.nav.items"))));
}
