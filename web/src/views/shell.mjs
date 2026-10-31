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
 * @property {{ run(): void }} scope what to wipe on lock
 * @property {() => HTMLElement} onLocked makes the unlock screen
 */

/** The shell that shows the lock event for each session; one at a time. @type {WeakMap<object, { wipe: (() => void) | null }>} */
const shells = new WeakMap();

/** @param {any} session @param {() => void} wipe */
function trackLock(session, wipe) {
  let slot = shells.get(session);
  if (!slot) {
    const made = { wipe: /** @type {(() => void) | null} */ (null) };
    slot = made;
    shells.set(session, made);
    session.onLock?.(() => made.wipe?.());
  }
  slot.wipe = wipe;
}

/**
 * The frame: a bar with the navigation, the sync status and the lock button,
 * the banners, and the screen. When the vault locks, the screen and the
 * banners are cleared and the unlock screen takes the whole frame.
 * @param {ShellOptions} options
 */
export function shellView({ t, engine, session, content, lock, touch, scope, onLocked }) {
  const root = el("div", { class: "vault-ui vault-shell", "data-role": "shell" });
  const status = el("span", { class: "sync-status", role: "status", "data-role": "sync-status" }, t("sync.state.syncing"));
  const banners = el("div", { class: "banners", "data-role": "banners" });
  const lockButton = el("button", { type: "button", class: "secondary", "data-role": "lock" }, t("vault.lock"));
  const bar = el("header", { class: "vault-bar" },
    el("a", { class: "brand", href: "#/items" }, t("app.name")),
    el("nav", { "aria-label": t("vault.nav.label") },
      el("a", { href: "#/items", "data-role": "nav-items" }, t("vault.nav.items")),
      el("a", { href: "#/items/new", "data-role": "nav-new" }, t("vault.nav.new"))),
    status,
    lockButton);
  const main = el("main", { class: "vault-main", "data-role": "content" }, content);
  mount(root, bar, banners, main);

  /** @type {Map<string, HTMLElement>} */
  const shown = new Map();
  /** @param {string} key @param {string} kind @param {string} text */
  function banner(key, kind, text) {
    const node = el("p", { class: `banner banner-${kind}`, role: kind === "error" ? "alert" : "status", "data-role": "banner", "data-banner": key }, text);
    const dismiss = el("button", { type: "button", class: "link", "data-role": "banner-dismiss" }, t("vault.banner.dismiss"));
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
      if (/^[a-z_]{1,64}$/.test(code)) banner(`warning:${code}`, "warning", t(`sync.warning.${code}`));
      return;
    }
    const kind = String(payload?.kind ?? "");
    if (/^(?:failed|idle|offline|retrying|syncing|unauthorized)$/.test(kind)) {
      mount(status, document.createTextNode(t(`sync.state.${kind}`)));
      status.setAttribute("data-state", kind);
      if (kind === "unauthorized") banner("unauthorized", "error", t("vault.banner.sign_in_again"));
    }
  }

  /** @param {any} payload */
  function onError(payload) {
    const code = String(payload?.code ?? "");
    const named = typeof payload?.id === "string" ? engine.list().find((/** @type {any} */ i) => i.id === payload.id) : null;
    const text = describeError(t, { code, reason: payload?.reason });
    banner(`error:${code}:${payload?.id ?? ""}`, "error", named ? t("vault.banner.item", { name: named.name, message: text }) : text);
  }

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
    mount(root, onLocked());
  }
  trackLock(session, wipe);

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
  session.attachSync?.(sync);
  const autoLock = autoLockFor(session, sync);

  const open = session.current?.() ?? null;
  const onUnlocked = () => go(path);
  const lockedScreen = () => unlockScreen({ session, t, go, onUnlocked });
  if (!open) return { locked: lockedScreen() };

  let engine = sync.current();
  if (!engine) {
    try {
      engine = await sync.start(scopeOf(open));
    } catch {
      engine = null;
    }
  }
  if (!engine) {
    const lockButton = el("button", { type: "button", "data-role": "lock" }, t("vault.lock"));
    lockButton.addEventListener("click", () => void autoLock.lock());
    return {
      locked: el("section", { class: "card vault-ui", role: "alert", "data-role": "sync-unavailable" },
        el("p", null, t("vault.error.sync_unavailable")), lockButton),
    };
  }
  if (!autoLock.running()) autoLock.start();

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
    page: (content) =>
      shellView({ t, engine, session, content, lock: () => autoLock.lock(), touch, scope, onLocked: lockedScreen }),
  };
}

/** A card with a message, for a screen that cannot be shown. @param {Translate} t @param {string} key */
export function messageCard(t, key) {
  return el("section", { class: "card", "data-role": "message" }, el("p", null, t(key)),
    el("p", null, el("a", { href: "#/items" }, t("vault.nav.items"))));
}
