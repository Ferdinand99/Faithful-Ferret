// The capture's side of the background (design document, section 10.9): the
// store of offers (offers.mjs), the registration of the capture script and the
// setting (captureRegistry.mjs), and the browser's events that tell the store
// what happened in a tab. This module wires them to the browser and to the core
// host; it holds no key and no password.
//
// Two core operations belong to it (`vault: false`: a capture is taken while the
// vault is locked, never touches a key and never moves the auto-lock deadline):
//
//   capture_event     a report of the capture script: the router hands over
//                     the type, the body and the sender it checked, and nothing
//                     comes back (a content script is never answered)
//   capture_settings  "Offer to save passwords", "Open the popup by itself" and
//                     the never list, from the settings page: what is on,
//                     whether the permission is there, the hosts. A host can be
//                     taken off the list or the list emptied; the page never
//                     sends a host to add (the offer's own "Never" does that)
//
// Three more belong to the offer in Ferret's popup (offerCards.mjs); the router
// refuses their messages while the vault is locked, and they answer from the
// store of offers, which only holds what the popup session was told of:
//
//   offer_list        the offers that are ready for a tab (host from the core,
//                     user name, kind; never a password), and the reason of a
//                     refused shortcut or menu click the tab shows, once
//   offer_dismiss     "Not now", or "Never for this site" with `never`
//   offer_reveal      the captured password of one offer, only on the click of
//                     "Show" in the popup, to the session that was told of it
//
// A build without the `save` feature does not make this host at all (main.mjs),
// and each operation refuses `not_available` before anything else if it is
// called all the same.
//
// The store is cleared at every lock, whatever the reason (a manual lock, the
// auto-lock, the system idle or a sleep, a sign-out, a forgotten server, a restart,
// a failed worker), and when a tab closes, capture is turned off or the permission is
// taken back. On every start the registration is reconciled with the permission and
// the setting.

import { FEATURES } from "../shared/features.mjs";
import { CAPTURE_ORIGINS } from "../shared/captureConfig.mjs";
import { createCaptureRegistry, createNeverList } from "./captureRegistry.mjs";
import { fillableFrames } from "./frames.mjs";
import { frameShownIn } from "./inject.mjs";
import { createOffers } from "./offers.mjs";

/** A popup session and an offer: 16 bytes in lower-case hex. */
const HEX32 = /^[0-9a-f]{32}$/;

/** The reports of the capture script the router hands over. */
const EVENT_TYPES = Object.freeze(["form_capture", "form_gone", "page_ready"]);
/** How far inside a frame's corner the parent-side check looks (CSS pixels): a frame smaller than this is not shown. */
const INSET = 8;
/** How long the parent-side check of a frame may take. */
const SHOWN_TIMEOUT_MS = 3000;

/** @param {string} code */
const fail = (code) => Object.assign(new Error(code), { code });

/** @param {unknown} n @returns {n is number} */
const isIndex = (n) => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

/** Refuses when saving passwords is off in this build. */
const saveFeature = () => {
  if (FEATURES.save !== true) throw fail("not_available");
};

/**
 * Whether the frame is shown in every document above it. The question goes to the documents above, never to the frame's
 * own document (a submitted form moves its frame on at once, and a document that is gone cannot be asked): each parent,
 * from the nearest up to the top, says whether the element that holds the frame is shown at a point a little inside the
 * frame's corner, passes the ancestor and size rules and is not covered, and hands the point on in its own coordinates.
 * A frame too small to hold that point (a hidden one) fails.
 * @param {{ executeScript: (injection: any) => Promise<any> }} scripting
 * @param {number} tabId
 * @param {import("./offers.mjs").FrameFact} frame
 * @returns {Promise<boolean>}
 */
async function frameIsShown(scripting, tabId, frame) {
  if (frame.frameId === 0) return true;
  if (frame.ancestors.length === 0 || frame.ancestors.at(-1)?.frameId !== 0) return false;
  /** @type {Array<[number, number]>} */
  let points = [[INSET, INSET]];
  let child = frame.frameId;
  for (const parent of frame.ancestors) {
    const answer = await frameShownIn({ scripting, tabId, parent, childFrameId: child, points });
    if (answer.verdict !== "shown" || !("points" in answer)) return false;
    points = answer.points;
    child = parent.frameId;
  }
  return true;
}

/**
 * @param {{
 *   now: () => number,
 *   random: (bytes: Uint8Array) => Uint8Array,
 *   webNavigation: any,
 *   tabs: any,
 *   scripting: any,
 *   permissions: any,
 *   storageLocal: any,
 *   badge?: (import("./offers.mjs").Badge & {
 *     refusalFor(tabId: number): string | null, acknowledge(tabId: number): void, forget(tabId: number): void,
 *     reapply(tabId: number): void, clearAll(): void,
 *   }) | null,
 *   autoOpen?: ReturnType<typeof import("./autoOpen.mjs").createAutoOpen> | null,
 *   writer?: import("./offers.mjs").Writer | null,
 *   timers?: import("./offers.mjs").Timers,
 * }} deps `writer` classifies a capture with the vault open (the write path); `badge` is the toolbar button's per-tab
 *   count and refusal mark (badge.mjs); `autoOpen` is the setting and the attempt to open the popup by itself
 */
export function createCaptureHost({ now, random, webNavigation, tabs, scripting, permissions, storageLocal, badge = null, autoOpen = null, writer = null, timers }) {
  /** The core host's `call`, set by `attach`. @type {((op: string, args?: unknown) => Promise<any>) | null} */
  let callCore = null;
  /** @param {string} op @param {unknown} args */
  const call = (op, args) => {
    if (callCore === null) return Promise.reject(fail("internal"));
    return callCore(op, args);
  };

  const never = createNeverList({ storageLocal });

  /** @type {import("./offers.mjs").Frames} */
  const frames = {
    async origin(url) {
      try {
        const origin = (await call("page_origin", { url }))?.origin;
        return typeof origin === "string" && origin !== "" && origin !== "null" && origin.length <= 300 ? origin : null;
      } catch {
        return null;
      }
    },
    async sameSite(a, b) {
      try {
        return (await call("same_site", { a, b }))?.same === true;
      } catch {
        return false;
      }
    },
    async host(url) {
      const shown = await call("display_host", { url });
      if (typeof shown?.a_label !== "string" || typeof shown?.unicode !== "string" || shown.a_label === "" || shown.unicode === "") throw fail("internal");
      return { a_label: shown.a_label, unicode: shown.unicode };
    },
    async frame(tabId, frameId) {
      const core = {
        page_origin: async (/** @type {string} */ url) => (await call("page_origin", { url })).origin,
        same_site: async (/** @type {string} */ a, /** @type {string} */ b) => (await call("same_site", { a, b })).same === true,
      };
      const all = await fillableFrames(tabId, { webNavigation, core });
      const found = all.find((f) => f.frameId === frameId);
      if (found === undefined) return null;
      const byId = new Map(all.map((f) => [f.frameId, f]));
      // A capture is never taken from `http`, loopback included: the frame and every frame above it must be `https`.
      const chainSecure = found.origin.startsWith("https://") && found.ancestors.every((a) => byId.get(a.frameId)?.origin.startsWith("https://") === true);
      return { frameId: found.frameId, ...(found.documentId !== undefined ? { documentId: found.documentId } : {}), url: found.url, origin: found.origin, ancestors: found.ancestors, chainSecure };
    },
    async shown(tabId, frame) {
      try {
        let timer = null;
        const limit = new Promise((resolve) => {
          timer = setTimeout(() => resolve(false), SHOWN_TIMEOUT_MS);
        });
        try {
          return (await Promise.race([frameIsShown(scripting, tabId, frame), limit])) === true;
        } finally {
          if (timer !== null) clearTimeout(timer);
        }
      } catch {
        return false;
      }
    },
    async incognito(tabId) {
      try {
        return (await tabs.get(tabId))?.incognito === true;
      } catch {
        // A tab that is gone is treated as a private one: its choice is not written to the disk.
        return true;
      }
    },
  };

  const offers = createOffers({ now, frames, random, never, writer, badge, ...(timers ? { timers } : {}) });

  const registry = createCaptureRegistry({
    scripting,
    permissions,
    storageLocal,
    onOff: (reason) => offers.clear(reason),
  });

  // What happened in a tab, from the browser: the offers that wait for it are told. Registered now, while the page
  // loads, so the event that woke it is not missed.
  webNavigation.onCommitted?.addListener((/** @type {any} */ d) => {
    // The browser resets a tab's badge when the tab goes to a new page: paint what the tab should show.
    if (isIndex(d?.tabId) && d.frameId === 0) badge?.reapply(d.tabId);
    if (isIndex(d?.tabId)) offers.onSignal(d.tabId, { type: "committed", frameId: d.frameId, url: String(d.url ?? ""), ...(typeof d.documentId === "string" ? { documentId: d.documentId } : {}) });
  });
  webNavigation.onCompleted?.addListener((/** @type {any} */ d) => {
    if (isIndex(d?.tabId) && d.frameId === 0) badge?.reapply(d.tabId);
    if (isIndex(d?.tabId)) offers.onSignal(d.tabId, { type: "completed", frameId: d.frameId, url: String(d.url ?? ""), ...(typeof d.documentId === "string" ? { documentId: d.documentId } : {}) });
  });
  webNavigation.onHistoryStateUpdated?.addListener((/** @type {any} */ d) => {
    if (isIndex(d?.tabId)) offers.onSignal(d.tabId, { type: "history", frameId: d.frameId, url: String(d.url ?? "") });
  });
  tabs.onRemoved?.addListener((/** @type {number} */ tabId) => {
    if (isIndex(tabId)) {
      offers.clear("tab_closed", { tabId });
      badge?.forget(tabId);
    }
  });
  permissions.onAdded?.addListener((/** @type {any} */ added) => {
    registry.onAdded(added).catch(() => {});
  });
  permissions.onRemoved?.addListener((/** @type {any} */ removed) => {
    registry.onRemoved(removed).then((gone) => {
      if (gone) offers.clear("permission_removed");
    }, () => {});
  });

  /** @param {any} args */
  async function captureEvent(args) {
    saveFeature();
    const type = args?.type;
    const sender = args?.sender;
    if (!EVENT_TYPES.includes(type) || typeof sender !== "object" || sender === null || !isIndex(sender.tabId) || !isIndex(sender.frameId) || typeof sender.url !== "string") {
      throw fail("invalid_input");
    }
    const body = args?.body ?? {};
    if (type === "form_capture") {
      await offers.onCapture(sender, body);
    } else if (type === "form_gone") {
      await offers.onSignal(sender.tabId, { type: "form_gone", frameId: sender.frameId, captureId: String(body?.capture_id ?? "") });
    } else {
      await offers.onSignal(sender.tabId, { type: "page_ready", frameId: sender.frameId, url: sender.url, ...(typeof sender.documentId === "string" ? { documentId: sender.documentId } : {}) });
    }
    // A content script is never answered with anything: not whether an offer was made, not a value.
    return { ok: true };
  }

  /** @returns {Promise<{ on: boolean, permission: boolean, never: string[], auto_open?: boolean, auto_open_state?: string }>} */
  async function settingsNow() {
    const status = await registry.status();
    return {
      on: status.on && status.registered,
      permission: status.permission,
      never: await never.list(),
      ...(autoOpen === null ? {} : { auto_open: await autoOpen.isOn(), auto_open_state: autoOpen.probe() }),
    };
  }

  /** @param {any} args */
  async function captureSettings(args) {
    saveFeature();
    if (args?.never_clear === true) for (const host of await never.list()) await never.remove(host);
    if (typeof args?.never_remove === "string") await never.remove(args.never_remove);
    if (typeof args?.auto_open === "boolean") await autoOpen?.setOn(args.auto_open);
    if (typeof args?.enable === "boolean") {
      const outcome = args.enable ? await registry.enable() : await registry.disable();
      const now_ = await settingsNow();
      return outcome.ok === true ? { ok: true, ...now_ } : { ok: false, reason: /** @type {any} */ (outcome).reason, ...now_ };
    }
    return { ok: true, ...(await settingsNow()) };
  }

  /**
   * The offers ready for a tab, for the popup session that asks (it is told of each, which is what lets it read and take
   * them afterwards), and the reason a refused shortcut or menu click left on the tab, once.
   * @param {any} args
   */
  async function offerList(args) {
    saveFeature();
    if (!isIndex(args?.tab_id) || typeof args?.session !== "string" || !HEX32.test(args.session)) throw fail("invalid_input");
    const list = offers.forTab(args.tab_id, args.session);
    const notice = badge?.refusalFor(args.tab_id) ?? null;
    if (notice !== null) badge?.acknowledge(args.tab_id);
    return { ok: true, offers: list, ...(notice !== null ? { notice } : {}) };
  }

  /**
   * "Not now" or "Never for this site": only an offer this popup session was told of.
   * @param {any} args
   */
  async function offerDismiss(args) {
    saveFeature();
    if (typeof args?.offer_id !== "string" || !HEX32.test(args.offer_id) || typeof args?.session !== "string" || !HEX32.test(args.session)) throw fail("invalid_input");
    const done = offers.dismiss(args.offer_id, { never: args.never === true, uiSession: args.session });
    return done ? { ok: true } : { ok: false, reason: "not_offered" };
  }

  /**
   * The captured password of an offer, to the popup session that was told of it, on the click of "Show". It is read
   * where it is held and left there (a copy goes out); nothing keeps it.
   * @param {any} args
   */
  async function offerReveal(args) {
    saveFeature();
    if (typeof args?.offer_id !== "string" || !HEX32.test(args.offer_id) || typeof args?.session !== "string" || !HEX32.test(args.session)) throw fail("invalid_input");
    const capture = offers.peek(args.offer_id, args.session);
    if (capture === null) return { ok: false, reason: "not_offered" };
    return { ok: true, value: capture.password };
  }

  const ops = Object.freeze({
    offer_list: { vault: false, worker: /** @type {const} */ ("none"), run: async (/** @type {any} */ _client, /** @type {any} */ args) => offerList(args) },
    offer_dismiss: { vault: false, worker: /** @type {const} */ ("none"), run: async (/** @type {any} */ _client, /** @type {any} */ args) => offerDismiss(args) },
    offer_reveal: { vault: false, worker: /** @type {const} */ ("none"), run: async (/** @type {any} */ _client, /** @type {any} */ args) => offerReveal(args) },
    capture_event: { vault: false, worker: /** @type {const} */ ("none"), run: async (/** @type {any} */ _client, /** @type {any} */ args) => captureEvent(args) },
    capture_settings: { vault: false, worker: /** @type {const} */ ("none"), run: async (/** @type {any} */ _client, /** @type {any} */ args) => captureSettings(args) },
  });

  return {
    ops,
    /** The offers, as the write path's capture source (`peek`, `take`) and for the popup (`forTab`, `dismiss`). */
    offers,
    never,
    registry,

    /**
     * Joins the core host: every lock clears the store, and the registration is reconciled now.
     * @param {{ call(op: string, args?: unknown): Promise<unknown>, onLocked(listener: (reason: string) => void): unknown }} coreHost
     */
    attach(coreHost) {
      callCore = (op, args) => /** @type {Promise<any>} */ (coreHost.call(op, args));
      coreHost.onLocked((reason) => {
        offers.clear(reason === "sign_out" ? "sign_out" : reason === "restart" ? "restart" : "lock");
        badge?.clearAll();
      });
      registry.reconcile().catch(() => {});
    },

    /**
     * The popup page `session` has gone.
     * @param {string} session
     */
    endSession(session) {
      offers.endSession(session);
    },

    CAPTURE_ORIGINS,
  };
}
