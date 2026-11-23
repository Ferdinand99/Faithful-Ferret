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
//   capture_settings  "Offer to save passwords" and the never list, from the
//                     settings page: what is on, whether the permission is
//                     there, the hosts. A host can be taken off the list or the
//                     list emptied; the page never sends a host to add (the
//                     offer's own "Never" does that)
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

/** The reports of the capture script the router hands over. */
const EVENT_TYPES = Object.freeze(["form_capture", "form_gone", "page_ready"]);
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
 * Whether the frame's content is shown in every document above it. The points are in the frame's own viewport; the
 * frame's script is not needed (nothing is injected into the frame itself: its size comes from a call into it), and
 * every document above is asked, as for a fill.
 * @param {{ executeScript: (injection: any) => Promise<any> }} scripting
 * @param {number} tabId
 * @param {import("./offers.mjs").FrameFact} frame
 * @returns {Promise<boolean>}
 */
async function frameIsShown(scripting, tabId, frame) {
  if (frame.frameId === 0) return true;
  if (frame.ancestors.length === 0 || frame.ancestors.at(-1)?.frameId !== 0) return false;
  const target = typeof frame.documentId === "string" && frame.documentId !== "" ? { tabId, documentIds: [frame.documentId] } : { tabId, frameIds: [frame.frameId] };
  const own = await scripting.executeScript({ target, func: () => [Math.floor(innerWidth / 2), Math.floor(innerHeight / 2)] });
  const middle = Array.isArray(own) && own.length === 1 ? own[0]?.result : null;
  if (!Array.isArray(middle) || middle.length !== 2 || !middle.every((v) => typeof v === "number" && Number.isFinite(v) && v >= 0 && v < 1e7)) return false;
  /** @type {Array<[number, number]>} */
  let points = [[middle[0], middle[1]]];
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
 *   badge?: import("./offers.mjs").Badge | null,
 *   writer?: import("./offers.mjs").Writer | null,
 *   timers?: import("./offers.mjs").Timers,
 * }} deps `writer` classifies a capture with the vault open (the write path); `badge` sets a tab's count on the toolbar
 *   button
 */
export function createCaptureHost({ now, random, webNavigation, tabs, scripting, permissions, storageLocal, badge = null, writer = null, timers }) {
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
    if (isIndex(d?.tabId)) offers.onSignal(d.tabId, { type: "committed", frameId: d.frameId, url: String(d.url ?? ""), ...(typeof d.documentId === "string" ? { documentId: d.documentId } : {}) });
  });
  webNavigation.onCompleted?.addListener((/** @type {any} */ d) => {
    if (isIndex(d?.tabId)) offers.onSignal(d.tabId, { type: "completed", frameId: d.frameId, url: String(d.url ?? ""), ...(typeof d.documentId === "string" ? { documentId: d.documentId } : {}) });
  });
  webNavigation.onHistoryStateUpdated?.addListener((/** @type {any} */ d) => {
    if (isIndex(d?.tabId)) offers.onSignal(d.tabId, { type: "history", frameId: d.frameId, url: String(d.url ?? "") });
  });
  tabs.onRemoved?.addListener((/** @type {number} */ tabId) => {
    if (isIndex(tabId)) offers.clear("tab_closed", { tabId });
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

  /** @returns {Promise<{ on: boolean, permission: boolean, never: string[] }>} */
  async function settingsNow() {
    const status = await registry.status();
    return { on: status.on && status.registered, permission: status.permission, never: await never.list() };
  }

  /** @param {any} args */
  async function captureSettings(args) {
    saveFeature();
    if (args?.never_clear === true) for (const host of await never.list()) await never.remove(host);
    if (typeof args?.never_remove === "string") await never.remove(args.never_remove);
    if (typeof args?.enable === "boolean") {
      const outcome = args.enable ? await registry.enable() : await registry.disable();
      const now_ = await settingsNow();
      return outcome.ok === true ? { ok: true, ...now_ } : { ok: false, reason: /** @type {any} */ (outcome).reason, ...now_ };
    }
    return { ok: true, ...(await settingsNow()) };
  }

  const ops = Object.freeze({
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
      coreHost.onLocked((reason) => offers.clear(reason === "sign_out" ? "sign_out" : reason === "restart" ? "restart" : "lock"));
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
