// The keyboard shortcut (`commands`, design document section 10.3.1) and the
// one step it shares with the context menu (menus.mjs): fill the login of the
// page when exactly one item matches, and open the popup otherwise.
//
// The command `fill-login` (suggested key Alt+Shift+L, which the user can change
// in about:addons) runs with `activeTab` on the tab it was pressed on. Then:
//
//   1. A locked vault opens the popup at once, in the turn of the shortcut, so
//      the popup asks for the master password.
//   2. The lock is checked as for any action in Ferret's UI, and the action
//      moves the deadline.
//   3. The page matching runs for the tab (`fill_offer`): the frames Ferret may
//      fill and the items whose addresses match each frame, by the core's rule.
//      It issues "fill" references in a session of this action alone.
//   4. Exactly one reference (for the menu: exactly one in the clicked frame)
//      is filled through the fill flow (`fill`), which fetches the frame again,
//      checks its origin and puts one value at a time into that frame only.
//      Several, none, or one for an `http` item (that needs the warning and one
//      more click, which only the popup shows) open the popup instead.
//   5. The session ends, and its references with it.
//
// A fill that was tried and refused (a frame that is hidden or covered, a page that did not answer) leaves no popup to say
// why, so the refusal is handed to `onRefused` with the tab and the reason: the toolbar button then shows "!" for thirty
// seconds and the popup, opened next, says what happened (badge.mjs, offerCards.mjs).
//
// This module never sees a value or a key: it reaches the vault only through
// the core host's `call` with the two operation names above, and what it gets
// back are references and frame numbers. A name or user name in a reply is
// never used.

import { aimFill, disarmFill } from "./inject.mjs";

/** The command of the manifest (manifest/parts/commands.json). */
export const FILL_COMMAND = "fill-login";

/**
 * @typedef {{ ref: string, frame_id?: number, frame_ids?: number[], insecure?: boolean }} OfferedHandle
 *   the part of a `fill_offer` reply this module reads: the frame of the reference, or the frames it is tied to
 *   (top first)
 * @typedef {{
 *   call(op: string, args?: unknown): Promise<any>,
 *   state(): "locked" | "unlocked",
 * }} FillCalls
 *   the core host, as this module uses it: the fill flow's operations `fill_offer`
 *   ({ session, tab_id, frame_id? } -> { handles: OfferedHandle[] }) and `fill`
 *   ({ session, ref, tab_id, frame_id? } -> { ok, reason? }); `frame_id` keeps that one frame (the menu's)
 * @typedef {{ endSession(session: string): void }} FillSessions
 *   the fill flow's end of a session: its references are dropped
 * @typedef {{ checkOrLock(type: string): Promise<boolean>, touch(): void }} LockCheck
 * @typedef {{ frameId: number, frameUrl: string, targetElementId: number }} Click
 *   a context menu click: the frame, its address as the menu saw it, and the clicked element
 * @typedef {"filled" | "not_filled" | "popup" | "busy" | "refused"} Outcome
 */

/** @param {unknown} n @returns {n is number} */
const isIndex = (n) => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

/**
 * The frames a handle's reference may fill: its tied frames (top first), or its one frame.
 * @param {OfferedHandle | null | undefined} handle
 * @returns {number[]}
 */
const framesOf = (handle) => {
  if (Array.isArray(handle?.frame_ids)) return handle.frame_ids.filter(isIndex);
  return isIndex(handle?.frame_id) ? [handle.frame_id] : [];
};

/** @param {Uint8Array} bytes */
const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

/**
 * The step the shortcut and the menu share.
 *
 * @param {{
 *   coreHost: FillCalls,
 *   lock: LockCheck,
 *   sessions?: FillSessions | null,
 *   openPopup: () => unknown,
 *   onRefused?: ((tabId: number, reason: string) => void) | null,
 *   scripting: { executeScript: (injection: any) => Promise<any[]> },
 *   webNavigation: { getFrame(details: { tabId: number, frameId: number }): Promise<{ url?: string, documentId?: string } | null> },
 *   random?: (bytes: Uint8Array) => Uint8Array,
 * }} options
 */
export function createQuickFill({
  coreHost,
  lock,
  sessions = null,
  openPopup,
  onRefused = null,
  scripting,
  webNavigation,
  random = (bytes) => {
    globalThis.crypto.getRandomValues(/** @type {Uint8Array<ArrayBuffer>} */ (bytes));
    return bytes;
  },
}) {
  /** One action at a time: a second press while the first runs does nothing. */
  let running = false;

  /** Opens the popup. A popup that cannot open is not an error of the action. @returns {Outcome} */
  function open() {
    try {
      const pending = /** @type {any} */ (openPopup());
      pending?.catch?.(() => {});
    } catch {
      // No popup: the user can still click the toolbar button.
    }
    return "popup";
  }

  /**
   * @param {number} tabId
   * @param {Click | null} click
   * @returns {Promise<Outcome>}
   */
  async function attempt(tabId, click) {
    if (!(await lock.checkOrLock("fill"))) return open();
    lock.touch();
    const session = hex(random(new Uint8Array(16)));
    try {
      // The menu asks for the clicked frame only; the shortcut for every frame Ferret may fill.
      const offer = await coreHost.call("fill_offer", { session, tab_id: tabId, ...(click === null ? {} : { frame_id: click.frameId }) }).catch(() => null);
      /** @type {OfferedHandle[]} */
      const all = Array.isArray(offer?.handles) ? offer.handles : [];
      // The menu fills only in the frame that was clicked: a match in any other frame does not count.
      const here = click === null ? all : all.filter((h) => framesOf(h).includes(click.frameId));
      if (here.length !== 1) return open();
      const [one] = here;
      if (typeof one?.ref !== "string") return open();
      if (framesOf(one).length === 0) return open();
      // An http item is offered with a warning and one more click, in the popup only.
      if (one.insecure === true) return open();
      /** The document the menu's aim went to. @type {string | null} */
      let aimedAt = null;
      if (click !== null) {
        // The frame the browser resolves for `info.frameId` must still show `info.frameUrl`: when the two disagree
        // (the frame moved on, or the id names another document now) nothing is filled. The frame must name its
        // document, so the aim and the fill land in the same one. Then the engine there must hold the clicked field.
        const frame = await webNavigation.getFrame({ tabId, frameId: click.frameId }).catch(() => null);
        if (typeof frame?.url !== "string" || frame.url !== click.frameUrl) return open();
        if (typeof frame.documentId !== "string" || frame.documentId === "") return open();
        try {
          await aimFill({ scripting, tabId, frameId: click.frameId, documentId: frame.documentId, targetElementId: click.targetElementId });
        } catch {
          return open();
        }
        aimedAt = frame.documentId;
      }
      // The menu fills in the clicked frame only. The shortcut lets the fill flow take the first of the reference's
      // frames (top first) whose fill script reports sign-in fields.
      const result = await coreHost.call("fill", { session, ref: one.ref, tab_id: tabId, ...(click === null ? {} : { frame_id: click.frameId }) }).catch(() => null);
      if (result?.ok === true) return "filled";
      // A fill that ended before its request began left the aim armed: it must not steer the next fill there.
      if (aimedAt !== null) await disarmFill({ scripting, tabId, documentId: aimedAt }).catch(() => {});
      // Nothing opens to say why: the button shows "!" and the popup tells the reason.
      try {
        onRefused?.(tabId, typeof result?.reason === "string" ? result.reason : "not_filled");
      } catch {
        // The mark is a help; the outcome stands.
      }
      return "not_filled";
    } finally {
      try {
        sessions?.endSession(session);
      } catch {
        // The references go at the next lock in any case.
      }
    }
  }

  return {
    /**
     * Fills the one login that matches the tab (or, for a menu click, the
     * clicked frame), or opens the popup.
     * @param {unknown} tabId
     * @param {Click | null} [click]
     * @returns {Promise<Outcome>}
     */
    fillOrOpen(tabId, click = null) {
      if (!isIndex(tabId)) return Promise.resolve("refused");
      // Locked: the popup asks for the master password. It opens in this turn, while the user's action lasts.
      if (coreHost.state() !== "unlocked") return Promise.resolve(open());
      if (running) return Promise.resolve("busy");
      running = true;
      return attempt(tabId, click)
        .catch(() => /** @type {Outcome} */ ("not_filled"))
        .finally(() => {
          running = false;
        });
    },

    open,
  };
}

/**
 * Listens for the shortcut. Call it while the background page loads, so the
 * command that woke the page reaches the listener.
 *
 * @param {{
 *   commands: { onCommand: { addListener(fn: (name: string, tab?: { id?: number }) => void): void } },
 *   quickFill: { fillOrOpen(tabId: unknown): Promise<Outcome> },
 * }} options
 */
export function listenForCommands({ commands, quickFill }) {
  commands.onCommand.addListener((name, tab) => {
    if (name !== FILL_COMMAND) return;
    quickFill.fillOrOpen(tab?.id).catch(() => {});
  });
}
