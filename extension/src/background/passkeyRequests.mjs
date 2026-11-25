// The background's side of the passkey bridge (the `passkeys` feature, design document § 9.2 and § 10.8).
//
// The bridge script of a page reports a call of `create` or `get` (`passkey_request`), the page's abort
// (`passkey_abort`), a provider that was there before Ferret (`passkey_foreign`) and, while a request waits, a ping
// (`passkey_ping`). The router hands each over with the sender it checked (tab, frame, document; never anything from the
// message) to the one core operation `passkey_event`, which ends here. The answer is a push of the request's id to that
// frame and that document only (`tabs.sendMessage` with `frameId` and `documentId`): `passkey_result`, `passkey_handover`
// or `passkey_error`. A sender without a `documentId` gets no answer, so an answer can never reach another document of
// the frame.
//
// This is the transport and the default. Until the request broker decides (origin and frames from the browser, the
// chooser window, the core), every request is handed to the browser at once: the page's call reaches the browser's own
// WebAuthn with the page's own options, exactly as without Ferret.

import { encode } from "../shared/protocol.mjs";

/** The core operation the router hands a message of the bridge to. */
export const PASSKEY_EVENT_OP = "passkey_event";

/**
 * @typedef {{ tabId: number, frameId: number, documentId?: string, url: string }} BridgeSender the sender the router checked
 * @typedef {{ type: string, sender: BridgeSender, body: any }} BridgeEvent
 */

/**
 * @param {{ tabs: { sendMessage(tabId: number, message: unknown, options: { frameId: number, documentId: string }): Promise<unknown> } }} deps
 */
export function createPasskeyRequests({ tabs }) {
  /**
   * The tabs whose top document's script found create or get changed by something else: another password manager or the site
   * itself (the script cannot tell which). Memory only, cleared when the top frame moves to a new document. It is for the
   * text of Ferret's UI only and never changes where a call goes: any page can set it.
   * By tab: the documentId of the top document that reported it (a later top document of the tab is not marked by it).
   * @type {Map<number, string>}
   */
  const foreign = new Map();
  /** The most tabs the mark is kept for (the oldest goes first). */
  const MAX_FOREIGN = 256;

  /**
   * An answer to one request, to the frame and document that asked and nowhere else.
   * @param {BridgeSender} sender @param {"passkey_result" | "passkey_handover" | "passkey_error"} type @param {Record<string, unknown>} body
   */
  const push = async (sender, type, body) => {
    if (typeof sender?.documentId !== "string" || sender.documentId === "") return false;
    try {
      await tabs.sendMessage(sender.tabId, encode(type, body), { frameId: sender.frameId, documentId: sender.documentId });
      return true;
    } catch {
      // The document is gone: there is no one to answer.
      return false;
    }
  };

  /** @param {BridgeEvent} event */
  const onEvent = async ({ type, sender, body }) => {
    if (type === "passkey_request") {
      // The default until the broker decides: the browser answers, with the page's own options.
      await push(sender, "passkey_handover", { request_id: body.request_id, once: false });
    } else if (type === "passkey_foreign") {
      // Only the top document's report counts (a frame of another site must not mark the page).
      if (sender.frameId === 0 && typeof sender.documentId === "string") {
        foreign.delete(sender.tabId);
        foreign.set(sender.tabId, sender.documentId);
        if (foreign.size > MAX_FOREIGN) foreign.delete(/** @type {number} */ (foreign.keys().next().value));
      }
    }
    // passkey_abort, passkey_ping: nothing waits here.
  };

  return {
    push,
    /**
     * Whether the tab's top document (`documentId`, from `webNavigation.getFrame` of frame 0 when the UI asks) found create or
     * get changed by something else. Text only. A new top document has no mark: the id differs.
     * @param {number} tabId @param {string} documentId
     */
    foreignIn: (tabId, documentId) => foreign.get(tabId) === documentId,
    ops: Object.freeze({
      [PASSKEY_EVENT_OP]: {
        vault: false,
        worker: /** @type {const} */ ("none"),
        run: async (/** @type {unknown} */ _client, /** @type {BridgeEvent} */ args) => {
          await onEvent(args);
        },
      },
    }),
  };
}
