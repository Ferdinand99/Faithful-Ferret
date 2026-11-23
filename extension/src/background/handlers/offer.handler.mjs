// The offer to save or update a password in the popup (design document, sections 8.2 to 8.6 and 10.9), over the UI port,
// in a build with saving from the extension on:
//
//   offer_list      the offers ready for a tab, and the reason of a refused shortcut or menu click
//   offer_classify  what an offer means for the vault (the core decides: save, update, choose, nothing)
//   folder_names    the folders the save card offers
//   offer_save      "Save": a new item from the offer
//   offer_update    "Update" (or "Save as new" through offer_save): the new password into one item
//   offer_dismiss   "Not now"
//   offer_never     "Never for this site"
//   offer_reveal    "Show" on the card's password
//
// Off in a build without the feature: every type is refused as `not_available` before anything else, as if this
// handler were not there.
//
// Nothing here is a write by itself. The write is the user's click on the card in Ferret's own popup, and this handler
// is where that is held to:
//
//   - the sender is checked again, first: the message must come from a top-level page of this extension (the router
//     checked the port; a content script, a web page, an extension page that a web page frames and another extension
//     are all refused here as well). The popup page is the one place that has such a sender;
//   - the popup session comes from the router's context (`ctx.session`, new for every port) and from nowhere else: no
//     message carries a session, and a body with a key the schema does not list never gets here;
//   - an offer is named by its id, which the store gave to this session in `offer_list` and to no other. An id the
//     session was not told of (another popup, a page, a guess) is `not_offered` and nothing happens;
//   - the password is never in a message from the popup. It is the one the background holds, taken once (a write) or
//     read once (the classification, "Show").
//
// The answers carry codes, names, hosts and the items' ids; the password only in the answer of `offer_reveal`.

import { FEATURES } from "../../shared/features.mjs";
import { isTopLevelExtensionPage } from "../../shared/origin.mjs";

/** The reasons a page has a text for (`offer.error.<reason>`). Every other code becomes `unknown`. */
export const REASONS = Object.freeze([
  "not_offered",
  "item_changed",
  "not_found",
  "not_a_target",
  "not_updatable",
  "origin_changed",
  "invalid_input",
  "busy",
  "vault_locked",
  "sync_not_running",
  "worker_failed",
  "read_only",
  "unknown",
]);

/** @param {unknown} code @returns {string} */
export function reasonOf(code) {
  if (code === "locked" || code === "stopped") return "vault_locked";
  if (code === "internal" || code === "kdf_out_of_memory") return "worker_failed";
  return typeof code === "string" && REASONS.includes(code) ? code : "unknown";
}

/** The session of a popup port: 16 bytes in lower-case hex (the router makes it). */
const SESSION = /^[0-9a-f]{32}$/;

const notAvailable = () => Object.assign(new Error("not_available"), { code: "not_available" });

/** @param {any} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  if (!FEATURES.save) throw notAvailable();
  // The sender, before anything else.
  if (ctx.channel !== "ui" || ctx.runtime === undefined || !isTopLevelExtensionPage(ctx.sender, ctx.runtime)) throw notAvailable();
  // The session is the port's, never the message's.
  const session = ctx.session;
  if (typeof session !== "string" || !SESSION.test(session)) throw notAvailable();
  const call = /** @type {NonNullable<typeof ctx.call>} */ (ctx.call);
  try {
    switch (ctx.type) {
      case "offer_list": {
        const reply = /** @type {any} */ (await call("offer_list", { tab_id: body.tab_id, session }));
        if (reply?.ok !== true) return { ok: false, reason: reasonOf(reply?.reason) };
        return { ok: true, offers: reply.offers, ...(typeof reply.notice === "string" ? { notice: reply.notice } : {}) };
      }
      case "offer_classify": {
        const reply = /** @type {any} */ (await call("offer_classify", { session, offer_id: body.offer_id }));
        if (reply?.ok !== true) return { ok: false, reason: reasonOf(reply?.reason) };
        return {
          ok: true,
          action: reply.action,
          targets: reply.targets,
          domain_only: reply.domain_only,
          reused: reply.reused,
          username_from: reply.username_from,
        };
      }
      case "folder_names": {
        const reply = /** @type {any} */ (await call("folder_names", {}));
        return Array.isArray(reply?.folders) ? { ok: true, folders: reply.folders } : { ok: false, reason: reasonOf(reply?.reason) };
      }
      case "offer_save": {
        const reply = /** @type {any} */ (
          await call("offer_save", {
            session,
            offer_id: body.offer_id,
            name: body.name,
            ...(body.username !== undefined ? { username: body.username } : {}),
            ...(body.folder !== undefined && body.folder !== "" ? { folder: body.folder } : {}),
          })
        );
        return written(reply);
      }
      case "offer_update": {
        const reply = /** @type {any} */ (
          await call("offer_update", { session, offer_id: body.offer_id, id: body.id, rev: body.rev, picked: body.picked === true })
        );
        return written(reply);
      }
      case "offer_dismiss":
      case "offer_never": {
        const reply = /** @type {any} */ (await call("offer_dismiss", { session, offer_id: body.offer_id, never: ctx.type === "offer_never" }));
        return reply?.ok === true ? { ok: true } : { ok: false, reason: reasonOf(reply?.reason) };
      }
      case "offer_reveal": {
        const reply = /** @type {any} */ (await call("offer_reveal", { session, offer_id: body.offer_id }));
        return reply?.ok === true && typeof reply.value === "string" ? { ok: true, value: reply.value } : { ok: false, reason: reasonOf(reply?.reason) };
      }
      default:
        throw notAvailable();
    }
  } catch (error) {
    const code = /** @type {any} */ (error)?.code;
    if (code === "not_available") throw error;
    return { ok: false, reason: reasonOf(code) };
  }
}

/**
 * The answer of a write: whether it waits for the sync, or why nothing was written (and, when the item changed since
 * the card was shown, what the offer means now).
 * @param {any} reply
 */
function written(reply) {
  if (reply?.ok === true) return { ok: true, pending: reply.pending !== false };
  return { ok: false, reason: reasonOf(reply?.reason), ...(reply?.classification !== undefined ? { classification: reply.classification } : {}) };
}

export default {
  types: ["offer_list", "offer_classify", "folder_names", "offer_save", "offer_update", "offer_dismiss", "offer_never", "offer_reveal"],
  channel: /** @type {"ui"} */ ("ui"),
  handle,
};
