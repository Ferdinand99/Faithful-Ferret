// The PIN, over the UI port (design document, sections 7.2 and 7.6), in a build with the `unlock` feature on:
//
//   unlock_policy   the administrator's rule and what this device has of a PIN (works while the vault is locked)
//   pin_set         sets or changes the PIN (the open vault, the network and the master password again)
//   pin_unlock      opens the vault with the PIN (works while the vault is locked)
//   pin_off         turns the PIN off
//   prf_options     what the unlock window needs for its one WebAuthn call (works while the vault is locked)
//   prf_window      opens the unlock window, or brings the open one to the front
//   prf_unlock      opens the vault with the 32 bytes a passkey gave; only the unlock window may send it
//
// Off in a build without the feature: every type is refused as `not_available` before anything else, as if this handler
// were not there. Only a top-level page of the extension itself can ask: the router accepts UI-port messages from such
// pages only, and the sender is checked here once more, so a page that a web page frames can never send a PIN.
//
// The PIN, the master password and the secret key go from the request to the PIN host's operation and nowhere else. No
// answer carries one, and no answer carries a text of the core or of the server: a reason from REASONS, or one of the
// session's (`attack_warning`, `signed_out`, ...). A refusal after an accepted PIN (the server's answers disagree with what
// this device has pinned) is the session's `attack_warning`, and the PIN is deleted by then.

import { FEATURES } from "../../shared/features.mjs";
import { isTopLevelExtensionPage } from "../../shared/origin.mjs";
import { reasonOf as sessionReasonOf } from "./session.handler.mjs";

/**
 * The reasons of `pin_unlock` (beside the session's: `attack_warning`, `signed_out`, `network`, `busy`, ...) and of
 * `pin_set`, which the pages have a text for. Every other code becomes `unknown`.
 */
export const PIN_REASONS = Object.freeze([
  // pin_unlock
  "wrong_pin",
  "pin_wiped",
  "pin_stale",
  "pin_wait",
  "pin_offline_expired",
  "out_of_memory",
  "pin_unavailable",
  // prf_options and prf_unlock
  "prf_unavailable",
  "prf_failed",
  // pin_set
  "wrong_credentials",
  "pin_rule",
  "pin_not_allowed",
  "after_restart_not_allowed",
  "not_acknowledged",
  "too_slow",
  "pin_too_slow",
  "vault_locked",
  "signed_out",
  "network",
  "invalid_input",
]);

/** @param {unknown} error @returns {string} */
export function reasonOf(error) {
  const code = /** @type {{ code?: unknown }} */ (error)?.code;
  if (typeof code === "string" && PIN_REASONS.includes(code)) return code;
  return sessionReasonOf(error);
}

/** The page that makes the one WebAuthn call of a passkey unlock, and sends its result. */
const UNLOCK_WINDOW_PATH = "pages/unlockWindow.html";

/**
 * True when `sender` is the unlock window: a top-level page of this extension whose address is the window page (a query
 * or a fragment aside).
 * @param {any} sender @param {{ id?: string, getURL: (path: string) => string } | undefined} runtime
 */
function isUnlockWindow(sender, runtime) {
  if (runtime === undefined || !isTopLevelExtensionPage(sender, runtime)) return false;
  const url = typeof sender?.url === "string" ? sender.url : "";
  const base = runtime.getURL(UNLOCK_WINDOW_PATH);
  return url === base || url.startsWith(`${base}?`) || url.startsWith(`${base}#`);
}

const notAvailable = () => Object.assign(new Error("not_available"), { code: "not_available" });

/**
 * Runs an operation whose failure is the user's to read: the answer is the operation's, or `{ ok: false, reason }`.
 * @param {() => Promise<unknown>} run
 */
async function answer(run) {
  try {
    return await run();
  } catch (error) {
    return { ok: false, reason: reasonOf(error) };
  }
}

/** @param {any} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  if (!FEATURES.unlock) throw notAvailable();
  // The sender, before anything else.
  if (ctx.channel !== "ui" || ctx.runtime === undefined || !isTopLevelExtensionPage(ctx.sender, ctx.runtime)) throw notAvailable();
  const call = /** @type {NonNullable<typeof ctx.call>} */ (ctx.call);
  switch (ctx.type) {
    case "unlock_policy":
      return call("unlock_policy", {});
    case "pin_set":
      return answer(() => call("pin_set", body));
    case "pin_unlock": {
      // An unlock never runs on top of an open vault: that one is locked first.
      const lock = /** @type {NonNullable<typeof ctx.lock>} */ (ctx.lock);
      if (ctx.state() === "unlocked") await lock("manual");
      return answer(() => call("pin_unlock", body));
    }
    case "pin_off":
      return answer(() => call("pin_off", {}));
    case "prf_window":
      return answer(() => call("prf_window", {}));
    case "prf_options":
      return answer(() => call("prf_options", {}));
    case "prf_unlock": {
      // Only the unlock window opens the vault with a passkey: a request from another page of the extension (the popup, say,
      // which cannot even make the call) is refused, and so is one from a window of the same page that a frame holds.
      if (!isUnlockWindow(ctx.sender, ctx.runtime)) throw notAvailable();
      // An unlock never runs on top of an open vault: that one is locked first.
      const lock = /** @type {NonNullable<typeof ctx.lock>} */ (ctx.lock);
      if (ctx.state() === "unlocked") await lock("manual");
      return answer(() => call("prf_unlock", body));
    }
    default:
      throw notAvailable();
  }
}

export default {
  types: ["unlock_policy", "pin_set", "pin_unlock", "pin_off", "prf_options", "prf_unlock", "prf_window"],
  channel: /** @type {"ui"} */ ("ui"),
  handle,
};
