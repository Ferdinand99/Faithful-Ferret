// The sync's messages from the extension's own pages (the popup, over the UI
// port): what the sync shows, "Try again" after a stop, "Accept the older
// state" of a restored server (what it would do first, then the accept), and
// "Forget this server" (what it would lose first, then the forget).
//
// Every answer is codes and counts and nothing else: the state of the engine,
// the code of a stop and of each warning (the page has a text for each, from
// the web vault's sync warnings), never an item, a name or a text of the server.

/** The reasons a page has a text for (`sync.error.<reason>`). Every other code becomes `unknown`. */
export const REASONS = Object.freeze([
  "sync_still_halted",
  "sync_not_running",
  "another_server",
  "busy",
  "forget_incomplete",
  "vault_locked",
  "worker_failed",
  "network",
  "not_confirmed",
  "changed",
  "not_verified",
  "not_verified_no_checkpoint",
  "invalid_state",
  "bad_feed",
  "unknown",
]);

/** @param {unknown} error @returns {string} */
export function reasonOf(error) {
  const code = /** @type {{ code?: unknown }} */ (error)?.code;
  if (code === "internal" || code === "kdf_out_of_memory") return "worker_failed";
  return typeof code === "string" && REASONS.includes(code) ? code : "unknown";
}

/** @param {unknown} n @returns {n is number} */
const isCount = (n) => typeof n === "number" && Number.isSafeInteger(n) && n >= 0 && n <= 1_000_000;

/**
 * The answer of an op as the page may get it: `ok`, or a reason from REASONS, and the named counts and flags (only
 * those the op gave).
 * @param {any} reply @param {readonly string[]} [counts] @param {readonly string[]} [flags]
 */
function answerOf(reply, counts = [], flags = []) {
  if (reply?.ok !== true) return { ok: false, reason: reasonOf({ code: reply?.reason }) };
  /** @type {Record<string, unknown>} */
  const out = { ok: true };
  for (const key of counts) if (isCount(reply[key])) out[key] = reply[key];
  for (const key of flags) if (typeof reply[key] === "boolean") out[key] = reply[key];
  return out;
}

/** @param {any} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  const call = /** @type {NonNullable<typeof ctx.call>} */ (ctx.call);
  if (ctx.type === "sync_state") return call("sync_state");
  try {
    switch (ctx.type) {
      case "sync_retry":
        return answerOf(await call("sync_retry"));
      case "sync_older_preview":
        return answerOf(await call("sync_older_preview"), ["reupload", "conflicts"], ["manifest_older"]);
      case "sync_accept_older":
        return answerOf(await call("sync_accept_older", { confirmed: body.confirmed === true }), ["reuploaded", "conflicts", "unreadable"], ["manifest_older"]);
      case "forget_preview":
        return answerOf(await call("forget_preview", { server: body.server }), ["pending"], ["shared"]);
      case "forget_server":
        return answerOf(await call("forget_server", { server: body.server, ...(body.expect_pending !== undefined ? { expect_pending: body.expect_pending } : {}) }));
      default:
        break;
    }
  } catch (error) {
    return { ok: false, reason: reasonOf(error) };
  }
  throw Object.assign(new Error("not_available"), { code: "not_available" });
}

export default {
  types: ["sync_state", "sync_retry", "sync_older_preview", "sync_accept_older", "forget_preview", "forget_server"],
  channel: /** @type {"ui"} */ ("ui"),
  handle,
};
