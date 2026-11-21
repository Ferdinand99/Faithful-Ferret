// The sync's messages from the extension's own pages (the popup, over the UI
// port): what the sync shows, "Try again" after a stop, and "Forget this
// server".
//
// Every answer is codes and nothing else: the state of the engine, the code of
// a stop and of each warning (the page has a text for each, from the web
// vault's sync warnings), never an item, a name or a text of the server.

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
  "unknown",
]);

/** @param {unknown} error @returns {string} */
export function reasonOf(error) {
  const code = /** @type {{ code?: unknown }} */ (error)?.code;
  if (code === "internal" || code === "kdf_out_of_memory") return "worker_failed";
  return typeof code === "string" && REASONS.includes(code) ? code : "unknown";
}

/** @param {any} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  const call = /** @type {NonNullable<typeof ctx.call>} */ (ctx.call);
  switch (ctx.type) {
    case "sync_state":
      return call("sync_state");
    case "sync_retry":
    case "forget_server":
      try {
        const reply = /** @type {{ ok: boolean, reason?: string }} */ (
          await call(ctx.type, ctx.type === "forget_server" ? { server: body.server } : undefined)
        );
        return reply.ok ? { ok: true } : { ok: false, reason: reasonOf({ code: reply.reason }) };
      } catch (error) {
        return { ok: false, reason: reasonOf(error) };
      }
    default:
      throw Object.assign(new Error("not_available"), { code: "not_available" });
  }
}

export default {
  types: ["sync_state", "sync_retry", "forget_server"],
  channel: /** @type {"ui"} */ ("ui"),
  handle,
};
