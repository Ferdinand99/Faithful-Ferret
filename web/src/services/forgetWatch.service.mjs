// Listens for "forget this server" in other tabs. When one tab forgets the server
// and account that this tab has open, this tab locks and stops its sync engine:
// the records it would save to are gone, and it must not write them back.
//
// The message is `{ type, serverKey, accountId }` on the page's
// `BroadcastChannel("ferret")`, which only pages of the same origin can reach. The type
// is "forgetting" (sent before anything is removed, so that no engine is saving while the
// records go) and "forgotten" (sent when it is done). Both do the same, and a tab that
// has locked already does nothing the second time. They are checked all the same: the
// type, this server and the open account must all match, and anything else is ignored.
import { hex16 } from "../b64.mjs";
import { serverKey } from "../store/idb.mjs";

/** @type {import("../app.mjs").ServiceDef} */
export default {
  name: "forgetWatch",
  deps: ["crypto", "sync"],
  // `serverUrl`, `makeChannel` and `navigate` are for tests: in the browser they are the page's own.
  create: ({
    crypto: session, sync,
    serverUrl = globalThis.location?.origin,
    makeChannel = () => (typeof BroadcastChannel === "function" ? new BroadcastChannel("ferret") : null),
    navigate = (/** @type {string} */ hash) => {
      if (globalThis.location) globalThis.location.hash = hash;
    },
  }) => {
    /** @type {string | null} */
    let server = null;
    try {
      server = serverKey(serverUrl);
    } catch {
      server = null;
    }
    const channel = server === null ? null : makeChannel();

    /** @param {unknown} data */
    async function onMessage(data) {
      const message = /** @type {any} */ (data);
      if (message === null || typeof message !== "object" || (message.type !== "forgotten" && message.type !== "forgetting")) return;
      if (message.serverKey !== server || !hex16.is(message.accountId)) return;
      const open = session.current?.();
      if (!open || open.accountId !== message.accountId) return;
      try {
        // Locking stops the engine too; stopping it again is harmless and does not depend on the order.
        await session.lock();
      } finally {
        sync.stop();
        navigate("#/login");
      }
    }

    channel?.addEventListener("message", (/** @type {any} */ event) => void onMessage(event?.data).catch(() => {}));

    return {
      /** Stops listening. */
      close() {
        channel?.close();
      },
    };
  },
};
