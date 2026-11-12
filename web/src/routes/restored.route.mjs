import { recordAcceptedRestore } from "../flows/restoreNote.mjs";
import { restoredView } from "../views/restored.mjs";
import { enterVault } from "../views/shell.mjs";

/** What to do when the server was restored to an earlier state. @type {import("../app.mjs").Route} */
export default {
  path: "/restored",
  title: "syncwarnings.restored.title",
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    const session = ctx.services.crypto;
    const accountId = session.current?.()?.accountId;
    // An accepted restore that took the unlock methods back leaves a local note, so that the next refusal can say why.
    const onAccepted = (/** @type {{ manifestOlder?: boolean }} */ result) =>
      recordAcceptedRestore({ store: ctx.services.store, serverUrl: session.serverUrl, accountId, result });
    return vault.page(restoredView({ engine: vault.engine, t: ctx.i18n.t, router: { go: ctx.go }, onAccepted }));
  },
};
