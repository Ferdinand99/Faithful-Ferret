import { restoredView } from "../views/restored.mjs";
import { enterVault } from "../views/shell.mjs";

/** What to do when the server was restored to an earlier state. @type {import("../app.mjs").Route} */
export default {
  path: "/restored",
  title: "syncwarnings.restored.title",
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    return vault.page(restoredView({ engine: vault.engine, t: ctx.i18n.t, router: { go: ctx.go } }));
  },
};
