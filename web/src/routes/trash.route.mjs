import { enterVault } from "../views/shell.mjs";
import { trashView } from "../views/trash.mjs";

/** The local trash. @type {import("../app.mjs").Route} */
export default {
  path: "/trash",
  title: "conflict.trash.title",
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    return vault.page(await trashView({ engine: vault.engine, t: ctx.i18n.t, locale: ctx.i18n.lang, touch: vault.touch, scope: vault.scope }));
  },
};
