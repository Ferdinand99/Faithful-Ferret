import { editView } from "../views/edit.mjs";
import { enterVault } from "../views/shell.mjs";

/** Making an item. @type {import("../app.mjs").Route} */
export default {
  path: "/items/new",
  title: "vault.new.title",
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    return vault.page(await editView({
      engine: vault.engine, client: vault.session.client ?? ctx.client, id: null, t: ctx.i18n.t,
      go: ctx.go, touch: vault.touch, scope: vault.scope,
    }));
  },
};
