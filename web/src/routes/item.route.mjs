import { hex16 } from "../b64.mjs";
import { itemView } from "../views/item.mjs";
import { enterVault, messageCard } from "../views/shell.mjs";

/** One item. @type {import("../app.mjs").Route} */
export default {
  path: "/items/:id",
  title: "vault.item.title",
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    const { id } = ctx.params;
    if (!hex16.is(id)) return vault.page(messageCard(ctx.i18n.t, "vault.item.not_found"));
    return vault.page(await itemView({
      engine: vault.engine, sync: vault.sync, client: vault.session.client ?? ctx.client, id, t: ctx.i18n.t,
      go: ctx.go, touch: vault.touch, scope: vault.scope,
    }));
  },
};
