import { hex16 } from "../b64.mjs";
import { editView } from "../views/edit.mjs";
import { enterVault, messageCard } from "../views/shell.mjs";

/** Changing an item. @type {import("../app.mjs").Route} */
export default {
  path: "/items/:id/edit",
  title: "vault.edit.title",
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    const { id } = ctx.params;
    if (!hex16.is(id)) return vault.page(messageCard(ctx.i18n.t, "vault.item.not_found"));
    return vault.page(await editView({
      engine: vault.engine, client: vault.session.client ?? ctx.client, id, t: ctx.i18n.t,
      go: ctx.go, touch: vault.touch, scope: vault.scope,
    }));
  },
};
