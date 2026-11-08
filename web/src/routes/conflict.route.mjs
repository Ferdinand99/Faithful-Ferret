import { hex16 } from "../b64.mjs";
import { conflictView } from "../views/conflict.mjs";
import { enterVault, messageCard } from "../views/shell.mjs";

/** The two versions of an item that was changed in two places. @type {import("../app.mjs").Route} */
export default {
  path: "/items/:id/conflict",
  title: "conflict.title",
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    const { id } = ctx.params;
    if (!hex16.is(id)) return vault.page(messageCard(ctx.i18n.t, "vault.item.not_found"));
    return vault.page(await conflictView({
      engine: vault.engine, client: vault.session.client ?? ctx.client, id, t: ctx.i18n.t, router: { go: ctx.go },
      locale: ctx.i18n.lang, touch: vault.touch, scope: vault.scope,
    }));
  },
};
