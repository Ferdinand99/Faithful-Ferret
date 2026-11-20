import { hex16 } from "../b64.mjs";
import { editView } from "../views/edit.mjs";
import { enterVault, messageCard, trackerOf } from "../views/shell.mjs";

/** Changing an item. @type {import("../app.mjs").Route} */
export default {
  path: "/items/:id/edit",
  title: "vault.edit.title",
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    const { id } = ctx.params;
    if (!hex16.is(id)) return vault.page(messageCard(ctx.i18n.t, "vault.item.not_found"));
    const tracker = trackerOf(vault.sync);
    // The vault was moved to another tab while this form had edits that were not saved, and is taken back: the same form goes on.
    const kept = tracker?.takeFrozen(`edit:${id}`) ?? null;
    if (kept) {
      kept.thaw({ engine: vault.engine, touch: vault.touch, scope: vault.scope, go: ctx.go, tracker });
      return vault.page(kept.root);
    }
    return vault.page(await editView({
      engine: vault.engine, client: vault.session.client ?? ctx.client, id, t: ctx.i18n.t,
      go: ctx.go, touch: vault.touch, scope: vault.scope, tracker,
    }));
  },
};
