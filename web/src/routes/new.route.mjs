import { editView } from "../views/edit.mjs";
import { enterVault, trackerOf } from "../views/shell.mjs";

/** Making an item. @type {import("../app.mjs").Route} */
export default {
  path: "/items/new",
  title: "vault.new.title",
  sidebar: { section: "primary", order: 10, icon: "plus", role: "nav-new", title: "vault.nav.new" },
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    const tracker = trackerOf(vault.sync);
    // The vault was moved to another tab while this form had edits that were not saved, and is taken back: the same form goes on.
    const kept = tracker?.takeFrozen("new") ?? null;
    if (kept) {
      kept.thaw({ engine: vault.engine, touch: vault.touch, scope: vault.scope, go: ctx.go, tracker });
      return vault.page(kept.root);
    }
    return vault.page(await editView({
      engine: vault.engine, client: vault.session.client ?? ctx.client, id: null, t: ctx.i18n.t,
      go: ctx.go, touch: vault.touch, scope: vault.scope, tracker,
    }));
  },
};
