import { generatorView } from "../views/generator.mjs";
import { generatedHandoff } from "../views/generatorModel.mjs";
import { enterVault } from "../views/shell.mjs";

/**
 * `#/generator`: a new password or passphrase from the core, to copy or to use for a new item. The value lives on the page
 * only and goes when the page, the lock or the sign-out does. @type {import("../app.mjs").Route}
 */
export default {
  path: "/generator",
  title: "generator.title",
  sidebar: { section: "tools", order: 10, icon: "generator", role: "nav-generator", title: "shell.nav.generator" },
  load: async (ctx) => {
    // A value that was left for the form of a new item and never taken goes now.
    generatedHandoff.clear();
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    return vault.page(generatorView({
      t: ctx.i18n.t, client: vault.session.client ?? ctx.client, go: ctx.go, touch: vault.touch, scope: vault.scope,
    }));
  },
};
