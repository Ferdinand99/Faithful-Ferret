import { listView } from "../views/list.mjs";
import { enterVault } from "../views/shell.mjs";

/** The item list. @type {import("../app.mjs").Route} */
export default {
  path: "/items",
  title: "vault.list.title",
  sidebar: { section: "main", order: 10, icon: "items", role: "nav-items", title: "shell.nav.items", count: "all" },
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    return vault.page(listView({ engine: vault.engine, router: { go: ctx.go }, t: ctx.i18n.t }));
  },
};
