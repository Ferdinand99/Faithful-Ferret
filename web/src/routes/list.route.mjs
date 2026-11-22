import { moveHook } from "../views/folderActions.mjs";
import { folderHref } from "../views/folderLinks.mjs";
import { listView } from "../views/list.mjs";
import { enterVault } from "../views/shell.mjs";

/** The item list. Its filters are in the address (`#/items?type=login&fav=1`). @type {import("../app.mjs").Route} */
export default {
  path: "/items",
  title: "vault.list.title",
  sidebar: { section: "main", order: 10, icon: "items", role: "nav-items", title: "shell.nav.items", count: "all" },
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    // The list reads its filters from the address and puts a change in it, as a new entry, so back and forward work.
    const nav = {
      query: ctx.query ?? "",
      set: (/** @type {string} */ query) => ctx.go(query === "" ? "/items" : `/items?${query}`),
      watch: (/** @type {(query: string) => void} */ fn) => (typeof ctx.watchQuery === "function" ? ctx.watchQuery(fn) : () => {}),
    };
    const move = moveHook({ t: ctx.i18n.t, engine: vault.engine, locale: ctx.i18n.lang, touch: vault.touch, scope: vault.scope });
    return vault.page(listView({
      engine: vault.engine, router: { go: ctx.go }, t: ctx.i18n.t, nav, locale: ctx.i18n.lang, touch: vault.touch, scope: vault.scope,
      moveToFolder: (items, where) => move(items.map((item) => item.id), where),
      folderLink: folderHref,
    }));
  },
};
