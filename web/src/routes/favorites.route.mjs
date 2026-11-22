import { listView } from "../views/list.mjs";
import { enterVault } from "../views/shell.mjs";

/**
 * The favourites: the item list over the favourite items only. The list screen is the same one; it is given a
 * view of the engine that holds the favourites, so it needs no filter of its own. @type {import("../app.mjs").Route}
 */
export default {
  path: "/favorites",
  title: "shell.nav.favorites",
  sidebar: { section: "main", order: 20, icon: "star", role: "nav-favorites", count: "favorites" },
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    const engine = vault.engine;
    const favourites = {
      list: () => engine.list().filter((/** @type {{ favorite?: boolean }} */ item) => item.favorite === true),
      on: (/** @type {string} */ event, /** @type {(payload: any) => void} */ fn) => engine.on(event, fn),
    };
    return vault.page(listView({ engine: favourites, router: { go: ctx.go }, t: ctx.i18n.t }));
  },
};
