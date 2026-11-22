import { el } from "../dom.mjs";

/**
 * The favourites are a filter of the item list, not a page of their own: the side menu entry (and any old link to
 * `#/favorites`) opens the list with that chip on. The redirect replaces this address in the history, so Back does not
 * come here again. @type {import("../app.mjs").Route}
 */
export default {
  path: "/favorites",
  title: "shell.nav.favorites",
  sidebar: { section: "main", order: 20, icon: "star", role: "nav-favorites", count: "favorites" },
  load: (ctx) => {
    ctx.replace("/items?fav=1");
    return el("div", { "data-role": "redirect" });
  },
};
