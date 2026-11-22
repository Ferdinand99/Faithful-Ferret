import { enterVault } from "../views/shell.mjs";
import { transferView } from "../views/transfer.mjs";

/**
 * `#/transfer`: the page behind the side menu's "Import and export" entry. It offers the two pages that do the work,
 * `#/import` and `#/export`, which belong to the same entry (`activeFor`). @type {import("../app.mjs").Route}
 */
export default {
  path: "/transfer",
  title: "transfer.title",
  sidebar: { section: "tools", order: 30, icon: "transfer", role: "nav-transfer", title: "shell.nav.transfer", activeFor: ["/import", "/export"] },
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    return vault.page(transferView({ t: ctx.i18n.t }));
  },
};
