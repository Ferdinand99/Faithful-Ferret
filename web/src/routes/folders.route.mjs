import { createUiPrefs } from "../uiPrefs.mjs";
import { folderHref } from "../views/folderLinks.mjs";
import { foldersPage } from "../views/foldersPage.mjs";
import { enterVault } from "../views/shell.mjs";

/** Every folder of the vault, with pin, rename and delete. The page of one folder is `#/folders/<token>`. @type {import("../app.mjs").Route} */
export default {
  path: "/folders",
  title: "folders.title",
  sidebar: { section: "manage", order: 10, icon: "folder", role: "nav-folders", title: "shell.nav.folders", activeFor: ["/folders/"] },
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    return vault.page(foldersPage({
      engine: vault.engine, t: ctx.i18n.t, prefs: createUiPrefs(), folderLink: folderHref, locale: ctx.i18n.lang, touch: vault.touch, scope: vault.scope,
    }));
  },
};
