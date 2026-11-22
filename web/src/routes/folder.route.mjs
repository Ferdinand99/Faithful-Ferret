import { el } from "../dom.mjs";
import { folderIndex } from "../folders.mjs";
import { createUiPrefs } from "../uiPrefs.mjs";
import { moveHook } from "../views/folderActions.mjs";
import { folderHref, keyOfToken } from "../views/folderLinks.mjs";
import { folderBar } from "../views/foldersPage.mjs";
import { listView } from "../views/list.mjs";
import { enterVault } from "../views/shell.mjs";

/**
 * The items of one folder: the list, with the folder filter on and the folder's name as its heading. The address holds a
 * token that this page made for the folder (views/folderLinks.mjs), never its name; a token from before a lock, or one
 * this page never made, leads to the list of folders. @type {import("../app.mjs").Route}
 */
export default {
  path: "/folders/:token",
  title: "folders.folder_title",
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    const t = ctx.i18n.t;
    const key = keyOfToken(ctx.params.token);
    const folder = key === null ? null : folderIndex(vault.engine.list(), ctx.i18n.lang).find((entry) => entry.key === key) ?? null;
    if (folder === null) {
      return vault.page(el("section", { class: "card", "data-role": "folder-gone" },
        el("p", null, t("folders.gone")),
        el("p", null, el("a", { href: "#/folders", "data-role": "folders-link" }, t("folders.gone_link")))));
    }
    const move = moveHook({ t, engine: vault.engine, locale: ctx.i18n.lang, touch: vault.touch, scope: vault.scope });
    const list = listView({
      engine: vault.engine, router: { go: ctx.go }, t, locale: ctx.i18n.lang, touch: vault.touch, scope: vault.scope,
      folder: folder.name, folderLink: folderHref,
      moveToFolder: (items, where) => move(items.map((item) => item.id), where),
    });
    return vault.page(el("div", { class: "folder-page", "data-role": "folder-page" },
      folderBar({ t, name: folder.name, prefs: createUiPrefs(), touch: vault.touch, scope: vault.scope }), list));
  },
};
