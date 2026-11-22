import { configuredAdminUrl } from "../flows/adminUrl.mjs";
import { getEntry } from "../flows/entry.mjs";
import { restoreNoteTools } from "../flows/restoreNote.mjs";
import { completeHandoff, goToAdmin } from "../flows/handoff.mjs";
import { loginView } from "../views/login.mjs";

/** The sign-in page (or "Unlock" for the account this browser remembers); `/vault/login` leads here, with or without a hand-over. @type {import("../app.mjs").Route} */
export default {
  path: "/login",
  title: "account.login.title",
  load: async ({ i18n, services, go }) => {
    const session = services.crypto;
    const info = await session.info();
    // With no session, the account this browser remembers makes the page "Unlock" (flows/rememberedAccount.mjs).
    const remembered = info === null && typeof session.remembered === "function" ? await session.remembered().catch(() => null) : null;
    return loginView({
      t: i18n.t,
      session,
      entry: getEntry(),
      adminUrl: configuredAdminUrl(),
      api: services.api,
      store: services.store,
      go,
      handoff: { completeHandoff, goToAdmin },
      info,
      remembered,
      ...restoreNoteTools({ store: services.store, serverUrl: session.serverUrl }),
      locale: i18n.lang,
    });
  },
};
