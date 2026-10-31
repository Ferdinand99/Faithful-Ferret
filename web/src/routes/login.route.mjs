import { configuredAdminUrl } from "../flows/adminUrl.mjs";
import { getEntry } from "../flows/entry.mjs";
import { completeHandoff, goToAdmin } from "../flows/handoff.mjs";
import { loginView } from "../views/login.mjs";

/** The sign-in page; `/vault/login` leads here, with or without a hand-over. @type {import("../app.mjs").Route} */
export default {
  path: "/login",
  title: "account.login.title",
  load: async ({ i18n, services, go }) => {
    const session = services.crypto;
    const info = await session.info();
    return loginView({
      t: i18n.t,
      session,
      entry: getEntry(),
      adminUrl: configuredAdminUrl(),
      api: services.api,
      go,
      handoff: { completeHandoff, goToAdmin },
      info,
    });
  },
};
