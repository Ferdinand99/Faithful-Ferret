import { configuredAdminUrl } from "../flows/adminUrl.mjs";
import { getEntry } from "../flows/entry.mjs";
import { completeHandoff, goToAdmin } from "../flows/handoff.mjs";
import { loginView } from "../views/login.mjs";

/** Confirms the master password again for the admin pages (`/vault/reauth`). @type {import("../app.mjs").Route} */
export default {
  path: "/reauth",
  title: "account.reauth.title",
  load: async ({ i18n, services, go }) => {
    const session = services.crypto;
    session.attachSync(services.sync);
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
      reauth: true,
    });
  },
};
