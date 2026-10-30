import { configuredAdminUrl } from "../flows/adminUrl.mjs";
import { clearSetupToken, getEntry } from "../flows/entry.mjs";
import { goToAdmin } from "../flows/handoff.mjs";
import { setupView } from "../views/setup.mjs";

/** The first administrator makes the account (`/vault/setup`). @type {import("../app.mjs").Route} */
export default {
  path: "/setup",
  title: "account.setup.title",
  load: ({ i18n, services, go }) => {
    const session = services.crypto;
    session.attachSync(services.sync);
    return setupView({
      t: i18n.t,
      session,
      setupToken: getEntry().setupToken,
      spentToken: clearSetupToken,
      adminUrl: configuredAdminUrl(),
      go,
      handoff: { goToAdmin },
      print: () => window.print(),
    });
  },
};
