import { configuredAdminUrl } from "../flows/adminUrl.mjs";
import { clearInvite, clearSetupToken, getEntry } from "../flows/entry.mjs";
import { goToAdmin } from "../flows/handoff.mjs";
import { checkInvite } from "../flows/invite.mjs";
import { setupView } from "../views/setup.mjs";

/**
 * Making an account (`/vault/setup`): the first administrator with the setup token, or a later person with an
 * invitation link (`#invite=`), who gets the "join" form of the page.
 * @type {import("../app.mjs").Route}
 */
export default {
  path: "/setup",
  title: "account.setup.title",
  load: ({ i18n, services, go }) => {
    const session = services.crypto;
    const entry = getEntry();
    return setupView({
      t: i18n.t,
      session,
      setupToken: entry.setupToken,
      spentToken: clearSetupToken,
      invite: entry.invite,
      checkInvite: (invite) => checkInvite(services.api, invite),
      spentInvite: clearInvite,
      host: globalThis.location?.host ?? "",
      locale: i18n.lang,
      adminUrl: configuredAdminUrl(),
      go,
      handoff: { goToAdmin },
      print: () => window.print(),
    });
  },
};
