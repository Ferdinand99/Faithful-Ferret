import { resolveForgetTarget } from "../flows/forgetServer.mjs";
import { forgetView } from "../views/forget.mjs";

/** "Forget this server"; it works signed in, locked or signed out. @type {import("../app.mjs").Route} */
export default {
  path: "/forget",
  title: "syncwarnings.forget.title",
  load: async ({ i18n, services, go }) => {
    const session = services.crypto;
    const target = await resolveForgetTarget({ session, store: services.store, serverUrl: session.serverUrl });
    return forgetView({
      t: i18n.t, session, store: services.store, api: services.api, serverUrl: session.serverUrl,
      accountId: target?.accountId ?? null, email: target?.email ?? null, go,
    });
  },
};
