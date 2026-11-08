import { forgetView } from "../views/forget.mjs";

/** "Forget this server"; it works signed in, locked or signed out. @type {import("../app.mjs").Route} */
export default {
  path: "/forget",
  title: "syncwarnings.forget.title",
  load: async ({ i18n, services, go }) => {
    const session = services.crypto;
    /** @type {string | null} */
    let accountId = session.current?.()?.accountId ?? null;
    if (accountId === null) {
      try {
        accountId = (await session.info())?.accountId ?? null;
      } catch {
        accountId = null; // the server cannot be asked: the account is asked for instead
      }
    }
    return forgetView({ t: i18n.t, session, store: services.store, api: services.api, serverUrl: session.serverUrl, accountId, go });
  },
};
