import { recoverAccount } from "../flows/recover.mjs";
import { recoverView } from "../views/recover.mjs";

/**
 * `/vault/#/recover`: a forgotten master password or a new browser, with the recovery key. The admin listener
 * sends the kit's sign-in code page here, so a one-time code is only typed on this page. @type {import("../app.mjs").Route}
 */
export default {
  path: "/recover",
  title: "recover.title",
  load: async ({ i18n, services, go }) => {
    const session = services.crypto;
    // Only a full session counts as signed in; a reset session from an earlier code is found again by the flow.
    const info = await session.info().catch(() => null);
    /** @type {import("../crypto/env.mjs").Env} */
    const env = {
      client: session.client,
      api: services.api,
      store: services.store,
      server: session.serverUrl,
      lock: () => session.lock(),
      now: Date.now,
      rand: (bytes) => globalThis.crypto.getRandomValues(bytes),
    };
    return recoverView({
      t: i18n.t,
      info,
      serverUrl: session.serverUrl,
      readSetupQr: (text) => session.readSetupQr(text),
      deviceStatus: (email) => session.deviceStatus(email),
      recover: async (args) => {
        // A vault that is open in this tab is locked first: the recovery opens the vault in the worker itself.
        if (session.current() !== null) await session.lock();
        // The sign-in that follows goes through the session, so the vault opens as after any sign-in.
        return recoverAccount(env, /** @type {any} */ (args), { signIn: (a) => session.unlock(a) });
      },
      go,
    });
  },
};
