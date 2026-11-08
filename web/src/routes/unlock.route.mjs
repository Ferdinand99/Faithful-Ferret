import { el } from "../dom.mjs";
import { restoreNoteFinder } from "../flows/restoreNote.mjs";
import { unlockScreen } from "../views/unlock.mjs";

/** The unlock screen, for a vault that is closed while the sign-in on the server is still good. @type {import("../app.mjs").Route} */
export default {
  path: "/unlock",
  title: "vault.unlock.title",
  load: ({ services, i18n, go }) => {
    const session = services.crypto;
    if (!session) throw new Error("vault: the account session is missing");
    if (session.current?.()) {
      go("/items");
      return el("section", { class: "auth-card", role: "status" }, el("p", null, i18n.t("vault.loading")));
    }
    const restoreNote = services.store ? restoreNoteFinder({ store: services.store, serverUrl: session.serverUrl }) : undefined;
    return unlockScreen({ session, t: i18n.t, go, onUnlocked: () => go("/items"), restoreNote, locale: i18n.lang });
  },
};
