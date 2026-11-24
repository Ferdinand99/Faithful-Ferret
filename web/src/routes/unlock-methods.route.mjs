import { el } from "../dom.mjs";
import { pageReauth } from "../views/renewRecovery.mjs";
import { enterVault } from "../views/shell.mjs";
import { unlockMethodsView } from "../views/unlockMethods.mjs";

/**
 * `#/unlock-methods`: the passkeys that open the vault. The page exists only when the server offers passkeys as unlock
 * methods (`GET /api/vault/policy`, `prf.enabled`): without that it is not in the account menu (`requires: "prf"`), and
 * its address shows a short notice and nothing to press. @type {import("../app.mjs").Route}
 */
export default {
  path: "/unlock-methods",
  title: "methods.title",
  menu: "account",
  menuOrder: 40,
  requires: "prf",
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    const session = ctx.services.crypto;
    const t = ctx.i18n.t;
    const offered = await Promise.resolve(session.passkeysOffered?.()).catch(() => false);
    if (offered !== true) {
      return vault.page(el("section", { class: "card methods-page", "data-role": "methods-unavailable" },
        el("h1", null, t("methods.heading")),
        el("p", null, t("methods.unavailable"))));
    }
    const reauth = pageReauth({ t, session, scope: vault.scope });
    // The passkey is tied to the exact host the page was delivered from, never to a parent domain.
    const site = globalThis.location?.hostname ?? "";
    return vault.page(unlockMethodsView({
      t,
      site,
      locale: ctx.i18n.lang,
      load: () => session.listPasskeys(),
      begin: () => session.beginAddPasskey(site === "" ? { reauth } : { reauth, rpId: site }),
      remove: (id) => session.removePasskey({ id, reauth }),
      scope: vault.scope,
    }));
  },
};
