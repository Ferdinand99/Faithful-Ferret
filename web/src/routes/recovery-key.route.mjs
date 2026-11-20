import { pageReauth, renewRecoveryView } from "../views/renewRecovery.mjs";
import { enterVault } from "../views/shell.mjs";

/**
 * `#/recovery-key`: a new recovery key, and "reapply the unlock methods" after an accepted restore.
 * @type {import("../app.mjs").Route}
 */
export default {
  path: "/recovery-key",
  title: "keys.recovery.title",
  menu: "account",
  menuOrder: 20,
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    const session = ctx.services.crypto;
    const t = ctx.i18n.t;
    const reauth = pageReauth({ t, session, scope: vault.scope });
    return vault.page(renewRecoveryView({
      t,
      renew: ({ confirmNewRk }) => session.renewRecoveryKey({ confirmNewRk, reauth }),
      offer: () => session.reapplyOffer(),
      reapply: ({ note, confirmNewRk }) => session.reapplyMethods({ note, confirmNewRk, reauth }),
      scope: vault.scope,
      locale: ctx.i18n.lang,
    }));
  },
};
