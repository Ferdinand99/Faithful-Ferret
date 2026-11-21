import { passwordView } from "../views/password.mjs";
import { enterVault } from "../views/shell.mjs";

/**
 * `/vault/password`: change the master password. The admin pages send people here; a vault that is locked shows
 * the unlock screen first and comes back. @type {import("../app.mjs").Route}
 */
export default {
  path: "/password",
  title: "security.password.title",
  menu: "account",
  menuOrder: 10,
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    const session = ctx.services.crypto;
    const email = session.current?.()?.email ?? null;
    /** @type {{ pinned: boolean, skBit: boolean | null, skStored: boolean } | null} */
    let status = null;
    try {
      status = email === null ? null : await session.deviceStatus(email);
    } catch {
      status = null;
    }
    return vault.page(passwordView({
      t: ctx.i18n.t,
      change: (args) => session.changePassword(args),
      skRequired: status?.skBit === true && status.skStored !== true,
      skBit: status?.skBit ?? null,
      scope: vault.scope,
    }));
  },
};
