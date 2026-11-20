import { reauthDialog } from "../views/reauthDialog.mjs";
import { accountView } from "../views/account.mjs";
import { enterVault } from "../views/shell.mjs";

/** The account page: the settings pages that say `menu: "account"`, and the password check. @type {import("../app.mjs").Route} */
export default {
  path: "/account",
  title: "security.account.title",
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    const session = ctx.services.crypto;
    const t = ctx.i18n.t;
    const email = session.current?.()?.email ?? null;
    /** Whether the account has a secret key this device does not hold: the dialog then asks for it. */
    const skRequired = async () => {
      try {
        const status = email === null ? null : await session.deviceStatus(email);
        return status?.skBit === true && status.skStored !== true;
      } catch {
        return false;
      }
    };
    return vault.page(accountView({
      t,
      routes: ctx.routes ?? [],
      email,
      locale: ctx.i18n.lang,
      fresh: () => session.reauthUntil(),
      reauth: async () => reauthDialog({
        t, run: (typed) => session.reauthenticate(typed), until: session.reauthUntil(), skRequired: await skRequired(), scope: vault.scope,
      }),
    }));
  },
};
