import { ADMIN_LANDING, configuredAdminUrl } from "../flows/adminUrl.mjs";
import { goToAdmin } from "../flows/handoff.mjs";
import { reauthDialog } from "../views/reauthDialog.mjs";
import { accountView, offeredRoutes } from "../views/account.mjs";
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
    // The way to the admin pages is for an administrator, and only where this vault has an admin address.
    const adminUrl = configuredAdminUrl();
    const admin = adminUrl !== null && (await session.info().catch(() => null))?.admin === true;
    // A page that needs a feature of the server (`requires`) is listed only when the server has it.
    const prf = await Promise.resolve(session.passkeysOffered?.()).catch(() => false);
    const routes = offeredRoutes(ctx.routes ?? [], { prf: prf === true });
    return vault.page(accountView({
      toAdmin: admin && adminUrl !== null ? () => goToAdmin({ adminUrl, next: ADMIN_LANDING, purpose: "login" }) : undefined,
      t,
      routes,
      email,
      locale: ctx.i18n.lang,
      fresh: () => session.reauthUntil(),
      reauth: async () => reauthDialog({
        t, run: (typed) => session.reauthenticate(typed), until: session.reauthUntil(), skRequired: await skRequired(), scope: vault.scope,
      }),
    }));
  },
};
