import { pageReauth } from "../views/renewRecovery.mjs";
import { accessSheetView } from "../views/secretKey.mjs";
import { enterVault } from "../views/shell.mjs";

/** `#/sheet`: page 1 of the emergency sheet again, as a PDF. @type {import("../app.mjs").Route} */
export default {
  path: "/sheet",
  title: "keys.sheet.title",
  menu: "account",
  menuOrder: 40,
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    const session = ctx.services.crypto;
    const t = ctx.i18n.t;
    const email = session.current?.()?.email ?? null;
    /** @type {{ pinned: boolean, skBit: boolean | null, skStored: boolean } | null} */
    let status = null;
    try {
      status = email === null ? null : await session.deviceStatus(email);
    } catch {
      status = null;
    }
    const reauth = pageReauth({ t, session, scope: vault.scope });
    return vault.page(accessSheetView({ t, make: () => session.accessSheet({ reauth, t }), status }));
  },
};
