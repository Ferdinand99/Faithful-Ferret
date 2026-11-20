import { pageReauth } from "../views/renewRecovery.mjs";
import { secretKeyView } from "../views/secretKey.mjs";
import { enterVault } from "../views/shell.mjs";

/** `#/secret-key`: the secret key this device remembers, as text or as a QR code. @type {import("../app.mjs").Route} */
export default {
  path: "/secret-key",
  title: "keys.secret.title",
  menu: "account",
  menuOrder: 30,
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
    return vault.page(secretKeyView({ t, show: () => session.showSecretKey({ reauth }), status, scope: vault.scope }));
  },
};
