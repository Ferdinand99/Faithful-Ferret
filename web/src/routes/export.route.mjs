import { refreshReadiness } from "../flows/export.mjs";
import { exportView } from "../views/export.mjs";
import { enterVault } from "../views/shell.mjs";

/**
 * `#/export`: the encrypted export and the plain export. It is listed on the account page, and the reminder to take
 * a new export leads here. @type {import("../app.mjs").Route}
 */
export default {
  path: "/export",
  title: "export.title",
  menu: "account",
  menuOrder: 50,
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    const session = ctx.services.crypto;
    const store = ctx.services.store;
    const open = session.current?.() ?? null;
    const email = open?.email ?? null;
    /** @type {{ pinned: boolean, skBit: boolean | null, skStored: boolean } | null} */
    let status = null;
    try {
      status = email === null ? null : await session.deviceStatus(email);
    } catch {
      status = null;
    }
    /** When the last encrypted export was made on this device (the date is not secret), or null. @type {number | null} */
    let lastExportAt = null;
    try {
      if (open !== null) lastExportAt = (await store.exportReminder.status(await store.open(), session.serverUrl, open.accountId, Date.now())).lastExportAt;
    } catch {
      lastExportAt = null;
    }
    return vault.page(exportView({
      t: ctx.i18n.t,
      exportEncrypted: (args) => session.exportEncrypted(args),
      exportPlain: (args) => session.exportPlain(args),
      readiness: () => refreshReadiness(vault.engine),
      skRequired: status?.skBit === true && status.skStored !== true,
      lastExportAt,
      locale: ctx.i18n.lang,
      scope: vault.scope,
    }));
  },
};
