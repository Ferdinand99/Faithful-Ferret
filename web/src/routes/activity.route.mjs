import { clearNotice, loadEvents, markSeen } from "../flows/accountEvents.mjs";
import { activityView } from "../views/activity.mjs";
import { enterVault } from "../views/shell.mjs";

/**
 * `#/activity`: the account log, newest first. Showing it clears the notice of new events: the mark of this browser and
 * account moves to the newest event shown (flows/accountEvents.mjs). @type {import("../app.mjs").Route}
 */
export default {
  path: "/activity",
  title: "activity.title",
  menu: "account",
  menuOrder: 35,
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    const session = ctx.services.crypto;
    const api = ctx.services.api;
    const store = ctx.services.store;
    const open = session.current?.() ?? null;
    // This page is where the notice leads: the frame around it has none, and this unlock has none after it.
    if (open !== null) clearNotice(open);
    return vault.page(activityView({
      t: ctx.i18n.t,
      locale: ctx.i18n.lang,
      load: (before) => loadEvents(api, before === undefined ? {} : { before }),
      onShown: async (events) => {
        if (open === null || typeof store?.activitySeen?.save !== "function") return;
        await markSeen({ save: async (mark) => store.activitySeen.save(await store.open(), session.serverUrl, open.accountId, mark) }, events);
      },
    }), { accountNotice: false });
  },
};
