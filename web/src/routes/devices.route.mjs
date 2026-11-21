import { checkStep } from "../wire.mjs";
import { devicesView } from "../views/devices.mjs";
import { reauthDialog } from "../views/reauthDialog.mjs";
import { enterVault } from "../views/shell.mjs";

/** The routes of the list of devices on the server. */
const DEVICES = "/api/auth/devices";

/**
 * `#/devices`: the browsers and devices of the account, revoking one, forgetting old ones and revoking all of them
 * after the master password again. @type {import("../app.mjs").Route}
 */
export default {
  path: "/devices",
  title: "devices.title",
  menu: "account",
  menuOrder: 30,
  load: async (ctx) => {
    const vault = await enterVault(ctx);
    if (vault.locked) return vault.locked;
    const session = ctx.services.crypto;
    const api = ctx.services.api;
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
    return vault.page(devicesView({
      t,
      locale: ctx.i18n.lang,
      load: async () => {
        const list = await api.get(DEVICES, { shape: "devices_res" });
        checkStep("devices_res", list);
        return list;
      },
      revoke: (id) => {
        if (typeof id !== "string" || !/^[0-9a-f]{32}$/.test(id)) throw new TypeError("a device id is 32 hexadecimal characters");
        return api.del(`${DEVICES}/${id}`);
      },
      revokeAll: () => api.post(`${DEVICES}/revoke-all`, undefined, { shape: "revoke_all_res" }),
      forgetOld: () => api.post(`${DEVICES}/forget-old`, undefined, { shape: "revoke_all_res" }),
      reauth: async () => reauthDialog({
        t, run: (typed) => session.reauthenticate(typed), until: session.reauthUntil(), skRequired: await skRequired(), scope: vault.scope,
      }),
    }));
  },
};
