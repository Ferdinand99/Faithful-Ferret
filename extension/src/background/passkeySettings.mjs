// The settings of the passkey provider (the `passkeys` feature), from the settings page over the UI port: "Use Ferret for passkeys"
// (the setting and the permission for https pages, which saving passwords shares, see background/httpsAccess.mjs), the "never" list
// of the sites where Ferret leaves passkeys to the browser (view, remove one, remove all; a site is added only from Ferret's
// chooser window), and "Count an unlock in the last 5 minutes as verification" (on unless the person turned it off).
//
// The page asks for the permission in its own click and says `enable`; this module checks the permission itself (the registry does)
// and switches the feature through the registry (`enable`/`disable`), never by writing the setting: the registry also registers the
// scripts. The reply is what is true now. It needs no key and works on a locked device; it does not move the lock deadline.
//
// What happens to the feature's own `storage.local` keys when it goes off: the setting itself is false; the "never" list and the
// recent-unlock choice stay (they are the person's choices, and a later turn-on finds them again); nothing else is kept. The only
// code that removes a key is the "never" list's own remove.
//
// Nothing here is a vault value or a key.

import { PASSKEY_RECENT_UNLOCK_KEY } from "./passkeyRegistry.mjs";

/**
 * Whether an unlock in the last five minutes counts as verification: on unless the person turned it off.
 * @param {{ get(key: string): Promise<Record<string, unknown>> }} storageLocal
 * @returns {Promise<boolean>}
 */
export async function recentUnlockOn(storageLocal) {
  try {
    return (await storageLocal.get(PASSKEY_RECENT_UNLOCK_KEY))?.[PASSKEY_RECENT_UNLOCK_KEY] !== false;
  } catch {
    // A read that fails counts as off: the person may have turned it off, and a click is then asked for verification the long way.
    return false;
  }
}

/** The operation's name, as the handler sends it. */
export const PASSKEY_SETTINGS_OP = "passkey_settings";

/**
 * @param {{
 *   registry: { enable(): Promise<{ ok: true } | { ok: false, reason: string }>, disable(): Promise<{ ok: boolean }>, status(): Promise<{ on: boolean, permission: boolean, signed_in: boolean, registered: boolean }>, markPending(): Promise<unknown>, clearPending(): Promise<unknown> },
 *   never: { list(): Promise<string[]>, remove(rpId: string): Promise<unknown> },
 *   storageLocal: { get(key: string): Promise<Record<string, unknown>>, set(items: Record<string, unknown>): Promise<void> },
 * }} deps
 */
export function createPasskeySettings({ registry, never, storageLocal }) {
  const state = async () => {
    const status = await registry.status();
    return {
      on: status.on,
      permission: status.permission,
      signed_in: status.signed_in,
      never: await never.list(),
      recent_unlock: await recentUnlockOn(storageLocal),
    };
  };

  /**
   * @param {any} args
   * @returns {Promise<Record<string, unknown>>}
   */
  async function run(args) {
    if (args?.never_clear === true) for (const host of await never.list()) await never.remove(host);
    if (typeof args?.never_remove === "string") await never.remove(args.never_remove);
    if (typeof args?.recent_unlock === "boolean") await storageLocal.set({ [PASSKEY_RECENT_UNLOCK_KEY]: args.recent_unlock });
    // The switch is about to ask for the permission (or the person said no): a grant that follows is this feature's to finish.
    if (typeof args?.pending === "boolean") await (args.pending ? registry.markPending() : registry.clearPending());
    if (typeof args?.enable === "boolean") {
      /** @type {{ ok: boolean, reason?: string }} */
      const outcome = args.enable ? await registry.enable() : await registry.disable();
      const now = await state();
      return outcome.ok === true ? { ok: true, ...now } : { ok: false, reason: outcome.reason, ...now };
    }
    return { ok: true, ...(await state()) };
  }

  return Object.freeze({
    run,
    ops: Object.freeze({
      [PASSKEY_SETTINGS_OP]: { vault: false, worker: /** @type {const} */ ("none"), run: async (/** @type {unknown} */ _client, /** @type {any} */ args) => run(args) },
    }),
  });
}
