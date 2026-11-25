// A build with the `passkeys` feature off (a release until Ferret is released as a passkey provider, a rollback to an older
// build) registers no script in web pages. The one thing it does at start is to remove the registrations that a build with
// the feature on may have left: the scripts are registered to persist across sessions, so a script from an older build
// would otherwise keep running in every page, with no code of the feature left to talk to it. Removing a script that is not
// registered does nothing.
//
// It also removes the one setting that could turn the feature on again by itself: the switch "Use Ferret for passkeys" (`use_passkeys`),
// so a later build that has the feature does not start answering for websites from a value an earlier build left. The person's own
// choices stay (the "never" list and the recent-unlock choice): they hold no secret, and a person who turns the feature on again
// finds them as they were.
//
// This is the only place where a build with the feature off names the scripts and the switch, and it only removes them. The module is
// small on purpose: the release check lists every file of the package that holds the ids.

/** The ids under which a build with the feature on registers its scripts: the one in the page's own world and the bridge. */
export const PASSKEY_SCRIPT_IDS = Object.freeze(["ferret-passkey-main", "ferret-passkey-bridge"]);

/** The switch of the feature in `storage.local` (background/passkeyRegistry.mjs PASSKEY_SETTING_KEY; named here because that module is not in a build without the feature). */
export const PASSKEY_SWITCH_KEY = "use_passkeys";

/**
 * Removes the scripts of the passkeys feature that are registered, and the switch that would turn it on. Never throws and never
 * rejects; the answer says whether the browser confirmed that no script is left (a failed removal is tried again at the next start).
 * @param {{
 *   getRegisteredContentScripts(filter: { ids: string[] }): Promise<Array<{ id: string }>>,
 *   unregisterContentScripts(filter: { ids: string[] }): Promise<void>,
 * } | null | undefined} scripting the extension's `scripting`
 * @param {{ remove(key: string): Promise<void>, get?(key: string): Promise<Record<string, unknown>> } | null | undefined} [storageLocal] the extension's `storage.local`
 * @param {{ release(feature: string): Promise<unknown> } | null | undefined} [access] the shared permission for https pages
 *   (background/httpsAccess.mjs): when the switch was on, the permission it was granted for is let go (kept while saving passwords needs it)
 * @returns {Promise<boolean>}
 */
export async function removePasskeyScripts(scripting, storageLocal = null, access = null) {
  try {
    /** @type {boolean} */
    let wasOn = false;
    try {
      wasOn = (await storageLocal?.get?.(PASSKEY_SWITCH_KEY))?.[PASSKEY_SWITCH_KEY] === true;
    } catch {
      wasOn = false;
    }
    await storageLocal?.remove(PASSKEY_SWITCH_KEY);
    if (wasOn) await access?.release("passkeys");
  } catch {
    // The switch stays; the next start tries again, and nothing reads it in a build without the feature.
  }
  try {
    if (!scripting) return false;
    const found = await scripting.getRegisteredContentScripts({ ids: [...PASSKEY_SCRIPT_IDS] });
    const ids = (Array.isArray(found) ? found : []).map((script) => script?.id).filter((id) => PASSKEY_SCRIPT_IDS.includes(id));
    // An id that is not registered makes the browser refuse the whole call, so only the ones that are there are named.
    if (ids.length > 0) await scripting.unregisterContentScripts({ ids });
    return true;
  } catch {
    return false;
  }
}
