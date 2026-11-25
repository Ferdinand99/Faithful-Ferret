// A build with the `passkeys` feature off (a release until Ferret is released as a passkey provider, a rollback to an older
// build) registers no script in web pages. The one thing it does at start is to remove the registrations that a build with
// the feature on may have left: the scripts are registered to persist across sessions, so a script from an older build
// would otherwise keep running in every page, with no code of the feature left to talk to it. Removing a script that is not
// registered does nothing.
//
// This is the only place where a build with the feature off names the scripts, and it only removes them. The module is
// small on purpose: the release check lists every file of the package that holds the ids.

/** The ids under which a build with the feature on registers its scripts: the one in the page's own world and the bridge. */
export const PASSKEY_SCRIPT_IDS = Object.freeze(["ferret-passkey-main", "ferret-passkey-bridge"]);

/**
 * Removes the scripts of the passkeys feature that are registered. Never throws and never rejects; the answer says
 * whether the browser confirmed that none is left (a failed removal is tried again at the next start).
 * @param {{
 *   getRegisteredContentScripts(filter: { ids: string[] }): Promise<Array<{ id: string }>>,
 *   unregisterContentScripts(filter: { ids: string[] }): Promise<void>,
 * } | null | undefined} scripting the extension's `scripting`
 * @returns {Promise<boolean>}
 */
export async function removePasskeyScripts(scripting) {
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
