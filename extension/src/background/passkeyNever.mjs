// "Never on this site" for passkeys (the `passkeys` feature, design document § 9.4, UK109): the RP IDs the person does not want
// Ferret to answer for. The chooser window offers it ("Never on this site"); the broker asks `has` before a window opens (a call of
// such a site goes to the browser with the page's own options, untouched), and the settings page lists and removes entries.
//
// The list is kept per RP ID, as the core gives it (an A-label, lower case), in `storage.local` under its own key, at most 500
// (the newest wins), in the order the entries were added. It is the offers' "never" list (background/captureRegistry.mjs) with another key,
// so the two keep the same rules: a choice made in a private window is kept in memory only (it never reaches the disk and is
// gone when the browser closes), a value that is not a host name is refused, and a read that fails leaves the list empty.
//
// Nothing here is a vault value, a key or the text of a website.

import { createNeverList } from "./captureRegistry.mjs";

/** The list, in `storage.local`: an array of RP IDs. */
export const PASSKEY_NEVER_KEY = "passkey_never";

/**
 * @param {{ storageLocal: { get(key: string): Promise<Record<string, unknown>>, set(items: Record<string, unknown>): Promise<void> } }} deps
 */
export function createPasskeyNever({ storageLocal }) {
  const list = createNeverList({ storageLocal, key: PASSKEY_NEVER_KEY });
  return Object.freeze({
    /** Whether the person said "never" for this RP ID (here, or in a private window of this browser session). @param {string} rpId */
    has: (rpId) => list.has(rpId),
    /**
     * Adds an RP ID. A private window's choice stays in memory.
     * @param {string} rpId @param {{ incognito?: boolean }} [options]
     */
    add: (rpId, options) => list.add(rpId, options),
    /** @param {string} rpId */
    remove: (rpId) => list.remove(rpId),
    /** Every RP ID the list holds now, sorted (those of private windows of this browser session too). */
    list: () => list.list(),
  });
}
