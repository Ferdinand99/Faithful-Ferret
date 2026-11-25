// The capture script's registration, and the setting and the list that go with
// it (design document, section 10.9).
//
// "Offer to save passwords" is off until the user turns it on in the settings
// tab, which explains why and asks for the optional permission for `https`
// pages (the page asks, in its own click). Only when the permission is there does
// the background register the capture script for every `https` page and frame
// (`scripting.registerContentScripts`, kept across browser sessions). The three
// things have to agree: the script is registered exactly when the permission is
// granted and the setting is on. `reconcile` makes it so, and runs on every start
// of the background page; the browser tells when the permission is taken back
// (`permissions.onRemoved`), and then the script is unregistered and the setting
// goes off. The other way round, when the permission is given (`permissions.onAdded`) the setting goes on only if the switch of
// this feature marked that it was asking (background/httpsAccess.mjs: the permission is shared with the passkeys, and a grant
// never switches a feature on by itself); a grant whose popup was closed by the browser's prompt is finished here. Turning the setting
// off takes the permission back too, unless the passkeys are on and need it (`disable` asks httpsAccess; the browser then tells this
// module, which finds nothing left to switch off). Tabs that are open when the script is registered get it only after
// they are loaded again; the settings page says so.
//
// The "never" list is the hosts the user does not want offers for: A-labels in
// `storage.local` (at most MAX_NEVER; the newest wins), checked before anything is
// held or shown. A choice made in a private window is kept in memory only, so the
// host does not reach the disk; it is gone when the browser closes.
//
// Nothing here is a vault value, a key or a captured form.

import { CAPTURE_ORIGINS, CAPTURE_SCRIPT_FILE, CAPTURE_SCRIPT_ID, MAX_NEVER } from "../shared/captureConfig.mjs";
import { createHttpsAccess } from "./httpsAccess.mjs";

/** The setting, in `storage.local`: a boolean, false when it is not there or not a boolean. */
export const SETTING_KEY = "offer_to_save";
/** The never list, in `storage.local`: an array of A-labels. */
export const NEVER_KEY = "capture_never";

/** The longest host the list keeps (a host name is at most 253 characters). */
const MAX_HOST = 253;
const LABEL = /^[a-z0-9.-]+$/;

/**
 * @typedef {{
 *   get(key: string): Promise<Record<string, unknown>>,
 *   set(items: Record<string, unknown>): Promise<void>,
 * }} StorageLocal
 * @typedef {{
 *   registerContentScripts(scripts: object[]): Promise<void>,
 *   unregisterContentScripts(filter: { ids: string[] }): Promise<void>,
 *   getRegisteredContentScripts(filter: { ids: string[] }): Promise<Array<{ id: string, js?: string[], matches?: string[], allFrames?: boolean, runAt?: string, persistAcrossSessions?: boolean }>>,
 * }} Scripting
 * @typedef {{ contains(wanted: { origins: string[] }): Promise<boolean>, remove?(gone: { origins: string[] }): Promise<boolean> }} Permissions
 */

/** @param {unknown} host @returns {string | null} the A-label as the list keeps it, or null */
export function listedHost(host) {
  if (typeof host !== "string") return null;
  const label = host.trim().toLowerCase().replace(/\.$/, "");
  return label !== "" && label.length <= MAX_HOST && LABEL.test(label) ? label : null;
}

/**
 * The never list.
 * @param {{ storageLocal: StorageLocal, key?: string }} deps `key`: where the list is kept in `storage.local` (the offers' own
 *   list by default; the passkeys feature keeps one of its own)
 */
export function createNeverList({ storageLocal, key = NEVER_KEY }) {
  /** What is on disk, in the order it was added. @type {string[]} */
  let kept = [];
  /** What private windows chose: memory only. @type {Set<string>} */
  const memory = new Set();
  const loaded = (async () => {
    try {
      const stored = (await storageLocal.get(key))?.[key];
      if (Array.isArray(stored)) kept = [...new Set(stored.map(listedHost).filter((h) => h !== null))].slice(-MAX_NEVER);
    } catch {
      // No list is read: nothing is on it (the offers it would have stopped come back).
    }
  })();
  /** Writes of the list go one after the other. @type {Promise<unknown>} */
  let writes = Promise.resolve();
  const save = () => {
    const snapshot = [...kept];
    writes = writes.then(() => storageLocal.set({ [key]: snapshot })).catch(() => {});
    return writes;
  };

  return {
    /** @param {string} aLabel @returns {Promise<boolean>} */
    async has(aLabel) {
      await loaded;
      const host = listedHost(aLabel);
      return host !== null && (kept.includes(host) || memory.has(host));
    },

    /**
     * Adds a host. A private window's choice stays in memory and never reaches `storage.local`.
     * @param {string} aLabel @param {{ incognito?: boolean }} [options]
     */
    async add(aLabel, { incognito = false } = {}) {
      await loaded;
      const host = listedHost(aLabel);
      if (host === null) return;
      if (incognito) {
        memory.add(host);
        return;
      }
      kept = [...kept.filter((h) => h !== host), host].slice(-MAX_NEVER);
      await save();
    },

    /** @param {string} aLabel */
    async remove(aLabel) {
      await loaded;
      const host = listedHost(aLabel);
      if (host === null) return;
      memory.delete(host);
      if (kept.includes(host)) {
        kept = kept.filter((h) => h !== host);
        await save();
      }
    },

    /** Every host the list holds now, those of this browser session too, sorted. @returns {Promise<string[]>} */
    async list() {
      await loaded;
      return [...new Set([...kept, ...memory])].sort();
    },
  };
}

/**
 * The registration of the capture script.
 * @param {{
 *   scripting: Scripting,
 *   permissions: Permissions,
 *   storageLocal: StorageLocal,
 *   onOff?: (reason: "capture_off" | "permission_removed") => void,
 *   access?: ReturnType<typeof createHttpsAccess>,
 * }} deps `onOff` is called when capture goes off after it was on (the held offers go with it); `access`: the shared permission
 *   for https pages (the one the passkeys use too; one is made when none is given)
 */
export function createCaptureRegistry({ scripting, permissions, storageLocal, onOff = () => {}, access = createHttpsAccess({ permissions, storageLocal }) }) {
  /** The registration is changed one step at a time. @type {Promise<unknown>} */
  let chain = Promise.resolve();
  /** @template T @param {() => Promise<T>} job @returns {Promise<T>} */
  const exclusive = (job) => {
    const run = chain.then(job, job);
    chain = run.catch(() => {});
    return run;
  };

  const definition = () => ({
    id: CAPTURE_SCRIPT_ID,
    js: [CAPTURE_SCRIPT_FILE],
    matches: [...CAPTURE_ORIGINS],
    allFrames: true,
    runAt: "document_idle",
    persistAcrossSessions: true,
  });

  const permitted = async () => {
    try {
      return (await permissions.contains({ origins: [...CAPTURE_ORIGINS] })) === true;
    } catch {
      return false;
    }
  };

  const setting = async () => {
    try {
      return (await storageLocal.get(SETTING_KEY))?.[SETTING_KEY] === true;
    } catch {
      return false;
    }
  };

  /** The registration the browser holds under the script's id, or null. */
  const found = async () => {
    try {
      return (await scripting.getRegisteredContentScripts({ ids: [CAPTURE_SCRIPT_ID] })).find((s) => s?.id === CAPTURE_SCRIPT_ID) ?? null;
    } catch {
      return null;
    }
  };

  const registered = async () => (await found()) !== null;

  /**
   * Whether a registration the browser holds is the current definition (the file names without a leading slash, the match
   * patterns in any order). A browser that does not report a field leaves the registration to be made again.
   * @param {Record<string, unknown>} held
   */
  const current = (held) => {
    const want = /** @type {Record<string, any>} */ (definition());
    // Lists compare as sets of names without a leading slash; anything else as it is.
    const norm = (/** @type {unknown} */ v) => (Array.isArray(v) ? JSON.stringify(v.map((x) => String(x).replace(/^\//, "")).sort()) : v);
    for (const key of Object.keys(want)) if (key !== "id" && norm(held[key]) !== norm(want[key])) return false;
    // What the definition does not name must be absent or its default: a registration that also excludes matches, adds styles, matches
    // by origin fallback or runs in the page's own world is not the one this module makes.
    for (const key of ["excludeMatches", "excludeJs", "css", "matchOriginAsFallback", "world"]) {
      if (key in want) continue;
      const v = held[key];
      if (v === undefined || v === null || v === false || (Array.isArray(v) && v.length === 0) || (key === "world" && v === "ISOLATED")) continue;
      return false;
    }
    return true;
  };

  const unregister = async () => {
    if (await registered()) {
      try {
        await scripting.unregisterContentScripts({ ids: [CAPTURE_SCRIPT_ID] });
      } catch {
        // A script that is not there is gone already.
      }
    }
  };

  const register = async () => {
    // A script left by an earlier version is replaced, so the definition is the current one.
    await unregister();
    await scripting.registerContentScripts([definition()]);
  };

  /**
   * A start that finds the current definition registered leaves it alone: an event page wakes often, and taking the script away
   * and putting it back leaves a moment in which a loading tab gets none.
   */
  const ensure = async () => {
    const held = await found();
    if (held !== null && current(held)) return;
    await register();
  };

  /** Switches the setting off and the script away. @param {"capture_off" | "permission_removed"} reason */
  const turnOff = async (reason) => {
    let was = false;
    try {
      was = (await setting()) || (await registered());
      await storageLocal.set({ [SETTING_KEY]: false });
    } catch {
      // The script is unregistered below whatever the storage says; the next start reconciles again.
    }
    await unregister();
    if (was) onOff(reason);
  };

  return {
    /**
     * Makes the registration agree with the permission and the setting: registered exactly when both are there. The
     * setting goes off when the permission is gone. Call it on every start of the background page.
     * @returns {Promise<{ on: boolean, permission: boolean, registered: boolean }>}
     */
    reconcile() {
      return exclusive(async () => {
        const [on, permission] = [await setting(), await permitted()];
        if (on && permission) {
          try {
            await ensure();
          } catch {
            // The script could not be registered: capture is off until it can be.
            await turnOff("capture_off");
            return { on: false, permission, registered: false };
          }
          return { on: true, permission, registered: true };
        }
        if (on && !permission) await turnOff("permission_removed");
        else await unregister();
        return { on: false, permission, registered: false };
      });
    },

    /**
     * Turns capture on, once the user has granted the permission in the settings page's own click. The permission is
     * checked here, not believed: without it nothing is registered and nothing is switched on.
     * @returns {Promise<{ ok: true } | { ok: false, reason: "permission_missing" | "register_failed" }>}
     */
    enable() {
      return exclusive(async () => {
        if (!(await permitted())) return { ok: false, reason: "permission_missing" };
        // This switch is turning capture on: its own grant, if one is still to come, needs no mark any more.
        await access.clearPending("save");
        try {
          // A start that finds the current definition registered leaves it alone, so a second `enable` (the settings view's own,
          // after the permission's `onAdded` already made one) does not register the script twice.
          await ensure();
          await storageLocal.set({ [SETTING_KEY]: true });
        } catch {
          await unregister();
          return { ok: false, reason: "register_failed" };
        }
        return { ok: true };
      });
    },

    /**
     * Turns capture off: the script goes, and so does everything held for it, and so does the access to https pages that was
     * asked for with it, unless the passkeys are on and need it (the permission is shared, see httpsAccess.mjs). The permission
     * is taken back here, not by the page that asked, so that "off" does not depend on the popup staying open. (`reconcile`
     * never removes it: a grant that is there with the setting off is finished by `onAdded` when this switch marked it, or by the
     * next press of the switch.)
     */
    disable() {
      return exclusive(async () => {
        await turnOff("capture_off");
        await access.clearPending("save");
        await access.release("save");
        return { ok: true };
      });
    },

    /** The switch is about to ask the browser for the permission: a grant that follows is this feature's to finish. */
    markPending: () => access.markPending("save"),
    /** The person said no, or the request failed: the mark is not needed. */
    clearPending: () => access.clearPending("save"),

    /**
     * The browser's `permissions.onAdded`: when the access to `https` pages is given and this feature's switch marked that it was
     * asking, capture goes on. The request is made in the click on the switch, and Firefox closes a toolbar popup when its prompt
     * opens, so the page that asked may be gone by the time the grant lands; the grant and the setting are one, so it is finished
     * here. A grant nobody here asked for (the passkeys' switch, the browser's add-on page) switches nothing on.
     * @param {{ origins?: string[] } | undefined} added
     * @returns {Promise<boolean>} whether capture was switched on by it
     */
    async onAdded(added) {
      const given = Array.isArray(added?.origins) && CAPTURE_ORIGINS.every((origin) => added.origins?.includes(origin));
      if (!given) return false;
      if (!(await access.takePending("save"))) return false;
      return (await this.enable()).ok;
    },

    /**
     * The browser's `permissions.onRemoved`: when the permission for `https` pages goes, capture goes off.
     * @param {{ origins?: string[] } | undefined} removed
     */
    onRemoved(removed) {
      const gone = Array.isArray(removed?.origins) && removed.origins.some((origin) => CAPTURE_ORIGINS.includes(origin));
      if (!gone) return Promise.resolve(false);
      return exclusive(async () => {
        await turnOff("permission_removed");
        return true;
      });
    },

    /** What is true now: the setting, the permission and the registration. */
    status() {
      return exclusive(async () => ({ on: await setting(), permission: await permitted(), registered: await registered() }));
    },
  };
}
