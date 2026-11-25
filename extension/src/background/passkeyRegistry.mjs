// The registration of the passkey scripts (the `passkeys` feature, design document § 9.2 and § 10.8): the script in the
// page's own world (content/passkey.main.inject.js) and the bridge of the isolated world (content/passkey.bridge.inject.js),
// for every `https` page and frame, at `document_start`, kept across browser sessions.
//
// Registered exactly when all of these hold, and never otherwise:
//   - "Use Ferret for passkeys" is on (`storage.local`, off when it is not there or not `true`);
//   - the extension has the optional permission for `https` pages (the same one as saving passwords);
//   - the extension is signed in: a server is stored (`storage.local` `server`, as the session keeps it).
// `reconcile` makes it so. It runs at every start of the background page (an install or an update, which clears the
// registrations, starts it too), when the permission is given or taken back (taken back, the setting goes off too), and when the
// setting or the server changes. The background still checks every request itself (signed in, the vault's own origin, the frames);
// the registration only keeps the scripts out of pages where they have nothing to do.
//
// The scripts are left out of the origins of the signed-in Ferret server (`excludeMatches`; a match pattern has no port,
// so every port of the host is left out), and, in a release, of localhost and the loopback addresses. The test variant keeps
// `https://localhost` for its fixtures; `http://localhost` is never matched (the feature asks for no permission beyond
// `https://*/*`). Extension pages are never matched: a registered script runs only in web pages.
//
// Nothing here is a vault value or a key.

/** The setting, in `storage.local`: a boolean, false when it is not there or not a boolean. */
export const PASSKEY_SETTING_KEY = "use_passkeys";
/** Where the session keeps the address of the signed-in server (background/session.mjs SERVER_KEY). */
export const SERVER_KEY = "server";
/** The permission the scripts need, and the pages they are registered for. */
export const PASSKEY_ORIGINS = Object.freeze(["https://*/*"]);
/** The ids of the two scripts (background/passkeyCleanup.mjs names the same ones to remove them in a build without the feature). */
export const PASSKEY_MAIN_ID = "ferret-passkey-main";
export const PASSKEY_BRIDGE_ID = "ferret-passkey-bridge";
const IDS = Object.freeze([PASSKEY_MAIN_ID, PASSKEY_BRIDGE_ID]);
/** The files in the package. */
export const PASSKEY_MAIN_FILE = "/content/passkey.main.inject.js";
export const PASSKEY_BRIDGE_FILE = "/content/passkey.bridge.inject.js";
/**
 * What a release leaves to the browser whatever else holds (design § 9.2 c): localhost, its subdomains and the loopback
 * addresses a match pattern can name. (The background refuses the rest of 127.0.0.0/8 itself; this is only a filter.)
 */
export const RELEASE_EXCLUDED = Object.freeze(["https://localhost/*", "https://*.localhost/*", "https://127.0.0.1/*", "https://[::1]/*"]);

/**
 * @typedef {{
 *   get(key: string | string[]): Promise<Record<string, unknown>>,
 *   set(items: Record<string, unknown>): Promise<void>,
 * }} StorageLocal
 * @typedef {{
 *   registerContentScripts(scripts: object[]): Promise<void>,
 *   unregisterContentScripts(filter: { ids: string[] }): Promise<void>,
 *   getRegisteredContentScripts(filter: { ids: string[] }): Promise<Array<Record<string, unknown>>>,
 * }} Scripting
 * @typedef {{ contains(wanted: { origins: string[] }): Promise<boolean> }} Permissions
 */

/**
 * The match pattern of a server's pages: its scheme and host, every path and (a pattern has no port) every port. Null for
 * anything that is not an `https` origin.
 * @param {unknown} server
 * @returns {string | null}
 */
export function serverPattern(server) {
  if (typeof server !== "string" || server === "") return null;
  try {
    const url = new URL(server);
    if (url.protocol !== "https:" || url.hostname === "") return null;
    return `https://${url.hostname}/*`;
  } catch {
    return null;
  }
}

/**
 * The two registrations for a signed-in `server`.
 * @param {{ server: string, release: boolean }} o
 * @returns {Array<Record<string, unknown>>}
 */
export function passkeyScripts({ server, release }) {
  const excluded = [...new Set([...(release ? RELEASE_EXCLUDED : []), ...[serverPattern(server)].filter((p) => p !== null)])].sort();
  const common = {
    matches: [...PASSKEY_ORIGINS],
    ...(excluded.length > 0 ? { excludeMatches: excluded } : {}),
    allFrames: true,
    runAt: "document_start",
    persistAcrossSessions: true,
  };
  return [
    { id: PASSKEY_MAIN_ID, js: [PASSKEY_MAIN_FILE], ...common, world: "MAIN" },
    { id: PASSKEY_BRIDGE_ID, js: [PASSKEY_BRIDGE_FILE], ...common },
  ];
}

/**
 * Whether a registration the browser holds is the one wanted (lists as sets of names without a leading slash; a world
 * that is not reported counts as the isolated one). A field the browser does not report makes it register again.
 * @param {Record<string, unknown>} held @param {Record<string, unknown>} want
 */
function same(held, want) {
  const norm = (/** @type {unknown} */ v) => (Array.isArray(v) ? JSON.stringify(v.map((x) => String(x).replace(/^\//, "")).sort()) : v);
  for (const key of ["js", "matches", "excludeMatches", "allFrames", "runAt", "persistAcrossSessions"]) {
    const wanted = want[key];
    const has = held[key];
    if (wanted === undefined) {
      if (has !== undefined && has !== null && !(Array.isArray(has) && has.length === 0)) return false;
    } else if (norm(has) !== norm(wanted)) {
      return false;
    }
  }
  const world = (/** @type {unknown} */ w) => (w === undefined || w === null ? "ISOLATED" : w);
  if (world(held.world) !== world(want.world)) return false;
  for (const key of ["excludeJs", "css", "matchOriginAsFallback"]) {
    const v = held[key];
    if (!(v === undefined || v === null || v === false || (Array.isArray(v) && v.length === 0))) return false;
  }
  return true;
}

/**
 * The registration of the passkey scripts.
 * @param {{ scripting: Scripting, permissions: Permissions, storageLocal: StorageLocal, release: boolean }} deps
 *   `release`: the build is a release (localhost is left to the browser)
 */
export function createPasskeyRegistry({ scripting, permissions, storageLocal, release }) {
  /** The registration is changed one step at a time. @type {Promise<unknown>} */
  let chain = Promise.resolve();
  /** @template T @param {() => Promise<T>} job @returns {Promise<T>} */
  const exclusive = (job) => {
    const run = chain.then(job, job);
    chain = run.catch(() => {});
    return run;
  };

  const permitted = async () => {
    try {
      return (await permissions.contains({ origins: [...PASSKEY_ORIGINS] })) === true;
    } catch {
      return false;
    }
  };
  /** @returns {Promise<{ on: boolean, server: string | null }>} */
  const stored = async () => {
    try {
      const items = (await storageLocal.get([PASSKEY_SETTING_KEY, SERVER_KEY])) ?? {};
      const server = items[SERVER_KEY];
      return { on: items[PASSKEY_SETTING_KEY] === true, server: serverPattern(server) !== null ? /** @type {string} */ (server) : null };
    } catch {
      return { on: false, server: null };
    }
  };
  /** The registrations the browser holds under the scripts' ids. */
  const found = async () => {
    try {
      const list = await scripting.getRegisteredContentScripts({ ids: [...IDS] });
      return (Array.isArray(list) ? list : []).filter((s) => IDS.includes(/** @type {string} */ (s?.id)));
    } catch {
      return [];
    }
  };
  const unregister = async () => {
    const ids = (await found()).map((s) => /** @type {string} */ (s.id));
    // An id that is not registered makes the browser refuse the whole call, so only the ones that are there are named.
    if (ids.length === 0) return;
    try {
      await scripting.unregisterContentScripts({ ids });
    } catch {
      // The next reconcile tries again.
    }
  };
  /**
   * A start that finds both current registrations leaves them alone: an event page wakes often, and taking the scripts away
   * and putting them back leaves a moment in which a loading tab gets none.
   * @param {string} server
   */
  const ensure = async (server) => {
    const want = passkeyScripts({ server, release });
    const held = await found();
    const current = want.every((w) => held.some((h) => h.id === w.id && same(h, w)));
    if (current && held.length === want.length) return;
    await unregister();
    await scripting.registerContentScripts(want);
  };
  const setOff = async () => {
    try {
      await storageLocal.set({ [PASSKEY_SETTING_KEY]: false });
    } catch {
      // The scripts go below whatever the storage says; the next start reconciles again.
    }
  };

  /** @returns {Promise<{ on: boolean, permission: boolean, signed_in: boolean, registered: boolean }>} */
  const reconcileNow = async () => {
    const [{ on, server }, permission] = [await stored(), await permitted()];
    if (on && permission && server !== null) {
      try {
        await ensure(server);
        return { on, permission, signed_in: true, registered: true };
      } catch {
        await unregister();
        return { on, permission, signed_in: true, registered: false };
      }
    }
    // The permission is gone: the setting goes with it, so a later grant (for saving passwords) does not bring it back.
    if (on && !permission) await setOff();
    await unregister();
    return { on: on && permission, permission, signed_in: server !== null, registered: false };
  };

  return {
    /** Makes the registration agree with the setting, the permission and the sign-in. Call it on every start. */
    reconcile() {
      return exclusive(reconcileNow);
    },

    /**
     * Turns the setting on once the user has granted the permission (in the settings page's own click); the permission is
     * checked here, not believed.
     * @returns {Promise<{ ok: true } | { ok: false, reason: "permission_missing" }>}
     */
    enable() {
      return exclusive(async () => {
        if (!(await permitted())) return { ok: false, reason: /** @type {const} */ ("permission_missing") };
        await storageLocal.set({ [PASSKEY_SETTING_KEY]: true });
        await reconcileNow();
        return { ok: /** @type {const} */ (true) };
      });
    },

    /** Turns the setting off and the scripts away. The permission stays: saving passwords may use it. */
    disable() {
      return exclusive(async () => {
        await setOff();
        await unregister();
        return { ok: true };
      });
    },

    /**
     * The browser's `permissions.onAdded`: the permission alone turns nothing on, but a setting that is on and a signed-in
     * extension get their scripts now.
     * @param {{ origins?: string[] } | undefined} added
     */
    onPermissionAdded(added) {
      const given = Array.isArray(added?.origins) && added.origins.some((origin) => PASSKEY_ORIGINS.includes(origin));
      if (!given) return Promise.resolve(false);
      return exclusive(async () => {
        await reconcileNow();
        return true;
      });
    },

    /**
     * The browser's `permissions.onRemoved`: when the permission for `https` pages goes, the scripts and the setting go.
     * @param {{ origins?: string[] } | undefined} removed
     */
    onPermissionRemoved(removed) {
      const gone = Array.isArray(removed?.origins) && removed.origins.some((origin) => PASSKEY_ORIGINS.includes(origin));
      if (!gone) return Promise.resolve(false);
      return exclusive(async () => {
        await reconcileNow();
        return true;
      });
    },

    /**
     * The browser's `storage.onChanged`: the setting or the server changed (a sign-in, a sign-out, another server).
     * @param {Record<string, unknown> | undefined} changes @param {string} area
     */
    onStorageChanged(changes, area) {
      if (area !== "local" || typeof changes !== "object" || changes === null) return Promise.resolve(false);
      if (!Object.hasOwn(changes, PASSKEY_SETTING_KEY) && !Object.hasOwn(changes, SERVER_KEY)) return Promise.resolve(false);
      return exclusive(async () => {
        await reconcileNow();
        return true;
      });
    },

    /** What is true now. */
    status() {
      return exclusive(async () => {
        const [{ on, server }, permission] = [await stored(), await permitted()];
        return { on, permission, signed_in: server !== null, registered: (await found()).length === IDS.length };
      });
    },
  };
}
