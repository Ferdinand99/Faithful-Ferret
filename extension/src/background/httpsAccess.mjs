// The one optional permission for `https` pages, shared by the features that need it (design document § 9.2 and § 10.9):
// "Offer to save passwords" (the capture script) and "Use Ferret for passkeys" (the passkey scripts) ask for the same match
// pattern, so the permission is a shared resource and only each feature's own switch turns that feature on.
//
// The rules, kept here so that no feature can break them alone:
//   - A grant never switches a feature on by itself. A feature's switch marks "I am asking" (`markPending`) right before the page
//     asks the browser, and the feature finishes its own turn-on when the grant arrives only if it finds that mark (`takePending`;
//     the mark is short-lived and used once). A grant that comes from anywhere else (the other feature's switch, the browser's
//     own add-on page, a test) changes nothing in either feature.
//   - Turning one feature off takes the permission back only when no other feature that this build has needs it (`release`): the
//     other feature's setting is on. A build that lacks a feature does not count its setting, so a stale value cannot keep the
//     permission.
//   - A permission taken back from outside (the browser's add-on page) turns every feature that needs it off: each feature's
//     registry does that itself when the browser says so.
//
// The mark is kept in `storage.local` (an event page may stop while the browser's prompt is open, and the grant wakes it); it
// holds only the name of a feature and a time. Nothing here is a vault value or a key.

import { CAPTURE_ORIGINS } from "../shared/captureConfig.mjs";

/** The origins of the shared permission. */
export const HTTPS_ORIGINS = CAPTURE_ORIGINS;
/** Where the marks are kept: an object of feature name to the time it ends. */
export const PENDING_KEY = "https_grant_pending";
/** How long a mark lasts: the browser's prompt waits for the person, but not for ever. */
export const PENDING_MS = 120_000;

/**
 * The features that need the permission, with the setting each keeps in `storage.local`. (The names are the build's flags.)
 * @type {Readonly<Record<string, { key: string }>>}
 */
export const HTTPS_USERS = Object.freeze({
  save: Object.freeze({ key: "offer_to_save" }),
  passkeys: Object.freeze({ key: "use_passkeys" }),
});

/**
 * @typedef {{
 *   get(key: string | string[]): Promise<Record<string, unknown>>,
 *   set(items: Record<string, unknown>): Promise<void>,
 * }} StorageLocal
 * @typedef {{ contains?(wanted: { origins: string[] }): Promise<boolean>, remove?(gone: { origins: string[] }): Promise<boolean> }} Permissions
 */

/**
 * @param {{ permissions: Permissions, storageLocal: StorageLocal, now?: () => number, features?: Readonly<Record<string, boolean>> }} deps
 *   `features`: which features this build has on (the build's flags, `FEATURES`; both when none is given)
 */
export function createHttpsAccess({ permissions, storageLocal, now = () => Date.now(), features = { save: true, passkeys: true } }) {
  /** The writes of the marks go one after the other. @type {Promise<unknown>} */
  let chain = Promise.resolve();
  /** @template T @param {() => Promise<T>} job @returns {Promise<T>} */
  const exclusive = (job) => {
    const run = chain.then(job, job);
    chain = run.catch(() => {});
    return run;
  };

  /** @param {unknown} feature @returns {feature is string} */
  const known = (feature) => typeof feature === "string" && Object.hasOwn(HTTPS_USERS, feature);

  /** The marks that have not ended, by feature. @returns {Promise<Record<string, number>>} */
  const marks = async () => {
    /** @type {Record<string, number>} */
    const out = {};
    try {
      const stored = (await storageLocal.get(PENDING_KEY))?.[PENDING_KEY];
      if (typeof stored !== "object" || stored === null) return out;
      const at = now();
      for (const [feature, until] of Object.entries(stored)) {
        // A mark that is longer than its time (the clock moved back) is not one.
        if (known(feature) && typeof until === "number" && until > at && until - at <= PENDING_MS) out[feature] = until;
      }
    } catch {
      // No marks are read: nothing is pending.
    }
    return out;
  };

  /** @param {Record<string, number>} next */
  const write = async (next) => {
    try {
      await storageLocal.set({ [PENDING_KEY]: next });
    } catch {
      // The mark is lost: the grant is finished by the switch's own next step.
    }
  };

  /** @param {string} feature @returns {Promise<boolean>} */
  const takePending = (feature) => {
    if (!known(feature)) return Promise.resolve(false);
    return exclusive(async () => {
      const held = await marks();
      const had = Object.hasOwn(held, feature);
      if (had) {
        delete held[feature];
        await write(held);
      }
      return had;
    });
  };

  /**
   * Whether another feature of this build, one that is on, needs the permission.
   * @param {string} feature the feature that is going off
   * @returns {Promise<boolean>}
   */
  const neededBesides = async (feature) => {
    const others = Object.entries(HTTPS_USERS).filter(([name]) => name !== feature && /** @type {any} */ (features)[name] === true);
    if (others.length === 0) return false;
    try {
      const items = (await storageLocal.get(others.map(([, user]) => user.key))) ?? {};
      return others.some(([, user]) => items[user.key] === true);
    } catch {
      // Not knowing, the permission stays: another feature may need it, and the person can take it back in the browser.
      return true;
    }
  };

  return Object.freeze({
    /** The feature's switch is about to ask the browser for the permission. @param {string} feature */
    markPending(feature) {
      if (!known(feature)) return Promise.resolve(false);
      return exclusive(async () => {
        // The latest click wins: only this feature's mark is kept, so a prompt the person refused in a popup that Firefox closed (the
        // page never cleared its mark) cannot let a later grant for the other feature switch this one on too.
        await write({ [feature]: now() + PENDING_MS });
        return true;
      });
    },

    takePending,

    /** The mark is dropped (the switch ended its turn-on or turn-off, or the person said no). @param {string} feature */
    clearPending: (feature) => takePending(feature).then(() => undefined),
    neededBesides,

    /**
     * A feature went off: takes the permission back unless another feature that is on needs it.
     * @param {string} feature
     * @returns {Promise<{ removed: boolean }>}
     */
    async release(feature) {
      if (await neededBesides(feature)) return { removed: false };
      try {
        await permissions.remove?.({ origins: [...HTTPS_ORIGINS] });
        return { removed: true };
      } catch {
        // The access stays and the state read next says so.
        return { removed: false };
      }
    },
  });
}
