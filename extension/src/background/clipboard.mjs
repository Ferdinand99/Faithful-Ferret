// The clipboard of a copy from Ferret's UI (design document, section 10.6).
//
// The background writes the value itself (`clipboardWrite`), so a copied
// password never passes through a page. Browser APIs cannot mark it as
// sensitive for the system, and the extension does not read the clipboard, so
// it cannot tell whether something else was copied since. What it can do:
// clear the clipboard 30 seconds after Ferret's last copy, if that copy is
// still Ferret's last.
//
// How: every copy gets a random mark. The mark is kept in `storage.session`
// (it is not a secret, and it outlives an unloaded background page) and an
// `alarms` alarm named after it fires 30 seconds later. When an alarm fires,
// the clipboard is cleared only if its mark is still the stored one; a second
// copy moves the mark, so the first copy's alarm finds another mark and does
// nothing. The listener is registered while the background page loads, so the
// alarm that wakes an unloaded page reaches it; nothing here needs the vault,
// so a locked vault is cleared up after just the same.

/** How long a copied value stays on the clipboard. */
export const CLEAR_AFTER_MS = 30_000;
/** The key of the mark in `storage.session`. */
export const MARK_KEY = "clipboard_mark";
/** The alarms of this module are named `<ALARM_PREFIX><mark>`. */
export const ALARM_PREFIX = "ferret-clipboard:";

const MARK = /^[0-9a-f]{32}$/;

/** The error of this module: a short code. */
export class ClipboardError extends Error {
  /** @param {string} code */
  constructor(code) {
    super(code);
    this.name = "ClipboardError";
    this.code = code;
  }
}

/**
 * @param {{
 *   writeText: (text: string) => Promise<void>,
 *   storageSession: { get: (key: string) => Promise<Record<string, unknown>>, set: (items: Record<string, unknown>) => Promise<void>, remove: (key: string) => Promise<void> },
 *   alarms: { create: (name: string, info: { when: number }) => unknown, clear: (name: string) => unknown, onAlarm: { addListener: (fn: (alarm: { name: string }) => unknown) => void } },
 *   now: () => number,
 *   random?: (bytes: Uint8Array) => Uint8Array,
 * }} options
 */
export function createClipboard({ writeText, storageSession, alarms, now, random = (bytes) => {
    globalThis.crypto.getRandomValues(/** @type {Uint8Array<ArrayBuffer>} */ (bytes));
    return bytes;
  } }) {
  // Copies and clears run one after the other, so a clear never runs between a copy's write and its mark.
  /** @type {Promise<unknown>} */
  let queue = Promise.resolve();
  /** @template T @param {() => Promise<T>} job @returns {Promise<T>} */
  const serial = (job) => {
    const run = queue.then(job);
    queue = run.catch(() => {});
    return run;
  };

  const newMark = () => Array.from(random(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");

  /** @returns {Promise<string | null>} */
  const storedMark = async () => {
    try {
      const value = (await storageSession.get(MARK_KEY))?.[MARK_KEY];
      return typeof value === "string" && MARK.test(value) ? value : null;
    } catch {
      return null;
    }
  };

  /** @param {string} name */
  const quiet = (name) => {
    try {
      const result = /** @type {any} */ (alarms.clear(name));
      result?.catch?.(() => {});
    } catch {
      // Nothing to clear.
    }
  };

  /**
   * The alarm of a mark: clears the clipboard when the mark is still Ferret's last copy.
   * @param {string} mark
   */
  const expire = (mark) =>
    serial(async () => {
      if ((await storedMark()) !== mark) return false;
      try {
        await writeText("");
      } finally {
        // The mark goes even when the write failed: a later alarm must not clear what the user copied since.
        await storageSession.remove(MARK_KEY).catch(() => {});
      }
      return true;
    });

  alarms.onAlarm.addListener((alarm) => {
    const name = alarm?.name;
    if (typeof name !== "string" || !name.startsWith(ALARM_PREFIX)) return undefined;
    const mark = name.slice(ALARM_PREFIX.length);
    if (!MARK.test(mark)) return undefined;
    // The browser ignores what a listener returns; the tests wait for it.
    return expire(mark).catch(() => false);
  });

  return {
    /**
     * Writes `text` to the clipboard as Ferret's last copy, and arms its clearing.
     * @param {string} text
     * @returns {Promise<void>}
     */
    copy(text) {
      return serial(async () => {
        if (typeof text !== "string" || text === "") throw new ClipboardError("nothing_to_copy");
        const before = await storedMark();
        try {
          await writeText(text);
        } catch {
          throw new ClipboardError("clipboard");
        }
        const mark = newMark();
        // The mark moves first: from now on only this copy's alarm clears.
        await storageSession.set({ [MARK_KEY]: mark });
        if (before !== null) quiet(`${ALARM_PREFIX}${before}`);
        try {
          const result = /** @type {any} */ (alarms.create(`${ALARM_PREFIX}${mark}`, { when: now() + CLEAR_AFTER_MS }));
          result?.catch?.(() => {});
        } catch {
          // Without an alarm the value stays until the next copy; there is nothing else that could clear it.
        }
      });
    },

    /** The mark of Ferret's last copy, or null (for the tests). */
    mark: storedMark,
  };
}
