// Handing a page's passkey request over to the browser (the `passkeys` feature, design document § 9.4).
//
// The browser's own `create` and `get` need a fresh user action, and Firefox lets that action last only a few seconds, while
// the person has been in Ferret's window and the page's tab has just got the focus back. A call made at once after the window
// closed is therefore a race: in the one build it works, in the other it fails with NotAllowedError (the same click can end both
// ways). So the hand-over does not call the browser at the moment the person chooses it. The page's call that opened the window ends
// (as the browser ends a call the person walked away from), the person is told to click the page's button once more, and the
// next call of the same kind from the same document, the same frame, the same tab and the same origin, within 60 seconds,
// goes to the browser untouched, with its own fresh click. That is the one-time pass kept here. It lives in the background's memory
// and, when the browser has one, in the session storage (which the browser keeps in memory too and empties when it closes), so
// that an event page that the browser stops while the person looks for the button still has it; nothing but the person's choice in
// Ferret's window makes one.
//
// A site on the "never" list needs no pass: its calls go to the browser at once and without a window (background/passkeyNever.mjs,
// asked by the broker before a window opens), so the click that made the call is the one the browser sees, whole.
//
// Nothing here is a vault value or a key.

/** After "use the browser", the next call of the same kind from the same document goes through within this. */
export const PASSKEY_PASS_ONCE_MS = 60_000;
/** The most passes kept at once (one per document that chose the browser; the oldest goes first). */
export const MAX_PASSES = 64;

/** Where the passes are kept in the session storage. */
export const PASSES_KEY = "passkey_passes";

/** Whether this build's browser routes by `hints`: the probe found that it does not (design document § 9.4). */
export const BROWSER_USES_HINTS = false;

/**
 * @typedef {{ tabId: number, frameId: number, documentId: string, origin: string, kind: string }} PassKey
 * @typedef {PassKey & { until: number }} Pass
 */

/**
 * The one-time passes: "the next call of this kind from this document goes to the browser".
 * @param {{
 *   now?: () => number, ttlMs?: number, max?: number,
 *   storage?: { get(key: string): Promise<Record<string, unknown>>, set(items: Record<string, unknown>): Promise<void> } | null,
 * }} [deps] `storage`: where the passes are also kept (the session storage), so that a stopped event page finds them again;
 *   `ready()` settles when what it held has been read
 */
export function createPassOnce({ now = () => Date.now(), ttlMs = PASSKEY_PASS_ONCE_MS, max = MAX_PASSES, storage = null } = {}) {
  /** @type {Pass[]} */
  let passes = [];
  /** Whether a stored pass is a pass: a record of the right fields, and not more than the time. @param {any} p @returns {p is Pass} */
  const valid = (p) =>
    typeof p === "object" && p !== null && Number.isSafeInteger(p.tabId) && Number.isSafeInteger(p.frameId) && typeof p.documentId === "string" && p.documentId.length <= 128 &&
    typeof p.origin === "string" && p.origin.length <= 300 && (p.kind === "create" || p.kind === "get") && Number.isFinite(p.until);
  const persist = () => {
    if (storage === null) return;
    try {
      Promise.resolve(storage.set({ [PASSES_KEY]: passes })).catch(() => {});
    } catch {
      // The passes stay in memory.
    }
  };
  const loaded = (async () => {
    if (storage === null) return;
    try {
      const stored = (await storage.get(PASSES_KEY))?.[PASSES_KEY];
      // What was granted before this page started comes first; what was granted since stays.
      if (Array.isArray(stored)) passes = [...stored.filter(valid), ...passes].slice(-max);
    } catch {
      // Nothing is read: the passes of the stopped page are lost, and the next call asks Ferret again (nothing is let through).
    }
  })();
  /** Forgets what ran out; a pass that is longer than its time (the clock moved) goes too. */
  const prune = () => {
    const at = now();
    passes = passes.filter((p) => p.until > at && p.until - at <= ttlMs);
  };
  /** @param {Pass} p @param {PassKey} k */
  const matches = (p, k) => p.tabId === k.tabId && p.frameId === k.frameId && p.documentId === k.documentId && p.origin === k.origin && p.kind === k.kind;
  return Object.freeze({
    /**
     * Grants one pass for a document and a kind. A second grant for the same document and kind replaces the first.
     * @param {PassKey} key @returns {number} when it ends
     */
    grant(key) {
      prune();
      passes = passes.filter((p) => !matches(p, key));
      const until = now() + ttlMs;
      passes.push({ tabId: key.tabId, frameId: key.frameId, documentId: key.documentId, origin: key.origin, kind: key.kind, until });
      if (passes.length > max) passes.shift();
      persist();
      return until;
    },
    /** Takes the pass of a document for a kind, if there is one: true once. @param {PassKey} key */
    take(key) {
      prune();
      const i = passes.findIndex((p) => matches(p, key));
      if (i < 0) return false;
      passes.splice(i, 1);
      persist();
      return true;
    },
    /**
     * What waits for a click in a tab: the kind and the end of the pass, for the toolbar button and the popup ("click the page
     * again"). Null when the tab has none.
     * @param {number} tabId @returns {{ kind: string, until: number } | null}
     */
    pendingIn(tabId) {
      prune();
      const found = passes.filter((p) => p.tabId === tabId).sort((a, b) => b.until - a.until)[0];
      return found === undefined ? null : { kind: found.kind, until: found.until };
    },
    /** Drops every pass of a tab (it closed). @param {number} tabId */
    forgetTab(tabId) {
      passes = passes.filter((p) => p.tabId !== tabId);
      persist();
    },
    /** Drops every pass of one document (it navigated away). @param {number} tabId @param {number} frameId @param {string} documentId */
    forgetDocument(tabId, frameId, documentId) {
      passes = passes.filter((p) => !(p.tabId === tabId && p.frameId === frameId && p.documentId === documentId));
      persist();
    },
    /** Drops all of them. */
    clear() {
      passes = [];
      persist();
    },
    /** Settles when the stored passes have been read (at once without a storage). */
    ready: () => loaded,
    /** How many are kept now (for the tests). */
    size() {
      prune();
      return passes.length;
    },
  });
}

/**
 * The options for a call that goes to the browser, when the person chose "a security key": the page's own options, with
 * `hints: ["security-key"]` added, and only where the probe found that the browser uses hints (Firefox read them but showed no
 * routing with the virtual authenticator, so `supported` is false in this build and the options go through unchanged). The page's
 * own hints stay after Ferret's; nothing else about the options changes.
 * @template {{ hints?: unknown }} T
 * @param {T} options @param {boolean} [supported]
 * @returns {T}
 */
export function withSecurityKeyHint(options, supported = BROWSER_USES_HINTS) {
  if (supported !== true || typeof options !== "object" || options === null) return options;
  const own = Array.isArray(options.hints) ? options.hints.filter((/** @type {unknown} */ h) => typeof h === "string" && h !== "security-key") : [];
  return { ...options, hints: ["security-key", ...own] };
}
