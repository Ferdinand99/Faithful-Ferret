// Who sent a message. Plain ESM, no dependencies.
//
// The origin of a sender always comes from the browser (`sender`, and later
// `webNavigation`), never from the content of a message and never from the
// page. Two opaque origins are both the string "null", so they compare equal as
// strings; every check here refuses "null" first.

const EXTENSION_URL = /^(?:moz|chrome)-extension:\/\/[^/?#\s]+\/$/;
const WEB_URL = /^https?:\/\//i;
const MAX_URL = 8192;

/**
 * @typedef {{ id?: string, url?: string, origin?: string, frameId?: number, documentId?: string, tab?: { id?: number } }} Sender
 * @typedef {{ id?: string, getURL: (path: string) => string }} Runtime
 */

/**
 * @param {unknown} n
 * @returns {n is number}
 */
function isIndex(n) {
  return typeof n === "number" && Number.isSafeInteger(n) && n >= 0;
}

/**
 * The base URL of this extension (`moz-extension://<uuid>/`), or null when the
 * runtime does not give a well-formed one.
 *
 * @param {Runtime} runtime
 * @returns {string | null}
 */
function extensionBase(runtime) {
  if (typeof runtime.id !== "string" || runtime.id === "") return null;
  let base;
  try {
    base = runtime.getURL("");
  } catch {
    return null;
  }
  if (typeof base !== "string" || !EXTENSION_URL.test(base)) return null;
  return base;
}

/**
 * True when `sender` is a page of this extension: the same extension id, and a
 * URL under the extension's own `moz-extension://<uuid>/` (or
 * `chrome-extension://<id>/`). A content script has the same `sender.id` but a
 * web page URL, so it fails on the URL. "null" origins, `data:` and
 * `about:blank` senders and the pages of another extension are refused.
 *
 * @param {Sender | null | undefined} sender
 * @param {Runtime} runtime
 * @returns {boolean}
 */
export function isExtensionPage(sender, runtime) {
  if (typeof sender !== "object" || sender === null) return false;
  const base = extensionBase(runtime);
  if (base === null) return false;
  if (sender.id !== runtime.id) return false;
  if (typeof sender.url !== "string" || sender.url.length > MAX_URL) return false;
  if (!sender.url.startsWith(base)) return false;
  if (sender.origin !== undefined) {
    // The browser gives the origin of the page. It must be ours and not "null".
    if (sender.origin === "null") return false;
    if (sender.origin !== base.slice(0, -1)) return false;
  }
  return true;
}

/**
 * True when `sender` is a top-level page of this extension, in a tab or a
 * popup. An extension page that a web page frames has the extension's URL too,
 * but a `frameId` above 0. The master password and the secret key are typed
 * only in pages that pass this check.
 *
 * @param {Sender | null | undefined} sender
 * @param {Runtime} runtime
 * @returns {boolean}
 */
export function isTopLevelExtensionPage(sender, runtime) {
  if (!isExtensionPage(sender, runtime)) return false;
  const frameId = /** @type {Sender} */ (sender).frameId;
  return frameId === undefined || frameId === 0;
}

/**
 * The sender of a message from a content script, or null. A content script has
 * this extension's id, a tab and a frame, and a web page URL. An extension page
 * has the extension's URL and is not a content script.
 *
 * @param {Sender | null | undefined} sender
 * @param {Runtime} runtime
 * @returns {{ tabId: number, frameId: number, documentId?: string, url: string } | null}
 */
export function contentSender(sender, runtime) {
  if (typeof sender !== "object" || sender === null) return null;
  if (typeof runtime.id !== "string" || runtime.id === "") return null;
  if (sender.id !== runtime.id) return null;
  if (typeof sender.tab !== "object" || sender.tab === null) return null;
  const tabId = sender.tab.id;
  if (!isIndex(tabId)) return null;
  if (!isIndex(sender.frameId)) return null;
  const url = sender.url;
  if (typeof url !== "string" || url.length > MAX_URL || !WEB_URL.test(url)) {
    return null;
  }
  if (sender.origin === "null") return null;
  /** @type {{ tabId: number, frameId: number, documentId?: string, url: string }} */
  const out = { tabId, frameId: sender.frameId, url };
  if (typeof sender.documentId === "string" && sender.documentId !== "") {
    out.documentId = sender.documentId;
  }
  return out;
}

/**
 * A content script's own `self.origin` can only narrow what the browser says.
 * It returns the browser's origin when `selfOrigin` is the same, and null when
 * either is "null" (an opaque origin) or they differ. It never returns a value
 * that did not come from the browser.
 *
 * @param {string} fromBrowser
 * @param {string} selfOrigin
 * @returns {string | null}
 */
export function narrowOrigin(fromBrowser, selfOrigin) {
  if (typeof fromBrowser !== "string" || typeof selfOrigin !== "string") return null;
  if (fromBrowser === "" || fromBrowser === "null") return null;
  if (selfOrigin === "" || selfOrigin === "null") return null;
  if (fromBrowser !== selfOrigin) return null;
  return fromBrowser;
}

/**
 * True when a port from `runtime.onConnect` is the extension's UI port from a
 * top-level extension page.
 *
 * @param {{ name?: string, sender?: Sender }} port
 * @param {Runtime} runtime
 * @param {string} portName
 * @returns {boolean}
 */
export function isUiPort(port, runtime, portName) {
  return (
    typeof port === "object" &&
    port !== null &&
    port.name === portName &&
    isTopLevelExtensionPage(port.sender, runtime)
  );
}
