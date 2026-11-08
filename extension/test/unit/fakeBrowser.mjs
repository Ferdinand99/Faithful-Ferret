// A small stand-in for the `browser` object, for the unit tests. It builds the
// runtime and the senders the browser would give, and nothing more.

export const EXTENSION_ID = "ferret@hedgerow.tools";
export const EXTENSION_UUID = "4d2f6a1e-8c3b-4a57-9e0d-1b7c5f3a9d20";

/**
 * @param {{ id?: string, uuid?: string, scheme?: string }} [opts]
 */
export function createFakeBrowser(opts = {}) {
  const id = opts.id ?? EXTENSION_ID;
  const uuid = opts.uuid ?? EXTENSION_UUID;
  const scheme = opts.scheme ?? "moz-extension";
  const base = `${scheme}://${uuid}/`;
  const runtime = {
    id,
    getURL: (/** @type {string} */ path) => `${base}${path}`,
  };
  return { runtime, base, origin: base.slice(0, -1) };
}

/** The sender of a message or port from one of the extension's own pages. */
export function extensionPageSender(fake, page = "pages/signin.html", extra = {}) {
  return {
    id: fake.runtime.id,
    url: fake.runtime.getURL(page),
    origin: fake.origin,
    frameId: 0,
    ...extra,
  };
}

/** The sender of a message from a content script in a web page. */
export function contentScriptSender(fake, url = "https://example.com/login", extra = {}) {
  return {
    id: fake.runtime.id,
    url,
    origin: new URL(url).origin,
    tab: { id: 7 },
    frameId: 0,
    documentId: "doc-1",
    ...extra,
  };
}

/** A port as `runtime.onConnect` gives it. */
export function fakePort(name, sender) {
  /** @type {string[]} */
  const sent = [];
  return { name, sender, sent, postMessage: (/** @type {string} */ m) => sent.push(m) };
}
