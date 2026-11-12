// A name for this page, made once when the page loads. The messages that pages of one browser send each
// other carry it, so that a page can tell its own message from another page's.

/** @returns {string} 16 lower-case hex characters */
function makeTabId() {
  const bytes = new Uint8Array(8);
  try {
    globalThis.crypto.getRandomValues(bytes);
  } catch {
    for (let i = 0; i < bytes.length; i += 1) bytes[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export const TAB_ID = makeTabId();
