// Hands a file (an export, a PDF) to the user: an object URL on a Blob and a
// temporary <a download>. `el()` refuses blob: links on purpose, so the one
// place that makes such a link is here, and the URL is revoked right after.

/**
 * @param {Uint8Array} bytes
 * @param {string} filename
 * @param {string} mime
 * @param {{ document: Document, URL: typeof URL, Blob: typeof Blob, setTimeout: (fn: () => void, ms: number) => unknown }} [env]
 */
export function downloadBlob(bytes, filename, mime, env = globalThis) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError("downloadBlob: bytes must be a Uint8Array");
  if (!/^[a-z]+\/[a-z0-9.+-]+$/.test(mime)) throw new TypeError("downloadBlob: bad media type");
  // A file name carries no path and no control character.
  const name = String(filename).replace(/[\u0000-\u001f\u007f/\\]/g, "_").slice(0, 200) || "download";
  const url = env.URL.createObjectURL(new env.Blob([/** @type {BlobPart} */ (bytes)], { type: mime }));
  try {
    const link = env.document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", name);
    link.setAttribute("rel", "noopener");
    env.document.body.appendChild(link);
    link.click();
    link.remove();
  } finally {
    env.setTimeout(() => env.URL.revokeObjectURL(url), 0);
  }
}
