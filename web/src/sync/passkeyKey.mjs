// The identity of a passkey for the import's dedupe: the site (as the vault's core stores it, canonical) and the
// credential id. It has no dependencies, because the sync engine, which is shared with the extension, builds it for
// every item that holds a passkey. Neither part is a secret.

/** @param {Uint8Array} bytes */
function toHex(bytes) {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/**
 * @param {string} rpId
 * @param {Uint8Array} credId
 * @returns {string}
 */
export function passkeyKey(rpId, credId) {
  return `${rpId}\n${toHex(credId)}`;
}
