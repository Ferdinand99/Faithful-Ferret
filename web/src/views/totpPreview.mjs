// The code of a one-time password that is not saved yet, for the preview in the edit form. The worker makes codes only for an open
// item, so the address is sealed in a throwaway item (a made-up id, never listed, stored or sent), the item is opened for this one
// call, the code is asked for, and the item is closed again. The secret stays in the worker; the page gets the digits.

/** A made-up item id: 16 bytes that are not all zero. */
function throwawayId() {
  const id = new Uint8Array(16);
  do globalThis.crypto.getRandomValues(id);
  while (id.every((b) => b === 0));
  return id;
}

/**
 * Whether the worker client has the calls the preview needs (a stand-in without them shows no preview).
 * @param {{ vault?: Record<string, unknown> } | null | undefined} client
 */
export function canPreview(client) {
  return ["encrypt_item", "open_item", "close_item", "totp_code"].every((fn) => typeof client?.vault?.[fn] === "function");
}

/**
 * @param {{ vault: Record<string, (...args: any[]) => Promise<any>> }} client
 * @param {string} uri the address to show a code for
 * @param {number} seconds Unix time, in whole seconds
 * @param {number} nowMs the time the throwaway item is dated with
 * @returns {Promise<{ code: string, seconds_left: number }>}
 */
export async function previewCode(client, uri, seconds, nowMs) {
  const itemId = throwawayId();
  const sealed = await client.vault.encrypt_item(itemId, 1, { item_type: "login", name: "totp", totp: { uri } }, undefined, nowMs);
  const handle = await client.vault.open_item(itemId, 1, sealed.envelope, sealed.tag);
  try {
    return await client.vault.totp_code(handle, seconds);
  } finally {
    await Promise.resolve(client.vault.close_item(handle)).catch(() => {});
  }
}
