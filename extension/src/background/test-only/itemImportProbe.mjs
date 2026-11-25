// What the Firefox tests of signing in with a key the vault holds need from the background, in the test build only (a folder
// named test-only: a release leaves it out). A core operation, called over the test build's core port:
//
//   item_import_probe  puts a key that a test registered at a test relying party into a new item of the open vault: the core's
//                      `passkey_import` seals it (the key goes from the arguments into the sealed item inside WASM), the sealed
//                      item is stored on the server with the device's own write (`PUT /api/sync/items/<id>`, as another device's
//                      new item would come), and the operation waits until the sync engine lists it.
//
// It answers with the new item's id: never a key, a value or a handle. The key is the test's own, made for a test site.

// The shared modules are copied into the package by the build (the unit tests load this file from the sources, where they are
// not): the encoder of the wire is loaded when the operation runs, and the byte forms are written here.

/** @param {Uint8Array} bytes */
const hexOf = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
/** @param {string} hex */
const bytesOfHex = (hex) => Uint8Array.from(hex.match(/../g) ?? [], (h) => parseInt(h, 16));
/** @param {Uint8Array} bytes */
const toB64u = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/[+]/g, "-").replace(/[/]/g, "_").replace(/=+$/, "");
/** @param {string} text */
const fromB64u = (text) => Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

/** @param {string} code */
const fail = (code) => Object.assign(new Error(code), { code });

/** How long the operation waits for the sync engine to list the new item. */
const LISTED_WITHIN_MS = 20_000;

/**
 * @param {{ engine: () => any, api: () => any, now: () => number, random?: (bytes: Uint8Array) => Uint8Array }} deps `engine`: the
 *   sync engine of the open vault, or null; `api`: the API client the engine was made with (the device's tokens), or null
 */
export function createItemImportProbe({ engine, api, now, random = (bytes) => globalThis.crypto.getRandomValues(/** @type {Uint8Array<ArrayBuffer>} */ (bytes)) }) {
  /** @param {unknown} text */
  const bytesOf = (text) => {
    if (typeof text !== "string" || text === "" || text.length > 4096) throw fail("invalid_input");
    return fromB64u(text);
  };
  /** @type {Readonly<Record<string, import("../coreHost.mjs").CoreOp>>} */
  const ops = Object.freeze({
    item_import_probe: {
      vault: true,
      worker: "vault",
      async run(client, args) {
        const running = engine();
        const http = api();
        if (running === null || http === null) throw fail("sync_not_running");
        const name = typeof args?.name === "string" && args.name !== "" && args.name.length <= 256 ? args.name : null;
        const rpId = typeof args?.rp_id === "string" && /^[a-z0-9.-]{1,253}$/.test(args.rp_id) ? args.rp_id : null;
        const userName = typeof args?.user_name === "string" && args.user_name.length <= 256 ? args.user_name : null;
        if (name === null || rpId === null || userName === null) throw fail("invalid_input");
        const id = hexOf(random(new Uint8Array(16)));
        const made = await client.vault.passkey_import(
          bytesOfHex(id),
          1,
          { item_type: "login", name },
          { cred_id: bytesOf(args.cred_id), rp_id: rpId, user_handle: bytesOf(args.user_handle), user_name: userName, created: now(), key_pkcs8: bytesOf(args.key_pkcs8) },
          now(),
        );
        const idem = hexOf(random(new Uint8Array(16)));
        const { encodeWireBytes } = await import("../../shared/wire.mjs");
        const body = encodeWireBytes("put_item_req", { base_rev: 0, blob: toB64u(made.item.envelope), tag: toB64u(made.item.tag), idem });
        await http.put(`/api/sync/items/${id}`, body, { shape: "put_item_res" });
        await Promise.resolve(running.verifyNow?.()).catch(() => {});
        const until = Date.now() + LISTED_WITHIN_MS;
        while (Date.now() < until) {
          if (running.list().some((/** @type {{ id: string }} */ item) => item.id === id)) return { ok: true, item_id: id };
          await new Promise((resolve) => setTimeout(resolve, 250));
        }
        throw fail("not_listed");
      },
    },
  });
  return { ops };
}
