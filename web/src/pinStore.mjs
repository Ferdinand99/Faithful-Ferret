// The pinned folders of this device, kept at rest encrypted under the vault key.
//
// A folder's name is an encrypted label of the vault, so the names of the pinned folders never sit in clear on the
// device. They are sealed by the core the way an item is: `encrypt_item` makes an item body that holds nothing but the
// pinned names in its `folders` list, under a random id of its own, with the vault key (so the core's rules for the
// names apply, and nothing here is new cryptography). That sealed body is kept in this browser's settings store and is
// never sent anywhere: it is not an item of the vault, the sync engine never sees it, and no request carries it. After
// an unlock it is opened with the same key and the names are read from its view; while the vault is locked nobody can
// read them, not even this page.
//
// The record is kept under `sync.flags.<account>.pins.<vault>`, among the account's sync flags, so that "Forget this
// server" removes it with them. A record that does not open (a damaged value) means no pins: it is a preference, not
// data, and it is replaced at the next pin. A record of another vault key epoch is removed when it is read: after a
// rekey the old key may be exposed, so its ciphertext is not kept.
import { hex16 } from "./b64.mjs";
import { MAX_FOLDERS } from "./folders.mjs";

/** The revision the sealed record always has. */
const REV = 1;

/**
 * The settings key of the record.
 * @param {string} accountId @param {string} vaultId
 */
export const pinsKey = (accountId, vaultId) => `sync.flags.${accountId}.pins.${vaultId}`;

/**
 * @typedef {object} PinRecord what is stored: no name, only the sealed body and what opens it
 * @property {1} v
 * @property {number} epoch the vault key epoch it was sealed under
 * @property {string} id the random id it was sealed under (32 hex characters)
 * @property {Uint8Array} envelope
 * @property {Uint8Array} tag
 */

/** @param {unknown} value @returns {value is PinRecord} */
function isRecord(value) {
  const r = /** @type {any} */ (value);
  return r !== null && typeof r === "object" && r.v === 1 && Number.isSafeInteger(r.epoch) && hex16.is(r.id)
    && r.envelope instanceof Uint8Array && r.tag instanceof Uint8Array && r.tag.length === 32 && r.envelope.length <= 64 * 1024;
}

/** Sixteen random bytes that are not all zero (the id of the manifest). */
function randomId() {
  const id = new Uint8Array(16);
  do globalThis.crypto.getRandomValues(id);
  while (id.every((b) => b === 0));
  return id;
}

/**
 * The pin store of one open vault.
 * @param {{
 *   vault: { encrypt_item: Function, open_item: Function, item_view: Function, close_item: Function },
 *   settings: { get(key: string): Promise<unknown>, set(key: string, value: unknown): Promise<void>, remove(key: string): Promise<void> },
 *   accountId: string, vaultId: string, vkEpoch: number, now?: () => number,
 * }} options
 */
export function createPinStore({ vault, settings, accountId, vaultId, vkEpoch, now = Date.now }) {
  const key = pinsKey(accountId, vaultId);
  return {
    /**
     * The pinned names, or [] when there is no record or it does not open.
     * @returns {Promise<string[]>}
     */
    async load() {
      let record;
      try {
        record = await settings.get(key);
      } catch {
        return [];
      }
      if (!isRecord(record)) return [];
      if (record.epoch !== vkEpoch) {
        // A record of another vault key epoch: after a rekey the old key may be exposed, so its ciphertext does not stay.
        await Promise.resolve().then(() => settings.remove(key)).catch(() => undefined);
        return [];
      }
      /** @type {number | null} */
      let handle = null;
      try {
        handle = await vault.open_item(hex16.decode(record.id), REV, record.envelope, record.tag);
        const view = await vault.item_view(handle);
        const names = /** @type {any} */ (view)?.folders;
        return Array.isArray(names) ? names.filter((n) => typeof n === "string").slice(0, MAX_FOLDERS) : [];
      } catch {
        return [];
      } finally {
        if (handle !== null) await Promise.resolve(vault.close_item(handle)).catch(() => {});
      }
    },

    /**
     * Seals and keeps the names (none: the record goes). Throws when the core refuses the names or the store fails.
     * @param {readonly string[]} names
     */
    async save(names) {
      if (names.length === 0) {
        await settings.remove(key);
        return;
      }
      const id = randomId();
      const draft = { item_type: "note", name: "", folders: [...names].slice(0, MAX_FOLDERS) };
      const sealed = await vault.encrypt_item(id, REV, draft, undefined, now());
      /** @type {PinRecord} */
      const record = { v: 1, epoch: vkEpoch, id: hex16.encode(id), envelope: new Uint8Array(sealed.envelope), tag: new Uint8Array(sealed.tag) };
      await settings.set(key, record);
    },
  };
}
