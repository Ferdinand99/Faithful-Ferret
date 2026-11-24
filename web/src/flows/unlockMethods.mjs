// The passkeys that unlock the vault (spec Fase 1 § 4.3, § 4.6, § 9.3, § 9.4): the list, adding one, removing one.
// Adding and removing are sensitive changes: the master password again, a new manifest sealed with the vault key, and a
// request signed with `sk_a` over the exact body the core wrote, in one transaction on the server.
//
// Adding a passkey, in order:
//
//   reauth                  the master password again (the page's dialog; skipped while the check is fresh)
//   GET session             who the session is; this device's pinned record of the account
//   GET unlock-methods      the server's list, checked against the manifest and the pinned record as at an unlock
//   (the vault's passkeys)  the credential ids of the passkey items of the vault, so that one Ferret stores itself is
//                           never made an unlock method (it would live in the vault it has to open, § 9.4)
//   prf_salt_new            a new 32-byte salt; a method id from the random source (never from public data)
//   -- the page waits for a click --
//   create                  WebAuthn create on this site's exact host, user verification required, PRF asked for
//   -- the page waits for a click: a browser lets a page make one WebAuthn call for each click --
//   get                     the one evaluation that is used: the same credential and salt; the user was verified and the
//                           result is exactly 32 bytes; when the registration gave a result too, the two are the same
//   wrap_prf                core: the key of the method from the result (the result is wiped by the call)
//   GET unlock-methods      the manifest as it is now (the methods may have changed while the user used the passkey)
//   manifest_add_method     core: the new manifest, with the name and the BE and BS flags inside it, and the body
//   POST challenge, auth_sign, POST unlock-methods   the signed write (`signedCall.mjs`): the core's body, byte for byte
//
// Nothing is sent before the passkey has answered both calls and the answers have been checked. A failure at any step
// leaves the server as it was (a passkey that was made and not used stays in the user's passkey provider; the page says
// so). The PRF output goes from the browser's answer to the core and nowhere else: not to the page, not to a log, not to
// storage, not to a request.
import { b64u, hex16 } from "../b64.mjs";
import { ApiError } from "../api.mjs";
import { AccountError } from "../crypto/errors.mjs";
import { MANIFEST_ID } from "../sync/engine.mjs";
import { browserDeps, createPasskey, evaluatePasskey, sameOutput } from "./passkeyCeremony.mjs";
import { accountContext } from "./reauth.mjs";
import { readMethods } from "./renewRecovery.mjs";
import { signedCall } from "./signedCall.mjs";

/** @typedef {import("../crypto/env.mjs").Env} Env */
/** @typedef {import("./passkeyCeremony.mjs").CeremonyDeps} CeremonyDeps */
/** @typedef {import("./passkeyCeremony.mjs").Registration} Registration */
/** @typedef {{ accountId: string, vaultId: string, vkEpoch: number }} VaultScope */

/** The path of the list, of an addition and (with an id) of a removal. */
export const METHODS_PATH = "/api/vault/unlock-methods";
/** The path of the server's rule for quick unlock. */
export const POLICY_PATH = "/api/vault/policy";
/** The most passkeys an account can have as unlock methods (the server holds the same limit). */
export const MAX_PASSKEYS = 10;
/** The longest name of a passkey, in characters. */
export const MAX_NAME_CHARS = 64;
/** The method type of a passkey on the wire. */
const PRF_TYPE = 3;
/** The marker `wrap_prf` takes when the vault has no passkey items. */
const NO_STORED_PASSKEYS = "no_stored_passkeys";
/** What a registration is called in the passkey provider of the user. */
const RP_NAME = "Faithful Ferret";
/** The generation of a new passkey method. */
const FIRST_GENERATION = 1;

/**
 * Whether the server offers passkeys as unlock methods. A server that has no such route, an answer that is not the
 * rule, or no answer at all says no: the page is hidden rather than left half working.
 * @param {import("../api.mjs").Api} api
 * @returns {Promise<boolean>}
 */
export async function passkeysOffered(api) {
  try {
    const rule = await api.get(POLICY_PATH);
    return rule?.prf?.enabled === true;
  } catch {
    return false;
  }
}

/** What a name must not hold: a control character, a line or paragraph separator, a bidirectional control, a zero width space or the byte order mark. */
const REFUSED_IN_NAME = /[\p{Cc}\u2028\u2029\u061C\u200B\u200E\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/u;

/**
 * The name of a passkey as the core will read it, or a refusal with the core's own code: 1 to 64 characters after
 * trimming and NFC, without the characters above. The core decides in the end; this is the check that comes before the
 * passkey is made, so that a name the core would refuse does not leave a passkey behind.
 * @param {unknown} name
 * @returns {string} the name as typed (the core normalises it)
 */
export function checkName(name) {
  if (typeof name !== "string") throw new AccountError("method_name_empty");
  const wellFormed = /** @type {any} */ (String.prototype).isWellFormed;
  if (typeof wellFormed === "function" && !wellFormed.call(name)) throw new AccountError("method_name_bad_character");
  const trimmed = name.normalize("NFC").trim();
  if (trimmed === "") throw new AccountError("method_name_empty");
  if (REFUSED_IN_NAME.test(name)) throw new AccountError("method_name_bad_character");
  if ([...trimmed].length > MAX_NAME_CHARS) throw new AccountError("method_name_too_long");
  return name;
}

/**
 * @param {unknown} a
 * @param {unknown} b
 */
function sameBytes(a, b) {
  return a instanceof Uint8Array && b instanceof Uint8Array && a.length === b.length && a.every((n, i) => n === b[i]);
}

/**
 * One row of the list of passkeys.
 * @typedef {object} PasskeyMethod
 * @property {string} id the method id, 32 hex characters
 * @property {string | null} name the name the user gave it, or null when it has none
 * @property {boolean} synced the registration said the passkey can be synced (BE): "synced passkey" instead of "this device only"
 * @property {string | null} aaguid the AAGUID as the server shows it (32 hex characters), or null when it is not known (none, or all zero)
 */

/**
 * The AAGUID for display: null when the server has none or it is all zero ("unknown").
 * @param {unknown} hex
 * @returns {string | null}
 */
function shownAaguid(hex) {
  if (typeof hex !== "string" || !hex16.is(hex) || /^0+$/.test(hex)) return null;
  return hex;
}

/**
 * The passkeys of the account for the list: the names and flags are from the sealed manifest (the server never sees
 * them), the AAGUID is the one the server keeps.
 * @param {Env} env
 * @returns {Promise<PasskeyMethod[]>}
 */
export async function listPasskeys(env) {
  const { client } = env;
  const { record } = await accountContext(env);
  const methods = await readMethods(env, record);
  return passkeysOf(await client.vault.prf_methods(methods.manifest), methods.all);
}

/**
 * @param {Array<Record<string, any>>} fromManifest what `prf_methods` gave
 * @param {Array<Record<string, any>>} fromServer the server's list
 * @returns {PasskeyMethod[]}
 */
function passkeysOf(fromManifest, fromServer) {
  const aaguids = new Map(fromServer.filter((m) => m.method_type === PRF_TYPE).map((m) => [m.method_id, m.aaguid]));
  return fromManifest.map((m) => {
    const id = hex16.encode(m.method_id);
    return {
      id,
      name: typeof m.name === "string" && m.name !== "" ? m.name : null,
      synced: m.synced === true,
      aaguid: shownAaguid(aaguids.get(id)),
    };
  });
}

/**
 * The `cred_id` of every passkey item of the open vault. The core refuses to wrap a credential the vault stores, but it
 * can only see items that are open; the web vault opens an item to read it and closes it again, so the ids are read here
 * from the rows this device holds.
 * @param {Env} env
 * @param {VaultScope} scope
 * @returns {Promise<Uint8Array[]>}
 */
async function storedPasskeyIds(env, scope) {
  const db = await env.store.open();
  /** @type {import("../store/cache.mjs").CachedRow[]} */
  const rows = await env.store.cache.getRows(db, scope);
  /** @type {Uint8Array[]} */
  const ids = [];
  for (const row of rows) {
    if (row.deleted || row.itemId === MANIFEST_ID || !row.envelope || !row.tag) continue;
    let handle;
    try {
      handle = await env.client.vault.open_item(hex16.decode(row.itemId), row.rev, row.envelope, row.tag);
      const view = await env.client.vault.item_view(handle);
      const id = view?.passkey?.cred_id;
      if (id instanceof Uint8Array && id.length > 0) ids.push(id.slice());
    } finally {
      if (handle !== undefined) await Promise.resolve(env.client.vault.close_item(handle)).catch(() => undefined);
    }
  }
  return ids;
}

/**
 * Whether a failure of the signed write leaves it unknown if the server took the change: it was sent, and the answer
 * is no answer, a server error or not an answer this page understands. An explicit refusal is not.
 * @param {unknown} error
 */
function outcomeUnknown(error) {
  const e = /** @type {any} */ (error);
  if (e?.afterSend !== true && e?.details?.afterSend !== true) return false;
  if (e instanceof ApiError) return e.status === 0 || e.status >= 500 || e.code === "bad_response" || e.code === "network";
  return e?.code === "bad_response";
}

/**
 * The signed write of a change, sent again once when the password check has run out while the user used the passkey.
 * @param {Env} env
 * @param {{ op: string, method: "POST" | "DELETE", path: string, bytes: Uint8Array }} change
 * @param {() => Promise<"ok" | "cancelled">} reauth
 */
async function writeChange(env, change, reauth) {
  const send = () => signedCall(env, { ...change, reply: null });
  try {
    let answer;
    try {
      answer = await send();
    } catch (error) {
      // The server refused before it changed anything: ask for the password once more and send the same change again.
      if (!(error instanceof ApiError && error.code === "reauth_required")) throw error;
      if ((await reauth()) !== "ok") throw new AccountError("cancelled");
      answer = await send();
    }
    if (answer === null || typeof answer !== "object" || !Number.isSafeInteger(answer.seq)) throw new AccountError("bad_response", { afterSend: true });
    return answer;
  } catch (error) {
    if (outcomeUnknown(error)) throw new AccountError("method_unconfirmed");
    throw error;
  }
}

/**
 * Checks the change the core made against what this device knows: it is signed for the key this device has pinned.
 * @param {Record<string, any>} change
 * @param {Record<string, any>} seeded the pinned record with the floors of the manifest
 */
function checkChange(change, seeded) {
  if (change === null || typeof change !== "object" || !(change.body instanceof Uint8Array) || typeof change.op !== "string") throw new AccountError("bad_response");
  if (!sameBytes(change.pk_a, seeded.pk_a)) throw new AccountError("pinned_auth_key");
}

/**
 * What the page holds while a passkey is being added. `create` and `confirm` are the two WebAuthn calls: the page calls
 * each from its own click, and nothing but the call itself comes first.
 * @typedef {object} AddingPasskey
 * @property {number} count the passkeys the account has now
 * @property {(name: string) => Promise<{ synced: boolean }>} create makes the passkey (the first click)
 * @property {() => Promise<PasskeyMethod>} confirm uses it once, wraps the vault key and writes the method (the second click)
 * @property {() => void} cancel drops what was made and held; the server was told nothing
 */

/**
 * The first part of adding a passkey: the password check, the checks of the server's list and the things the two calls
 * need. Nothing is made and nothing is sent.
 * @param {Env} env
 * @param {{
 *   reauth: () => Promise<"ok" | "cancelled">,
 *   scope: VaultScope,
 *   rpId?: string,
 *   deps?: CeremonyDeps,
 * }} args `rpId` is the exact host of the vault (the page's own); `deps` is for tests.
 * @returns {Promise<AddingPasskey>}
 */
export async function beginAddPasskey(env, { reauth, scope, rpId, deps = browserDeps() }) {
  const { client } = env;
  if (typeof reauth !== "function") throw new TypeError("adding a passkey needs the password check");
  if ((await reauth()) !== "ok") throw new AccountError("cancelled");
  const host = rpId ?? new URL(env.server).hostname;

  const { record } = await accountContext(env);
  const methods = await readMethods(env, record);
  const listed = methods.all.filter((m) => m.method_type === PRF_TYPE);
  if (listed.length >= MAX_PASSKEYS) throw new AccountError("too_many_passkeys");
  const exclude = listed.map((m) => b64u.decode(m.credential_id));
  const stored = await storedPasskeyIds(env, scope);

  const salt = await client.vault.prf_salt_new();
  if (!(salt instanceof Uint8Array) || salt.length !== 32) throw new AccountError("bad_response");
  // The id of the method is made from the random source and nothing else: it is not derived from the credential or from
  // anything public.
  const methodId = deps.rand(new Uint8Array(16));
  if (methodId.every((byte) => byte === 0)) throw new AccountError("bad_response");

  /** @type {{ registration: Registration, label: string } | null} */
  let made = null;
  let ended = false;
  let retry = false;
  const drop = () => {
    made?.registration.firstResult?.fill(0);
    made = null;
  };

  return {
    count: listed.length,

    async create(name) {
      if (ended || made !== null) throw new AccountError("passkey_sequence");
      const label = checkName(name);
      // The first thing after the click is the WebAuthn call itself.
      const registration = await createPasskey({ rpId: host, rpName: RP_NAME, userName: label.trim(), salt, exclude }, deps);
      made = { registration, label };
      return { synced: registration.be };
    },

    async confirm() {
      if (ended || made === null) throw new AccountError("passkey_sequence");
      const { registration, label } = made;
      /** @type {Uint8Array | null} */
      let output = null;
      try {
        try {
          output = await evaluatePasskey({ rpId: host, credentialId: registration.credentialId, salt }, deps);
        } catch (error) {
          // The user said no, or the system did, before anything was made of the passkey: the click can be made again.
          const code = /** @type {any} */ (error)?.code;
          if (code === "passkey_cancelled" || code === "passkey_blocked") retry = true;
          throw error;
        }
        // A passkey that gives another result the second time is no stable key: a method made from it would lock the user out.
        if (!sameOutput(registration.firstResult, output)) throw new AccountError("passkey_unstable");
        registration.firstResult?.fill(0);
        /** @type {Record<string, any>} */
        let wrap;
        try {
          // The core wipes `output` (and the client does too, after copying it for the worker).
          wrap = await client.vault.wrap_prf(
            registration.credentialId.slice(), salt.slice(), output, methodId.slice(), FIRST_GENERATION, registration.aaguid.slice(),
            stored.length === 0 ? NO_STORED_PASSKEYS : stored.map((id) => id.slice()),
          );
        } catch (error) {
          // A passkey that Ferret itself stores, or Ferret's own authenticator: it could never open the vault it lives in.
          if (/** @type {any} */ (error)?.code === "invalid_state") throw new AccountError("passkey_stored_here");
          throw error;
        }
        output = null;

        // The manifest as the server has it now: the methods may have changed while the user used the passkey.
        const fresh = await readMethods(env, record);
        if (fresh.all.filter((m) => m.method_type === PRF_TYPE).length >= MAX_PASSKEYS) throw new AccountError("too_many_passkeys");
        /** @type {Record<string, any>} */
        let change;
        try {
          change = await client.vault.manifest_add_method(fresh.manifest, wrap, registration.aaguid.slice(), label, registration.be, registration.bs);
        } catch (error) {
          if (/** @type {any} */ (error)?.code === "invalid_state") throw new AccountError("passkey_stored_here");
          throw error;
        }
        checkChange(change, fresh.seeded);
        await writeChange(env, { op: change.op, method: "POST", path: METHODS_PATH, bytes: change.body }, reauth);
        return { id: hex16.encode(methodId), name: label.normalize("NFC").trim(), synced: registration.be, aaguid: shownAaguid(hex16.encode(registration.aaguid)) };
      } finally {
        /** @type {Uint8Array | null} */ (output)?.fill(0);
        if (retry) {
          retry = false;
        } else {
          drop();
          ended = true;
        }
      }
    },

    cancel() {
      ended = true;
      drop();
    },
  };
}

/**
 * Removes a passkey from the unlock methods: the master password again, a new manifest without it, and the signed delete.
 * The passkey stays in the provider that holds it (Windows, iCloud, a phone); the page says so.
 * @param {Env} env
 * @param {{ id: string, reauth: () => Promise<"ok" | "cancelled"> }} args `id` is the method id (32 hex characters)
 * @returns {Promise<{ remaining: number }>}
 */
export async function removePasskeyMethod(env, { id, reauth }) {
  const { client } = env;
  if (typeof reauth !== "function") throw new TypeError("removing a passkey needs the password check");
  if (!hex16.is(id)) throw new TypeError("a method id is 32 hexadecimal characters");
  if ((await reauth()) !== "ok") throw new AccountError("cancelled");
  const { record } = await accountContext(env);
  const methods = await readMethods(env, record);
  // Only a passkey goes this way: the password and the recovery key have pages of their own.
  const target = methods.all.find((m) => m.method_id === id);
  if (target === undefined) throw new AccountError("method_not_found");
  if (target.method_type !== PRF_TYPE) throw new AccountError("not_a_passkey");
  const change = await client.vault.manifest_remove_method(methods.manifest, hex16.decode(id));
  checkChange(change, methods.seeded);
  await writeChange(env, { op: change.op, method: "DELETE", path: `${METHODS_PATH}/${id}`, bytes: change.body }, reauth);
  return { remaining: methods.all.filter((m) => m.method_type === PRF_TYPE).length - 1 };
}
