// Exporting the vault (spec Fase 1 § 6.4): the encrypted file (`.ferretexport`) and the plain
// copy for moving to another service. Both need the master password again, typed on the page
// and checked by a fresh sign-in (`reauth.mjs`), even though the vault is open.
//
// The encrypted export, in order:
//
//   (cache rows)                        the live rows this device holds, as the server sent them (ciphertext)
//   login_start ... POST login/finish   the fresh re-authentication (the vault that is open is not touched)
//   reauth_grant                        core: the one-time token that only that sign-in makes
//   export_begin                        core: takes the token (the file holds every secret, passkey keys included),
//                                       opens every row (a row that does not open fails the export),
//                                       draws the salt, keeps the draft in WASM. 256 MiB, 3 passes, 1 lane.
//   argon2_export_key                   job worker: the slow step. The core refuses an export password that
//                                       is shorter than 12 characters or equal to the master password.
//   export_finish                       core: seals the file with that key and wipes the key
//   download                            the browser is given the file; the byte array is wiped after
//
// The plain export needs the same one-time grant (`reauth_grant`, five minutes, one attempt), and an explicit `confirmed: true` that the page gets from two separate
// confirmations. JSON includes passkey keys only when asked for; CSV never does, and the core
// neutralizes formulas in CSV.
//
// What is read is what this device holds: the live rows of the local copy of the feed. Changes still
// waiting in the outbox, and changes the server has that this device has not read, are not in the
// file; the page warns about both before it starts (`exportReadiness`). Nothing here is logged, stored
// or put in an address. A JavaScript string (the passwords, the text of a plain export) cannot be
// wiped; the byte arrays are, and the core wipes its own copies. The browser's copy of a download
// (the Blob) is out of reach, and the page says where the file ends up.
import { hex16 } from "../b64.mjs";
import { AccountError } from "../crypto/errors.mjs";
import { downloadBlob } from "../download.mjs";
import { MANIFEST_ID } from "../sync/engine.mjs";
import { reauthenticate } from "./reauth.mjs";

/** @typedef {import("../crypto/env.mjs").Env} Env */
/** @typedef {{ accountId: string, vaultId: string, vkEpoch: number }} VaultScope */

/** The cost of an export file: 256 MiB, 3 passes, one lane (spec Fase 1 § 6.4). `m_kib` is in KiB. */
export const EXPORT_KDF = Object.freeze({ m_kib: 262_144, t: 3, p: 1 });

/** The shortest export password (spec Fase 1 § 6.4); the core is the one that decides. */
export const EXPORT_PASSWORD_MIN = 12;

/** The file's media type. The extension is what says what it is. */
const FILE_MIME = "application/octet-stream";

/** The error `code`s that mean "the user typed something the page can see is wrong"; nothing was sent. */
export const FORM_ERRORS = Object.freeze(["password_required", "password_mismatch", "input_too_short", "plain_not_confirmed"]);

/**
 * Calls `use`, and turns a core `decrypt` (a row that does not open) into `export_item_unreadable`: in this place it
 * does not mean a wrong password (the re-authentication has passed already).
 * @template T
 * @param {() => Promise<T>} use
 * @returns {Promise<T>}
 * @param {() => Promise<string[]>} [unreadable] names the rows that do not open (item ids)
 */
async function opening(use, unreadable = async () => /** @type {string[]} */ ([])) {
  try {
    return await use();
  } catch (error) {
    if (/** @type {any} */ (error)?.code === "decrypt") throw new AccountError("export_item_unreadable", { ids: await unreadable() });
    throw error;
  }
}

/** The most items named in the refusal; the rest are only counted by "and more" in the page's list. */
const MAX_NAMED = 20;

/**
 * Which rows do not open: each is opened and closed again (the same call the list uses; nothing secret comes back, and
 * no grant is spent). Best effort; a call that fails for another reason ends the search.
 * @param {Env} env
 * @param {Array<{ item_id: Uint8Array, rev: number, envelope: Uint8Array, tag: Uint8Array }>} rows
 * @returns {Promise<string[]>} item ids (32 hex characters)
 */
async function findUnreadable(env, rows) {
  /** @type {string[]} */
  const ids = [];
  for (const row of rows) {
    if (ids.length >= MAX_NAMED) break;
    try {
      const handle = await env.client.vault.open_item(row.item_id, row.rev, row.envelope, row.tag);
      await Promise.resolve(env.client.vault.close_item(handle)).catch(() => undefined);
    } catch (error) {
      if (/** @type {any} */ (error)?.code === "decrypt") ids.push(hex16.encode(row.item_id));
      else break;
    }
  }
  return ids;
}

/**
 * The live rows this device holds for the vault, as the core takes them. The unlock-method manifest is a row, not
 * an item, and deleted items are not live.
 * @param {Env} env
 * @param {VaultScope} scope
 */
async function exportRows(env, scope) {
  const db = await env.store.open();
  /** @type {import("../store/cache.mjs").CachedRow[]} */
  const rows = await env.store.cache.getRows(db, scope);
  const live = rows.filter((row) => !row.deleted && row.itemId !== MANIFEST_ID && row.envelope && row.tag);
  if (live.length === 0) throw new AccountError("nothing_to_export");
  return live.map((row) => ({ item_id: hex16.decode(row.itemId), rev: row.rev, envelope: /** @type {Uint8Array} */ (row.envelope), tag: /** @type {Uint8Array} */ (row.tag) }));
}

/** @param {number} ms */
function dayOf(ms) {
  return new Date(ms).toISOString().slice(0, 10);
}

/** @param {unknown} scope */
function checkScope(scope) {
  const s = /** @type {any} */ (scope);
  if (s === null || typeof s !== "object" || !hex16.is(s.accountId) || !hex16.is(s.vaultId) || !Number.isSafeInteger(s.vkEpoch)) {
    throw new TypeError("an export needs the scope of the open vault");
  }
}

/**
 * The encrypted export: opens the rows, seals them under a key made from the export password, and hands the
 * file to the browser. `masterPassword` is checked again by a fresh sign-in first; the export password is typed
 * twice and is refused when it is shorter than 12 characters or equal to the master password.
 *
 * `onProgress({ phase })` says where it is: `checking` (the sign-in), `reading` (the rows are opened), `stretching`
 * (the key is made: seconds, 256 MiB), `sealing`, `saving`. The password is never in it.
 * With `incomplete: true` (the user went on past the warning that the file may miss changes) the 30-day reminder is not reset.
 * @param {Env} env
 * @param {{
 *   masterPassword: string, exportPassword: string, exportPasswordAgain: string, skCode?: string,
 *   scope: VaultScope, incomplete?: boolean,
 *   onProgress?: (progress: { phase: "checking" | "reading" | "stretching" | "sealing" | "saving", items?: number }) => void,
 *   download?: typeof downloadBlob,
 * }} args `scope` is the open vault (`session.current()`); `download` is for tests.
 * @returns {Promise<{ items: number }>}
 */
export async function encryptedExport(env, { masterPassword, exportPassword, exportPasswordAgain, skCode, scope, incomplete = false, onProgress = () => {}, download = downloadBlob }) {
  checkScope(scope);
  // What the page can see is wrong stops here, before the slow sign-in.
  if (typeof masterPassword !== "string" || masterPassword === "" || typeof exportPassword !== "string" || exportPassword === "") {
    throw new AccountError("password_required");
  }
  if (exportPassword !== exportPasswordAgain) throw new AccountError("password_mismatch");
  // Fewer code points is always fewer characters for the core as well, so this never refuses what the core would accept.
  if ([...exportPassword].length < EXPORT_PASSWORD_MIN) throw new AccountError("input_too_short");

  const { client } = env;
  // Ciphertext only; an empty vault stops here, before the slow sign-in.
  const rows = await exportRows(env, scope);
  onProgress({ phase: "checking" });
  // The master password again: a wrong one stops here, and the vault that is open stays open. The sign-in makes the
  // one-time grant that the core needs to start the export (it holds every secret of the vault).
  const done = await reauthenticate(env, { password: masterPassword, skCode, wantGrant: true });
  const grant = done.grant;
  if (!(grant instanceof Uint8Array)) throw new AccountError("reauth_required");

  /** @type {Uint8Array | null} */
  let key = null;
  /** @type {Uint8Array | null} */
  let file = null;
  /** The core holds a draft that was begun and not yet sealed. */
  let draft = false;
  /** The vault was locked (or its worker ended) while this ran: nothing is left to clean up there. */
  let gone = false;
  try {
    onProgress({ phase: "reading", items: rows.length });
    const begun = await opening(() => client.vault.export_begin(rows, env.now(), EXPORT_KDF, grant), () => findUnreadable(env, rows));
    draft = true;
    // The cost is the core's to keep; this makes a change of its default visible here instead of in a weaker file.
    if (!begun?.kdf || begun.kdf.m_kib < EXPORT_KDF.m_kib || begun.kdf.t < EXPORT_KDF.t || begun.kdf.p < EXPORT_KDF.p) {
      throw new AccountError("kdf_out_of_range");
    }
    onProgress({ phase: "stretching" });
    // The core compares with the master password before it spends any memory: an equal export password is refused there.
    key = await client.job.argon2_export_key(exportPassword, begun.salt, begun.kdf, "write", masterPassword);
    onProgress({ phase: "sealing" });
    const sealed = await client.vault.export_finish(key);
    file = sealed;
    draft = false;
    onProgress({ phase: "saving" });
    download(sealed, `ferret-export-${dayOf(env.now())}.ferretexport`, FILE_MIME);
  } catch (error) {
    const code = /** @type {any} */ (error)?.code;
    gone = code === "locked" || code === "worker_failed" || code === "vault_locked";
    throw error;
  } finally {
    // The core wipes the grant and the key it was given; this is for the calls that did not get that far.
    grant.fill(0);
    key?.fill(0);
    // The Blob has its own copy; the array is no longer needed.
    file?.fill(0);
    // A draft that was begun and not sealed is dropped (not by calling a worker that a lock has ended: that would start a new one).
    if (draft && !gone) await Promise.resolve(client.vault.export_abort()).catch(() => undefined);
  }
  // The reminder counts from now, unless the file is known to be incomplete. A store that cannot keep the date does not undo the export.
  if (incomplete === true) return { items: rows.length };
  try {
    await env.store.exportReminder.mark(await env.store.open(), env.server, scope.accountId, env.now());
  } catch {
    // The next reminder simply comes sooner.
  }
  return { items: rows.length };
}

/**
 * The plain export (CSV or JSON), for moving to another service. It exists only behind the master password again
 * (a fresh sign-in that makes the one-time grant) and an explicit `confirmed: true`, which the page gets from two
 * separate confirmations. The file holds every secret in the clear. Passkey private keys and PRF seeds are in the JSON
 * only when `includePasskeys` is true; CSV never has them.
 * @param {Env} env
 * @param {{
 *   masterPassword: string, format: "json" | "csv", includePasskeys?: boolean, confirmed: boolean, skCode?: string,
 *   scope: VaultScope,
 *   download?: typeof downloadBlob,
 * }} args
 * @returns {Promise<void>}
 */
export async function plainExport(env, { masterPassword, format, includePasskeys = false, confirmed, skCode, scope, download = downloadBlob }) {
  checkScope(scope);
  if (confirmed !== true) throw new AccountError("plain_not_confirmed");
  if (format !== "json" && format !== "csv") throw new AccountError("invalid_input");
  if (typeof masterPassword !== "string" || masterPassword === "") throw new AccountError("password_required");

  const { client } = env;
  // Ciphertext only; read first, so that the grant (good for five minutes) is not spent waiting for it.
  const rows = await exportRows(env, scope);
  // The one-time grant: only a fresh sign-in with the master password makes it, and it is used up by one attempt.
  const done = await reauthenticate(env, { password: masterPassword, skCode, wantGrant: true });
  const grant = done.grant;
  if (!(grant instanceof Uint8Array)) throw new AccountError("reauth_required");
  /** @type {Uint8Array | null} */
  let bytes = null;
  try {
    // The core leaves passkey keys out of CSV whatever is asked; nothing is asked of it that CSV cannot have.
    const withPasskeys = format === "json" && includePasskeys === true;
    const text = await opening(() => client.vault.reveal_plain_export(rows, format, withPasskeys, grant, env.now()), () => findUnreadable(env, rows));
    bytes = new TextEncoder().encode(text);
    download(bytes, `ferret-plain-export-${dayOf(env.now())}.${format}`, format === "json" ? "application/json" : "text/csv");
  } finally {
    // The core wipes the grant it was given; this is for the path that never reached it.
    grant.fill(0);
    bytes?.fill(0);
  }
}

/**
 * What the page warns about before an export: how many items have writes that the server has not accepted (waiting,
 * refused, in conflict or being uploaded again: none of them are in the file as the user sees them), and whether
 * this device has read the server's newest state (`atTop`). `lastState` is the last status the engine reported
 * (`idle` after a pass that ended well); without it only what `health()` knows is used.
 * @param {{ list(): Array<Record<string, any>>, health(): { halted: string | null, warnings: string[] } }} engine
 * @param {{ lastState?: string | null }} [options]
 * `damaged` counts the items whose newest row did not open or whose deletion could not be checked: the file has their last readable version, or misses them.
 * @returns {{ pendingWrites: number, atTop: boolean, damaged: number }}
 */
export function exportReadiness(engine, { lastState } = {}) {
  const items = engine.list();
  const pendingWrites = items.filter((item) => item.pending === true || item.blocked === true || item.conflict === true || item.missingOnServer === true).length;
  const damaged = items.filter((item) => item.damaged === true || item.quarantined === true).length;
  const health = engine.health();
  const behind = health.halted !== null || health.warnings.length > 0 || (typeof lastState === "string" && lastState !== "idle");
  return { pendingWrites, atTop: !behind, damaged };
}

/**
 * Reads the feed once more and says how ready the vault is for an export (`exportReadiness`). A pass that does not end
 * within `timeoutMs` counts as not at the top. The engine's own events are only listened to for the length of the pass.
 * @param {{ list(): Array<Record<string, any>>, health(): { halted: string | null, warnings: string[] }, syncNow(): Promise<void>, on(event: string, fn: (payload: any) => void): () => void }} engine
 * @param {{ timeoutMs?: number }} [options]
 * @returns {Promise<{ pendingWrites: number, atTop: boolean, damaged: number }>}
 */
export async function refreshReadiness(engine, { timeoutMs = 15_000 } = {}) {
  /** @type {string | null} */
  let lastState = null;
  const off = engine.on("state", (/** @type {any} */ payload) => {
    if (typeof payload?.kind === "string" && /^(?:failed|halted|idle|offline|retrying|syncing|unauthorized)$/.test(payload.kind)) lastState = payload.kind;
  });
  /** @type {ReturnType<typeof setTimeout> | undefined} */
  let timer;
  try {
    const timeout = new Promise((resolve) => {
      timer = setTimeout(() => resolve("timeout"), timeoutMs);
    });
    const outcome = await Promise.race([Promise.resolve(engine.syncNow()).then(() => "done", () => "failed"), timeout]);
    if (outcome !== "done") lastState = outcome;
  } finally {
    clearTimeout(timer);
    off();
  }
  return exportReadiness(engine, { lastState });
}
