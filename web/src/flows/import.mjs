// Importing items into the vault (spec Fase 1 § 5.2 and § 6.4): a file of Ferret's own (`.ferretexport`) or an
// unencrypted export of Bitwarden (JSON or CSV) or of AliasVault (`.avux` or CSV). The plain text of a file is
// never in the main thread:
//
//   plain files            the page gives an import worker the `File` and one end of a port to the vault worker;
//                          the worker reads the file, makes the drafts and has the vault seal each one over the
//                          port. The page gets back sealed envelopes and a report of counts and warning codes.
//   .ferretexport          the page reads the (encrypted) file, the job worker makes the key from the export
//                          password, and the vault opens the file and seals every item inside WASM
//                          (`import_open`, `import_seal`): no field of an item passes through JavaScript.
//
// The steps of an import, in order:
//
//   previewImport      reads the file in the worker (or reads the header of an export) and says what is in it, how
//                      much room the vault has, and whether the vault is empty. Nothing is sent to the server.
//   runImport          the fit is checked (a file that does not fit stops here, before anything is written), then
//                      a fresh re-authentication with the master password, then (for an export) the file is opened
//                      and sealed, then `POST /api/sync/import` opens an import window for as many items as there
//                      are, and only then does `engine.importItems` store every item in the outbox and send them.
//   continueImport     "Continue import": the server closed the window (it ran out, or the server started again) or
//                      the page was loaded again after that. A fresh re-authentication, a new window for the items
//                      that are left, and `engine.resumeImport` sends only those, under the keys they had.
//
// Whatever the user typed stays in the call that needs it and is not kept. The sealed items are ciphertext; they are
// held in memory (not in any store) between the preview and the import, and let go of by `discardImport`, by the
// import itself, and by a lock of the vault (the session ends the import worker and drops the previews). Nothing of
// an import is logged, stored outside the vault, or put in an address. An error carries a code, never a text of the file.
import { hex16 } from "../b64.mjs";
import { AccountError } from "../crypto/errors.mjs";
import { IMPORT_ERROR_TEXT, MAX_AVUX_FILE_BYTES, MAX_FILE_BYTES } from "../import/limits.mjs";
import { MAX_SITES, PASSKEY_SKIP_REASONS } from "../import/passkeys.mjs";
import { encodeWire } from "../wire.mjs";
import { reauthenticate } from "./reauth.mjs";

/** @typedef {import("../crypto/env.mjs").Env} Env */
/** @typedef {import("../import/map.mjs").ImportReport} ImportReport */

/** The most live rows a vault has (spec Fase 1 § 6.4); the unlock-method manifest is one of them. */
export const VAULT_ROW_LIMIT = 10_000;

/** How long an import worker may take before the page ends it (reading, and sealing up to 10 000 items). */
export const IMPORT_TIMEOUT_MS = 300_000;

/** The largest `.ferretexport` the page reads into memory: the body is at most 128 MiB (`MAX_BODY_LEN` of the core), plus a header. */
export const MAX_EXPORT_FILE_BYTES = 128 * 1024 * 1024 + 4096;

/** Where the server says whether it has the import of passkeys (`passkeys.import`). */
const POLICY_PATH = "/api/vault/policy";

/**
 * Whether the server offers the import of passkeys from another password manager's file (`GET /api/vault/policy`, `passkeys.import`).
 * False when it does not say so, or cannot be asked: the passkeys of a file are then left out, as before.
 * @param {{ get(path: string): Promise<any> } | undefined} api
 * @returns {Promise<boolean>}
 */
export async function passkeyImportOffered(api) {
  try {
    const rule = await api?.get(POLICY_PATH);
    return rule?.passkeys?.import === true;
  } catch {
    return false;
  }
}

/** The kinds of file the import takes: what a preview says the file is. */
export const IMPORT_KINDS = Object.freeze(["ferretexport", "bitwarden_json", "bitwarden_csv", "aliasvault_csv", "aliasvault_avux"]);

/** The most items one import can bring in: the vault's rows less the manifest. */
const MAX_IMPORT_ITEMS = VAULT_ROW_LIMIT - 1;

/**
 * What a preview keeps for the import that follows: never part of the preview that the page can read.
 * @type {WeakMap<object, PreviewState>}
 */
const states = new WeakMap();

/**
 * What a preview says of the passkeys of a file when their import is on: why some are left out, how many must be registered at
 * their site again (and the first few of those sites), how many lost their PRF key, how many got an item of their own.
 * @typedef {{
 *   skipped: Record<"not_discoverable" | "other_key" | "bad_site" | "unreadable" | "duplicate", number>,
 *   registerAgain: number, prfDropped: number, extra: number, sites: ReadonlyArray<string>,
 * }} PasskeyReport
 *
 * @typedef {{ id: Uint8Array, rev: number, envelope: Uint8Array, tag: Uint8Array }} Sealed
 * @typedef {{
 *   file: Blob | null,
 *   kind: "ferretexport" | "bitwarden_json" | "bitwarden_csv" | "aliasvault_csv" | "aliasvault_avux",
 *   sealed: Sealed[] | null,
 *   header: { salt: Uint8Array, kdf: Record<string, number> } | null,
 *   running: boolean,
 *   gone: boolean,
 * }} PreviewState
 *
 * @typedef {{
 *   kind: "ferretexport" | "bitwarden_json" | "bitwarden_csv" | "aliasvault_csv" | "aliasvault_avux",
 *   counts: ImportReport["counts"] | null,
 *   skipped: ImportReport["skipped"] | null,
 *   passkeys: PasskeyReport | null,
 *   warnings: ReadonlyArray<{ code: string, count: number }>,
 *   warningsDropped: number,
 *   free: number,
 *   used: number,
 *   vaultEmpty: boolean,
 *   fits: boolean,
 *   createdAt: number | null,
 * }} Preview
 */

/**
 * The page's view of how full the vault is, from the engine's list (items the vault shows now, an import under way
 * included). The server counts live rows and has the last word; the manifest is one of its rows.
 * @param {{ list(): unknown[] }} engine
 * @returns {{ used: number, free: number }}
 */
export function vaultRoom(engine) {
  const used = engine.list().length;
  return { used, free: Math.max(0, MAX_IMPORT_ITEMS - used) };
}

/**
 * What to ask for, by the name of the file: the page never reads a file that is not a kind it takes. A `.csv` file
 * may be an export of Bitwarden or of AliasVault: the worker looks at its header and the preview says which it was.
 * The worker looks at the first bytes of a JSON or CSV file again (a ZIP file under another name is `import_zip`).
 * An `.avex` file is the encrypted export of AliasVault, which Ferret cannot open.
 * @param {{ name?: unknown }} file
 * @returns {"ferretexport" | "bitwarden_json" | "csv" | "aliasvault_avux"}
 */
export function kindOfFile(file) {
  const name = typeof file?.name === "string" ? file.name.toLowerCase() : "";
  if (name.endsWith(".ferretexport")) return "ferretexport";
  if (name.endsWith(".json")) return "bitwarden_json";
  if (name.endsWith(".csv")) return "csv";
  if (name.endsWith(".avux")) return "aliasvault_avux";
  if (name.endsWith(".avex")) throw new AccountError("import_encrypted_export");
  if (name.endsWith(".zip")) throw new AccountError("import_zip");
  throw new AccountError("import_bad_format");
}

/** @param {unknown} scope */
function mustBeEngine(scope) {
  const engine = /** @type {any} */ (scope);
  if (engine === null || typeof engine !== "object" || typeof engine.list !== "function") {
    throw new TypeError("an import needs the sync engine of the open vault");
  }
  return engine;
}

/** A number that is a count, or 0. @param {unknown} n */
const count = (n) => (typeof n === "number" && Number.isSafeInteger(n) && n >= 0 ? n : 0);

/**
 * Copies the numbers of a group of the worker's report: only the keys that are named, only counts.
 * @template {Record<string, number>} T
 * @param {unknown} source
 * @param {T} shape the keys that are taken (their values are not used)
 * @returns {T}
 */
function numbersOf(source, shape) {
  /** @type {Record<string, number>} */
  const out = {};
  const from = source !== null && typeof source === "object" ? /** @type {Record<string, unknown>} */ (source) : {};
  for (const key of Object.keys(shape)) out[key] = count(from[key]);
  return /** @type {T} */ (out);
}

const COUNT_KEYS = Object.freeze({
  items: 0, login: 0, note: 0, card: 0, identity: 0, urls: 0, totp: 0, customFields: 0, matchNull: 0, http: 0, textAddresses: 0, sealed: 0, passkeys: 0,
});
const SKIPPED_KEYS = Object.freeze({
  passkeys: 0, folders: 0, linked: 0, unknownKeys: 0, otherTypes: 0, trashed: 0, tooLarge: 0, passwordHistory: 0, reprompt: 0,
  attachments: 0, fieldHistory: 0, tags: 0,
});

/** The name of a site as the vault spells it: lower case letters, digits, dots and hyphens, 253 at the most. */
const SITE = /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/;

/**
 * The passkey part of a worker's report: counts by reason, and the sites that look like sites.
 * @param {unknown} source
 * @returns {PasskeyReport}
 */
function readPasskeys(source) {
  const p = source !== null && typeof source === "object" ? /** @type {Record<string, any>} */ (source) : {};
  const skipped = /** @type {PasskeyReport["skipped"]} */ (numbersOf(p.skipped, Object.fromEntries(PASSKEY_SKIP_REASONS.map((reason) => [reason, 0]))));
  const sites = (Array.isArray(p.sites) ? p.sites : []).filter((site) => typeof site === "string" && SITE.test(site)).slice(0, MAX_SITES);
  return { skipped, registerAgain: count(p.registerAgain), prfDropped: count(p.prfDropped), extra: count(p.extra), sites };
}

/**
 * What the page may take from a worker's report: the counts, and the warning codes counted (never an index or a value).
 * @param {unknown} report
 */
function readReport(report) {
  const r = report !== null && typeof report === "object" ? /** @type {Record<string, any>} */ (report) : {};
  /** @type {Map<string, number>} */
  const byCode = new Map();
  for (const warning of Array.isArray(r.warnings) ? r.warnings : []) {
    const code = warning?.code;
    if (typeof code !== "string" || !/^[a-z0-9_]{1,64}$/.test(code)) continue;
    byCode.set(code, (byCode.get(code) ?? 0) + 1);
  }
  return {
    counts: numbersOf(r.counts, COUNT_KEYS),
    skipped: numbersOf(r.skipped, SKIPPED_KEYS),
    passkeys: readPasskeys(r.passkeys),
    warnings: [...byCode].map(([code, n]) => ({ code, count: n })).sort((a, b) => (a.code < b.code ? -1 : 1)),
    warningsDropped: count(r.warningsDropped),
  };
}

/**
 * Runs the import worker for one request and answers what it answers. The worker is ended when it has answered,
 * when `signal` aborts (a lock of the vault) and when `timeoutMs` has passed: a vault worker that dies without a
 * word would leave it waiting for ever. The port to the vault worker goes to the worker with the file; the page keeps
 * no end of it.
 * @param {Env & { createImportWorker?: () => any }} env
 * @param {{ kind: string, file: Blob, labels?: unknown, passkeys?: { known: string[] } }} request
 * @param {{ signal?: AbortSignal, timeoutMs?: number }} options
 * @returns {Promise<Record<string, any>>}
 */
function runWorker(env, request, { signal, timeoutMs = IMPORT_TIMEOUT_MS }) {
  if (typeof env.createImportWorker !== "function") throw new AccountError("import_worker_failed");
  if (signal?.aborted) throw new AccountError("locked");
  const port = env.client.importPort();
  /** @type {any} */
  let worker;
  try {
    worker = env.createImportWorker();
  } catch {
    try {
      port.close();
    } catch {
      // closed already
    }
    throw new AccountError("import_worker_failed");
  }
  return new Promise((resolve, reject) => {
    let over = false;
    /** @type {ReturnType<typeof setTimeout> | undefined} */
    let timer;
    /**
     * @param {(value: any) => void} settle
     * @param {unknown} value
     */
    const finish = (settle, value) => {
      if (over) return;
      over = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      worker.onmessage = null;
      worker.onerror = null;
      worker.onmessageerror = null;
      try {
        worker.terminate();
      } catch {
        // already gone
      }
      try {
        port.close();
      } catch {
        // transferred, or closed already
      }
      settle(value);
    };
    const onAbort = () => finish(reject, new AccountError("locked"));
    timer = setTimeout(() => finish(reject, new AccountError("import_timeout")), timeoutMs);
    signal?.addEventListener("abort", onAbort, { once: true });
    worker.onmessage = (/** @type {{ data: unknown }} */ event) => finish(resolve, event.data);
    worker.onerror = () => finish(reject, new AccountError("import_worker_failed"));
    worker.onmessageerror = () => finish(reject, new AccountError("import_worker_failed"));
    try {
      worker.postMessage({ id: 1, kind: request.kind, file: request.file, port, ...(request.labels === undefined ? {} : { labels: request.labels }), ...(request.passkeys === undefined ? {} : { passkeys: request.passkeys }) }, [port]);
    } catch {
      finish(reject, new AccountError("import_worker_failed"));
    }
  });
}

/**
 * The refusal a worker answered, as an error the page has a text for: only a known code and a line number go on.
 * @param {Record<string, any>} data
 */
function workerRefusal(data) {
  const code = typeof data.error === "string" && Object.hasOwn(IMPORT_ERROR_TEXT, data.error) ? data.error : "import_unreadable";
  return new AccountError(code, Number.isSafeInteger(data.line) && data.line > 0 ? { line: data.line } : null);
}

/**
 * The sealed items of a worker's answer, checked: ids of 16 bytes (never the manifest's), revision 1, an envelope
 * and a tag of 32 bytes each, no id twice, and as many as the report says.
 * @param {unknown} sealed
 * @returns {Sealed[]}
 */
function readSealed(sealed) {
  if (!Array.isArray(sealed) || sealed.length > MAX_IMPORT_ITEMS) throw new AccountError("import_bad_answer");
  const seen = new Set();
  for (const item of sealed) {
    const ok = item !== null && typeof item === "object" && item.id instanceof Uint8Array && item.id.length === 16 && item.rev === 1
      && item.envelope instanceof Uint8Array && item.envelope.length > 0 && item.tag instanceof Uint8Array && item.tag.length === 32;
    if (!ok) throw new AccountError("import_bad_answer");
    const id = hex16.encode(item.id);
    if (id === "0".repeat(32) || seen.has(id)) throw new AccountError("import_bad_answer");
    seen.add(id);
  }
  return /** @type {Sealed[]} */ (sealed);
}

/**
 * Reads the file and says what is in it. Nothing is sent to the server and nothing is stored.
 *
 * A JSON or CSV file is read by the import worker, which also has the vault seal every item (the sealed items are
 * kept for `runImport`; `discardImport` lets go of them). An export of Ferret's is only looked at here: its header
 * is read (its Argon2id cost is checked by the core), and what is in it is known only once the export password has
 * opened it, so `counts` is null and `createdAt` says when it was made.
 * @param {Env & { createImportWorker?: () => any }} env
 * @param {Blob & { name?: string }} file
 * @param {{ engine: { list(): unknown[] }, labels?: unknown, signal?: AbortSignal, timeoutMs?: number }} options
 * `labels`: the names of the fields of the items (user name, password, ...) in the language of the page.
 * A JSON file of Bitwarden and an `.avux` of AliasVault have their passkeys imported when the server offers it (`passkeyImportOffered`)
 * and the engine can say which passkeys the vault has already (`passkeyKeys`, items and trash); otherwise they are counted and left out.
 * @returns {Promise<Preview>}
 */
export async function previewImport(env, file, { engine, labels, signal, timeoutMs } = /** @type {any} */ ({})) {
  mustBeEngine(engine);
  if (typeof Blob === "undefined" || !(file instanceof Blob)) throw new TypeError("an import needs a file");
  const kind = kindOfFile(file);
  if (file.size === 0) throw new AccountError("import_empty");
  const { used, free } = vaultRoom(engine);

  if (kind === "ferretexport") {
    if (file.size > MAX_EXPORT_FILE_BYTES) throw new AccountError("import_export_too_large");
    /** @type {Record<string, any>} */
    let header = {};
    // Only the bytes of the file (ciphertext) pass through here, and only for the header.
    const bytes = new Uint8Array(await file.arrayBuffer());
    try {
      header = await env.client.vault.import_header(bytes);
    } catch (error) {
      const code = /** @type {any} */ (error)?.code;
      if (code === "locked" || code === "worker_failed" || code === "vault_locked") throw error;
      throw new AccountError("import_bad_export", typeof code === "string" && /^[a-z0-9_]{1,64}$/.test(code) ? { reason: code } : null);
    } finally {
      bytes.fill(0);
    }
    if (!(header?.salt instanceof Uint8Array) || header.kdf === null || typeof header.kdf !== "object") throw new AccountError("import_bad_export");
    const createdAt = Number.isSafeInteger(header.created_at) && header.created_at > 0 ? header.created_at : null;
    /** @type {Preview} */
    const preview = Object.freeze({
      kind, counts: null, skipped: null, passkeys: null, warnings: [], warningsDropped: 0, free, used, vaultEmpty: used === 0, fits: free > 0, createdAt,
    });
    states.set(preview, { file, kind, sealed: null, header: { salt: header.salt, kdf: { ...header.kdf } }, running: false, gone: false });
    return preview;
  }

  // An `.avux` archive may be large (attachments and logos); only its manifest is read.
  if (kind === "aliasvault_avux" ? file.size > MAX_AVUX_FILE_BYTES : file.size > MAX_FILE_BYTES) {
    throw new AccountError(kind === "aliasvault_avux" ? "import_archive_too_large" : "import_too_large");
  }
  // The passkeys of a file are read only when the server says so and the page can tell which the vault has already (a passkey is
  // never imported twice: not from the vault, not from the trash, not from the file).
  /** @type {{ known: string[] } | undefined} */
  let passkeys;
  if ((kind === "bitwarden_json" || kind === "aliasvault_avux") && typeof /** @type {any} */ (engine).passkeyKeys === "function" && await passkeyImportOffered(env.api)) {
    const known = await /** @type {any} */ (engine).passkeyKeys();
    if (Array.isArray(known) && known.every((key) => typeof key === "string")) passkeys = { known };
  }
  const answer = await runWorker(env, { kind, file, labels, ...(passkeys === undefined ? {} : { passkeys }) }, { signal, timeoutMs });
  if (answer === null || typeof answer !== "object" || answer.id !== 1 || typeof answer.ok !== "boolean") throw new AccountError("import_bad_answer");
  if (answer.ok !== true) throw workerRefusal(answer);
  const sealed = readSealed(answer.sealed);
  const report = readReport(answer.report);
  if (sealed.length === 0) throw new AccountError("import_empty");
  if (report.counts.sealed !== sealed.length) throw new AccountError("import_bad_answer");
  // What the worker read the file as: a `.csv` file is Bitwarden's or AliasVault's by its header. The kind has to be one that
  // the name allowed.
  const readAs = answer.kind;
  /** @type {string[]} */
  const allowed = kind === "csv" ? ["bitwarden_csv", "aliasvault_csv"] : [kind];
  if (typeof readAs !== "string" || !allowed.includes(readAs)) throw new AccountError("import_bad_answer");
  /** @type {Preview} */
  const preview = Object.freeze({
    kind: /** @type {Preview["kind"]} */ (readAs),
    counts: Object.freeze({ ...report.counts, items: sealed.length }),
    skipped: Object.freeze(report.skipped),
    passkeys: passkeys === undefined ? null : Object.freeze({ ...report.passkeys, skipped: Object.freeze(report.passkeys.skipped), sites: Object.freeze(report.passkeys.sites) }),
    warnings: Object.freeze(report.warnings.map((w) => Object.freeze(w))),
    warningsDropped: report.warningsDropped,
    free, used, vaultEmpty: used === 0, fits: sealed.length <= free, createdAt: null,
  });
  // Only an export of Ferret's is read again; a plain file is not kept once it has been parsed.
  states.set(preview, { file: null, kind: preview.kind, sealed, header: null, running: false, gone: false });
  return preview;
}

/**
 * Lets go of what a preview keeps (the sealed items and the file). The preview itself stays readable.
 * @param {object} preview
 */
export function discardImport(preview) {
  const state = states.get(preview);
  if (!state) return;
  state.sealed = null;
  state.header = null;
  state.file = null;
  state.gone = true;
  states.delete(preview);
}

/**
 * Asks the server for an import window for `ops` items: only a fresh re-authentication gets one. A refusal keeps its
 * code (`import_window_open`: another device holds one; `quota_exceeded`: the vault has no room; `reauth_required`).
 * @param {Env} env
 * @param {number} ops
 * @returns {Promise<string>} the window id (32 hex characters)
 */
async function openWindow(env, ops) {
  const answer = await env.api.post("/api/sync/import", encodeWire("import_window_req", { ops }), { shape: "import_window_res" });
  if (answer.ops < ops) throw new AccountError("quota_exceeded");
  return answer.window_id;
}

/** A new item id: 16 random bytes, never all zero (the manifest's). @param {Env} env */
function newItemId(env) {
  const id = new Uint8Array(16);
  do {
    env.rand(id);
  } while (id.every((b) => b === 0));
  return id;
}

/**
 * Opens an export of Ferret's with the export password and seals every item of it, inside WASM. The key made from
 * the password is wiped after it was given to the core; the open items are dropped from the core's memory at the end.
 * @param {Env} env
 * @param {PreviewState} state
 * @param {string} exportPassword
 * @param {{ free: number, onProgress: (p: { phase: string, items?: number }) => void, signal?: AbortSignal }} options
 * @returns {Promise<Sealed[]>}
 */
async function openAndSeal(env, state, exportPassword, { free, onProgress, signal }) {
  const { client } = env;
  const header = state.header;
  if (header === null) throw new AccountError("import_preview_gone");
  if (state.file === null) throw new AccountError("import_preview_gone");
  const bytes = new Uint8Array(await state.file.arrayBuffer());
  /** @type {Uint8Array | null} */
  let key = null;
  /** The core holds the opened items. */
  let opened = false;
  try {
    onProgress({ phase: "stretching" });
    key = await client.job.argon2_export_key(exportPassword, header.salt, header.kdf, "open");
    if (signal?.aborted) throw new AccountError("locked");
    onProgress({ phase: "opening" });
    /** @type {{ count?: unknown }} */
    let info = {};
    try {
      info = await client.vault.import_open(bytes, key);
    } catch (error) {
      // After the master password has been confirmed, a refusal here is the file or its password.
      const code = /** @type {any} */ (error)?.code;
      if (code === "decrypt") throw new AccountError("import_wrong_export_password");
      throw error;
    }
    opened = true;
    const total = Number(info?.count);
    if (!Number.isSafeInteger(total) || total < 0 || total > MAX_IMPORT_ITEMS) throw new AccountError("import_bad_answer");
    if (total === 0) throw new AccountError("import_empty");
    if (total > free) throw new AccountError("import_does_not_fit", { items: total, free });
    onProgress({ phase: "sealing", items: total });
    /** @type {Sealed[]} */
    const sealed = [];
    for (let index = 0; index < total; index += 1) {
      if (signal?.aborted) throw new AccountError("locked");
      const id = newItemId(env);
      const made = await client.vault.import_seal(index, id, 1);
      if (!(made?.envelope instanceof Uint8Array) || !(made?.tag instanceof Uint8Array) || made.rev !== 1) throw new AccountError("import_bad_answer");
      sealed.push({ id, rev: 1, envelope: made.envelope, tag: made.tag });
    }
    return sealed;
  } finally {
    // The core wipes the key it was given; this is for the path that never reached it.
    key?.fill(0);
    bytes.fill(0);
    if (opened) {
      // Not by calling a worker that a lock has ended (that would start a new one).
      if (signal?.aborted !== true) await Promise.resolve(client.vault.import_close()).catch(() => undefined);
    }
  }
}

/** @param {Sealed[]} sealed */
const toItems = (sealed) => sealed.map(({ id, rev, envelope, tag }) => ({ id: hex16.encode(id), rev: /** @type {1} */ (rev), envelope, tag }));

/**
 * Runs the import of a previewed file: checks that it fits, confirms the master password again (a fresh sign-in),
 * opens the file and seals it (an export of Ferret's), gets an import window from the server, and hands the sealed
 * items to the engine, which stores all of them in the outbox before anything is sent and then sends them in
 * batches. Resolves when the items are queued: the sending goes on, and the engine's `import` events say how far it is.
 *
 * A failure leaves the preview as it was (a wrong password can be typed again), and nothing was written unless
 * `engine.importItems` was reached. `onProgress({ phase, items? })`: `checking`, `stretching`, `opening`, `sealing`,
 * `window`, `queueing`.
 * @param {Env & { createImportWorker?: () => any }} env
 * @param {Preview} preview what `previewImport` gave
 * @param {{
 *   masterPassword: string, exportPassword?: string, skCode?: string,
 *   engine: { list(): unknown[], importStatus?(): { queued: number }, importItems(items: any[], options: { windowId: string }): Promise<{ queued: number }> },
 *   onProgress?: (progress: { phase: string, items?: number }) => void, signal?: AbortSignal,
 * }} args
 * @returns {Promise<{ queued: number }>}
 */
export async function runImport(env, preview, { masterPassword, exportPassword, skCode, engine, onProgress = () => {}, signal }) {
  mustBeEngine(engine);
  const state = preview !== null && typeof preview === "object" ? states.get(preview) : undefined;
  if (!state || state.gone) throw new AccountError("import_preview_gone");
  if (state.running) throw new AccountError("import_busy");
  if (typeof masterPassword !== "string" || masterPassword === "") throw new AccountError("password_required");
  const needsExportPassword = state.kind === "ferretexport" && state.sealed === null;
  if (needsExportPassword && (typeof exportPassword !== "string" || exportPassword === "")) throw new AccountError("import_export_password_required");

  const { free } = vaultRoom(engine);
  // A file that does not fit stops here, before anything is asked of the server or written.
  if (state.sealed !== null && state.sealed.length > free) throw new AccountError("import_does_not_fit", { items: state.sealed.length, free });
  if (free === 0) throw new AccountError("import_does_not_fit", { items: 0, free });

  state.running = true;
  try {
    onProgress({ phase: "checking" });
    // The master password again. The vault that is open is not touched, and a wrong password stops here.
    await reauthenticate(env, { password: masterPassword, skCode });
    if (signal?.aborted) throw new AccountError("locked");
    if (state.sealed === null) {
      state.sealed = await openAndSeal(env, state, /** @type {string} */ (exportPassword), { free, onProgress, signal });
    }
    const sealed = state.sealed;
    if (state.gone) throw new AccountError("import_preview_gone");
    onProgress({ phase: "window", items: sealed.length });
    // An import that is not finished goes on under this window with the new items (the engine moves it), so the window is for both.
    const carried = typeof engine.importStatus === "function" ? engine.importStatus().queued : 0;
    const windowId = await openWindow(env, sealed.length + carried);
    onProgress({ phase: "queueing", items: sealed.length });
    const result = await engine.importItems(toItems(sealed), { windowId });
    // Spent: the sealed items are in the outbox now.
    discardImport(preview);
    return { queued: result.queued };
  } finally {
    state.running = false;
  }
}

/**
 * "Continue import": the server closed the import window (`import_window_closed`), or the page was loaded after that.
 * A fresh re-authentication, a new window for as many items as are left, and the engine sends only those, under the
 * keys they had (what the server stored before the window closed comes back as a replay and costs nothing).
 * @param {Env} env
 * @param {{
 *   masterPassword: string, skCode?: string,
 *   engine: { importStatus(): { queued: number }, resumeImport(options: { windowId: string }): Promise<void> },
 *   onProgress?: (progress: { phase: string, items?: number }) => void,
 * }} args
 * @returns {Promise<{ remaining: number }>}
 */
export async function continueImport(env, { masterPassword, skCode, engine, onProgress = () => {} }) {
  if (engine === null || typeof engine !== "object" || typeof engine.importStatus !== "function" || typeof engine.resumeImport !== "function") {
    throw new TypeError("continuing an import needs the sync engine of the open vault");
  }
  if (typeof masterPassword !== "string" || masterPassword === "") throw new AccountError("password_required");
  const { queued } = engine.importStatus();
  if (queued === 0) throw new AccountError("import_nothing_left");
  onProgress({ phase: "checking" });
  await reauthenticate(env, { password: masterPassword, skCode });
  onProgress({ phase: "window", items: queued });
  const windowId = await openWindow(env, queued);
  onProgress({ phase: "queueing", items: queued });
  await engine.resumeImport({ windowId });
  return { remaining: queued };
}
