// The import worker. An import file is read here and nowhere else on the page: the main thread
// gives the worker the File and a port to the vault worker, the worker reads the file, makes the
// drafts and sends them over the port, so no plain text of an import passes through the main
// thread (Spec: Fase 1 § 5.2; Global Constraint 46). The build starts this file as
// /js/import.worker.mjs (a one-line module that loads it), the address the page's Trusted Types policy
// lists (src/tt.mjs). The server answers both addresses with a policy that has `connect-src 'none'`,
// so the worker cannot send what it reads anywhere.
//
// Request (from the page, with the port in the transfer list):
//   { id, kind: "bitwarden_json" | "bitwarden_csv" | "aliasvault_csv" | "aliasvault_avux" | "csv", file: File, port: MessagePort, labels?: {...},
//     passkeys?: { known: string[] } }
//   (`csv` is a CSV file of either service: the header says which, and the answer names the kind it was read as. `passkeys` turns the
//   import of passkeys on, for a JSON file of Bitwarden and an `.avux` of AliasVault: `known` are the `passkeyKey`s of the passkeys
//   the vault already holds, in items and in the trash. Without it a passkey is counted and left out.)
// Answer (once, to the page):
//   { id, ok: true, kind, sealed: [{ id, rev, envelope, tag }], report }  or  { id, ok: false, error, line? }
// `sealed` holds the 16-byte item ids and the envelopes the vault made; `report` holds counts and
// warnings (a code and the position of an item), never a name or a value. The caller ends the worker
// after the answer.
//
// The worker makes the item ids (random, 16 bytes), sends every draft over the port as
// `{ id, method: "encrypt_item", args: [itemId, 1, draft, "no_existing", nowMs] }` (the only message
// the vault worker takes from an import port) and waits for `{ id, ok, value | code }`. A draft
// A passkey is sealed with `{ id, method: "passkey_import", args: [itemId, 1, draft, passkey, nowMs] }`: into the login it belongs to
// (the draft of that login), or, for a second passkey of a login, into an item of its own. The key of a passkey goes to the vault worker
// in that message and nowhere else: no draft, report, error or log holds it, and the worker wipes its copy of the bytes when the item is sealed. A
// passkey the vault refuses (another kind of key, a site that is no site, one it already has) is counted by reason and its login is sealed
// without it. A draft
// whose one-time password the vault refuses (`malformed_otpauth`, or `invalid_input` for an address
// it cannot normalise, such as a bad `%` escape) is sent again with the address in a hidden field;
// a draft that is too large to seal is left out with a warning; any other refusal stops the import. One import per worker: a second request is `unsupported`.

import { parseCsv } from "../import/csv.mjs";
import { AVUX_MANIFEST_ENTRY, fromAliasVaultCsv, fromAvuxManifest, isAliasVaultCsvHeader } from "../import/aliasvault.mjs";
import { fromBitwardenCsv, fromBitwardenJson } from "../import/bitwarden.mjs";
import { ImportError, MAX_AVUX_ENTRIES, MAX_AVUX_FILE_BYTES, MAX_FILE_BYTES } from "../import/limits.mjs";
import { resolveLabels, warn, withTotpAsHidden } from "../import/map.mjs";
import { MAX_SITES, passkeyKey, skipPasskey, wipeInput } from "../import/passkeys.mjs";

/** @typedef {import("../import/passkeys.mjs").PasskeyTask} PasskeyTask */
import { safeJsonParse } from "../import/prescan.mjs";
import { readZipEntry } from "../import/zip.mjs";

/** The value that says "no item exists under this id", as the vault worker's import port wants it. */
export const NO_EXISTING = "no_existing";

/** The kinds of file the worker reads. */
export const KINDS = Object.freeze(["bitwarden_json", "bitwarden_csv", "aliasvault_csv", "aliasvault_avux", "csv"]);

/** How many drafts are on their way to the vault worker at once. */
const IN_FLIGHT = 16;

/** The most passkeys of the vault the page names: a vault holds at most 10 000 items. */
const MAX_KNOWN_PASSKEYS = 20_000;

/**
 * The answer to a request that is none the worker takes: the id of the request, if it had one, and
 * the code `unsupported`.
 * @param {unknown} message
 * @returns {{ id: number | string | null, ok: false, error: "unsupported" }}
 */
export function answer(message) {
  const id = message !== null && typeof message === "object" ? /** @type {{ id?: unknown }} */ (message).id : undefined;
  return { id: typeof id === "number" || typeof id === "string" ? id : null, ok: false, error: "unsupported" };
}

/**
 * @typedef {{
 *   postMessage(message: unknown): void,
 *   onmessage: ((event: { data: unknown }) => void) | null,
 *   close(): void,
 * }} VaultPort
 * @typedef {{ id: Uint8Array, rev: number, envelope: Uint8Array, tag: Uint8Array }} Sealed
 * @typedef {{ id: number | string, kind: string, file: Blob, port: VaultPort, labels?: unknown, passkeys?: { known: string[] } }} ImportRequest
 * @typedef {{ now?: () => number, random?: (bytes: Uint8Array) => Uint8Array }} Deps
 */

/**
 * Whether a message is a well-formed import request.
 * @param {unknown} message
 * @returns {message is ImportRequest}
 */
function isRequest(message) {
  if (message === null || typeof message !== "object") return false;
  const m = /** @type {Record<string, unknown>} */ (message);
  if (typeof m.id !== "number" && typeof m.id !== "string") return false;
  if (typeof m.kind !== "string" || !KINDS.includes(m.kind)) return false;
  if (typeof Blob === "undefined" || !(m.file instanceof Blob)) return false;
  if (m.passkeys !== undefined) {
    const p = /** @type {Record<string, unknown> | null} */ (m.passkeys);
    if (p === null || typeof p !== "object" || !Array.isArray(p.known) || p.known.length > MAX_KNOWN_PASSKEYS) return false;
    if (!p.known.every((key) => typeof key === "string" && key.length <= 4096)) return false;
  }
  const port = /** @type {Record<string, unknown> | null} */ (m.port);
  return port !== null && typeof port === "object" && typeof port.postMessage === "function" && typeof port.close === "function";
}

/**
 * Reads the file into drafts.
 * @param {string} kind
 * @param {Blob} file
 * @param {unknown} labels
 * @param {{ passkeys: boolean, now: number }} read what the readers are asked: whether to read passkeys, and the time
 * @returns {Promise<{ drafts: import("../import/map.mjs").ItemDraft[], report: import("../import/map.mjs").ImportReport, kind: string, passkeys: PasskeyTask[] }>}
 */
async function readDrafts(kind, file, labels, read) {
  // The size is the file's own, known before a byte is read. An archive may be large: only its directory and its manifest are read.
  if (file.size > (kind === "aliasvault_avux" ? MAX_AVUX_FILE_BYTES : MAX_FILE_BYTES)) {
    throw new ImportError(kind === "aliasvault_avux" ? "import_archive_too_large" : "import_too_large");
  }
  const head = new Uint8Array(await file.slice(0, 512).arrayBuffer());
  const zipped = head[0] === 0x50 && head[1] === 0x4b && head[2] === 0x03 && head[3] === 0x04;
  if (kind === "aliasvault_avux") {
    if (!zipped) {
      // The encrypted export of AliasVault is a small JSON file that says what it is; it is not opened.
      const start = new TextDecoder().decode(head);
      throw new ImportError(/"format"\s*:\s*"avex"/.test(start) ? "import_encrypted_export" : "import_bad_zip");
    }
    // Only the manifest is read; the attachments and logos of the archive are never unpacked.
    const bytes = await readZipEntry(file, AVUX_MANIFEST_ENTRY, {
      maxBytes: MAX_FILE_BYTES,
      maxEntries: MAX_AVUX_ENTRIES,
      maxFileBytes: MAX_AVUX_FILE_BYTES,
      codes: { file: "import_archive_too_large", entries: "import_archive_too_many", entry: "import_manifest_too_large" },
    });
    /** @type {string} */
    let manifest;
    try {
      manifest = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw new ImportError("import_bad_json");
    }
    return { ...fromAvuxManifest(safeJsonParse(manifest), { labels, passkeys: read.passkeys, now: read.now }), kind };
  }
  if (zipped) throw new ImportError("import_zip");
  /** @type {string} */
  let text;
  try {
    text = await file.text();
  } catch {
    throw new ImportError("import_unreadable");
  }
  if (kind === "bitwarden_json") return { ...fromBitwardenJson(safeJsonParse(text), { labels, passkeys: read.passkeys, now: read.now }), kind };
  const { rows, lines } = parseCsv(text);
  // A CSV file named only `.csv` is read as what its header says it is.
  const as = kind === "csv" ? (isAliasVaultCsvHeader(rows[0]) ? "aliasvault_csv" : "bitwarden_csv") : kind;
  if (as === "aliasvault_csv") return { ...fromAliasVaultCsv(rows, { labels, lines }), kind: as, passkeys: [] };
  return { ...fromBitwardenCsv(rows, { labels, lines }), kind: as, passkeys: [] };
}

/**
 * A new item id: 16 random bytes, never all zero (the id of the manifest).
 * @param {(bytes: Uint8Array) => Uint8Array} random
 */
function newItemId(random) {
  const id = new Uint8Array(16);
  do {
    random(id);
  } while (id.every((b) => b === 0));
  return id;
}

/**
 * What the vault answers to a refused `passkey_import`, as the reason the passkey is left out. A code that is not here is not about
 * the passkey (a locked vault, a failure of the worker): it stops the import.
 */
const PASSKEY_REFUSALS = Object.freeze({
  invalid_state: "duplicate",
  unsupported: "other_key",
  malformed_rp_id: "bad_site",
  malformed_webauthn_options: "unreadable",
  malformed_item_body: "unreadable",
  too_large: "unreadable",
  invalid_input: "unreadable",
});

/**
 * One item the worker seals: a draft, and perhaps the passkey that goes into it.
 * @typedef {{
 *   draft: import("../import/map.mjs").ItemDraft,
 *   task: PasskeyTask | null,
 *   plain: import("../import/map.mjs").ItemDraft | null,
 * }} Job `plain`: for a login that a passkey joins, its draft without the passkey (what is sealed when the passkey is left out)
 */

/**
 * The jobs of an import: one for each draft, the first passkey of a login in the draft of the login, and one for each passkey that
 * gets an item of its own.
 * @param {import("../import/map.mjs").ItemDraft[]} drafts
 * @param {PasskeyTask[]} tasks
 * @param {Readonly<Record<string, string>>} labels
 * @returns {Job[]}
 */
function makeJobs(drafts, tasks, labels) {
  /** @type {Map<number, PasskeyTask>} */
  const joins = new Map();
  for (const task of tasks) if (!task.extra && !joins.has(task.index)) joins.set(task.index, task);
  /** @param {import("../import/map.mjs").ItemDraft} draft @param {number} counter @param {string} [extra] */
  const withNote = (draft, counter, extra = "") => {
    const lines = [extra, counter > 0 ? labels.passkey_register_again : ""].filter((line) => line !== "");
    if (lines.length === 0) return draft;
    return { ...draft, notes: [draft.notes ?? "", ...lines].filter((part) => part !== "").join("\n\n") };
  };
  /** @type {Job[]} */
  const jobs = drafts.map((draft, index) => {
    const task = joins.get(index) ?? null;
    return task === null ? { draft, task: null, plain: null } : { draft: withNote(draft, task.input.counter), task, plain: draft };
  });
  for (const task of tasks) {
    if (!task.extra) continue;
    const base = drafts[task.index];
    const username = base?.item_type === "login" ? base.fields?.find((field) => field.id === "username") : undefined;
    /** @type {import("../import/map.mjs").ItemDraft} */
    const own = { item_type: "login", name: base?.name ?? labels.untitled, favorite: false, ...(username ? { fields: [username] } : {}) };
    jobs.push({ draft: withNote(own, task.input.counter, labels.passkey_extra), task, plain: null });
  }
  return jobs;
}

/**
 * Seals every draft through the vault port, and the passkeys that go with them.
 * @param {import("../import/map.mjs").ItemDraft[]} drafts
 * @param {PasskeyTask[]} tasks the passkeys read from the file (the page asked for them), each into the login it belongs to or an item of its own
 * @param {import("../import/map.mjs").ImportReport} report
 * @param {VaultPort} port
 * @param {Readonly<Record<string, string>>} labels
 * @param {{ now: () => number, random: (bytes: Uint8Array) => Uint8Array, known: Set<string> }} deps `known`: the passkeys the vault has already, and (as they are sealed) the ones this import has
 * @returns {Promise<Sealed[]>}
 */
function sealAll(drafts, tasks, report, port, labels, deps) {
  return new Promise((resolve, reject) => {
    const jobs = makeJobs(drafts, tasks, labels);
    const total = jobs.length;
    /** @type {(Sealed | null)[]} */
    const results = new Array(total).fill(null);
    /** @type {Map<number, { index: number, job: Job, draft: import("../import/map.mjs").ItemDraft, passkey: boolean, itemId: Uint8Array, retried: boolean }>} */
    const pending = new Map();
    let next = 0;
    let settled = 0;
    let requestId = 1;
    let over = false;

    /** The key of a passkey is wiped as soon as its item is sealed or its passkey is left out. @param {Job} job */
    const spend = (job) => {
      if (job.task !== null) wipeInput(job.task.input);
    };

    /** @param {ImportError | null} error */
    const finish = (error) => {
      if (over) return;
      over = true;
      port.onmessage = null;
      try {
        port.close();
      } catch {
        // closed already
      }
      pending.clear();
      for (const job of jobs) spend(job);
      // The drafts are plain text of the file: let go of them as early as this can.
      drafts.length = 0;
      tasks.length = 0;
      if (error) reject(error);
      else resolve(/** @type {Sealed[]} */ (results.filter((r) => r !== null)));
    };

    /**
     * @param {number} index
     * @param {Job} job
     * @param {import("../import/map.mjs").ItemDraft} draft
     * @param {boolean} passkey whether the passkey goes with it
     * @param {Uint8Array} itemId
     * @param {boolean} retried
     */
    const send = (index, job, draft, passkey, itemId, retried) => {
      const id = requestId++;
      pending.set(id, { index, job, draft, passkey, itemId, retried });
      port.postMessage(
        passkey && job.task !== null
          ? { id, method: "passkey_import", args: [itemId, 1, draft, job.task.input, deps.now()] }
          : { id, method: "encrypt_item", args: [itemId, 1, draft, NO_EXISTING, deps.now()] },
      );
    };

    const pump = () => {
      while (!over && pending.size < IN_FLIGHT && next < total) {
        const index = next++;
        const job = jobs[index];
        send(index, job, job.draft, job.task !== null, newItemId(deps.random), false);
      }
      if (!over && settled === total) finish(null);
    };

    /**
     * A passkey that is left out: counted, and its login (when it had one) is sealed without it.
     * @param {{ index: number, job: Job, itemId: Uint8Array }} entry
     * @param {string} reason
     */
    const leftOut = (entry, reason) => {
      skipPasskey(report, reason);
      spend(entry.job);
      if (entry.job.plain !== null) {
        send(entry.index, entry.job, entry.job.plain, false, entry.itemId, false);
      } else {
        settled++;
      }
    };

    /**
     * The answer to a passkey that was imported.
     * @param {{ index: number, job: Job, itemId: Uint8Array }} entry
     * @param {any} value
     * @returns {boolean} whether the answer is one that can be read
     */
    const imported = (entry, value) => {
      const item = value?.item;
      const ok = item && item.envelope instanceof Uint8Array && item.tag instanceof Uint8Array && typeof item.rev === "number" && typeof value.rp_id === "string" && value.notes !== null && typeof value.notes === "object";
      if (!ok) return false;
      const task = /** @type {PasskeyTask} */ (entry.job.task);
      const key = passkeyKey(value.rp_id, task.input.cred_id);
      if (deps.known.has(key)) {
        // The same site and credential id as one the vault has (or an earlier one of the file): the vault keeps what it has.
        leftOut(entry, "duplicate");
        return true;
      }
      deps.known.add(key);
      results[entry.index] = { id: entry.itemId, rev: item.rev, envelope: item.envelope, tag: item.tag };
      report.counts.passkeys++;
      if (task.extra) {
        report.counts.items++;
        report.counts.login++;
      }
      if (value.notes.register_again === true) {
        report.passkeys.registerAgain++;
        if (report.passkeys.sites.length < MAX_SITES && !report.passkeys.sites.includes(value.rp_id)) report.passkeys.sites.push(value.rp_id);
        warn(report, "passkey_register_again", task.index);
      }
      spend(entry.job);
      settled++;
      return true;
    };

    port.onmessage = (event) => {
      if (over) return;
      const m = /** @type {Record<string, any> | null} */ (event.data);
      if (m === null || typeof m !== "object") return;
      if (m.closed === true) {
        finish(new ImportError("import_port_closed"));
        return;
      }
      const entry = typeof m.id === "number" ? pending.get(m.id) : undefined;
      if (!entry) return;
      pending.delete(m.id);
      const value = m.value;
      if (entry.passkey) {
        if (m.ok === true) {
          if (!imported(entry, value)) {
            finish(new ImportError("import_seal_failed", { reason: "bad_reply" }));
            return;
          }
        } else if (m.ok === false && (m.code === "malformed_otpauth" || (m.code === "invalid_input" && entry.draft.totp)) && !entry.retried && entry.draft.totp) {
          // The core refused the one-time password of the login (or an address): keep it as a hidden field, and the passkey goes with it.
          const fallback = withTotpAsHidden(entry.draft, labels.totp);
          if (fallback === null) {
            finish(new ImportError("import_seal_failed", { reason: String(m.code) }));
            return;
          }
          warn(report, "totp_invalid", entry.job.task?.index ?? 0);
          report.counts.totp--;
          if (entry.job.plain !== null) entry.job.plain = withTotpAsHidden(entry.job.plain, labels.totp) ?? entry.job.plain;
          send(entry.index, entry.job, fallback, true, entry.itemId, true);
          return;
        } else if (m.ok === false && typeof m.code === "string" && Object.hasOwn(PASSKEY_REFUSALS, m.code)) {
          leftOut(entry, PASSKEY_REFUSALS[/** @type {keyof typeof PASSKEY_REFUSALS} */ (m.code)]);
        } else {
          finish(new ImportError("import_seal_failed", { reason: m.ok === false ? String(m.code) : "bad_reply" }));
          return;
        }
      } else if (m.ok === true && value && value.envelope instanceof Uint8Array && value.tag instanceof Uint8Array && typeof value.rev === "number") {
        results[entry.index] = { id: entry.itemId, rev: value.rev, envelope: value.envelope, tag: value.tag };
        settled++;
      } else if (m.ok === false && (m.code === "malformed_otpauth" || m.code === "invalid_input") && !entry.retried && entry.draft.totp) {
        // The core refused the one-time password (its strict parser, or a bad escape in the address that
        // its normalisation does not take): keep it as a hidden field.
        const fallback = withTotpAsHidden(entry.draft, labels.totp);
        if (fallback === null) {
          finish(new ImportError("import_seal_failed", { reason: String(m.code) }));
          return;
        }
        warn(report, "totp_invalid", entry.index);
        report.counts.totp--;
        send(entry.index, entry.job, fallback, false, entry.itemId, true);
        return;
      } else if (m.ok === false && m.code === "too_large") {
        warn(report, "item_too_large", entry.index);
        report.skipped.tooLarge++;
        settled++;
      } else {
        finish(new ImportError("import_seal_failed", { reason: m.ok === false ? String(m.code) : "bad_reply" }));
        return;
      }
      pump();
    };
    pump();
  });
}

/**
 * Runs one import: reads the file, makes the drafts, has the vault seal them, and returns what the
 * page may see.
 * @param {ImportRequest} request
 * @param {Deps} [deps]
 */
export async function runImport(request, deps = {}) {
  const now = deps.now ?? Date.now;
  const random = deps.random ?? ((/** @type {Uint8Array} */ bytes) => (globalThis.crypto.getRandomValues(/** @type {Uint8Array<ArrayBuffer>} */ (bytes)), bytes));
  const labels = resolveLabels(request.labels);
  /** @type {PasskeyTask[]} */
  let tasks = [];
  try {
    const read = await readDrafts(request.kind, request.file, request.labels, { passkeys: request.passkeys !== undefined, now: now() });
    const { drafts, report, kind } = read;
    tasks = read.passkeys;
    const known = new Set(request.passkeys?.known ?? []);
    const sealed = await sealAll(drafts, tasks, report, request.port, labels, { now, random, known });
    report.counts.sealed = sealed.length;
    return { sealed, report, kind };
  } finally {
    // Whatever key a passkey still holds (an import that stopped half way) is wiped.
    for (const task of tasks) wipeInput(task.input);
    try {
      request.port.onmessage = null;
      request.port.close();
    } catch {
      // closed already
    }
  }
}

/**
 * The function that answers the messages of the page. A worker does one import: after it has taken a
 * request, every other message is `unsupported`.
 * @param {Deps} [deps]
 */
export function createHandler(deps) {
  let taken = false;
  /** @param {unknown} message */
  return async function handle(message) {
    if (taken || !isRequest(message)) return answer(message);
    taken = true;
    try {
      const result = await runImport(message, deps);
      return { id: message.id, ok: /** @type {const} */ (true), kind: result.kind, sealed: result.sealed, report: result.report };
    } catch (error) {
      // Only a code goes back: no message of an error holds anything of the file.
      if (error instanceof ImportError) {
        return { id: message.id, ok: /** @type {const} */ (false), error: error.code, ...(error.line !== undefined ? { line: error.line } : {}) };
      }
      return { id: message.id, ok: /** @type {const} */ (false), error: /** @type {const} */ ("import_unreadable") };
    }
  };
}

// Only inside a worker: importing the module anywhere else (the tests) starts nothing.
const scope = /** @type {any} */ (globalThis);
if (typeof scope.WorkerGlobalScope === "function" && scope instanceof scope.WorkerGlobalScope) {
  const handle = createHandler();
  scope.onmessage = async (/** @type {MessageEvent} */ event) => {
    scope.postMessage(await handle(event.data));
  };
}
