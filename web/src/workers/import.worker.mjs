// The import worker. An import file is read here and nowhere else on the page: the main thread
// gives the worker the File and a port to the vault worker, the worker reads the file, makes the
// drafts and sends them over the port, so no plain text of an import passes through the main
// thread (Spec: Fase 1 § 5.2; Global Constraint 46). The build starts this file as
// /js/import.worker.mjs (a one-line module that loads it), the address the page's Trusted Types policy
// lists (src/tt.mjs). The server answers both addresses with a policy that has `connect-src 'none'`,
// so the worker cannot send what it reads anywhere.
//
// Request (from the page, with the port in the transfer list):
//   { id, kind: "bitwarden_json" | "bitwarden_csv" | "aliasvault_csv" | "aliasvault_avux" | "csv", file: File, port: MessagePort, labels?: {...} }
//   (`csv` is a CSV file of either service: the header says which, and the answer names the kind it was read as)
// Answer (once, to the page):
//   { id, ok: true, kind, sealed: [{ id, rev, envelope, tag }], report }  or  { id, ok: false, error, line? }
// `sealed` holds the 16-byte item ids and the envelopes the vault made; `report` holds counts and
// warnings (a code and the position of an item), never a name or a value. The caller ends the worker
// after the answer.
//
// The worker makes the item ids (random, 16 bytes), sends every draft over the port as
// `{ id, method: "encrypt_item", args: [itemId, 1, draft, "no_existing", nowMs] }` (the only message
// the vault worker takes from an import port) and waits for `{ id, ok, value | code }`. A draft
// whose one-time password the vault refuses (`malformed_otpauth`, or `invalid_input` for an address
// it cannot normalise, such as a bad `%` escape) is sent again with the address in a hidden field;
// a draft that is too large to seal is left out with a warning; any other refusal stops the import. One import per worker: a second request is `unsupported`.

import { parseCsv } from "../import/csv.mjs";
import { AVUX_MANIFEST_ENTRY, fromAliasVaultCsv, fromAvuxManifest, isAliasVaultCsvHeader } from "../import/aliasvault.mjs";
import { fromBitwardenCsv, fromBitwardenJson } from "../import/bitwarden.mjs";
import { ImportError, MAX_FILE_BYTES } from "../import/limits.mjs";
import { resolveLabels, warn, withTotpAsHidden } from "../import/map.mjs";
import { safeJsonParse } from "../import/prescan.mjs";
import { readZipEntry } from "../import/zip.mjs";

/** The value that says "no item exists under this id", as the vault worker's import port wants it. */
export const NO_EXISTING = "no_existing";

/** The kinds of file the worker reads. */
export const KINDS = Object.freeze(["bitwarden_json", "bitwarden_csv", "aliasvault_csv", "aliasvault_avux", "csv"]);

/** How many drafts are on their way to the vault worker at once. */
const IN_FLIGHT = 16;

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
 * @typedef {{ id: number | string, kind: string, file: Blob, port: VaultPort, labels?: unknown }} ImportRequest
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
  const port = /** @type {Record<string, unknown> | null} */ (m.port);
  return port !== null && typeof port === "object" && typeof port.postMessage === "function" && typeof port.close === "function";
}

/**
 * Reads the file into drafts.
 * @param {string} kind
 * @param {Blob} file
 * @param {unknown} labels
 * @returns {Promise<{ drafts: import("../import/map.mjs").ItemDraft[], report: import("../import/map.mjs").ImportReport, kind: string }>}
 */
async function readDrafts(kind, file, labels) {
  // The size is the file's own, known before a byte is read.
  if (file.size > MAX_FILE_BYTES) throw new ImportError("import_too_large");
  const head = new Uint8Array(await file.slice(0, 512).arrayBuffer());
  const zipped = head[0] === 0x50 && head[1] === 0x4b && head[2] === 0x03 && head[3] === 0x04;
  if (kind === "aliasvault_avux") {
    if (!zipped) {
      // The encrypted export of AliasVault is a small JSON file that says what it is; it is not opened.
      const start = new TextDecoder().decode(head);
      throw new ImportError(/"format"\s*:\s*"avex"/.test(start) ? "import_encrypted_export" : "import_bad_zip");
    }
    // Only the manifest is read; the attachments and logos of the archive are never unpacked.
    const bytes = await readZipEntry(file, AVUX_MANIFEST_ENTRY);
    /** @type {string} */
    let manifest;
    try {
      manifest = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw new ImportError("import_bad_json");
    }
    return { ...fromAvuxManifest(safeJsonParse(manifest), { labels }), kind };
  }
  if (zipped) throw new ImportError("import_zip");
  /** @type {string} */
  let text;
  try {
    text = await file.text();
  } catch {
    throw new ImportError("import_unreadable");
  }
  if (kind === "bitwarden_json") return { ...fromBitwardenJson(safeJsonParse(text), { labels }), kind };
  const { rows, lines } = parseCsv(text);
  // A CSV file named only `.csv` is read as what its header says it is.
  const as = kind === "csv" ? (isAliasVaultCsvHeader(rows[0]) ? "aliasvault_csv" : "bitwarden_csv") : kind;
  if (as === "aliasvault_csv") return { ...fromAliasVaultCsv(rows, { labels, lines }), kind: as };
  return { ...fromBitwardenCsv(rows, { labels, lines }), kind: as };
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
 * Seals every draft through the vault port.
 * @param {import("../import/map.mjs").ItemDraft[]} drafts
 * @param {import("../import/map.mjs").ImportReport} report
 * @param {VaultPort} port
 * @param {Readonly<Record<string, string>>} labels
 * @param {{ now: () => number, random: (bytes: Uint8Array) => Uint8Array }} deps
 * @returns {Promise<Sealed[]>}
 */
function sealAll(drafts, report, port, labels, deps) {
  return new Promise((resolve, reject) => {
    const total = drafts.length;
    /** @type {(Sealed | null)[]} */
    const results = new Array(total).fill(null);
    /** @type {Map<number, { index: number, draft: import("../import/map.mjs").ItemDraft, itemId: Uint8Array, retried: boolean }>} */
    const pending = new Map();
    let next = 0;
    let settled = 0;
    let requestId = 1;
    let over = false;

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
      // The drafts are plain text of the file: let go of them as early as this can.
      drafts.length = 0;
      if (error) reject(error);
      else resolve(/** @type {Sealed[]} */ (results.filter((r) => r !== null)));
    };

    /**
     * @param {number} index
     * @param {import("../import/map.mjs").ItemDraft} draft
     * @param {Uint8Array} itemId
     * @param {boolean} retried
     */
    const send = (index, draft, itemId, retried) => {
      const id = requestId++;
      pending.set(id, { index, draft, itemId, retried });
      port.postMessage({ id, method: "encrypt_item", args: [itemId, 1, draft, NO_EXISTING, deps.now()] });
    };

    const pump = () => {
      while (!over && pending.size < IN_FLIGHT && next < total) {
        const index = next++;
        send(index, drafts[index], newItemId(deps.random), false);
      }
      if (!over && settled === total) finish(null);
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
      if (m.ok === true && value && value.envelope instanceof Uint8Array && value.tag instanceof Uint8Array && typeof value.rev === "number") {
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
        send(entry.index, fallback, entry.itemId, true);
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
  try {
    const { drafts, report, kind } = await readDrafts(request.kind, request.file, request.labels);
    const sealed = await sealAll(drafts, report, request.port, labels, { now, random });
    report.counts.sealed = sealed.length;
    return { sealed, report, kind };
  } finally {
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
