// SPDX-License-Identifier: GPL-3.0-only
// Modified by Faithful Ferret: written for Faithful Ferret from the export formats of Bitwarden. The
// formats (the names of the keys, the numbers of the item types, of the field types and of the address
// match rules, the columns of the CSV export and how a CSV cell holds the custom fields and addresses of
// an item) were read from the Bitwarden SDK (crates/bitwarden-exporters/src/json.rs and csv.rs,
// crates/bitwarden-vault/src/cipher/{login,cipher}.rs, GNU GPL v3) and from the Bitwarden clients
// (libs/importer/src/importers/bitwarden/bitwarden-csv-importer.ts and base-importer.ts, GNU GPL v3).
// The reader is bounded and strict, which those importers are not, and maps to Ferret's item drafts
// (see map.mjs). The reader is derived from those GPL v3 sources, so this file is GPL-3.0-only, as
// the entry for it in notices-extra.json and THIRD-PARTY-NOTICES says. The rest of Faithful Ferret
// is under the GNU Affero General Public License v3, which GPL v3 section 13 allows to be combined
// with it.
//
// Reads a Bitwarden export, either the unencrypted JSON of the web vault, the apps and the CLI, or the
// CSV, and returns item drafts and a report. It reads; it stores nothing and calls nothing.
//
// Not read: an encrypted export (`encrypted: true`, an account export, or `passwordProtected: true`, an
// export password): `import_encrypted_export`, Ferret has no way to open another product's
// cryptography. Counted and left out: passkeys, folders, collections, linked custom fields, keys that
// this reader does not know, and item types other than login, note, card and identity (SSH keys and
// the newer bank account, driver's licence and passport items).

import { ImportError, MAX_ITEMS } from "./limits.mjs";
import { cardDraft, createReport, identityDraft, loginDraft, noteDraft, resolveLabels, scalar, warn } from "./map.mjs";

/**
 * @typedef {import("./map.mjs").ImportReport} ImportReport
 * @typedef {import("./map.mjs").ItemDraft} ItemDraft
 * @typedef {{ labels?: unknown }} ReadOptions
 */

const KNOWN_TOP = new Set(["encrypted", "folders", "items", "collections"]);
const KNOWN_ITEM = new Set([
  "id", "folderId", "organizationId", "collectionIds", "name", "notes", "type", "login", "identity", "card",
  "secureNote", "sshKey", "favorite", "reprompt", "fields", "passwordHistory", "revisionDate", "creationDate", "deletedDate",
]);
const KNOWN_LOGIN = new Set(["username", "password", "uris", "totp", "fido2Credentials"]);
const KNOWN_URI = new Set(["uri", "match"]);
const KNOWN_FIELD = new Set(["name", "value", "type", "linkedId"]);
const KNOWN_CARD = new Set(["cardholderName", "expMonth", "expYear", "code", "brand", "number"]);
const KNOWN_IDENTITY = new Set([
  "title", "firstName", "middleName", "lastName", "address1", "address2", "address3", "city", "state",
  "postalCode", "country", "company", "email", "phone", "ssn", "username", "passportNumber", "licenseNumber",
]);

/** The item types that Ferret skips, by the number in the file. */
const SKIPPED_TYPES = new Map([
  [5, "type_ssh_key"],
  [6, "type_bank_account"],
  [7, "type_drivers_license"],
  [8, "type_passport"],
]);

/**
 * @param {unknown} value
 * @returns {Record<string, unknown> | null}
 */
function asObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? /** @type {Record<string, unknown>} */ (value) : null;
}

/**
 * @param {unknown} value
 * @returns {unknown[]}
 */
function asArray(value) {
  return Array.isArray(value) ? value : [];
}

/**
 * How many keys of `object` are not in `known`.
 * @param {Record<string, unknown> | null} object
 * @param {Set<string>} known
 */
function unknownKeys(object, known) {
  if (object === null) return 0;
  let count = 0;
  for (const key of Object.keys(object)) if (!known.has(key)) count++;
  return count;
}

/**
 * Reads an unencrypted Bitwarden JSON export.
 * @param {unknown} data the result of `safeJsonParse`
 * @param {ReadOptions} [options]
 * @returns {{ drafts: ItemDraft[], report: ImportReport }}
 * @throws {ImportError} `import_encrypted_export` for an encrypted export (account or password), `import_bad_format`
 *   for anything that is not an export, `import_empty` for an export with no items, `import_too_many`
 */
export function fromBitwardenJson(data, options = {}) {
  const root = asObject(data);
  if (root === null) throw new ImportError("import_bad_format");
  if (root.encrypted === true || root.passwordProtected === true) throw new ImportError("import_encrypted_export");
  if (!Array.isArray(root.items)) throw new ImportError("import_bad_format");
  if (root.items.length === 0) throw new ImportError("import_empty");
  if (root.items.length > MAX_ITEMS) throw new ImportError("import_too_many");

  const labels = resolveLabels(options.labels);
  const report = createReport();
  report.skipped.unknownKeys += unknownKeys(root, KNOWN_TOP);
  report.skipped.folders += asArray(root.folders).length;
  report.skipped.collections += asArray(root.collections).length;

  /** @type {ItemDraft[]} */
  const drafts = [];
  root.items.forEach((entry, index) => {
    const item = asObject(entry);
    if (item === null) throw new ImportError("import_bad_format");
    const context = { report, index, labels };
    const fields = asArray(item.fields).map(asObject).filter((f) => f !== null);

    if (item.deletedDate !== null && item.deletedDate !== undefined && item.deletedDate !== "") {
      report.skipped.trashed++;
      warn(report, "item_trashed", index);
      return;
    }
    const type = item.type;
    if (typeof type === "number" && SKIPPED_TYPES.has(type)) {
      report.skipped.otherTypes++;
      warn(report, /** @type {string} */ (SKIPPED_TYPES.get(type)), index);
      return;
    }
    if (type !== 1 && type !== 2 && type !== 3 && type !== 4) {
      report.skipped.otherTypes++;
      warn(report, "type_unknown", index);
      return;
    }
    // Only the items that are read count for what is left behind in them (an item that is skipped as
    // a whole is counted once, by its type).
    report.skipped.unknownKeys += unknownKeys(item, KNOWN_ITEM);
    for (const f of fields) report.skipped.unknownKeys += unknownKeys(f, KNOWN_FIELD);
    // Not imported, and said so in the report: the old passwords of an item, and the flag that asks
    // for the master password before the item is shown.
    report.skipped.passwordHistory += asArray(item.passwordHistory).length;
    if (item.reprompt === 1) report.skipped.reprompt++;
    const common = { name: item.name, notes: item.notes, favorite: item.favorite, fields };
    switch (type) {
      case 1: {
        const login = asObject(item.login) ?? Object.create(null);
        report.skipped.unknownKeys += unknownKeys(login, KNOWN_LOGIN);
        const passkeys = asArray(login.fido2Credentials).length;
        if (passkeys > 0) {
          report.skipped.passkeys += passkeys;
          warn(report, "passkey_skipped", index);
        }
        const uris = asArray(login.uris).map(asObject).filter((u) => u !== null);
        for (const u of uris) report.skipped.unknownKeys += unknownKeys(u, KNOWN_URI);
        drafts.push(loginDraft({ ...common, username: login.username, password: login.password, totp: login.totp, uris }, context));
        return;
      }
      case 2:
        drafts.push(noteDraft(common, context));
        return;
      case 3: {
        const card = asObject(item.card) ?? Object.create(null);
        report.skipped.unknownKeys += unknownKeys(card, KNOWN_CARD);
        drafts.push(cardDraft({ ...common, card }, context));
        return;
      }
      case 4: {
        const identity = asObject(item.identity) ?? Object.create(null);
        report.skipped.unknownKeys += unknownKeys(identity, KNOWN_IDENTITY);
        drafts.push(identityDraft({ ...common, identity }, context));
        return;
      }
    }
  });
  return { drafts, report };
}

/** The columns of a Bitwarden CSV export (and the short names an importer also takes). */
const CSV_COLUMNS = new Set([
  "folder", "favorite", "type", "name", "notes", "fields", "reprompt", "login_uri", "login_username",
  "login_password", "login_totp", "collections", "uri", "username", "password", "totp",
]);

/**
 * The text of a column of a row, the first of the names that has a value.
 * @param {Record<string, string>} row
 * @param {...string} names
 */
function cell(row, ...names) {
  for (const name of names) {
    const value = row[name];
    if (value !== undefined && value !== "") return value;
  }
  return "";
}

/**
 * Reads a Bitwarden CSV export: the rows of `parseCsv`, header first.
 * @param {string[][]} rows
 * @param {ReadOptions & { lines?: number[] }} [options] `lines` are the lines on which the rows start (as `parseCsv` gives them), for the error of a row that does not fit the header
 * @returns {{ drafts: ItemDraft[], report: ImportReport }}
 * @throws {ImportError} `import_bad_format` when the header has no `name` column, `import_bad_csv` (with the line) for a row
 *   with more cells than the header, `import_empty`, `import_too_many`
 */
export function fromBitwardenCsv(rows, options = {}) {
  if (!Array.isArray(rows) || rows.length === 0) throw new ImportError("import_empty");
  if (rows.length - 1 > MAX_ITEMS) throw new ImportError("import_too_many");
  const header = rows[0].map((h) => h.trim().toLowerCase());
  if (!header.includes("name")) throw new ImportError("import_bad_format");
  if (rows.length === 1) throw new ImportError("import_empty");
  const labels = resolveLabels(options.labels);
  const report = createReport();
  report.skipped.unknownKeys += header.filter((h) => h !== "" && !CSV_COLUMNS.has(h)).length;
  const folders = new Set();
  const collections = new Set();

  /** @type {ItemDraft[]} */
  const drafts = [];
  for (let r = 1; r < rows.length; r++) {
    const cells = rows[r];
    const index = r - 1;
    const line = options.lines?.[r] ?? r + 1;
    if (cells.length > header.length) throw new ImportError("import_bad_csv", { line });
    /** @type {Record<string, string>} */
    const row = Object.create(null);
    header.forEach((name, c) => {
      if (name !== "" && row[name] === undefined) row[name] = cells[c] ?? "";
    });
    const folder = scalar(row.folder).trim();
    if (folder !== "") folders.add(folder);
    for (const name of scalar(row.collections).split(",")) if (name.trim() !== "") collections.add(name.trim());

    const type = scalar(row.type).trim().toLowerCase();
    const context = { report, index, labels };
    const fields = [];
    for (const text of scalar(row.fields).split(/\r\n|\n|\r/)) {
      if (text.trim() === "") continue;
      const at = text.lastIndexOf(": ");
      if (at < 0) {
        warn(report, "field_unreadable", index);
        continue;
      }
      // The CSV does not say what kind a custom field is, so it is kept hidden (the user can show it).
      fields.push({ name: text.slice(0, at), value: text.slice(at + 2), type: 1 });
    }
    if (scalar(row.reprompt).trim() === "1" && (type === "note" || type === "login" || type === "")) report.skipped.reprompt++;
    const common = { name: row.name, notes: row.notes, favorite: cell(row, "favorite") !== "" && row.favorite !== "0", fields };
    if (type === "note") {
      drafts.push(noteDraft(common, context));
    } else if (type === "login" || type === "") {
      const uris = cell(row, "login_uri", "uri")
        .split(/\r\n|\n|\r|,/)
        .map((uri) => uri.trim())
        .filter((uri) => uri !== "")
        .map((uri) => ({ uri, match: null }));
      drafts.push(
        loginDraft(
          { ...common, username: cell(row, "login_username", "username"), password: cell(row, "login_password", "password"), totp: cell(row, "login_totp", "totp"), uris },
          context,
        ),
      );
    } else {
      report.skipped.otherTypes++;
      warn(report, "type_unknown", index);
    }
  }
  report.skipped.folders += folders.size;
  report.skipped.collections += collections.size;
  return { drafts, report };
}
