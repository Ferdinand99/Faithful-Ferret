// SPDX-License-Identifier: AGPL-3.0-only
// Modified by Faithful Ferret: this reader is adapted from the readers of the export formats of AliasVault
// (https://github.com/aliasvault/aliasvault, commit 7e7cd6f3141c94f884ddd1666987aec3ffcdcdf3, GNU Affero
// General Public License v3), in core/client/src/transfer/: export/AvuxManifest.ts (the shape of the manifest
// of an .avux file), export/AliasVaultCsvExportService.ts (the columns of the CSV file),
// import/importers/aliasvault/{AvuxManifestReader,AvuxImportService,AliasVaultCsvImportService}.ts (how the
// property names are matched, which system field keys there are, how the fields of an item are read) and
// ../models/src/vault/FieldKey.ts (the system field keys). Kept: the names of the keys and columns, matching
// the names of the manifest without regard to case, the one version of the manifest that is read ("1.0.0"),
// reading the address column as a list split at commas, and the otpauth address that a code of an item is
// made into. Changed: the reader is bounded and strict (a value of the wrong type refuses the file), it reads
// plain values and returns Faithful Ferret's item drafts and a report (see map.mjs) instead of AliasVault's
// own item rows, and everything that is not text of an item (attachments, logos, passkeys, folders, tags,
// the earlier values of a field) is counted and left out.
//
// Reads an AliasVault export: the manifest of an unencrypted `.avux` file (a ZIP file; the worker unpacks
// `manifest.json` with zip.mjs and nothing else of it) or the CSV file. It reads; it stores nothing and
// calls nothing. The encrypted `.avex` is not read: Ferret has no way to open another product's
// cryptography (`import_encrypted_export`; the page tells the user to export as `.avux` or CSV).
//
// Nothing here ever widens what the file says. An address has no match rule in an AliasVault export, so it
// is matched on its exact host (`host`), the narrowest rule an address gets besides `exact`, and the report
// counts those (`counts.matchNull`); an address with another scheme than http or https goes to a text field
// (map.mjs), never to `urls`.

import { ImportError, MAX_ITEMS } from "./limits.mjs";
import { addAddresses, addCustomFields, addField, addTotp, createReport, resolveLabels, scalar, startDraft, warn } from "./map.mjs";

/**
 * @typedef {import("./map.mjs").ImportReport} ImportReport
 * @typedef {import("./map.mjs").ItemDraft} ItemDraft
 * @typedef {{ labels?: unknown }} ReadOptions
 */

/** The one version of the `.avux` manifest that is read. */
export const AVUX_VERSION = "1.0.0";

/** The name of the entry of an `.avux` file that holds everything that is read. */
export const AVUX_MANIFEST_ENTRY = "manifest.json";

/** The system field keys of AliasVault (FieldKey.ts), by the key of the value they fill in {@link blankValues}. */
const SYSTEM_KEYS = Object.freeze({
  "login.username": "username",
  "login.password": "password",
  "login.email": "email",
  "login.url": "urls",
  "notes.content": "notes",
  "alias.first_name": "firstName",
  "alias.last_name": "lastName",
  "alias.gender": "gender",
  "alias.birthdate": "birthdate",
  "card.number": "cardNumber",
  "card.cardholder_name": "cardholder",
  "card.expiry_month": "expMonth",
  "card.expiry_year": "expYear",
  "card.cvv": "cvv",
  "card.pin": "pin",
});

const KNOWN_TOP = new Set(["version", "exportedat", "exportedby", "items", "folders", "tags", "itemtags", "fielddefinitions", "logos"]);
const KNOWN_ITEM = new Set([
  "id", "name", "itemtype", "createdat", "updatedat", "folderid", "logoid", "archivedat",
  "fieldvalues", "fieldhistories", "attachments", "totpcodes", "passkeys",
]);

/**
 * The values of one item, before they are made into a draft. Both formats are read into this.
 * @typedef {{
 *   name: unknown, type: "login" | "note" | "card",
 *   username: string[], password: string[], email: string[], urls: string[], notes: string[],
 *   firstName: string[], lastName: string[], nickname: string[], gender: string[], birthdate: string[],
 *   cardNumber: string[], cardholder: string[], expMonth: string[], expYear: string[], cvv: string[], pin: string[],
 *   totps: unknown[], custom: { name: string, value: string, kind: string }[],
 * }} Values
 */

/** An empty set of values. @param {unknown} name @param {"login" | "note" | "card"} type @returns {Values} */
function blankValues(name, type) {
  return {
    name, type,
    username: [], password: [], email: [], urls: [], notes: [],
    firstName: [], lastName: [], nickname: [], gender: [], birthdate: [],
    cardNumber: [], cardholder: [], expMonth: [], expYear: [], cvv: [], pin: [],
    totps: [], custom: [],
  };
}

/**
 * The members of an object under their names in lower case (the names of a manifest are matched without
 * regard to case, as AliasVault does; the first of two members that differ only in case wins).
 * @param {unknown} value
 * @returns {Record<string, unknown> | null} an object without a prototype, or null when `value` is no plain object
 */
function members(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  /** @type {Record<string, unknown>} */
  const out = Object.create(null);
  for (const key of Object.keys(value)) {
    const lower = key.toLowerCase();
    if (!(lower in out)) out[lower] = /** @type {Record<string, unknown>} */ (value)[key];
  }
  return out;
}

const bad = () => new ImportError("import_bad_format");

/**
 * A member that is text or absent.
 * @param {Record<string, unknown>} object
 * @param {string} name
 * @returns {string | null}
 */
function text(object, name) {
  const value = object[name];
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") throw bad();
  return value;
}

/**
 * A member that is a number or absent.
 * @param {Record<string, unknown>} object
 * @param {string} name
 * @returns {number | null}
 */
function number(object, name) {
  const value = object[name];
  if (value === undefined || value === null) return null;
  if (typeof value !== "number" || !Number.isFinite(value)) throw bad();
  return value;
}

/**
 * A member that is a list of objects, or absent.
 * @param {Record<string, unknown>} object
 * @param {string} name
 * @returns {Record<string, unknown>[]}
 */
function objects(object, name) {
  const value = object[name];
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw bad();
  return value.map((entry) => {
    const one = members(entry);
    if (one === null) throw bad();
    return one;
  });
}

/**
 * How many members of `object` (names in lower case) are not in `known`.
 * @param {Record<string, unknown>} object
 * @param {Set<string>} known
 */
function unknownCount(object, known) {
  let n = 0;
  for (const key of Object.keys(object)) if (!known.has(key)) n++;
  return n;
}

/**
 * The list sorted by weight (a stable sort: values of the same weight stay in the order of the file).
 * @template {{ weight: number }} T
 * @param {T[]} list
 * @returns {T[]}
 */
function byWeight(list) {
  return [...list].sort((a, b) => a.weight - b.weight);
}

/**
 * The otpauth address of a code of an item (AliasVault's `formatTotpUri`): the name is the label, or
 * `issuer:label`; the algorithm, the digits and the period are what AliasVault would use (an unknown one is the
 * default). A secret that is not base32 is not made into an address; the caller keeps it as it was.
 * @param {{ name: string, secret: string, algorithm: string | null, digits: number | null, period: number | null }} code
 * @returns {string | null} the address, or null when the secret is no base32 text
 */
export function totpAddress({ name, secret, algorithm, digits, period }) {
  const seed = secret.replace(/\s+/g, "");
  if (!/^[A-Za-z2-7]+=*$/.test(seed) || seed.length > 1024) return null;
  const trimmed = name.trim();
  const colon = trimmed.indexOf(":");
  const issuer = colon > 0 ? trimmed.slice(0, colon).trim() : "";
  const label = issuer !== "" ? trimmed.slice(colon + 1).trim() : trimmed;
  const algo = (algorithm ?? "").trim().toUpperCase().replace(/[-_\s]/g, "");
  const params = [`secret=${seed}`];
  if (issuer !== "") params.push(`issuer=${encodeURIComponent(issuer)}`);
  params.push(`algorithm=${algo === "SHA256" || algo === "SHA512" ? algo : "SHA1"}`);
  params.push(`digits=${digits === 7 || digits === 8 ? digits : 6}`);
  params.push(`period=${Number.isInteger(period) && /** @type {number} */ (period) > 0 && /** @type {number} */ (period) <= 300 ? period : 30}`);
  return `otpauth://totp/${encodeURIComponent(label)}?${params.join("&")}`;
}

/**
 * Makes the draft of one item from its values.
 * @param {Values} v
 * @param {{ report: ImportReport, index: number, labels: Readonly<Record<string, string>> }} context
 * @returns {ItemDraft}
 */
function draftOf(v, context) {
  const { report, index, labels } = context;
  const notes = v.notes.filter((n) => n.trim() !== "").join("\n\n");
  const draft = startDraft(v.type, v.name, notes, false, labels);

  /**
   * A field with one value, or with several (the others get `id-2`, `id-3`, ... so that none is lost).
   * @param {string} id @param {string} label @param {string} kind @param {string[]} values
   */
  const put = (id, label, kind, values) => {
    values.filter((value) => value !== "").forEach((value, n) => addField(draft, n === 0 ? id : `${id}-${n + 1}`, label, kind, value));
  };
  put("username", labels.username, "text", v.username);
  put("password", labels.password, "password", v.password);
  put("email", labels.email, "email", v.email);
  if (v.email.some((value) => value !== "")) warn(report, "alias_needs_aliasvault", index);
  put("first_name", labels.first_name, "text", v.firstName);
  put("last_name", labels.last_name, "text", v.lastName);
  put("nickname", labels.nickname, "text", v.nickname);
  put("gender", labels.gender, "text", v.gender);
  put("birthdate", labels.birthdate, "text", v.birthdate);
  put("cardholder_name", labels.cardholder_name, "text", v.cardholder);
  put("number", labels.number, "hidden", v.cardNumber);
  put("exp_month", labels.exp_month, "text", v.expMonth);
  put("exp_year", labels.exp_year, "text", v.expYear);
  put("code", labels.code, "hidden", v.cvv);
  put("pin", labels.pin, "hidden", v.pin);

  addAddresses(draft, v.urls.map((uri) => ({ uri, match: null })), context);

  // An item has one code; the others are kept as hidden fields with the address as it would have been.
  v.totps.forEach((code, n) => {
    if (n === 0) {
      addTotp(draft, code, context);
      return;
    }
    warn(report, "totp_extra", index);
    const value = scalar(code);
    if (value !== "") (draft.fields ??= []).push({ id: `totp-${n + 1}`, label: labels.totp, kind: "hidden", value });
  });

  addCustomFields(draft, v.custom, context);
  report.counts.items++;
  report.counts[v.type]++;
  return draft;
}

// ------------------------------------------------------------------------------------------------ .avux

/**
 * Reads the manifest of an unencrypted `.avux` file.
 * @param {unknown} data the parsed `manifest.json` (the result of `safeJsonParse`)
 * @param {ReadOptions} [options]
 * @returns {{ drafts: ItemDraft[], report: ImportReport }}
 * @throws {ImportError} `import_bad_format` for anything that is not a manifest of version 1.0.0 or has a value of the wrong
 *   type, `import_empty`, `import_too_many`
 */
export function fromAvuxManifest(data, options = {}) {
  const root = members(data);
  if (root === null) throw bad();
  const version = text(root, "version") ?? AVUX_VERSION;
  if (version !== AVUX_VERSION) throw bad();
  if (!Array.isArray(root.items)) throw bad();
  if (root.items.length === 0) throw new ImportError("import_empty");
  if (root.items.length > MAX_ITEMS) throw new ImportError("import_too_many");

  const labels = resolveLabels(options.labels);
  const report = createReport();
  report.skipped.unknownKeys += unknownCount(root, KNOWN_TOP);
  report.skipped.folders += objects(root, "folders").length;
  report.skipped.tags += objects(root, "tags").length;

  /** The definitions of custom fields by id. @type {Map<string, { label: string, kind: string, hidden: boolean, section: boolean }>} */
  const definitions = new Map();
  for (const definition of objects(root, "fielddefinitions")) {
    const id = text(definition, "id") ?? "";
    const type = (text(definition, "fieldtype") ?? "Text").toLowerCase();
    const hidden = definition.ishidden === true || type === "hidden" || type === "password";
    /** @type {string} */
    let kind = "text";
    if (hidden) kind = type === "password" ? "password" : "hidden";
    else if (type === "email") kind = "email";
    else if (type === "phone") kind = "phone";
    definitions.set(id, { label: text(definition, "label") ?? "", kind, hidden, section: type === "section" });
  }

  /** @type {ItemDraft[]} */
  const drafts = [];
  root.items.forEach((entry, index) => {
    const item = members(entry);
    if (item === null) throw bad();
    const itemType = (text(item, "itemtype") ?? "").toLowerCase();
    /** @type {"login" | "note" | "card" | null} */
    let type = null;
    if (itemType === "login" || itemType === "alias") type = "login";
    else if (itemType === "note") type = "note";
    else if (itemType === "creditcard") type = "card";
    if (type === null) {
      report.skipped.otherTypes++;
      warn(report, "type_unknown", index);
      return;
    }
    const v = blankValues(text(item, "name"), type);
    report.skipped.unknownKeys += unknownCount(item, KNOWN_ITEM);
    if (text(item, "archivedat") !== null) warn(report, "item_archived", index);

    const values = byWeight(objects(item, "fieldvalues").map((f) => ({
      key: text(f, "fieldkey") ?? "", definition: text(f, "fielddefinitionid") ?? "", value: text(f, "value") ?? "", weight: number(f, "weight") ?? 0,
    })));
    for (const { key, definition, value } of values) {
      if (key === "") {
        const known = definitions.get(definition);
        if (known === undefined) {
          report.skipped.unknownKeys++;
          continue;
        }
        if (known.section || value === "") continue;
        v.custom.push({ name: known.label, value, kind: known.kind });
        continue;
      }
      const slot = Object.hasOwn(SYSTEM_KEYS, key) ? SYSTEM_KEYS[/** @type {keyof typeof SYSTEM_KEYS} */ (key)] : null;
      if (slot === null) {
        report.skipped.unknownKeys++;
        continue;
      }
      if (value !== "") /** @type {string[]} */ (v[slot]).push(scalar(value));
    }

    for (const code of objects(item, "totpcodes")) {
      const secret = text(code, "secretkey") ?? "";
      if (secret.trim() === "") continue;
      const address = totpAddress({
        name: text(code, "name") ?? "", secret, algorithm: text(code, "algorithm"), digits: number(code, "digits"), period: number(code, "period"),
      });
      // A secret that is no base32 text is handed on as it is: `mapTotp` keeps it as a hidden field with a warning.
      v.totps.push(address ?? secret);
    }

    const passkeys = objects(item, "passkeys").length;
    if (passkeys > 0) {
      report.skipped.passkeys += passkeys;
      warn(report, "passkey_skipped", index);
    }
    report.skipped.attachments += objects(item, "attachments").length;
    report.skipped.fieldHistory += objects(item, "fieldhistories").length;
    drafts.push(draftOf(v, { report, index, labels }));
  });
  return { drafts, report };
}

// -------------------------------------------------------------------------------------------------- CSV

/** The columns of the CSV file (AliasVaultCsvExportService.ts) and of the older one of the mobile app, in lower case. */
const CSV_COLUMNS = new Set([
  "servicename", "folderpath", "serviceurl", "username", "currentpassword", "aliasemail", "twofactorsecret", "aliasgender",
  "aliasfirstname", "aliaslastname", "aliasnickname", "aliasbirthdate", "cardholdername", "cardnumber", "cardexpirymonth",
  "cardexpiryyear", "cardcvv", "cardpin", "notes", "createdat", "updatedat",
]);

/**
 * Whether the header row of a CSV file is that of an AliasVault export: it has the `ServiceName` column.
 * @param {string[] | undefined} header
 */
export function isAliasVaultCsvHeader(header) {
  return Array.isArray(header) && header.some((h) => h.trim().toLowerCase() === "servicename");
}

/**
 * A birth date as the CSV writes it (`MM/DD/YYYY HH:mm:ss`) is kept as `YYYY-MM-DD`, as the manifest writes it; text
 * of any other shape is kept as it is.
 * @param {string} value
 */
function birthdateOf(value) {
  const match = /^(\d{2})\/(\d{2})\/(\d{4})(?: \d{2}:\d{2}:\d{2})?$/.exec(value.trim());
  if (match === null) return value;
  const [, month, day, year] = match;
  return Number(month) >= 1 && Number(month) <= 12 && Number(day) >= 1 && Number(day) <= 31 ? `${year}-${month}-${day}` : value;
}

/**
 * Reads an AliasVault CSV export: the rows of `parseCsv`, header first.
 * @param {string[][]} rows
 * @param {ReadOptions & { lines?: number[] }} [options] `lines` are the lines on which the rows start (as `parseCsv` gives them)
 * @returns {{ drafts: ItemDraft[], report: ImportReport }}
 * @throws {ImportError} `import_bad_format` when the header has no `ServiceName` column, `import_bad_csv` (with the line) for a row
 *   with more cells than the header, `import_empty`, `import_too_many`
 */
export function fromAliasVaultCsv(rows, options = {}) {
  if (!Array.isArray(rows) || rows.length === 0) throw new ImportError("import_empty");
  if (rows.length - 1 > MAX_ITEMS) throw new ImportError("import_too_many");
  if (!isAliasVaultCsvHeader(rows[0])) throw bad();
  if (rows.length === 1) throw new ImportError("import_empty");
  const header = rows[0].map((h) => h.trim().toLowerCase());
  const labels = resolveLabels(options.labels);
  const report = createReport();
  report.skipped.unknownKeys += header.filter((h) => h !== "" && !CSV_COLUMNS.has(h)).length;
  const folders = new Set();

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
      if (name !== "" && row[name] === undefined) row[name] = scalar(cells[c] ?? "");
    });
    const cell = (/** @type {string} */ name) => row[name] ?? "";
    const folder = cell("folderpath").trim();
    if (folder !== "") folders.add(folder);

    const login = ["username", "currentpassword", "serviceurl", "twofactorsecret", "aliasemail"].some((name) => cell(name).trim() !== "");
    const alias = ["aliasgender", "aliasfirstname", "aliaslastname", "aliasnickname", "aliasbirthdate"].some((name) => cell(name).trim() !== "");
    const card = ["cardholdername", "cardnumber", "cardexpirymonth", "cardexpiryyear", "cardcvv", "cardpin"].some((name) => cell(name).trim() !== "");
    /** @type {"login" | "note" | "card"} */
    let type = "login";
    // A row with nothing but a name and notes was a secure note; a row of a card has no login in it. A row that has both
    // keeps all of it as a login, with the card fields in it.
    if (card && !login && !alias) type = "card";
    else if (!card && !login && !alias && cell("notes").trim() !== "") type = "note";
    if (card && (login || alias)) warn(report, "card_and_login", index);

    const v = blankValues(cell("servicename"), type);
    v.username.push(cell("username"));
    v.password.push(cell("currentpassword"));
    v.email.push(cell("aliasemail").trim());
    v.urls.push(...cell("serviceurl").split(/\r\n|\n|\r|,/).map((u) => u.trim()).filter((u) => u !== ""));
    v.notes.push(cell("notes"));
    v.firstName.push(cell("aliasfirstname"));
    v.lastName.push(cell("aliaslastname"));
    v.nickname.push(cell("aliasnickname"));
    v.gender.push(cell("aliasgender"));
    v.birthdate.push(birthdateOf(cell("aliasbirthdate")));
    v.cardholder.push(cell("cardholdername"));
    v.cardNumber.push(cell("cardnumber"));
    v.expMonth.push(cell("cardexpirymonth"));
    v.expYear.push(cell("cardexpiryyear"));
    v.cvv.push(cell("cardcvv"));
    v.pin.push(cell("cardpin"));
    if (cell("twofactorsecret").trim() !== "") v.totps.push(cell("twofactorsecret"));
    drafts.push(draftOf(v, { report, index, labels }));
  }
  report.skipped.folders += folders.size;
  return { drafts, report };
}
