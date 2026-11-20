// What an import makes of the data of another password manager: item drafts for the vault, and
// the report the import view shows before anything is sent (Spec: Fase 1 § 5.2, the item body).
//
// The functions here take plain values from a reader (`bitwarden.mjs`) and return drafts in the shape
// that `Vault.encrypt_item` takes (`item_type`, `name`, `favorite`, `fields`, `urls`, `totp`, `notes`).
// The rules that keep an import safe live here, once, for every format:
//
// * An address with the scheme `http` or `https` goes to `urls`. One without a scheme gets `https://`
//   and a warning. An address with any other scheme (`androidapp://`, a script scheme, `data:`, `file:`
//   and the rest), and one that has whitespace or control characters in it, goes to a text field and
//   never to `urls`, so it can never be matched against a page.
// * A match rule never gets wider: `host` stays `host`, `exact` stays `exact`, `domain` stays
//   `domain`, no rule is `host`, `startsWith` becomes `exact` with a warning, and `never` or a
//   regular expression puts the address in a text field (a regular expression is no address).
// * A one-time password is read as `otpauth://totp/`; a bare base32 secret becomes
//   `otpauth://totp/?secret=...`; `steam://` and everything that does not read go to a hidden field
//   with a warning. The core's strict parser has the last word when the item is sealed.
// * Nothing of the file but counts and a position leaves the report: a warning is a code and the
//   index of the item in the file.

/** The most warnings one report keeps; the rest are counted in `report.warningsDropped`. */
export const MAX_WARNINGS = 20_000;

/** The text of the labels the drafts carry. The page may pass its own, in its language. */
export const DEFAULT_LABELS = Object.freeze({
  username: "User name",
  password: "Password",
  totp: "One-time password",
  address: "Address",
  field: "Field",
  untitled: "(no name)",
  cardholder_name: "Cardholder name",
  brand: "Brand",
  number: "Card number",
  exp_month: "Expiry month",
  exp_year: "Expiry year",
  code: "Security code",
  title: "Title",
  first_name: "First name",
  middle_name: "Middle name",
  last_name: "Last name",
  address1: "Address 1",
  address2: "Address 2",
  address3: "Address 3",
  city: "City",
  state: "State",
  postal_code: "Postal code",
  country: "Country",
  company: "Company",
  email: "E-mail",
  phone: "Phone",
  ssn: "National ID",
  identity_username: "User name",
  passport_number: "Passport number",
  license_number: "Licence number",
});

/** The longest label a page may pass, in UTF-16 units. */
const MAX_LABEL_LENGTH = 128;

/**
 * The labels of an import: the defaults with those of `custom` that are text of a sane length.
 * An unknown key, or a value that is not text, is ignored.
 * @param {unknown} custom
 * @returns {Readonly<Record<keyof typeof DEFAULT_LABELS, string>>}
 */
export function resolveLabels(custom) {
  const labels = { ...DEFAULT_LABELS };
  if (custom !== null && typeof custom === "object" && !Array.isArray(custom)) {
    for (const key of Object.keys(labels)) {
      if (!Object.hasOwn(custom, key)) continue;
      const value = /** @type {Record<string, unknown>} */ (custom)[key];
      if (typeof value === "string" && value.trim() !== "" && value.length <= MAX_LABEL_LENGTH) {
        /** @type {Record<string, string>} */ (labels)[key] = wellFormed(value);
      }
    }
  }
  return Object.freeze(labels);
}

/**
 * @typedef {{
 *   counts: {
 *     items: number, login: number, note: number, card: number, identity: number,
 *     urls: number, totp: number, customFields: number,
 *     matchNull: number, http: number, textAddresses: number, sealed: number,
 *   },
 *   skipped: {
 *     passkeys: number, folders: number, collections: number, linked: number,
 *     unknownKeys: number, otherTypes: number, trashed: number, tooLarge: number,
 *     passwordHistory: number, reprompt: number,
 *   },
 *   warnings: { code: string, index: number }[],
 *   warningsDropped: number,
 * }} ImportReport
 */

/**
 * An empty report.
 * @returns {ImportReport}
 */
export function createReport() {
  return {
    counts: { items: 0, login: 0, note: 0, card: 0, identity: 0, urls: 0, totp: 0, customFields: 0, matchNull: 0, http: 0, textAddresses: 0, sealed: 0 },
    skipped: { passkeys: 0, folders: 0, collections: 0, linked: 0, unknownKeys: 0, otherTypes: 0, trashed: 0, tooLarge: 0, passwordHistory: 0, reprompt: 0 },
    warnings: [],
    warningsDropped: 0,
  };
}

/**
 * Adds a warning for the item at `index` (its position in the file, from 0).
 * @param {ImportReport} report
 * @param {string} code
 * @param {number} index
 */
export function warn(report, code, index) {
  if (report.warnings.length >= MAX_WARNINGS) {
    report.warningsDropped++;
    return;
  }
  report.warnings.push({ code, index });
}

/**
 * A text with no lone surrogate (the vault refuses one) from any scalar of a file; anything that
 * is not a string, number or boolean is the empty text.
 * @param {unknown} value
 * @returns {string}
 */
export function scalar(value) {
  if (typeof value === "string") return wellFormed(value);
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  if (typeof value === "boolean") return String(value);
  return "";
}

/**
 * @param {string} text
 * @returns {string}
 */
export function wellFormed(text) {
  const modern = /** @type {{ toWellFormed?: () => string }} */ (/** @type {unknown} */ (text));
  if (typeof modern.toWellFormed === "function") return modern.toWellFormed();
  return text.replace(/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g, "\ufffd");
}

/**
 * @typedef {{ id: string, label: string, kind: string, value: string }} FieldDraft
 * @typedef {{ url: string, matching: string }} UrlDraft
 * @typedef {{
 *   item_type: string, name: string, favorite: boolean,
 *   fields?: FieldDraft[], urls?: UrlDraft[], totp?: { uri: string }, notes?: string,
 * }} ItemDraft
 */

/** The start of the address that a bare base32 secret is made into. */
const BARE_SECRET_PREFIX = "otpauth://totp/?secret=";

/**
 * How the one-time password of an item is kept.
 * @param {unknown} raw the text from the file
 * @returns {{ uri?: string, hidden?: string, warning?: string }} `uri` for the item's `totp`, or `hidden` for a
 *   hidden field with the text as it was, and a warning code if the text is not a plain one-time password
 */
export function mapTotp(raw) {
  const text = scalar(raw).trim();
  if (text === "") return {};
  if (/^steam:\/\//i.test(text)) return { hidden: text, warning: "totp_steam" };
  if (/^otpauth:\/\//i.test(text)) {
    return /^otpauth:\/\/totp\//i.test(text) && text.length <= 2048 ? { uri: text } : { hidden: text, warning: "totp_invalid" };
  }
  const secret = text.replace(/\s+/g, "");
  if (/^[A-Za-z2-7]+=*$/.test(secret) && secret.length <= 1024) return { uri: BARE_SECRET_PREFIX + secret };
  return { hidden: text, warning: "totp_invalid" };
}

/**
 * The draft of an item whose one-time password the core did not accept: the address moves to a
 * hidden field as it was in the file (a bare secret without its white space), and the draft has no
 * `totp` any more. The vault's parser is stricter than a first look, so this is how an item survives
 * it. Returns `null` when the draft has no `totp`.
 * @param {ItemDraft} draft
 * @param {string} label the label of the hidden field
 * @returns {ItemDraft | null}
 */
export function withTotpAsHidden(draft, label) {
  if (!draft.totp) return null;
  const { totp, ...rest } = draft;
  const uri = totp.uri;
  const value = uri.startsWith(BARE_SECRET_PREFIX) && !uri.includes("&") ? uri.slice(BARE_SECRET_PREFIX.length) : uri;
  return { ...rest, fields: [...(draft.fields ?? []), { id: "totp", label, kind: "hidden", value }] };
}

/**
 * Splits a Bitwarden match number into a Ferret rule.
 * @param {unknown} match the `match` of an address (null when the file has none)
 * @returns {{ matching: string, warning?: string, never?: boolean, text?: boolean, defaulted?: boolean }}
 */
export function mapMatch(match) {
  if (match === null || match === undefined) return { matching: "host", defaulted: true };
  switch (match) {
    case 0:
      return { matching: "domain" };
    case 1:
      return { matching: "host" };
    case 3:
      return { matching: "exact" };
    case 2:
      return { matching: "exact", warning: "match_starts_with" };
    case 4:
      // A regular expression is not an address: it is kept as text and never matched.
      return { matching: "exact", warning: "match_regex", text: true };
    case 5:
      return { matching: "host", never: true, warning: "match_never" };
    default:
      return { matching: "exact", warning: "match_unknown" };
  }
}

/** Whitespace or a control character anywhere in an address. */
const UNCLEAN = /[\s\u0000-\u001f\u007f]/;

/**
 * Where an address goes.
 * @param {string} address trimmed, not empty
 * @returns {{ kind: "web", url: string, https: boolean, http: boolean } | { kind: "text" }}
 */
export function classifyAddress(address) {
  if (UNCLEAN.test(address) || address.length > 8 * 1024) return { kind: "text" };
  const schemeEnd = address.indexOf("://");
  const scheme = schemeEnd > 0 && /^[A-Za-z][A-Za-z0-9+.-]*$/.test(address.slice(0, schemeEnd)) ? address.slice(0, schemeEnd).toLowerCase() : null;
  if (scheme === "http" || scheme === "https") {
    // The rest must be an address and not an empty host.
    return address.length > schemeEnd + 3 ? { kind: "web", url: address, https: false, http: scheme === "http" } : { kind: "text" };
  }
  if (scheme !== null) return { kind: "text" };
  // No "://". A scheme such as `data:`, `mailto:` or `tel:` has no slashes; a host with a port
  // (`localhost:8080/x`) looks like one but is followed by digits.
  if (/^[^\s:/?#]+:\d+(?:[/?#]|$)/.test(address)) return { kind: "web", url: `https://${address}`, https: true, http: false };
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(address)) return { kind: "text" };
  if (address.startsWith("//") || address.startsWith("/")) return { kind: "text" };
  return { kind: "web", url: `https://${address}`, https: true, http: false };
}

/**
 * A mutable place where the parts of one draft are put together.
 * @param {string} type
 * @param {unknown} name
 * @param {unknown} notes
 * @param {unknown} favorite
 * @param {Readonly<Record<string, string>>} labels
 */
function startDraft(type, name, notes, favorite, labels) {
  /** @type {ItemDraft} */
  const draft = {
    item_type: type,
    name: scalar(name) === "" ? labels.untitled : scalar(name),
    favorite: favorite === true || favorite === 1 || favorite === "1" || favorite === "true",
  };
  const text = scalar(notes);
  if (text !== "") draft.notes = text;
  return draft;
}

/**
 * @param {ItemDraft} draft
 * @param {string} id
 * @param {string} label
 * @param {string} kind
 * @param {unknown} value
 */
function addField(draft, id, label, kind, value) {
  const text = scalar(value);
  if (text === "") return;
  (draft.fields ??= []).push({ id, label, kind, value: text });
}

/**
 * Puts addresses into a draft.
 * @param {ItemDraft} draft
 * @param {{ uri?: unknown, match?: unknown }[]} uris
 * @param {{ report: ImportReport, index: number, labels: Readonly<Record<string, string>> }} context
 */
function addAddresses(draft, uris, { report, index, labels }) {
  let textCount = 0;
  const toText = (/** @type {string} */ value) => {
    textCount++;
    report.counts.textAddresses++;
    addField(draft, `address-${textCount}`, labels.address, "text", value);
  };
  for (const entry of uris) {
    const address = typeof entry?.uri === "string" ? wellFormed(entry.uri).trim() : "";
    if (address === "") continue;
    const rule = mapMatch(entry.match);
    if (rule.text) {
      // A rule that is not an address (a regular expression): the text of the file, as it was.
      warn(report, rule.warning ?? "match_regex", index);
      toText(address);
      continue;
    }
    const where = classifyAddress(address);
    if (where.kind === "text") {
      toText(address);
      continue;
    }
    if (rule.never) {
      // The user turned matching off for this address: it must not match now either.
      warn(report, "match_never", index);
      toText(where.url);
      continue;
    }
    if (where.https) warn(report, "uri_https_added", index);
    if (rule.warning) warn(report, rule.warning, index);
    if (rule.defaulted) report.counts.matchNull++;
    if (where.http) report.counts.http++;
    (draft.urls ??= []).push({ url: where.url, matching: rule.matching });
    report.counts.urls++;
  }
}

/**
 * Puts the custom fields of an item into a draft.
 * @param {ItemDraft} draft
 * @param {{ name?: unknown, value?: unknown, type?: unknown }[]} fields
 * @param {{ report: ImportReport, index: number, labels: Readonly<Record<string, string>> }} context
 */
function addCustomFields(draft, fields, { report, index, labels }) {
  let n = 0;
  for (const field of fields) {
    // A linked field points at another field of the item and holds no value of its own.
    if (field?.type === 3) {
      report.skipped.linked++;
      warn(report, "linked_field_skipped", index);
      continue;
    }
    n++;
    /** @type {string} */
    let kind = "text";
    if (field?.type === 1) kind = "hidden";
    else if (field?.type !== 0 && field?.type !== 2 && field?.type !== undefined && field?.type !== null) {
      // A kind this reader does not know: kept hidden, because a secret is likelier than not.
      kind = "hidden";
      warn(report, "field_type_unknown", index);
    }
    const name = scalar(field?.name);
    (draft.fields ??= []).push({
      id: `custom-${n}`,
      label: name === "" ? labels.field : name,
      kind,
      value: scalar(field?.value),
    });
    report.counts.customFields++;
  }
}

/**
 * Puts the one-time password of an item into a draft.
 * @param {ItemDraft} draft
 * @param {unknown} raw
 * @param {{ report: ImportReport, index: number, labels: Readonly<Record<string, string>> }} context
 */
function addTotp(draft, raw, { report, index, labels }) {
  const mapped = mapTotp(raw);
  if (mapped.warning) warn(report, mapped.warning, index);
  if (mapped.uri !== undefined) {
    draft.totp = { uri: mapped.uri };
    report.counts.totp++;
  } else if (mapped.hidden !== undefined) {
    (draft.fields ??= []).push({ id: "totp", label: labels.totp, kind: "hidden", value: mapped.hidden });
  }
}

/**
 * @typedef {{ report: ImportReport, index: number, labels: Readonly<Record<string, string>> }} MapContext
 */

/**
 * A login.
 * @param {{
 *   name?: unknown, notes?: unknown, favorite?: unknown, username?: unknown, password?: unknown, totp?: unknown,
 *   uris?: { uri?: unknown, match?: unknown }[], fields?: { name?: unknown, value?: unknown, type?: unknown }[],
 * }} item
 * @param {MapContext} context
 * @returns {ItemDraft}
 */
export function loginDraft(item, context) {
  const { labels, report } = context;
  const draft = startDraft("login", item.name, item.notes, item.favorite, labels);
  addField(draft, "username", labels.username, "text", item.username);
  addField(draft, "password", labels.password, "password", item.password);
  addAddresses(draft, item.uris ?? [], context);
  addTotp(draft, item.totp, context);
  addCustomFields(draft, item.fields ?? [], context);
  report.counts.items++;
  report.counts.login++;
  return draft;
}

/**
 * A secure note.
 * @param {{ name?: unknown, notes?: unknown, favorite?: unknown, fields?: { name?: unknown, value?: unknown, type?: unknown }[] }} item
 * @param {MapContext} context
 * @returns {ItemDraft}
 */
export function noteDraft(item, context) {
  const draft = startDraft("note", item.name, item.notes, item.favorite, context.labels);
  addCustomFields(draft, item.fields ?? [], context);
  context.report.counts.items++;
  context.report.counts.note++;
  return draft;
}

/** The card fields: key in the file, id and label key of the draft, kind. */
const CARD_FIELDS = /** @type {const} */ ([
  ["cardholderName", "cardholder_name", "text"],
  ["brand", "brand", "text"],
  ["number", "number", "hidden"],
  ["expMonth", "exp_month", "text"],
  ["expYear", "exp_year", "text"],
  ["code", "code", "hidden"],
]);

/** The identity fields: key in the file, id and label key of the draft, kind. */
const IDENTITY_FIELDS = /** @type {const} */ ([
  ["title", "title", "text"],
  ["firstName", "first_name", "text"],
  ["middleName", "middle_name", "text"],
  ["lastName", "last_name", "text"],
  ["address1", "address1", "text"],
  ["address2", "address2", "text"],
  ["address3", "address3", "text"],
  ["city", "city", "text"],
  ["state", "state", "text"],
  ["postalCode", "postal_code", "text"],
  ["country", "country", "text"],
  ["company", "company", "text"],
  ["email", "email", "email"],
  ["phone", "phone", "phone"],
  ["ssn", "ssn", "hidden"],
  ["username", "identity_username", "text"],
  ["passportNumber", "passport_number", "hidden"],
  ["licenseNumber", "license_number", "hidden"],
]);

/**
 * A card.
 * @param {{ name?: unknown, notes?: unknown, favorite?: unknown, card?: Record<string, unknown>, fields?: { name?: unknown, value?: unknown, type?: unknown }[] }} item
 * @param {MapContext} context
 * @returns {ItemDraft}
 */
export function cardDraft(item, context) {
  const draft = startDraft("card", item.name, item.notes, item.favorite, context.labels);
  for (const [key, id, kind] of CARD_FIELDS) addField(draft, id, context.labels[id], kind, item.card?.[key]);
  addCustomFields(draft, item.fields ?? [], context);
  context.report.counts.items++;
  context.report.counts.card++;
  return draft;
}

/**
 * An identity.
 * @param {{ name?: unknown, notes?: unknown, favorite?: unknown, identity?: Record<string, unknown>, fields?: { name?: unknown, value?: unknown, type?: unknown }[] }} item
 * @param {MapContext} context
 * @returns {ItemDraft}
 */
export function identityDraft(item, context) {
  const draft = startDraft("identity", item.name, item.notes, item.favorite, context.labels);
  for (const [key, id, kind] of IDENTITY_FIELDS) addField(draft, id, context.labels[id], kind, item.identity?.[key]);
  addCustomFields(draft, item.fields ?? [], context);
  context.report.counts.items++;
  context.report.counts.identity++;
  return draft;
}
