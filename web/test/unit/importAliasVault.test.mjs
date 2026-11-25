// The AliasVault readers: the manifest of an .avux file and the CSV file, on synthetic fixtures, and the
// worker reading both (a real ZIP file, unpacked with the bounded reader).
import assert from "node:assert/strict";
import { test } from "node:test";
import { AVUX_MANIFEST_ENTRY, fromAliasVaultCsv, fromAvuxManifest, isAliasVaultCsvHeader, totpAddress } from "../../src/import/aliasvault.mjs";
import { parseCsv } from "../../src/import/csv.mjs";
import { ImportError, MAX_AVUX_ENTRIES, MAX_AVUX_FILE_BYTES, MAX_FILE_BYTES, MAX_ITEMS } from "../../src/import/limits.mjs";
import { safeJsonParse } from "../../src/import/prescan.mjs";
import { readZipEntry } from "../../src/import/zip.mjs";
import { createHandler } from "../../src/workers/import.worker.mjs";
import { allStrings, avBytes, avFile, avText, textFile, vaultPort } from "./importHelpers.mjs";
import { zip } from "./zipHelper.mjs";

const manifest = (options) => fromAvuxManifest(safeJsonParse(avText("synthetic-manifest.json")), options);
const csv = (text, options) => {
  const { rows, lines } = parseCsv(text);
  return fromAliasVaultCsv(rows, { lines, ...options });
};
const refusal = (code) => (error) => error instanceof ImportError && error.code === code;
const warnings = (report, code) => report.warnings.filter((w) => w.code === code).map((w) => w.index);
const field = (draft, id) => draft.fields?.find((f) => f.id === id);
const ids = (draft) => (draft.fields ?? []).map((f) => f.id);

/** Words from the fixtures that must not be in what a page gets, or in a draft that was left out. */
const LEFT_BEHIND = ["PRIVATE-KEY-THAT-MUST-NOT-LEAK", "old-password", "readme.txt", "important", "mail.example.test.png", "gina"];

test("aliasvault_maps_every_field_in_the_synthetic_export", () => {
  const { drafts, report } = manifest();
  assert.equal(drafts.length, 8);
  assert.deepEqual(drafts.map((d) => d.item_type), ["login", "login", "card", "note", "login", "login", "login", "login"]);
  assert.deepEqual(drafts.map((d) => d.name), [
    "Mail login", "Alias with address", "Synthetic card", "A secure note", "Custom fields", "Two codes", "Not a base32 secret", "Left behind",
  ]);
  const [login, alias, card, note, custom, two, odd, behind] = drafts;

  // A login: user name, password, the notes of the item, both addresses (no rule in the file: the exact host) and the one-time password.
  assert.deepEqual(login.fields, [
    { id: "username", label: "User name", kind: "text", value: "alice@example.test" },
    { id: "password", label: "Password", kind: "password", value: "synthetic-password-1" },
  ]);
  assert.equal(login.notes, "Notes for the mail login, with æøå");
  assert.deepEqual(login.urls, [
    { url: "https://mail.example.test/login", matching: "host" },
    { url: "https://accounts.example.test", matching: "host" },
  ]);
  // The name of the code is its label or `issuer:label`; the parameters are those of the file.
  assert.deepEqual(login.totp, { uri: "otpauth://totp/alice?secret=GEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA256&digits=8&period=60" });
  assert.equal(login.favorite, false);

  // An alias: the address of the alias is an e-mail field, the identity of the alias is text, and the item is a login.
  assert.deepEqual(alias.fields.slice(0, 7), [
    { id: "username", label: "User name", kind: "text", value: "bob.synthetic" },
    { id: "password", label: "Password", kind: "password", value: "synthetic-password-2" },
    { id: "email", label: "E-mail", kind: "email", value: "bob.synthetic@alias.example.test" },
    { id: "first_name", label: "First name", kind: "text", value: "Bob" },
    { id: "last_name", label: "Last name", kind: "text", value: "Syntetisk" },
    { id: "gender", label: "Gender", kind: "text", value: "Male" },
    { id: "birthdate", label: "Birth date", kind: "text", value: "1990-12-31" },
  ]);

  // A card: the number and the codes are hidden.
  assert.deepEqual(card.fields, [
    { id: "cardholder_name", label: "Cardholder name", kind: "text", value: "Alice Synthetic" },
    { id: "number", label: "Card number", kind: "hidden", value: "0000000000000000" },
    { id: "exp_month", label: "Expiry month", kind: "text", value: "12" },
    { id: "exp_year", label: "Expiry year", kind: "text", value: "2031" },
    { id: "code", label: "Security code", kind: "hidden", value: "000" },
    { id: "pin", label: "PIN", kind: "hidden", value: "0000" },
  ]);

  // A note keeps its text, line break and all.
  assert.equal(note.notes, "Line one\nLine two");
  assert.equal(note.fields, undefined);
  assert.equal(note.urls, undefined);

  // Custom fields: the kind comes from the definition (hidden, e-mail, phone), a section has no value, an address is plain text.
  assert.deepEqual(custom.fields, [
    { id: "username", label: "User name", kind: "text", value: "carol" },
    { id: "custom-1", label: "Text field", kind: "text", value: "text value" },
    { id: "custom-2", label: "Hidden field", kind: "hidden", value: "hidden value" },
    { id: "custom-3", label: "Email field", kind: "email", value: "carol@example.test" },
    { id: "custom-4", label: "Phone field", kind: "phone", value: "+4700000000" },
    { id: "custom-5", label: "Link field", kind: "text", value: "https://link.example.test" },
    // A value of a system field that this reader does not know is the user's data: kept, hidden, under its key.
    { id: "custom-6", label: "login.future_key", kind: "hidden", value: "a key this reader does not know" },
  ]);

  // Two codes: the first is the item's code, the second is kept as a hidden field with its address.
  assert.deepEqual(two.totp, { uri: "otpauth://totp/?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30" });
  assert.deepEqual(field(two, "totp-2"), {
    id: "totp-2", label: "One-time password", kind: "hidden", value: "otpauth://totp/Second?secret=KRSXG5CTMVRXEZLU&algorithm=SHA1&digits=6&period=30",
  });
  // A secret that is not base32 is kept as it was, hidden.
  assert.equal(odd.totp, undefined);
  assert.deepEqual(field(odd, "totp"), { id: "totp", label: "One-time password", kind: "hidden", value: "not base32 !!" });
  assert.deepEqual(ids(behind), ["username", "password"]);

  assert.deepEqual(report.counts, {
    items: 8, login: 6, note: 1, card: 1, identity: 0,
    urls: 4, totp: 2, customFields: 6, matchNull: 4, http: 1, textAddresses: 2, sealed: 0, passkeys: 0,
  });
  // Left out, and said so: the passkey, the attachment, the earlier value, the tag, the item of a kind from the future,
  // an orphaned custom value and a key that the reader does not know. The folder is the item's folder now.
  assert.deepEqual(drafts.find((d) => d.name === "Left behind")?.folders, ["Work"]);
  assert.equal(drafts.filter((d) => d.folders !== undefined).length, 1);
  assert.deepEqual(report.skipped, {
    passkeys: 1, folders: 0, linked: 0, unknownKeys: 1, otherTypes: 1, trashed: 0, tooLarge: 0, passwordHistory: 0, reprompt: 0,
    attachments: 1, fieldHistory: 1, tags: 1,
  });
  assert.deepEqual(warnings(report, "passkey_skipped"), [7]);
  assert.deepEqual(warnings(report, "type_unknown"), [8]);
  assert.deepEqual(warnings(report, "item_archived"), [1]);
  assert.deepEqual(warnings(report, "alias_needs_aliasvault"), [1]);
  assert.deepEqual(warnings(report, "totp_extra"), [5]);
  assert.deepEqual(warnings(report, "totp_invalid"), [6]);
  assert.deepEqual(warnings(report, "uri_https_added"), [1]);
  assert.deepEqual(warnings(report, "field_type_unknown"), [4]);

  // Nothing that was left out is in a draft.
  const everything = JSON.stringify(drafts);
  for (const word of LEFT_BEHIND) assert.ok(!everything.includes(word), word);
  assert.equal(report.warningsDropped, 0);
});

test("aliasvault_names_are_matched_without_regard_to_case_and_values_are_ordered_by_weight", () => {
  // AliasVault writes camelCase; its readers match the names of a manifest without regard to case.
  const text = avText("synthetic-manifest.json").replace(/"([A-Za-z]+)":/g, (_, name) => `"${name[0].toUpperCase()}${name.slice(1)}":`);
  const upper = fromAvuxManifest(safeJsonParse(text));
  assert.deepEqual(upper.drafts, manifest().drafts);
  assert.deepEqual(upper.report, manifest().report);

  const first = fromAvuxManifest(safeJsonParse(JSON.stringify({
    version: "1.0.0",
    items: [{
      name: "Order", itemType: "Login",
      fieldValues: [
        { fieldKey: "login.url", value: "https://third.example.test", weight: 2 },
        { fieldKey: "login.url", value: "https://first.example.test", weight: 0 },
        { fieldKey: "login.username", value: "later", weight: 5 },
        { fieldKey: "login.username", value: "earlier", weight: 1 },
        { fieldKey: "notes.content", value: "one", weight: 0 },
        { fieldKey: "notes.content", value: "two", weight: 1 },
      ],
    }],
  })));
  const [draft] = first.drafts;
  assert.deepEqual(draft.urls.map((u) => u.url), ["https://first.example.test", "https://third.example.test"]);
  // A second value of a one-value field is kept as another field and not lost.
  assert.deepEqual(draft.fields, [
    { id: "username", label: "User name", kind: "text", value: "earlier" },
    { id: "username-2", label: "User name", kind: "text", value: "later" },
  ]);
  assert.equal(draft.notes, "one\n\ntwo");
});

test("aliasvault_csv_maps_logins_aliases_cards_notes_and_codes", () => {
  const { drafts, report } = csv(avText("synthetic.csv"));
  assert.equal(drafts.length, 8);
  assert.deepEqual(drafts.map((d) => d.item_type), ["login", "login", "card", "note", "login", "login", "login", "login"]);
  const [login, alias, card, note, code, quoted, odd, mixed] = drafts;

  assert.deepEqual(login.fields, [
    { id: "username", label: "User name", kind: "text", value: "alice@example.test" },
    { id: "password", label: "Password", kind: "password", value: "synthetic-password-1" },
  ]);
  assert.equal(login.notes, "Notes for the mail login with æøå");
  assert.deepEqual(login.urls, [
    { url: "https://mail.example.test/login", matching: "host" },
    { url: "https://accounts.example.test", matching: "host" },
  ]);
  // A bare secret is the code of the item.
  assert.deepEqual(login.totp, { uri: "otpauth://totp/?secret=GEZDGNBVGY3TQOJQ" });

  assert.deepEqual(alias.fields.slice(0, 7), [
    { id: "username", label: "User name", kind: "text", value: "bob.synthetic" },
    { id: "password", label: "Password", kind: "password", value: "synthetic-password-2" },
    { id: "email", label: "E-mail", kind: "email", value: "bob.synthetic@alias.example.test" },
    { id: "first_name", label: "First name", kind: "text", value: "Bob" },
    { id: "last_name", label: "Last name", kind: "text", value: "Syntetisk" },
    { id: "gender", label: "Gender", kind: "text", value: "Male" },
    // The file writes a date and a time; the date is what is kept.
    { id: "birthdate", label: "Birth date", kind: "text", value: "1990-12-31" },
  ]);
  assert.deepEqual(ids(card), ["cardholder_name", "number", "exp_month", "exp_year", "code", "pin"]);
  assert.equal(field(card, "number").kind, "hidden");
  assert.equal(note.notes, "Line one");
  assert.equal(note.fields, undefined);

  // An address in the code column is the code as it is.
  assert.deepEqual(code.totp, { uri: "otpauth://totp/Example:carol?secret=GEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA256&digits=8&period=60" });
  // Quotes, a comma and a line break inside a quoted cell.
  assert.equal(quoted.notes, 'Line one, with a comma\nand a second line with "quotes"');
  assert.deepEqual(field(odd, "totp"), { id: "totp", label: "One-time password", kind: "hidden", value: "not base32 !!" });
  // A row with a card and a login in it keeps both, as one login.
  assert.deepEqual(ids(mixed), ["username", "password", "cardholder_name", "number", "exp_month", "exp_year", "code", "pin"]);
  assert.deepEqual(warnings(report, "card_and_login"), [7]);

  assert.deepEqual(report.counts, {
    items: 8, login: 6, note: 1, card: 1, identity: 0,
    urls: 4, totp: 2, customFields: 0, matchNull: 4, http: 1, textAddresses: 2, sealed: 0, passkeys: 0,
  });
  // The folder path of a row is its folder, as AliasVault writes it.
  assert.deepEqual(drafts.find((d) => d.name === "Alias with address")?.folders, ["Work/Sub"]);
  assert.equal(drafts.filter((d) => d.folders !== undefined).length, 1);
  assert.deepEqual(report.skipped, {
    passkeys: 0, folders: 0, linked: 0, unknownKeys: 0, otherTypes: 0, trashed: 0, tooLarge: 0, passwordHistory: 0, reprompt: 0,
    attachments: 0, fieldHistory: 0, tags: 0,
  });
  assert.deepEqual(warnings(report, "alias_needs_aliasvault"), [1]);
  assert.deepEqual(warnings(report, "totp_invalid"), [6]);
  assert.deepEqual(warnings(report, "uri_https_added"), [1]);
});

test("the_older_csv_of_the_mobile_app_has_a_nickname_and_fewer_columns", () => {
  const { drafts, report } = csv(avText("old-mobile.csv"));
  assert.equal(drafts.length, 3);
  const [a, b, c] = drafts;
  assert.deepEqual(a.totp, { uri: "otpauth://totp/?secret=JBSWY3DPEHPK3PXP" });
  assert.deepEqual(ids(a), ["username"]);
  assert.equal(a.notes, "without password");
  assert.deepEqual(b.fields, [
    { id: "username", label: "User name", kind: "text", value: "username2" },
    { id: "password", label: "Password", kind: "password", value: "password2" },
    { id: "email", label: "E-mail", kind: "email", value: "service2@alias.example.test" },
    { id: "first_name", label: "First name", kind: "text", value: "firstname2" },
    { id: "last_name", label: "Last name", kind: "text", value: "lastname2" },
    { id: "nickname", label: "Nickname", kind: "text", value: "nickname2" },
    { id: "gender", label: "Gender", kind: "text", value: "gender2" },
  ]);
  assert.equal(field(c, "birthdate").value, "1970-01-01");
  assert.equal(c.notes, "notes1");
  assert.equal(report.skipped.unknownKeys, 0);
  assert.equal(report.counts.items, 3);
});

test("aliasvault_match_rules_never_get_wider", () => {
  // An AliasVault export has no match rule for an address. Every address that is read is matched on its exact host (never on the
  // domain, which would reach every subdomain), and the report counts them so that the preview can say so.
  for (const { drafts, report } of [manifest(), csv(avText("synthetic.csv")), csv(avText("old-mobile.csv"))]) {
    const urls = drafts.flatMap((d) => d.urls ?? []);
    assert.ok(urls.length > 0);
    assert.ok(urls.every((u) => u.matching === "host"), JSON.stringify(urls));
    assert.equal(report.counts.matchNull, urls.length);
    // Only http and https addresses are addresses.
    assert.ok(urls.every((u) => /^https?:\/\//i.test(u.url)));
  }

  const { drafts, report } = fromAvuxManifest(safeJsonParse(JSON.stringify({
    version: "1.0.0",
    items: [{
      name: "Addresses", itemType: "Login",
      fieldValues: [
        "https://www.example.test", "http://plain.example.test", "HTTPS://Upper.example.test", "example.test/path", "localhost:8080/app",
        "androidapp://net.example", "iosapp://net.example", "javascript:alert(1)", "data:text/html;base64,PHA+PC9wPg==", "file:///etc/example",
        "mailto:alice@example.test", "https://has space.example.test", "//scheme-relative.example.test", "/just/a/path", "https://",
      ].map((value, weight) => ({ fieldKey: "login.url", value, weight })),
    }],
  })));
  const [item] = drafts;
  assert.deepEqual(item.urls, [
    { url: "https://www.example.test", matching: "host" },
    { url: "http://plain.example.test", matching: "host" },
    { url: "HTTPS://Upper.example.test", matching: "host" },
    { url: "https://example.test/path", matching: "host" },
    { url: "https://localhost:8080/app", matching: "host" },
  ]);
  // Everything else is text on the item and never an address: no script, data, file, app or relative address reaches `urls`.
  assert.deepEqual(item.fields.filter((f) => f.id.startsWith("address-")).map((f) => f.value), [
    "androidapp://net.example", "iosapp://net.example", "javascript:alert(1)", "data:text/html;base64,PHA+PC9wPg==", "file:///etc/example",
    "mailto:alice@example.test", "https://has space.example.test", "//scheme-relative.example.test", "/just/a/path", "https://",
  ]);
  assert.equal(report.counts.urls, 5);
  assert.equal(report.counts.textAddresses, 10);
  assert.equal(report.counts.http, 1);
  assert.deepEqual(warnings(report, "uri_https_added"), [0, 0]);
});

test("the_otpauth_address_of_a_code_follows_the_parameters_of_the_file", () => {
  const address = (code) => totpAddress({ name: "", secret: "GEZDGNBVGY3TQOJQ", algorithm: null, digits: null, period: null, ...code });
  assert.equal(address({}), "otpauth://totp/?secret=GEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=6&period=30");
  assert.equal(address({ name: "Example:alice", algorithm: "sha-512", digits: 7, period: 45 }), "otpauth://totp/alice?secret=GEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA512&digits=7&period=45");
  // What AliasVault would not accept is the default: an algorithm it does not know, digits outside 6 to 8, a period outside 1 to 300.
  assert.equal(address({ algorithm: "MD5", digits: 12, period: 9000 }), "otpauth://totp/?secret=GEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=6&period=30");
  assert.equal(address({ digits: 8, period: 300 }), "otpauth://totp/?secret=GEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=8&period=300");
  // The name is escaped, so it cannot add a parameter.
  assert.equal(address({ name: "a&secret=EVIL b" }), "otpauth://totp/a%26secret%3DEVIL%20b?secret=GEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=6&period=30");
  assert.equal(address({ name: "Is&su er:x" }), "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&issuer=Is%26su%20er&algorithm=SHA1&digits=6&period=30");
  // White space in a secret is dropped; a secret that is no base32 text gives no address.
  assert.equal(address({ secret: "GEZD GNBV" }), "otpauth://totp/?secret=GEZDGNBV&algorithm=SHA1&digits=6&period=30");
  assert.equal(address({ secret: "abc!def" }), null);
  assert.equal(address({ secret: "A".repeat(1025) }), null);
});

test("an_item_with_nothing_but_a_name_and_notes_is_a_note_and_the_header_is_read_without_regard_to_case", () => {
  const header = "ServiceName,Username,Notes\n";
  const { drafts } = csv(`${header}Only notes,,hello\nOnly a name,,\nLogin,user,\n`);
  assert.deepEqual(drafts.map((d) => d.item_type), ["note", "login", "login"]);
  assert.equal(drafts[1].name, "Only a name");
  // A column the file lacks is not an error, and a column in another case is the same column.
  const { drafts: lower } = csv("servicename,USERNAME\nx,y\n");
  assert.deepEqual(lower[0].fields, [{ id: "username", label: "User name", kind: "text", value: "y" }]);
  // A name that is blank gets the label of an item without a name.
  assert.equal(csv("ServiceName,Username\n,y\n").drafts[0].name, "(no name)");
});

test("the_labels_a_page_passes_are_the_labels_of_the_fields_of_an_aliasvault_item", () => {
  const labels = { username: "Brukernavn", email: "E-post", gender: "Kjønn", birthdate: "Fødselsdato", nickname: "Kallenavn", pin: "PIN-kode", untitled: "(uten navn)", totp: "Engangspassord" };
  const { drafts } = csv("ServiceName,Username,AliasEmail,AliasGender,AliasBirthDate,AliasNickName,CardPin,TwoFactorSecret\n,u,e@example.test,g,01/02/2003 00:00:00,n,1234,not base32 !!\n", { labels });
  assert.equal(drafts[0].name, "(uten navn)");
  assert.deepEqual(drafts[0].fields.map((f) => f.label), ["Brukernavn", "E-post", "Kallenavn", "Kjønn", "Fødselsdato", "PIN-kode", "Engangspassord"]);
});

test("the_committed_avux_holds_the_synthetic_manifest_and_reads_like_it", async () => {
  const file = avFile("synthetic.avux");
  const bytes = await readZipEntry(file, AVUX_MANIFEST_ENTRY);
  assert.equal(Buffer.from(bytes).toString("utf8"), avText("synthetic-manifest.json"));
  // The attachment and the logo are in the archive and are not read.
  assert.equal((await readZipEntry(file, "attachments/readme.txt")).length > 0, true);
  const { drafts, report } = fromAvuxManifest(safeJsonParse(Buffer.from(bytes).toString("utf8")));
  assert.equal(drafts.length, 8);
  assert.equal(report.skipped.attachments, 1);
});

test("hostile_aliasvault_files_are_refused", async () => {
  const bad = (value) => () => fromAvuxManifest(safeJsonParse(typeof value === "string" ? value : JSON.stringify(value)));
  const item = (extra = {}) => ({ name: "x", itemType: "Login", fieldValues: [], ...extra });

  // Not a manifest, or not the version that is read.
  assert.throws(bad("[]"), refusal("import_bad_format"));
  assert.throws(bad("null"), refusal("import_bad_format"));
  assert.throws(bad('"a manifest"'), refusal("import_bad_format"));
  assert.throws(bad({ items: [item()], version: "2.0.0" }), refusal("import_bad_format"));
  assert.throws(bad({ items: [item()], version: 1 }), refusal("import_bad_format"));
  assert.throws(bad({ version: "1.0.0" }), refusal("import_bad_format"));
  assert.throws(bad({ version: "1.0.0", items: {} }), refusal("import_bad_format"));
  assert.throws(bad({ version: "1.0.0", items: [] }), refusal("import_empty"));
  assert.throws(bad({ version: "1.0.0", items: Array.from({ length: MAX_ITEMS + 1 }, () => ({})) }), refusal("import_too_many"));
  // A value of the wrong type is a refusal of the file and not a guess.
  for (const wrong of [
    { items: [5] }, { items: [[]] }, { items: [item({ name: 5 })] }, { items: [item({ itemType: {} })] }, { items: [item({ fieldValues: {} })] },
    { items: [item({ fieldValues: [5] })] }, { items: [item({ fieldValues: [{ fieldKey: "login.username", value: 5 }] })] },
    { items: [item({ fieldValues: [{ fieldKey: "login.username", value: "x", weight: "1" }] })] },
    { items: [item({ fieldValues: [{ fieldKey: ["login.username"], value: "x" }] })] }, { items: [item({ totpCodes: "x" })] },
    { items: [item({ totpCodes: [{ secretKey: 5 }] })] }, { items: [item({ totpCodes: [{ secretKey: "AAAA", digits: "6" }] })] },
    { items: [item()], fieldDefinitions: [5] }, { items: [item()], folders: "x" }, { items: [item({ passkeys: 5 })] },
  ]) {
    assert.throws(bad({ version: "1.0.0", ...wrong }), refusal("import_bad_format"), JSON.stringify(wrong).slice(0, 80));
  }
  // The rules of every reader hold before the manifest is read: hostile keys, depth, and text that is no JSON.
  assert.throws(bad('{"version":"1.0.0","items":[{"__proto__":{"x":1}}]}'), refusal("import_bad_key"));
  assert.throws(bad('{"version":"1.0.0","items":[{"fieldValues":[{"constructor":1}]}]}'), refusal("import_bad_key"));
  assert.throws(bad("[".repeat(100_000)), refusal("import_too_deep"));
  assert.throws(bad("{not json"), refusal("import_bad_json"));

  // A CSV file with no ServiceName column is not an AliasVault export, a row that does not fit its header is refused with its line.
  assert.throws(() => csv("name,login_username\nx,y\n"), refusal("import_bad_format"));
  assert.throws(() => csv("ServiceName\n"), refusal("import_empty"));
  assert.throws(() => csv(""), refusal("import_empty"));
  assert.throws(() => csv("ServiceName,Username\nx,y\nx,y,z\n"), (e) => e.code === "import_bad_csv" && e.line === 3);
  assert.throws(() => csv('ServiceName,Username\nx,"unterminated\n'), (e) => e.code === "import_bad_csv" && e.line === 2);
  assert.throws(() => csv(`ServiceName\n${"x\n".repeat(MAX_ITEMS + 1)}`), refusal("import_too_many"));
  assert.equal(isAliasVaultCsvHeader(["a", " servicename "]), true);
  assert.equal(isAliasVaultCsvHeader(["name"]), false);
  assert.equal(isAliasVaultCsvHeader(undefined), false);

  // The worker, with the files it takes: each refusal is a code and the vault port is never used.
  /** @param {Blob} file @param {string} [kind] */
  const ask = async (file, kind = "aliasvault_avux") => {
    const port = vaultPort();
    const reply = await createHandler()({ id: 3, kind, file, port });
    assert.equal(port.sent.length, 0, "no draft is sent for a refused file");
    return reply;
  };
  const avux = (entries, options) => zip(entries, options);
  const json = (value) => Buffer.from(typeof value === "string" ? value : JSON.stringify(value));
  const good = { version: "1.0.0", items: [item()] };

  assert.deepEqual(await ask(textFile("not a zip file", "x.avux")), { id: 3, ok: false, error: "import_bad_zip" });
  assert.deepEqual(await ask(new File([new Uint8Array(0)], "x.avux")), { id: 3, ok: false, error: "import_bad_zip" });
  assert.deepEqual(await ask(avux([{ name: "other.json", data: json(good) }])), { id: 3, ok: false, error: "import_zip_entry_missing" });
  // The encrypted export of AliasVault is a JSON file that says what it is.
  assert.deepEqual(await ask(avFile("encrypted.avex", "x.avux")), { id: 3, ok: false, error: "import_encrypted_export" });
  // An encrypted entry; an entry that would unpack far beyond what it says (a zip bomb); one that lies about its size; a bad name.
  assert.deepEqual(await ask(avux([{ name: "manifest.json", data: json(good), flags: 0x0001 }])), { id: 3, ok: false, error: "import_zip_encrypted" });
  assert.deepEqual(await ask(avux([{ name: "manifest.json", data: Buffer.alloc(8 * 1024 * 1024, 0x20) }])), { id: 3, ok: false, error: "import_bad_zip" });
  assert.deepEqual(await ask(avux([{ name: "manifest.json", data: json(good), size: 3 }])), { id: 3, ok: false, error: "import_bad_zip" });
  assert.deepEqual(await ask(avux([{ name: "manifest.json", data: json(good), crc: 1 }])), { id: 3, ok: false, error: "import_bad_zip" });
  assert.deepEqual(await ask(avux([{ name: "manifest.json", data: json(good) }, { name: "../outside.txt", data: json("x") }])), { id: 3, ok: false, error: "import_bad_zip" });
  assert.deepEqual(await ask(avux([{ name: "manifest.json", data: json(good) }, { name: "manifest.json", data: json(good) }])), { id: 3, ok: false, error: "import_bad_zip" });
  // The manifest is read as bounded JSON: not UTF-8, hostile keys, very deep, not a manifest, an empty one.
  assert.deepEqual(await ask(avux([{ name: "manifest.json", data: Buffer.from([0x7b, 0xff, 0xfe, 0x7d]) }])), { id: 3, ok: false, error: "import_bad_json" });
  assert.deepEqual(await ask(avux([{ name: "manifest.json", data: json('{"version":"1.0.0","items":[{"__proto__":{}}]}') }])), { id: 3, ok: false, error: "import_bad_key" });
  assert.deepEqual(await ask(avux([{ name: "manifest.json", data: json("[".repeat(50_000)) }])), { id: 3, ok: false, error: "import_too_deep" });
  assert.deepEqual(await ask(avux([{ name: "manifest.json", data: json({ version: "9.0.0", items: [item()] }) }])), { id: 3, ok: false, error: "import_bad_format" });
  assert.deepEqual(await ask(avux([{ name: "manifest.json", data: json({ version: "1.0.0", items: [] }) }])), { id: 3, ok: false, error: "import_empty" });
  // A CSV file that is not AliasVault's, asked for as AliasVault's, and a ZIP file asked for as a CSV file.
  assert.deepEqual(await ask(textFile("name,x\na,b\n", "x.csv"), "aliasvault_csv"), { id: 3, ok: false, error: "import_bad_format" });
  assert.deepEqual(await ask(avFile("synthetic.avux", "x.csv"), "csv"), { id: 3, ok: false, error: "import_zip" });
  assert.deepEqual(await ask(avFile("synthetic.avux", "x.json"), "bitwarden_json"), { id: 3, ok: false, error: "import_zip" });
});

test("the_worker_reads_an_avux_file_and_both_csv_files_and_the_page_gets_no_text_of_them", async () => {
  const words = [
    "synthetic-password", "alice@example.test", "GEZDGNBV", "example.test", "Notes for the mail", "Mail login", "Alice Synthetic", "0000000000000000",
    "hidden value", "A secure note", "Bob", "Syntetisk", ...LEFT_BEHIND,
  ];
  for (const [kind, name, items] of [["aliasvault_avux", "synthetic.avux", 8], ["aliasvault_csv", "synthetic.csv", 8], ["csv", "synthetic.csv", 8], ["csv", "old-mobile.csv", 3]]) {
    const port = vaultPort();
    const reply = await createHandler()({ id: 1, kind, file: avFile(name), port });
    assert.equal(reply.ok, true, name);
    assert.deepEqual(Object.keys(reply).sort(), ["id", "kind", "ok", "report", "sealed"]);
    // A `.csv` file is read as what its header says it is, and the answer says which.
    assert.equal(reply.kind, kind === "csv" ? "aliasvault_csv" : kind);
    assert.equal(reply.sealed.length, items);
    assert.equal(reply.report.counts.sealed, items);
    assert.equal(port.sent.length, items);
    for (const message of port.sent) {
      assert.equal(message.method, "encrypt_item");
      assert.equal(message.args.length, 5);
      assert.equal(message.args[1], 1);
      assert.equal(message.args[3], "no_existing");
    }
    const seen = JSON.stringify(reply, (_, v) => (v instanceof Uint8Array ? `<${v.length} bytes>` : v));
    for (const word of words) assert.ok(!seen.includes(word), `${name}: ${word}`);
    for (const text of allStrings({ ...reply, sealed: [] })) assert.ok(/^[a-z0-9_]+$/i.test(text), `a reply holds only codes and keys: ${text}`);
    assert.equal(port.closed, true);
  }
  // A CSV file of Bitwarden's, named only .csv, is still read as Bitwarden's.
  const reply = await createHandler()({ id: 1, kind: "csv", file: textFile("name,login_username\nx,y\n", "x.csv"), port: vaultPort() });
  assert.equal(reply.kind, "bitwarden_csv");
});

test("an_otpauth_address_the_core_refuses_in_an_aliasvault_item_is_kept_as_a_hidden_field", async () => {
  // The code of the first item is refused by the vault (the strict parser has the last word): the item is sent again with it hidden.
  const port = vaultPort({
    reply: (message, index) => (index === 0 && message.args[2].totp
      ? { id: message.id, ok: false, code: "malformed_otpauth" }
      : { id: message.id, ok: true, value: { rev: 1, envelope: new Uint8Array([0xe0, 1, 2, 3]), tag: new Uint8Array(32) } }),
  });
  const reply = await createHandler()({ id: 1, kind: "aliasvault_csv", file: avFile("synthetic.csv"), port });
  assert.equal(reply.ok, true);
  assert.equal(port.sent.length, 9);
  const retried = port.sent[8].args[2];
  assert.equal(retried.totp, undefined);
  assert.deepEqual(retried.fields.find((f) => f.id === "totp"), { id: "totp", label: "One-time password", kind: "hidden", value: "GEZDGNBVGY3TQOJQ" });
  assert.deepEqual(port.sent[8].args[0], port.sent[0].args[0]);
  assert.equal(reply.report.counts.totp, 1);
});

test("a_custom_field_of_an_unknown_type_is_kept_hidden_with_a_warning_and_known_types_keep_their_kind", () => {
  const types = ["Text", "TextArea", "Date", "Number", "URL", "Email", "Phone", "Password", "Hidden", "FromTheFuture"];
  const { drafts, report } = fromAvuxManifest(safeJsonParse(JSON.stringify({
    version: "1.0.0",
    fieldDefinitions: types.map((fieldType, i) => ({ id: `d${i}`, fieldType, label: fieldType, isHidden: false })),
    items: [{ name: "Types", itemType: "Login", fieldValues: types.map((_, i) => ({ fieldKey: null, fieldDefinitionId: `d${i}`, value: `v${i}`, weight: i })) }],
  })));
  const kinds = Object.fromEntries(drafts[0].fields.map((f) => [f.label, f.kind]));
  assert.deepEqual(kinds, {
    Text: "text", TextArea: "text", Date: "text", Number: "text", URL: "text", Email: "email", Phone: "phone", Password: "password", Hidden: "hidden",
    FromTheFuture: "hidden",
  });
  assert.deepEqual(warnings(report, "field_type_unknown"), [0]);
  // The value of an empty unknown system field is nothing to keep.
  const empty = fromAvuxManifest(safeJsonParse(JSON.stringify({ version: "1.0.0", items: [{ name: "x", itemType: "Login", fieldValues: [{ fieldKey: "login.later", value: "" }] }] })));
  assert.equal(empty.drafts[0].fields, undefined);
  assert.equal(empty.report.warnings.length, 0);
});

test("a_real_avux_with_many_entries_and_a_large_attachment_is_read_and_each_limit_says_what_was_exceeded", async () => {
  const good = Buffer.from(JSON.stringify({ version: "1.0.0", items: [{ name: "x", itemType: "Login", fieldValues: [{ fieldKey: "login.username", value: "u" }] }] }));
  const ask = async (file) => createHandler()({ id: 3, kind: "aliasvault_avux", file, port: vaultPort() });

  // Logos and attachments: one entry each, far more than 1 000 for a big vault.
  const many = [{ name: "manifest.json", data: good }, ...Array.from({ length: 2_000 }, (_, i) => ({ name: `logos/site${i}.example.test_${i}.png`, data: "x", method: 0 }))];
  const reply = await ask(zip(many));
  assert.equal(reply.ok, true);
  assert.equal(reply.report.counts.items, 1);

  // An archive over 50 MiB because of an attachment that is never read.
  const large = zip([{ name: "attachments/big.bin", data: Buffer.alloc(MAX_FILE_BYTES + 1024 * 1024), method: 0 }, { name: "manifest.json", data: good }]);
  assert.ok(large.size > MAX_FILE_BYTES);
  const read = await ask(large);
  assert.equal(read.ok, true);
  assert.equal(read.report.counts.items, 1);

  // The limits that do hold, each with its own code.
  const huge = new File(["x"], "huge.avux");
  Object.defineProperty(huge, "size", { value: MAX_AVUX_FILE_BYTES + 1 });
  huge.slice = () => {
    throw new Error("read");
  };
  assert.deepEqual(await ask(huge), { id: 3, ok: false, error: "import_archive_too_large" });
  assert.deepEqual(await ask(zip([{ name: "manifest.json", data: "x", size: MAX_FILE_BYTES + 1 }])), { id: 3, ok: false, error: "import_manifest_too_large" });
  assert.equal(MAX_AVUX_ENTRIES, 65_534);
  // A file that is not an archive is still held to 50 MiB by the other kinds.
  const bigCsv = new File(["x"], "big.csv");
  Object.defineProperty(bigCsv, "size", { value: MAX_FILE_BYTES + 1 });
  assert.deepEqual(await createHandler()({ id: 4, kind: "csv", file: bigCsv, port: vaultPort() }), { id: 4, ok: false, error: "import_too_large" });
});
