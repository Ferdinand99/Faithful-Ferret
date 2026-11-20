// The Bitwarden readers: the unencrypted JSON export and the CSV export, on synthetic fixtures.
import assert from "node:assert/strict";
import { test } from "node:test";
import { fromBitwardenCsv, fromBitwardenJson } from "../../src/import/bitwarden.mjs";
import { parseCsv } from "../../src/import/csv.mjs";
import { ImportError } from "../../src/import/limits.mjs";
import { safeJsonParse } from "../../src/import/prescan.mjs";
import { fixture } from "./importHelpers.mjs";

const json = (name, options) => fromBitwardenJson(safeJsonParse(fixture(name)), options);
const csv = (text, options) => {
  const { rows, lines } = parseCsv(text);
  return fromBitwardenCsv(rows, { lines, ...options });
};
const refusal = (code) => (error) => error instanceof ImportError && error.code === code;
const warnings = (report, code) => report.warnings.filter((w) => w.code === code).map((w) => w.index);

test("bitwarden_json_maps_every_type_and_field_kind", () => {
  const { drafts, report } = json("every-type.json");
  assert.equal(drafts.length, 8);
  assert.deepEqual(drafts.map((d) => d.item_type), ["login", "login", "note", "card", "identity", "login", "login", "login"]);

  const [login, , note, card, identity] = drafts;
  assert.equal(login.name, "Every login field");
  assert.equal(login.favorite, true);
  assert.equal(login.notes, "Synthetic notes");
  assert.deepEqual(login.fields, [
    { id: "username", label: "User name", kind: "text", value: "alice@example.test" },
    { id: "password", label: "Password", kind: "password", value: "synthetic-password-1" },
    { id: "custom-1", label: "Text field", kind: "text", value: "text value" },
    { id: "custom-2", label: "Hidden field", kind: "hidden", value: "hidden value" },
    { id: "custom-3", label: "Boolean true", kind: "text", value: "true" },
    { id: "custom-4", label: "Boolean false", kind: "text", value: "false" },
  ]);
  assert.deepEqual(login.urls, [
    { url: "https://www.example.test/login", matching: "host" },
    { url: "https://accounts.example.test", matching: "domain" },
    { url: "https://host.example.test", matching: "host" },
    { url: "https://exact.example.test/path", matching: "exact" },
  ]);
  assert.deepEqual(login.totp, { uri: "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQ&issuer=Example" });

  assert.equal(note.name, "A secure note");
  assert.equal(note.notes, "Note body");
  assert.equal(note.fields, undefined);
  assert.equal(note.urls, undefined);

  assert.equal(card.item_type, "card");
  assert.deepEqual(card.fields, [
    { id: "cardholder_name", label: "Cardholder name", kind: "text", value: "Alice Example" },
    { id: "brand", label: "Brand", kind: "text", value: "Synthetic" },
    { id: "number", label: "Card number", kind: "hidden", value: "0000000000000000" },
    { id: "exp_month", label: "Expiry month", kind: "text", value: "12" },
    { id: "exp_year", label: "Expiry year", kind: "text", value: "2030" },
    { id: "code", label: "Security code", kind: "hidden", value: "000" },
  ]);

  const kinds = Object.fromEntries(identity.fields.map((f) => [f.id, f.kind]));
  assert.equal(identity.fields.length, 18 - 2); // address2 and address3 are empty and left out
  assert.equal(kinds.email, "email");
  assert.equal(kinds.phone, "phone");
  assert.equal(kinds.ssn, "hidden");
  assert.equal(kinds.passport_number, "hidden");
  assert.equal(kinds.license_number, "hidden");
  assert.equal(kinds.first_name, "text");
  assert.equal(new Set(identity.fields.map((f) => f.id)).size, identity.fields.length);

  // Counts and skips: what was read and what was left out, by name.
  assert.deepEqual(report.counts, {
    items: 8, login: 5, note: 1, card: 1, identity: 1,
    urls: 7, totp: 2, customFields: 4, matchNull: 2, http: 1, textAddresses: 2, sealed: 0,
  });
  assert.deepEqual(report.skipped, { passkeys: 1, folders: 2, collections: 1, linked: 1, unknownKeys: 2, otherTypes: 2, trashed: 1, tooLarge: 0, passwordHistory: 1, reprompt: 0, attachments: 0, fieldHistory: 0, tags: 0 });
});

test("passkeys_folders_linked_fields_and_unknown_keys_are_counted_and_skipped", () => {
  const { drafts, report } = json("every-type.json");
  assert.equal(report.skipped.passkeys, 1);
  assert.equal(report.skipped.folders, 2);
  assert.equal(report.skipped.collections, 1);
  assert.equal(report.skipped.linked, 1);
  assert.equal(report.skipped.unknownKeys, 2); // httpAuthenticationEnabled and archivedDate
  assert.deepEqual(warnings(report, "passkey_skipped"), [0]);
  assert.deepEqual(warnings(report, "linked_field_skipped"), [0]);
  // The SSH key (type 5) and the passport (type 8) are skipped by name, and the trashed item too.
  assert.equal(report.skipped.otherTypes, 2);
  assert.deepEqual(warnings(report, "type_ssh_key"), [5]);
  assert.deepEqual(warnings(report, "type_passport"), [6]);
  assert.equal(report.skipped.trashed, 1);
  assert.deepEqual(warnings(report, "item_trashed"), [7]);
  // None of it is in a draft: no passkey, no folder, no linked field, nothing of the skipped items.
  const everything = JSON.stringify(drafts);
  for (const absent of ["synthetic-credential-id", "synthetic-key-value", "Synthetic folder", "Linked field", "synthetic-private-key", "In the trash", "synthetic-password-3", "A passport", "An SSH key", "synthetic-old-password"]) {
    assert.ok(!everything.includes(absent), absent);
  }
  assert.ok(drafts.every((d) => !("passkey" in d)));
  // A type number that no one knows is skipped by number and counted too.
  const odd = fromBitwardenJson(safeJsonParse('{"encrypted":false,"items":[{"type":99,"name":"x"},{"type":2,"name":"y"}]}'));
  assert.equal(odd.drafts.length, 1);
  assert.deepEqual(warnings(odd.report, "type_unknown"), [0]);
  assert.equal(odd.report.skipped.otherTypes, 1);
  for (const [type, code] of [[6, "type_bank_account"], [7, "type_drivers_license"]]) {
    const one = fromBitwardenJson(safeJsonParse(`{"encrypted":false,"items":[{"type":${type},"name":"x"},{"type":2,"name":"y"}]}`));
    assert.deepEqual(warnings(one.report, code), [0]);
  }
});

test("scheme_less_uris_get_https_and_a_warning", () => {
  const { drafts, report } = json("schemes.json");
  const [item] = drafts;
  assert.deepEqual(item.urls, [
    { url: "https://www.example.test", matching: "host" },
    { url: "https://example.test/login?x=1", matching: "domain" },
    { url: "https://localhost:8080/app", matching: "exact" },
    { url: "https://secure.example.test", matching: "host" },
    { url: "HTTP://Upper.example.test", matching: "host" },
  ]);
  // The three without a scheme got https:// and a warning each; the ones that had one did not.
  assert.deepEqual(warnings(report, "uri_https_added"), [0, 0, 0]);
  assert.equal(report.counts.http, 1);
  assert.equal(report.counts.urls, 5);
});

test("non_http_schemes_go_to_a_text_field_and_never_to_urls", () => {
  const { drafts, report } = json("schemes.json");
  const [item] = drafts;
  const addresses = item.fields.filter((f) => f.id.startsWith("address-"));
  assert.deepEqual(addresses.map((f) => f.value), [
    "androidapp://com.example.test.app",
    "iosapp://com.example.test.app",
    "javascript:alert(1)",
    "data:text/html;base64,PHA+PC9wPg==",
    "file:///etc/example",
    "ftp://files.example.test",
    "mailto:alice@example.test",
    "https://has space.example.test",
  ]);
  assert.ok(addresses.every((f) => f.kind === "text" && f.label === "Address"));
  assert.equal(report.counts.textAddresses, 8);
  // Not one of them is in urls, whatever its match rule was.
  for (const { url } of item.urls) assert.match(url, /^https?:\/\//i);
  assert.ok(!item.urls.some((u) => /javascript|data:|file:|androidapp|iosapp|ftp|mailto|has space/i.test(u.url)));
  // Every address of the file that is not blank is somewhere, once.
  assert.equal(item.urls.length + addresses.length, 13);
});

test("match_rules_never_get_wider", () => {
  const { drafts, report } = json("every-type.json");
  const rules = drafts[1];
  assert.deepEqual(rules.urls, [
    { url: "https://starts.example.test/app", matching: "exact" },
    { url: "https://odd.example.test", matching: "exact" },
    { url: "http://plain.example.test", matching: "host" },
  ]);
  // The address whose match was "never" is a text field, not a match.
  // The regular expression is no address either: it is text, as it was in the file.
  assert.deepEqual(rules.fields.filter((f) => f.id.startsWith("address")).map((f) => f.value), ["https://regex.example.test/.*", "https://never.example.test"]);
  assert.deepEqual(warnings(report, "match_starts_with"), [1]);
  assert.deepEqual(warnings(report, "match_regex"), [1]);
  assert.deepEqual(warnings(report, "match_never"), [1]);
  assert.deepEqual(warnings(report, "match_unknown"), [1]);
  // The preview counts what Bitwarden matched by base domain and what is plain http.
  assert.equal(report.counts.matchNull, 2);
  assert.equal(report.counts.http, 1);
  // No draft has a rule outside the three Ferret has, and `domain` only where the file said domain (0).
  for (const d of drafts) for (const u of d.urls ?? []) assert.ok(["host", "domain", "exact"].includes(u.matching));
  assert.deepEqual(drafts.flatMap((d) => d.urls ?? []).filter((u) => u.matching === "domain").map((u) => u.url), ["https://accounts.example.test"]);
});

test("an_invalid_totp_is_kept_hidden_with_a_warning", () => {
  const { drafts, report } = json("every-type.json");
  const [bare, steam, invalid] = drafts.slice(5);
  // A bare secret is a one-time password now, spaces dropped.
  assert.deepEqual(bare.totp, { uri: "otpauth://totp/?secret=GEZDGNBVGY3TQOJQ" });
  // Steam is kept hidden, with its own warning, and is not a totp.
  assert.equal(steam.totp, undefined);
  assert.deepEqual(steam.fields.at(-1), { id: "totp", label: "One-time password", kind: "hidden", value: "steam://GEZDGNBVGY3TQOJQ" });
  assert.deepEqual(warnings(report, "totp_steam"), [9]);
  // A value that is no secret is kept hidden as it was, with a warning.
  assert.equal(invalid.totp, undefined);
  assert.deepEqual(invalid.fields.at(-1), { id: "totp", label: "One-time password", kind: "hidden", value: "not a secret!" });
  assert.deepEqual(warnings(report, "totp_invalid"), [10]);
  assert.equal(report.counts.totp, 2);
  // The hidden field is secret by kind.
  assert.equal(steam.fields.at(-1).kind, "hidden");
});

test("a_password_protected_bitwarden_export_is_refused_with_a_clear_text", () => {
  for (const name of ["encrypted.json", "password-protected.json"]) {
    const error = (() => {
      try {
        json(name);
      } catch (e) {
        return e;
      }
    })();
    assert.ok(error instanceof ImportError, name);
    assert.equal(error.code, "import_encrypted_export", name);
    assert.match(error.message, /encrypted/);
    assert.match(error.message, /\.json or \.csv/);
  }
  // `passwordProtected` alone is enough, and so is `encrypted` alone.
  assert.throws(() => fromBitwardenJson(safeJsonParse('{"passwordProtected":true,"items":[]}')), refusal("import_encrypted_export"));
  assert.throws(() => fromBitwardenJson(safeJsonParse('{"encrypted":true}')), refusal("import_encrypted_export"));
  // `encrypted: false` with a `passwordProtected` of false is a plain export.
  assert.doesNotThrow(() => fromBitwardenJson(safeJsonParse('{"encrypted":false,"passwordProtected":false,"items":[{"type":2,"name":"n"}]}')));
});

test("bitwarden_json_refuses_what_is_not_an_export", () => {
  for (const text of ["[]", "5", '"x"', "null", "{}", '{"items":5}', '{"items":{}}']) {
    assert.throws(() => fromBitwardenJson(safeJsonParse(text)), refusal("import_bad_format"), text);
  }
  assert.throws(() => fromBitwardenJson(safeJsonParse('{"items":[]}')), refusal("import_empty"));
  assert.throws(() => fromBitwardenJson(safeJsonParse('{"items":[5]}')), refusal("import_bad_format"));
  assert.throws(() => fromBitwardenJson(safeJsonParse('{"items":[null]}')), refusal("import_bad_format"));
  assert.throws(() => fromBitwardenJson(safeJsonParse('{"items":[[]]}')), refusal("import_bad_format"));
  // Items with nothing but a type still make a draft with a name for it.
  const { drafts } = fromBitwardenJson(safeJsonParse('{"items":[{"type":1},{"type":2},{"type":3},{"type":4}]}'));
  assert.equal(drafts.length, 4);
  assert.ok(drafts.every((d) => d.name === "(no name)"));
  // Odd shapes inside an item are read as empty, never as a crash.
  const odd = fromBitwardenJson(safeJsonParse('{"items":[{"type":1,"name":7,"login":[],"fields":"x"},{"type":3,"card":5},{"type":1,"login":{"uris":[5,null,{"uri":5},{"uri":"https://a.example.test"}],"totp":{}}}]}'));
  assert.equal(odd.drafts.length, 3);
  assert.equal(odd.drafts[0].name, "7");
  assert.deepEqual(odd.drafts[2].urls, [{ url: "https://a.example.test", matching: "host" }]);
});

test("the_fields_of_a_draft_are_well_formed_text", () => {
  const { drafts } = fromBitwardenJson(safeJsonParse('{"items":[{"type":1,"name":"a\\ud800b","notes":"c\\udc00","login":{"username":"u\\ud800","password":"p"}}]}'));
  const text = JSON.stringify(drafts);
  assert.ok(!/\\ud[89ab]|\\ud[c-f]/i.test(text), "no lone surrogate escape");
  assert.equal(drafts[0].name, "a�b");
  assert.equal(drafts[0].notes, "c�");
});

test("bitwarden_csv_maps_logins_and_notes", () => {
  const { drafts, report } = csv(fixture("small.csv"));
  assert.equal(drafts.length, 3);
  const [login, note, quoted] = drafts;

  assert.equal(login.item_type, "login");
  assert.equal(login.name, "Example login");
  assert.equal(login.favorite, true);
  assert.equal(login.notes, "A synthetic login.");
  assert.deepEqual(login.fields, [
    { id: "username", label: "User name", kind: "text", value: "alice@example.test" },
    { id: "password", label: "Password", kind: "password", value: "synthetic-password-1" },
    { id: "address-1", label: "Address", kind: "text", value: "androidapp://example.test.app" },
    { id: "custom-1", label: "Pin", kind: "hidden", value: "0000" },
    { id: "custom-2", label: "Memo", kind: "hidden", value: "none" },
  ]);
  assert.deepEqual(login.urls, [{ url: "https://www.example.test/login", matching: "host" }]);
  assert.deepEqual(login.totp, { uri: "otpauth://totp/?secret=GEZDGNBVGY3TQOJQ" });

  assert.equal(note.item_type, "note");
  assert.equal(note.name, "Example note");
  assert.equal(note.notes, "Line one\nLine two");
  assert.equal(note.favorite, false);
  assert.equal(note.urls, undefined);

  assert.equal(quoted.name, 'Quoted, "name"');
  assert.deepEqual(quoted.urls, [{ url: "https://www.example.test", matching: "host" }]);
  assert.deepEqual(warnings(report, "uri_https_added"), [2]);

  assert.equal(report.counts.items, 3);
  assert.equal(report.counts.login, 2);
  assert.equal(report.counts.note, 1);
  assert.equal(report.counts.customFields, 2);
  assert.equal(report.skipped.folders, 1);
  assert.equal(report.skipped.unknownKeys, 0);
});

test("bitwarden_csv_reads_short_names_odd_types_and_refuses_a_bad_shape", () => {
  // The short column names that other tools write, and a header in capitals.
  const short = csv("NAME,Username,Password,URI,TOTP\nSite,u,p,https://a.example.test,GEZDGNBVGY3TQOJQ\n");
  assert.equal(short.drafts[0].name, "Site");
  assert.deepEqual(short.drafts[0].fields.map((f) => f.value), ["u", "p"]);
  assert.deepEqual(short.drafts[0].urls, [{ url: "https://a.example.test", matching: "host" }]);
  assert.ok(short.drafts[0].totp);
  // A column that is not known is counted; a type that is not login or note is skipped.
  const odd = csv("name,type,extra\nA,card,x\nB,note,y\n");
  assert.equal(odd.drafts.length, 1);
  assert.equal(odd.report.skipped.unknownKeys, 1);
  assert.equal(odd.report.skipped.otherTypes, 1);
  assert.deepEqual(warnings(odd.report, "type_unknown"), [0]);
  // Several addresses on separate lines or separated by commas; a field line without ': ' is left out.
  const many = csv('name,login_uri,fields\nA,"https://a.example.test,https://b.example.test","no delimiter\nk: v"\n');
  assert.equal(many.drafts[0].urls.length, 2);
  assert.deepEqual(warnings(many.report, "field_unreadable"), [0]);
  assert.deepEqual(many.drafts[0].fields, [{ id: "custom-1", label: "k", kind: "hidden", value: "v" }]);
  // The CSV does not say what kind a custom field is: none of them is kept as visible text.
  assert.ok(csv('name,fields\nA,"a: 1\nb: 2"\n').drafts[0].fields.every((f) => f.kind === "hidden"));
  // A missing name column is not a Bitwarden export; a header alone is empty.
  assert.throws(() => csv("a,b\n1,2\n"), refusal("import_bad_format"));
  assert.throws(() => csv("name,type\n"), refusal("import_empty"));
  assert.throws(() => fromBitwardenCsv([]), refusal("import_empty"));
  // A row with more cells than the header is refused with its line (an unquoted comma in a cell).
  assert.throws(
    () => csv("name,notes\nA,b\nB,has, comma\n"),
    (error) => error instanceof ImportError && error.code === "import_bad_csv" && error.line === 3,
  );
  // A short row is fine; its missing cells are empty.
  assert.equal(csv("name,notes,login_username\nA\n").drafts[0].name, "A");
  // Favourite is 1, anything not empty and not 0.
  assert.deepEqual(csv("name,favorite\nA,1\nB,\nC,0\n").drafts.map((d) => d.favorite), [true, false, false]);
});

test("the_labels_a_page_passes_are_the_labels_of_the_fields", () => {
  const labels = { username: "Brukernavn", password: "Passord", totp: "Engangskode", untitled: "(uten navn)" };
  const { drafts } = json("every-type.json", { labels });
  assert.deepEqual(drafts[0].fields.slice(0, 2).map((f) => f.label), ["Brukernavn", "Passord"]);
  assert.equal(drafts[7].fields.at(-1).label, "Engangskode");
});

test("old_passwords_and_the_reprompt_flag_are_counted_as_not_imported", () => {
  const items = [
    { type: 1, name: "A", reprompt: 1, passwordHistory: [{ password: "old-1" }, { password: "old-2" }], login: { username: "u" } },
    { type: 2, name: "B", reprompt: 1 },
    { type: 2, name: "C", reprompt: 0, passwordHistory: [{ password: "old-3" }] },
  ];
  const { drafts, report } = fromBitwardenJson(safeJsonParse(JSON.stringify({ encrypted: false, items })));
  assert.equal(report.skipped.passwordHistory, 3);
  assert.equal(report.skipped.reprompt, 2);
  assert.ok(!JSON.stringify(drafts).includes("old-"));
  // The CSV has the flag too, not the history.
  const rows = csv("name,reprompt\nA,1\nB,0\nC,1\n");
  assert.equal(rows.report.skipped.reprompt, 2);
  assert.equal(rows.report.skipped.passwordHistory, 0);
});

test("the_unknown_keys_of_an_item_that_is_skipped_as_a_whole_are_not_counted", () => {
  const items = [
    { type: 5, name: "ssh", sshKey: {}, extraA: 1 },
    { type: 6, name: "bank", bankAccount: {}, extraB: 1 },
    { type: 2, name: "trash", deletedDate: "2026-01-01T00:00:00.000Z", extraC: 1 },
    { type: 99, name: "odd", extraD: 1 },
    { type: 2, name: "kept", extraE: 1 },
  ];
  const { report } = fromBitwardenJson(safeJsonParse(JSON.stringify({ encrypted: false, items })));
  assert.equal(report.skipped.unknownKeys, 1);
  assert.equal(report.skipped.otherTypes, 3);
  assert.equal(report.skipped.trashed, 1);
});
