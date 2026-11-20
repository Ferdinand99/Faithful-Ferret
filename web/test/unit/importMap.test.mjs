// The rules of the translation (addresses, match rules, one-time passwords, labels) and the report.
import assert from "node:assert/strict";
import { test } from "node:test";
import { DEFAULT_LABELS, MAX_WARNINGS, classifyAddress, cardDraft, createReport, identityDraft, loginDraft, mapMatch, mapTotp, noteDraft, resolveLabels, scalar, warn, wellFormed, withTotpAsHidden } from "../../src/import/map.mjs";

const context = (index = 0, labels = resolveLabels(undefined)) => ({ report: createReport(), index, labels });

test("an_address_goes_to_urls_to_a_text_field_or_gets_https", () => {
  /** @type {[string, any][]} */
  const cases = [
    ["https://a.example.test", { kind: "web", url: "https://a.example.test", https: false, http: false }],
    ["http://a.example.test", { kind: "web", url: "http://a.example.test", https: false, http: true }],
    ["HTTP://A.example.test", { kind: "web", url: "HTTP://A.example.test", https: false, http: true }],
    ["www.example.test", { kind: "web", url: "https://www.example.test", https: true, http: false }],
    ["example.test/a?b=1#c", { kind: "web", url: "https://example.test/a?b=1#c", https: true, http: false }],
    ["localhost:8080", { kind: "web", url: "https://localhost:8080", https: true, http: false }],
    ["example.test:443/login", { kind: "web", url: "https://example.test:443/login", https: true, http: false }],
    ["androidapp://com.example", { kind: "text" }],
    ["iosapp://com.example", { kind: "text" }],
    ["javascript:alert(1)", { kind: "text" }],
    ["JavaScript:alert(1)", { kind: "text" }],
    ["data:text/html,<p>", { kind: "text" }],
    ["file:///etc/passwd", { kind: "text" }],
    ["mailto:a@example.test", { kind: "text" }],
    ["tel:+4700000000", { kind: "text" }],
    ["ftp://files.example.test", { kind: "text" }],
    ["//cdn.example.test/x", { kind: "text" }],
    ["/relative/path", { kind: "text" }],
    ["https://has space.example.test", { kind: "text" }],
    ["https://tab\texample.test", { kind: "text" }],
    ["https://nul\u0000.example.test", { kind: "text" }],
    ["https://", { kind: "text" }],
    [`https://example.test/${"a".repeat(9000)}`, { kind: "text" }],
  ];
  for (const [address, expected] of cases) assert.deepEqual(classifyAddress(address), expected, address.slice(0, 60));
});

test("match_rules_never_get_wider", () => {
  assert.deepEqual(mapMatch(null), { matching: "host", defaulted: true });
  assert.deepEqual(mapMatch(undefined), { matching: "host", defaulted: true });
  assert.deepEqual(mapMatch(0), { matching: "domain" });
  assert.deepEqual(mapMatch(1), { matching: "host" });
  assert.deepEqual(mapMatch(3), { matching: "exact" });
  assert.deepEqual(mapMatch(2), { matching: "exact", warning: "match_starts_with" });
  assert.deepEqual(mapMatch(4), { matching: "exact", warning: "match_regex" });
  assert.deepEqual(mapMatch(5), { matching: "host", never: true, warning: "match_never" });
  for (const odd of [6, 99, -1, "1", "host", true, {}, [], 1.5, NaN]) {
    assert.deepEqual(mapMatch(odd), { matching: "exact", warning: "match_unknown" }, String(odd));
  }
  // The strictness order host < domain is the one Ferret has; nothing maps to a rule wider than its source:
  // an unknown or regex rule is never `domain`, and nothing but 0 is `domain`.
  const widest = new Set();
  for (const code of [null, 0, 1, 2, 3, 4, 5, 6, "x"]) if (mapMatch(code).matching === "domain") widest.add(code);
  assert.deepEqual([...widest], [0]);

  // In a draft: `never` never reaches urls, and the other rules arrive as mapped.
  const c = context();
  const draft = loginDraft(
    {
      name: "x",
      uris: [
        { uri: "https://a.example.test", match: 2 },
        { uri: "https://b.example.test", match: 4 },
        { uri: "https://c.example.test", match: 5 },
        { uri: "https://d.example.test", match: 0 },
      ],
    },
    c,
  );
  assert.deepEqual(draft.urls, [
    { url: "https://a.example.test", matching: "exact" },
    { url: "https://b.example.test", matching: "exact" },
    { url: "https://d.example.test", matching: "domain" },
  ]);
  assert.deepEqual(draft.fields, [{ id: "address-1", label: "Address", kind: "text", value: "https://c.example.test" }]);
  assert.deepEqual(c.report.warnings.map((w) => w.code), ["match_starts_with", "match_regex", "match_never"]);
});

test("a_one_time_password_is_read_normalised_or_kept_hidden", () => {
  assert.deepEqual(mapTotp(null), {});
  assert.deepEqual(mapTotp(""), {});
  assert.deepEqual(mapTotp("   "), {});
  assert.deepEqual(mapTotp("otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQ"), { uri: "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQ" });
  assert.deepEqual(mapTotp("  otpauth://totp/?secret=GEZDGNBVGY3TQOJQ&period=60 "), { uri: "otpauth://totp/?secret=GEZDGNBVGY3TQOJQ&period=60" });
  // A bare base32 secret: any case, spaces dropped, fill allowed.
  assert.deepEqual(mapTotp("GEZDGNBVGY3TQOJQ"), { uri: "otpauth://totp/?secret=GEZDGNBVGY3TQOJQ" });
  assert.deepEqual(mapTotp("gezd gnbv gy3t qojq"), { uri: "otpauth://totp/?secret=gezdgnbvgy3tqojq" });
  assert.deepEqual(mapTotp("GEZDGNBVGY3TQOJQ===="), { uri: "otpauth://totp/?secret=GEZDGNBVGY3TQOJQ====" });
  // Steam is kept as it was, hidden, with its own warning.
  assert.deepEqual(mapTotp("steam://GEZDGNBVGY3TQOJQ"), { hidden: "steam://GEZDGNBVGY3TQOJQ", warning: "totp_steam" });
  assert.deepEqual(mapTotp("STEAM://abc"), { hidden: "STEAM://abc", warning: "totp_steam" });
  // Anything that is not a one-time password the core would read.
  for (const bad of ["not a secret!", "otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ&counter=1", "otpauth://", "0189", "GEZD-GNBV!", "otpauth://totp".padEnd(3000, "x").replace("totp", "totp/")]) {
    assert.deepEqual(Object.keys(mapTotp(bad)).sort(), ["hidden", "warning"], bad.slice(0, 40));
    assert.equal(mapTotp(bad).warning, "totp_invalid");
  }
  assert.deepEqual(mapTotp(12345), { hidden: "12345", warning: "totp_invalid" });
  assert.deepEqual(mapTotp({ secret: "x" }), {});

  // The draft form: an address the core refuses moves to a hidden field, as it was in the file.
  const bare = { item_type: "login", name: "x", favorite: false, totp: { uri: "otpauth://totp/?secret=GEZDGNBVGY3TQOJQ" }, fields: [{ id: "username", label: "User", kind: "text", value: "u" }] };
  const hidden = withTotpAsHidden(bare, "One-time password");
  assert.equal(hidden.totp, undefined);
  assert.deepEqual(hidden.fields.at(-1), { id: "totp", label: "One-time password", kind: "hidden", value: "GEZDGNBVGY3TQOJQ" });
  assert.equal(hidden.fields.length, 2);
  const full = withTotpAsHidden({ ...bare, totp: { uri: "otpauth://totp/A?secret=X&period=0" } }, "T");
  assert.equal(full.fields.at(-1).value, "otpauth://totp/A?secret=X&period=0");
  assert.equal(withTotpAsHidden({ item_type: "note", name: "n", favorite: false }, "T"), null);
  // The original draft is not changed.
  assert.ok(bare.totp);
});

test("labels_default_and_a_page_may_translate_them", () => {
  assert.equal(resolveLabels(undefined).password, DEFAULT_LABELS.password);
  const own = resolveLabels({ password: "Passord", username: "  ", field: 5, nope: "x", totp: "x".repeat(500) });
  assert.equal(own.password, "Passord");
  assert.equal(own.username, DEFAULT_LABELS.username);
  assert.equal(own.field, DEFAULT_LABELS.field);
  assert.equal(own.totp, DEFAULT_LABELS.totp);
  assert.equal("nope" in own, false);
  assert.ok(Object.isFrozen(own));
  assert.equal(resolveLabels(null).address, DEFAULT_LABELS.address);
  assert.equal(resolveLabels([]).address, DEFAULT_LABELS.address);
  assert.equal(resolveLabels({ password: "Passord" }).password, "Passord");
  // A lone surrogate in a label is made well-formed.
  assert.equal(resolveLabels({ password: "a\ud800b" }).password, "a�b");
});

test("scalars_are_text_without_lone_surrogates", () => {
  assert.equal(scalar("a\ud800b"), "a�b");
  assert.equal(scalar("\udc00"), "�");
  assert.equal(scalar("😀"), "😀");
  assert.equal(scalar(12), "12");
  assert.equal(scalar(true), "true");
  assert.equal(scalar(null), "");
  assert.equal(scalar(undefined), "");
  assert.equal(scalar({}), "");
  assert.equal(scalar([1]), "");
  assert.equal(scalar(NaN), "");
  assert.equal(wellFormed("ok"), "ok");
});

test("a_draft_has_the_shape_the_vault_takes_and_nothing_else", () => {
  const login = loginDraft(
    { name: "Site", notes: "n", favorite: true, username: "u", password: "p", totp: "GEZDGNBVGY3TQOJQ", uris: [{ uri: "https://x.example.test", match: 1 }], fields: [{ name: "F", value: "v", type: 1 }] },
    context(),
  );
  assert.deepEqual(login, {
    item_type: "login",
    name: "Site",
    favorite: true,
    notes: "n",
    fields: [
      { id: "username", label: "User name", kind: "text", value: "u" },
      { id: "password", label: "Password", kind: "password", value: "p" },
      { id: "custom-1", label: "F", kind: "hidden", value: "v" },
    ],
    urls: [{ url: "https://x.example.test", matching: "host" }],
    totp: { uri: "otpauth://totp/?secret=GEZDGNBVGY3TQOJQ" },
  });
  // A key the vault's draft does not know would be refused; the only keys a draft may have:
  const allowed = new Set(["item_type", "name", "favorite", "fields", "urls", "totp", "notes"]);
  for (const draft of [login, noteDraft({ name: "N", notes: "b" }, context()), cardDraft({ name: "C", card: { number: "1" } }, context()), identityDraft({ name: "I", identity: { email: "a@b" } }, context())]) {
    for (const key of Object.keys(draft)) assert.ok(allowed.has(key), key);
    assert.equal("passkey" in draft, false);
  }
  // An item without a name gets the label for it; field ids are unique in an item.
  const unnamed = loginDraft({ name: "", username: "u", fields: [{ name: "", value: "a" }, { name: "", value: "b" }] }, context());
  assert.equal(unnamed.name, "(no name)");
  assert.deepEqual(unnamed.fields.map((f) => f.id), ["username", "custom-1", "custom-2"]);
  assert.equal(new Set(unnamed.fields.map((f) => f.id)).size, 3);
  assert.equal(unnamed.fields[1].label, "Field");
  // The labels a page passes are used.
  const nb = loginDraft({ name: "", username: "u", password: "p" }, context(0, resolveLabels({ untitled: "(uten navn)", password: "Passord", username: "Brukernavn" })));
  assert.equal(nb.name, "(uten navn)");
  assert.deepEqual(nb.fields.map((f) => f.label), ["Brukernavn", "Passord"]);
});

test("the_report_counts_and_keeps_a_code_and_a_position_only", () => {
  const report = createReport();
  assert.deepEqual(Object.keys(report), ["counts", "skipped", "warnings", "warningsDropped"]);
  assert.deepEqual(Object.keys(report.skipped).sort(), ["collections", "folders", "linked", "otherTypes", "passkeys", "tooLarge", "trashed", "unknownKeys"]);
  warn(report, "x", 4);
  assert.deepEqual(report.warnings, [{ code: "x", index: 4 }]);
  for (let i = 0; i < MAX_WARNINGS + 5; i++) warn(report, "y", i);
  assert.equal(report.warnings.length, MAX_WARNINGS);
  assert.equal(report.warningsDropped, 6);
  // Two reports share nothing.
  assert.notEqual(createReport().counts, createReport().counts);
});
