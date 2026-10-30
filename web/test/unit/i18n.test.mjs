import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createI18n, negotiate } from "../../src/i18n.mjs";
import { web } from "./helpers.mjs";

const en = { "a.one": "One", "a.hello": "Hello {name}, you have {count} items", "a.only": "Only English" };
const nb = { "a.one": "En", "a.hello": "Hei {name}, du har {count} ting" };

test("i18n_falls_back_to_english_and_records_missing_keys", () => {
  const i18n = createI18n({ en, nb }, "nb");
  assert.equal(i18n.lang, "nb");
  assert.equal(i18n.t("a.one"), "En");
  assert.equal(i18n.t("a.hello", { name: "Kari", count: 3 }), "Hei Kari, du har 3 ting");
  assert.deepEqual(i18n.missing, []);
  assert.equal(i18n.t("a.only"), "Only English");
  assert.equal(i18n.t("a.nowhere"), "a.nowhere");
  i18n.t("a.only");
  assert.deepEqual(i18n.missing, ["a.only", "a.nowhere"]);
  // A variable that is not given stays as written; a value is never read as a pattern.
  assert.equal(i18n.t("a.hello", { name: "$&" }), "Hei $&, du har {count} ting");
  // An unknown language is English, and keys that look like object internals are just missing.
  assert.equal(createI18n({ en }, "fr").lang, "en");
  assert.equal(createI18n({ en }, "en").t("constructor"), "constructor");
  assert.equal(createI18n({ en }, "en").t("a.hello", { name: "x", count: 1 }), "Hello x, you have 1 items");
});

test("negotiate_picks_the_first_supported_language", () => {
  const supported = ["en", "nb"];
  assert.equal(negotiate(["nb-NO", "en"], supported), "nb");
  assert.equal(negotiate(["no"], supported), "nb");
  assert.equal(negotiate(["nn-NO", "en-GB"], supported), "nb");
  assert.equal(negotiate(["de", "en-US"], supported), "en");
  assert.equal(negotiate(["de", "fr"], supported), "en");
  assert.equal(negotiate([], supported), "en");
});

/** The placeholders of a text, sorted. */
const placeholders = (text) => [...text.matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((m) => m[1]).sort();

/** The merged catalog of one language, as the build makes it (all feature files). */
function catalog(lang) {
  const dir = join(web, "src", "locales", lang);
  const out = {};
  for (const name of readdirSync(dir)) Object.assign(out, JSON.parse(readFileSync(join(dir, name), "utf8")));
  return out;
}

test("catalogs_en_and_nb_have_identical_keys_and_placeholders", () => {
  assert.deepEqual(readdirSync(join(web, "src", "locales")).sort(), ["en", "nb"]);
  assert.deepEqual(readdirSync(join(web, "src", "locales", "en")), readdirSync(join(web, "src", "locales", "nb")));
  const english = catalog("en");
  const norwegian = catalog("nb");
  assert.deepEqual(Object.keys(norwegian).sort(), Object.keys(english).sort());
  for (const key of Object.keys(english)) {
    assert.deepEqual(placeholders(norwegian[key]), placeholders(english[key]), key);
    assert.notEqual(english[key].trim(), "", key);
    assert.notEqual(norwegian[key].trim(), "", key);
  }
});
