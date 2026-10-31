// The vault's texts: English and Norwegian have the same keys, and every key the
// vault sources ask for exists, so no screen shows a bare key.
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { ACCOUNT_ERRORS } from "../../src/views/unlock.mjs";
import { web } from "./helpers.mjs";

const read = (lang, name) => JSON.parse(readFileSync(join(web, "src", "locales", lang, `${name}.json`), "utf8"));

/** All catalogs of a language, merged as the build does. */
function catalog(lang) {
  const out = {};
  for (const name of readdirSync(join(web, "src", "locales", lang))) {
    Object.assign(out, read(lang, name.replace(/\.json$/, "")));
  }
  return out;
}

/** The source files of the vault screens. */
const SOURCES = [
  "lock.mjs", "views/common.mjs", "views/shell.mjs", "views/unlock.mjs", "views/list.mjs", "views/item.mjs", "views/edit.mjs",
  "routes/list.route.mjs", "routes/item.route.mjs", "routes/edit.route.mjs", "routes/new.route.mjs", "routes/unlock.route.mjs",
  "routes/home.route.mjs",
];

const text = (file) => readFileSync(join(web, "src", file), "utf8");

test("vault_texts_exist_in_english_and_norwegian_with_the_same_keys", () => {
  const en = read("en", "vault");
  const nb = read("nb", "vault");
  assert.deepEqual(Object.keys(en), Object.keys(nb));
  for (const [key, value] of Object.entries(en)) {
    assert.ok(key.startsWith("vault."), key);
    assert.equal(typeof value, "string");
    assert.ok(value.length > 0 && typeof nb[key] === "string" && nb[key].length > 0, key);
    // The placeholders match between the languages.
    const names = (s) => [...s.matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((m) => m[1]).sort();
    assert.deepEqual(names(nb[key]), names(value), key);
  }
});

test("every_text_key_the_vault_sources_use_is_in_the_catalog", () => {
  const en = catalog("en");
  const nb = catalog("nb");
  /** @type {Set<string>} */
  const used = new Set();
  for (const file of SOURCES) {
    const source = text(file);
    for (const m of source.matchAll(/["'`]((?:vault|sync|home|app)\.[a-z_]+(?:\.[a-z_]+)*)["'`]/g)) used.add(m[1]);
    // Keys built from a code or a mark: the fixed lists in the source name every value.
    for (const m of source.matchAll(/`((?:vault|sync)\.(?:error|mark|type|warning|state))\.\$\{/g)) used.add(`${m[1]}.*`);
  }
  assert.ok(used.size > 60, "the scan found the keys");
  const missing = [...used].filter((key) => !key.endsWith(".*") && !(key in en));
  assert.deepEqual(missing, [], "keys used but not in the English catalog");
  const missingNb = [...used].filter((key) => !key.endsWith(".*") && !(key in nb));
  assert.deepEqual(missingNb, [], "keys used but not in the Norwegian catalog");
});

test("every_code_the_screens_translate_has_a_text", () => {
  const en = catalog("en");
  const source = text("views/common.mjs");
  const lists = [...source.matchAll(/const (SYNC|VAULT)_ERRORS = new Set\(\[([\s\S]*?)\]\)/g)];
  assert.equal(lists.length, 2, "both lists are in the source");
  for (const [, name, body] of lists) {
    const prefix = name === "SYNC" ? "sync.error." : "vault.error.";
    const codes = [...body.matchAll(/"([a-z_]+)"/g)].map((m) => m[1]);
    assert.ok(codes.length > 5);
    for (const code of codes) assert.ok(`${prefix}${code}` in en, `${prefix}${code}`);
  }
  for (const mark of ["damaged", "quarantined", "missing", "blocked", "read_only", "pending"]) assert.ok(`vault.mark.${mark}` in en, mark);
  for (const type of ["login", "note", "card", "identity"]) assert.ok(`vault.type.${type}` in en, type);
  for (const state of ["failed", "idle", "offline", "retrying", "syncing", "unauthorized"]) assert.ok(`sync.state.${state}` in en, state);
});

test("the_vault_sources_never_build_markup_from_text_or_use_a_storage_api", () => {
  for (const file of SOURCES) {
    const source = text(file);
    assert.doesNotMatch(source, /\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write|eval\(|new Function\(/, file);
    assert.doesNotMatch(source, /localStorage|sessionStorage|indexedDB|console\./, `${file} keeps nothing in browser storage and logs nothing`);
  }
});

test("the_unlock_screen_uses_the_sign_in_pages_texts_when_those_are_in_the_build", () => {
  // The texts belong to the account flows. When their catalog is part of the build, every code listed here has one.
  if (!existsSync(join(web, "src", "locales", "en", "account.json"))) return;
  for (const lang of ["en", "nb"]) {
    const texts = catalog(lang);
    for (const code of ACCOUNT_ERRORS) assert.ok(`account.error.${code}` in texts, `${lang}: account.error.${code}`);
    assert.ok("account.error.retry_in" in texts);
  }
});
