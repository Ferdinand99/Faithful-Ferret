// The "Import and export" page behind the side menu entry: two plain choices, one to each page, and the entry stays the
// current one on all three addresses.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createI18n } from "../../src/i18n.mjs";
import { transferView } from "../../src/views/transfer.mjs";
import transferRoute from "../../src/routes/transfer.route.mjs";
import exportRoute from "../../src/routes/export.route.mjs";
import importRoute from "../../src/routes/import.route.mjs";
import { currentEntry, sidebarModel } from "../../src/views/sidebarModel.mjs";
import { web } from "./helpers.mjs";
import { find, textOf, withDom } from "./vaultHelpers.mjs";

const catalog = (lang) => JSON.parse(readFileSync(join(web, "src", "locales", lang, "transfer.json"), "utf8"));

test("the_page_offers_import_and_export_as_two_links", async () => {
  await withDom(async () => {
    for (const [lang, import_, export_] of [["en", "Import", "Export"], ["nb", "Import", "Eksport"]]) {
      const t = createI18n({ en: catalog("en"), nb: catalog("nb") }, lang).t;
      const root = transferView({ t });
      assert.equal(find(root, "transfer-import").getAttribute("href"), "#/import");
      assert.equal(find(root, "transfer-export").getAttribute("href"), "#/export");
      assert.ok(textOf(find(root, "transfer-import")).trim().startsWith(import_), lang);
      assert.ok(textOf(find(root, "transfer-export")).trim().startsWith(export_), lang);
    }
  });
});

test("the_texts_exist_in_both_languages", () => {
  assert.deepEqual(Object.keys(catalog("nb")), Object.keys(catalog("en")));
});

test("the_menu_entry_leads_to_the_page_and_is_current_on_all_three_addresses", () => {
  const sections = sidebarModel({ routes: [transferRoute, exportRoute, importRoute] });
  const entries = sections.flatMap((s) => s.entries).filter((e) => e.kind === "link");
  assert.deepEqual(entries.map((e) => [e.id, e.href, e.role]), [["/transfer", "#/transfer", "nav-transfer"]], "export and import add no entries of their own");
  for (const path of ["/transfer", "/export", "/import"]) assert.equal(currentEntry(sections, path), "/transfer", path);
});

test("the_route_is_not_listed_on_the_account_page", async () => {
  await withDom(async () => {
    assert.equal(transferRoute.path, "/transfer");
    assert.equal(transferRoute.title, "transfer.title");
    assert.equal(transferRoute.menu, undefined, "the account page lists the two pages themselves");
  });
});
