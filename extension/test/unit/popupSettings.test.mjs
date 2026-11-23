// The "Settings" button in the popup's header: it opens the settings page and closes the popup, in every build.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { openSettings } from "../../src/pages/popupSettings.mjs";

const src = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "src");

test("the_popup_settings_button_opens_the_options_page_and_closes_the_popup", async () => {
  /** @type {string[]} */
  const log = [];
  assert.equal(await openSettings({ runtime: { openOptionsPage: async () => void log.push("open") }, close: () => void log.push("close") }), true);
  assert.deepEqual(log, ["open", "close"], "the page is opened first, then the popup closes");
  // A browser that cannot open it leaves the popup as it is.
  log.length = 0;
  assert.equal(await openSettings({ runtime: { openOptionsPage: () => Promise.reject(new Error("no")) }, close: () => void log.push("close") }), false);
  assert.equal(await openSettings({ runtime: { openOptionsPage: () => { throw new Error("no"); } }, close: () => void log.push("close") }), false);
  assert.deepEqual(log, []);
});

test("the_popup_settings_item_has_a_name_in_both_languages_and_opens_the_page_through_the_bar", () => {
  const html = readFileSync(join(src, "pages", "popup.html"), "utf8");
  assert.equal(html.includes('id="settings"'), false, "the entry is in the bottom bar, not in the header");
  for (const lang of ["en", "nb"]) {
    const catalog = JSON.parse(readFileSync(join(src, "locales", lang, "session.json"), "utf8"));
    assert.equal(typeof catalog["session.settings"], "string", lang);
  }
  const popup = readFileSync(join(src, "pages", "popup.mjs"), "utf8");
  assert.match(popup, /onSettings: \(\) => void openSettings\(\{ runtime: browser\.runtime/);
});
