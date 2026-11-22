// The theme choice, the early theme script and the font loader.
// Storage and the page are fakes; no browser is needed.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import vm from "node:vm";
import { bytesFromBase64, FONT_FAMILY, FONT_MODULE, loadInter } from "../../src/font.mjs";
import { applyTheme, createThemeChoice, readTheme, storeTheme, THEME_KEY } from "../../src/theme.mjs";
import { web } from "./helpers.mjs";

/** A storage that remembers what was written, or throws when blocked. */
function memoryStorage(initial = {}, { blocked = false } = {}) {
  const data = new Map(Object.entries(initial));
  const guard = () => {
    if (blocked) throw new DOMException("blocked", "SecurityError");
  };
  return {
    data,
    getItem: (key) => (guard(), data.get(key) ?? null),
    setItem: (key, value) => (guard(), void data.set(key, String(value))),
    removeItem: (key) => (guard(), void data.delete(key)),
  };
}

const fakeRoot = () => {
  const attributes = new Map();
  return {
    attributes,
    setAttribute: (name, value) => void attributes.set(name, value),
    removeAttribute: (name) => void attributes.delete(name),
  };
};


test("the_stored_theme_is_light_dark_or_auto_and_nothing_else", () => {
  assert.equal(readTheme(memoryStorage()), "auto");
  assert.equal(readTheme(memoryStorage({ [THEME_KEY]: "light" })), "light");
  assert.equal(readTheme(memoryStorage({ [THEME_KEY]: "dark" })), "dark");
  assert.equal(readTheme(memoryStorage({ [THEME_KEY]: "purple" })), "auto");
  assert.equal(readTheme(memoryStorage({ [THEME_KEY]: "auto" })), "auto");
  assert.equal(readTheme(null), "auto");
});

test("a_blocked_storage_never_throws_and_the_page_still_changes", () => {
  const blocked = memoryStorage({}, { blocked: true });
  assert.equal(readTheme(blocked), "auto");
  assert.doesNotThrow(() => storeTheme("dark", blocked));
  assert.doesNotThrow(() => storeTheme("auto", blocked));
  assert.doesNotThrow(() => storeTheme("dark", null));
  const root = fakeRoot();
  applyTheme("dark", root);
  assert.equal(root.attributes.get("data-theme"), "dark");
});

test("only_the_one_word_of_the_theme_is_ever_stored", () => {
  const storage = memoryStorage();
  storeTheme("dark", storage);
  assert.deepEqual([...storage.data], [[THEME_KEY, "dark"]]);
  storeTheme("light", storage);
  assert.deepEqual([...storage.data], [[THEME_KEY, "light"]]);
  // Auto stores nothing; anything that is not a theme is not stored either.
  storeTheme("auto", storage);
  assert.equal(storage.data.size, 0);
  storeTheme("s3cret-master-password", storage);
  assert.equal(storage.data.size, 0);
});

test("applying_auto_leaves_the_decision_to_the_system", () => {
  const root = fakeRoot();
  applyTheme("light", root);
  assert.equal(root.attributes.get("data-theme"), "light");
  applyTheme("auto", root);
  assert.equal(root.attributes.has("data-theme"), false);
  applyTheme("nonsense", root);
  assert.equal(root.attributes.has("data-theme"), false);
  assert.doesNotThrow(() => applyTheme("dark", null));
});

test("the_choice_reads_the_stored_word_and_changes_the_page_and_the_storage", () => {
  const storage = memoryStorage({ [THEME_KEY]: "dark" });
  const root = fakeRoot();
  const choice = createThemeChoice({ storage, root });
  assert.equal(choice.current(), "dark");

  choice.set("light");
  assert.equal(root.attributes.get("data-theme"), "light");
  assert.equal(storage.data.get(THEME_KEY), "light");
  assert.equal(choice.current(), "light");

  // System (auto): the page decides again and nothing is stored.
  choice.set("auto");
  assert.equal(root.attributes.has("data-theme"), false);
  assert.equal(storage.data.has(THEME_KEY), false);
  assert.equal(choice.current(), "auto");
});

test("the_choice_ignores_a_word_that_is_not_a_theme_and_survives_a_blocked_storage", () => {
  const storage = memoryStorage({}, { blocked: true });
  const root = fakeRoot();
  const choice = createThemeChoice({ storage, root });
  assert.doesNotThrow(() => choice.set("dark"));
  assert.equal(root.attributes.get("data-theme"), "dark", "the page still changes");
  assert.equal(choice.current(), "auto", "but nothing is remembered");
  choice.set("s3cret-master-password");
  assert.equal(root.attributes.get("data-theme"), "dark", "a word that is not a theme changes nothing");
  assert.equal(memoryStorage().data.size, 0);
});

test("the_choice_is_read_again_so_that_another_tabs_change_shows", () => {
  const storage = memoryStorage();
  const choice = createThemeChoice({ storage, root: fakeRoot() });
  assert.equal(choice.current(), "auto");
  storage.data.set(THEME_KEY, "dark"); // another tab chose
  assert.equal(choice.current(), "dark");
});

test("the_page_has_no_footer_that_adds_height_to_a_short_page", () => {
  const html = readFileSync(join(web, "src", "index.html"), "utf8");
  assert.doesNotMatch(html, /<footer/);
  assert.doesNotMatch(html, /id="foot"/);
  const boot = readFileSync(join(web, "src", "boot.mjs"), "utf8");
  assert.doesNotMatch(boot, /mountFooter|"foot"/);
});

/** Runs theme-init.mjs, a classic script, against a fake page. */
function runEarlyScript({ stored, blocked = false }) {
  const root = fakeRoot();
  const localStorage = memoryStorage(stored === undefined ? {} : { [THEME_KEY]: stored }, { blocked });
  const context = vm.createContext({ document: { documentElement: root }, localStorage });
  vm.runInContext(readFileSync(join(web, "src", "theme-init.mjs"), "utf8"), context);
  return root.attributes;
}

test("the_early_script_applies_a_stored_theme_before_paint_and_survives_blocked_storage", () => {
  assert.equal(runEarlyScript({ stored: "dark" }).get("data-theme"), "dark");
  assert.equal(runEarlyScript({ stored: "light" }).get("data-theme"), "light");
  assert.equal(runEarlyScript({ stored: "auto" }).has("data-theme"), false);
  assert.equal(runEarlyScript({ stored: "x\"><script>" }).has("data-theme"), false);
  assert.equal(runEarlyScript({}).has("data-theme"), false);
  assert.equal(runEarlyScript({ blocked: true }).has("data-theme"), false);
  // A classic script: it must not use module syntax, or the browser would refuse it.
  assert.doesNotMatch(readFileSync(join(web, "src", "theme-init.mjs"), "utf8"), /^\s*(import|export)\s/m);
  // It reads the same key as the module.
  assert.match(readFileSync(join(web, "src", "theme-init.mjs"), "utf8"), new RegExp(`getItem\\("${THEME_KEY}"\\)`));
});

test("base64_text_becomes_the_same_bytes", () => {
  const bytes = Uint8Array.from([0x77, 0x4f, 0x46, 0x32, 0, 255, 128, 1]);
  assert.deepEqual([...bytesFromBase64(Buffer.from(bytes).toString("base64"))], [...bytes]);
});

test("inter_is_added_from_the_shipped_bytes", async () => {
  const bytes = Uint8Array.from([0x77, 0x4f, 0x46, 0x32, 9, 8, 7]);
  const seen = [];
  class FakeFace {
    constructor(family, source, descriptors) {
      Object.assign(this, { family, source, descriptors });
      seen.push(this);
    }
    async load() {
      this.loaded = true;
    }
  }
  const added = [];
  const asked = [];
  const done = await loadInter({
    importModule: async (url) => (asked.push(url), { default: Buffer.from(bytes).toString("base64") }),
    FontFaceClass: FakeFace,
    fonts: { add: (face) => added.push(face) },
  });
  assert.equal(done, true);
  assert.deepEqual(asked, [FONT_MODULE]);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].family, FONT_FAMILY);
  assert.deepEqual([...seen[0].source], [...bytes]);
  assert.deepEqual(seen[0].descriptors, { weight: "100 900", style: "normal", display: "swap" });
  assert.deepEqual(added, [seen[0]]);
});

test("a_font_that_cannot_be_added_leaves_the_system_font_and_throws_nothing", async () => {
  const fonts = { add: () => assert.fail("nothing is added") };
  assert.equal(await loadInter({ FontFaceClass: undefined, fonts }), false);
  assert.equal(await loadInter({ FontFaceClass: class {}, fonts: null }), false);
  assert.equal(await loadInter({ importModule: async () => { throw new Error("404"); }, FontFaceClass: class {}, fonts }), false);
  class Broken {
    async load() {
      throw new Error("bad font");
    }
  }
  assert.equal(await loadInter({ importModule: async () => ({ default: "AAAA" }), FontFaceClass: Broken, fonts }), false);
});
