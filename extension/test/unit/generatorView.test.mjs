// The generator's part of the popup (generatorView.mjs, popupTabs.mjs), on a small stand-in for the DOM with the texts of
// the built package: the tabs exist only with the feature `save` on; the options are the popup's own, kept in
// `storage.local` and never a value; the value is shown from what the background answered and is never sent back; the
// view knows a text for every reason the handler can give, in both languages.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { test } from "node:test";
import { build } from "../../scripts/build.mjs";
import { makeRoot } from "./buildHelpers.mjs";
import { byRole, click, fire, one, settle, textsOf, useDocument, withAttribute } from "./pageDom.mjs";
import { pkg } from "./sessionHelpers.mjs";

const SENTINEL = "Sentinel-Zq9!-never-stored";
const GENERATION = "a".repeat(32);

/** The package's module `path`, its English texts, and its catalog of a language. @param {string} dir */
function packageOf(dir) {
  return {
    load: (/** @type {string} */ path) => import(pathToFileURL(join(dir, ...path.split("/"))).href),
    texts: (/** @type {string} */ lang) => textsOf(JSON.parse(readFileSync(join(dir, `locales.${lang}.json`), "utf8")), lang),
    catalog: (/** @type {string} */ lang) => JSON.parse(readFileSync(join(dir, `locales.${lang}.json`), "utf8")),
  };
}

/**
 * A fake `storage.local` that keeps every write.
 * @param {Record<string, unknown>} [start]
 */
function fakeArea(start = {}) {
  /** @type {Map<string, unknown>} */
  const data = new Map(Object.entries(start));
  /** @type {string[]} */
  const writes = [];
  return {
    data,
    writes,
    get: async (/** @type {string} */ key) => (data.has(key) ? { [key]: structuredClone(data.get(key)) } : {}),
    set: async (/** @type {Record<string, unknown>} */ items) => {
      for (const [key, value] of Object.entries(items)) {
        writes.push(JSON.stringify({ [key]: value }));
        data.set(key, structuredClone(value));
      }
    },
  };
}

/**
 * The generator's requests as a fake background answers them: every request is kept; a value is made for `generate`.
 * @param {{ answer?: (type: string, body: any) => any }} [options]
 */
function fakeBackground({ answer } = {}) {
  /** @type {Array<{ type: string, body: any }>} */
  const requests = [];
  let count = 0;
  /** @type {string | null} */
  let held = null;
  const request = async (/** @type {string} */ type, /** @type {any} */ body) => {
    requests.push({ type, body });
    const custom = answer?.(type, body);
    if (custom !== undefined) return custom;
    if (type === "generate" && body.current === true) {
      return held === null ? { ok: false, reason: "nothing_kept" } : { ok: true, generation_id: GENERATION, value: held, kind: "password", bits: 120, expires_at: 99 };
    }
    if (type === "generate") {
      count += 1;
      held = `${SENTINEL}-${count}`;
      return { ok: true, generation_id: GENERATION, value: held, kind: body.kind, bits: body.kind === "passphrase" ? 65 : 120, expires_at: 99 };
    }
    return { ok: true, length: undefined, offer: false };
  };
  return { requests, request };
}

/** Every `data-role` below the root, for a quick look at what is shown. @param {any} root @param {string} role */
const roles = (root, role) => byRole(root, role);

test("the_bottom_bar_shows_vault_health_and_settings_and_with_the_save_feature_on_the_generator_too", async () => {
  useDocument();
  // The test variant: three items, the generator's part made only when its item is first chosen.
  const on = packageOf((await pkg()).dir);
  const tabsOn = await on.load("pages/popupTabs.mjs");
  const el = (await on.load("shared/dom.mjs")).el;
  const vault = el("div", { "data-role": "vault-list" }, "the vault");
  let made = 0;
  let settingsMade = 0;
  const tabs = tabsOn.createPopupTabs({
    texts: on.texts("en"),
    vault,
    makeGenerator: () => {
      made += 1;
      return el("section", { "data-role": "generator" });
    },
    makeSettings: () => {
      settingsMade += 1;
      return el("section", { "data-role": "settings-view" });
    },
  });
  assert.notEqual(tabs.root, vault);
  const names = ["tab-vault", "tab-generator", "tab-settings"].map((role) => one(tabs.root, role)?.textContent);
  assert.deepEqual(roles(tabs.root, "tabs")[0].childNodes.map((n) => /** @type {any} */ (n).getAttribute("data-role")), ["tab-vault", "tab-generator", "tab-health", "tab-settings"], "the order of the layout");
  assert.deepEqual(names, ["Vault", "Generator", "Settings"]);
  assert.equal(one(tabs.root, "tab-health")?.getAttribute("aria-disabled"), "true", "Health is in the bar, not available yet");
  assert.equal(one(tabs.root, "tabs")?.tagName, "NAV");
  assert.equal(made, 0, "opening the popup makes no generator");
  assert.equal(tabs.selected(), "vault");
  assert.equal(one(tabs.root, "panel-generator")?.hidden, true);
  assert.equal(one(tabs.root, "tab-vault")?.getAttribute("aria-current"), "page");
  assert.equal(one(tabs.root, "tab-generator")?.hasAttribute("aria-current"), false);
  // "Health" has no view yet: disabled, tagged, still in the tab order (a disabled item of a bar stays focusable, so that it is
  // found and read as disabled), and a click does nothing.
  const health = one(tabs.root, "tab-health");
  assert.equal(health?.hasAttribute("tabindex"), false, "a button's own place in the tab order, not taken out of it");
  assert.equal(one(health, "tab-soon")?.textContent, "Coming soon");
  assert.equal(health?.getAttribute("title"), "Coming soon");
  assert.equal(health?.textContent, "Health Coming soon", "the name reads Health, then the tag");
  assert.equal(one(tabs.root, "tabs")?.getAttribute("aria-label"), "Navigation");
  const nb = tabsOn.createPopupTabs({ texts: on.texts("nb"), vault: el("div"), makeGenerator: () => null, makeSettings: () => null });
  assert.equal(one(nb.root, "tab-vault")?.textContent, "Hvelv");
  assert.equal(one(nb.root, "tab-health")?.textContent, "Helse Kommer snart");
  assert.equal(one(nb.root, "tabs")?.getAttribute("aria-label"), "Navigasjon");
  await click(health);
  assert.equal(tabs.selected(), "vault", "a click on Health changes nothing");
  assert.equal(health?.hasAttribute("aria-current"), false);
  // The generator's item: its part is made once, shown, and the vault's part is only hidden (still in the page).
  await click(one(tabs.root, "tab-generator"));
  assert.equal(made, 1);
  assert.equal(tabs.selected(), "generator");
  assert.equal(one(tabs.root, "panel-generator")?.hidden, false);
  assert.equal(one(tabs.root, "panel-vault")?.hidden, true);
  assert.equal(roles(tabs.root, "vault-list").length, 1);
  assert.equal(one(tabs.root, "tab-generator")?.getAttribute("aria-current"), "page");
  assert.equal(one(tabs.root, "tab-vault")?.hasAttribute("aria-current"), false);
  await click(one(tabs.root, "tab-vault"));
  await click(one(tabs.root, "tab-generator"));
  assert.equal(made, 1, "the generator is made once");
  // "Settings" is a part of the popup like the others: made once, on the first choice of its item, shown with the mark, and no
  // tab or page is opened (the popup is given nothing to open one with).
  assert.equal(settingsMade, 0, "opening the popup asks nothing of the settings");
  assert.equal(one(tabs.root, "panel-settings")?.hidden, true);
  await click(one(tabs.root, "tab-settings"));
  assert.equal(settingsMade, 1);
  assert.equal(tabs.selected(), "settings");
  assert.equal(one(tabs.root, "panel-settings")?.hidden, false);
  assert.equal(roles(tabs.root, "settings-view").length, 1);
  assert.equal(one(tabs.root, "panel-vault")?.hidden, true);
  assert.equal(one(tabs.root, "panel-generator")?.hidden, true);
  assert.equal(one(tabs.root, "tab-settings")?.getAttribute("aria-current"), "page");
  assert.equal(one(tabs.root, "tab-generator")?.hasAttribute("aria-current"), false);
  await click(one(tabs.root, "tab-vault"));
  await click(one(tabs.root, "tab-settings"));
  assert.equal(settingsMade, 1, "the settings part is made once");
  assert.equal(one(tabs.root, "tab-settings")?.getAttribute("aria-current"), "page");
  await click(one(tabs.root, "tab-generator"));
  assert.equal(tabs.selected(), "generator", "the popup goes on to the part chosen");
  assert.equal(one(tabs.root, "tab-settings")?.hasAttribute("aria-current"), false);
  // Every item is a button (operable with the keyboard) with an icon that screen readers skip; only the generator's item and
  // part carry the mark that the release check looks for.
  for (const role of ["tab-vault", "tab-generator", "tab-settings"]) assert.equal(one(tabs.root, role)?.tagName, "BUTTON", role);
  assert.deepEqual(withAttribute(tabs.root, "data-feature").map((n) => n.getAttribute("data-role")), ["tab-generator"]);

  // A build with the feature off (a test build with --features none): the bar is Vault, Health and Settings; no generator.
  const env = makeRoot();
  try {
    const release = await build({ root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, out: env.out, manifest: "mv2", variant: "test", features: [] });
    const off = packageOf(release.dir);
    const tabsOff = await off.load("pages/popupTabs.mjs");
    const offVault = el("div", { "data-role": "vault-list" }, "the vault");
    let madeOff = 0;
    let settingsOff = 0;
    const plain = tabsOff.createPopupTabs({
      texts: off.texts("en"),
      vault: offVault,
      makeGenerator: () => { madeOff += 1; return el("section"); },
      makeSettings: () => { settingsOff += 1; return el("section", { "data-role": "settings-view" }); },
    });
    assert.deepEqual(roles(plain.root, "tab-vault").length + roles(plain.root, "tab-settings").length, 2);
    assert.equal(roles(plain.root, "tab-generator").length, 0);
    assert.deepEqual(withAttribute(plain.root, "data-feature"), []);
    assert.deepEqual(["tab-vault", "tab-settings"].map((role) => one(plain.root, role)?.textContent), ["Vault", "Settings"]);
    assert.deepEqual(roles(plain.root, "tabs")[0].childNodes.map((n) => /** @type {any} */ (n).getAttribute("data-role")), ["tab-vault", "tab-health", "tab-settings"], "Vault, Health (not yet) and Settings");
    assert.equal(one(plain.root, "tab-health")?.getAttribute("aria-disabled"), "true");
    assert.equal(one(plain.root, "tab-health")?.textContent, "Health Coming soon", "the bar's own texts are there without the feature");
    assert.equal(one(plain.root, "tabs")?.getAttribute("aria-label"), "Navigation");
    await click(one(plain.root, "tab-health"));
    assert.equal(plain.selected(), "vault");
    assert.equal(one(plain.root, "tab-vault")?.getAttribute("aria-current"), "page");
    plain.select("generator");
    assert.equal(madeOff, 0);
    assert.equal(plain.selected(), "vault");
    await click(one(plain.root, "tab-settings"));
    assert.equal(settingsOff, 1, "settings is shown in every build");
    assert.equal(plain.selected(), "settings");
    assert.equal(one(plain.root, "tab-settings")?.getAttribute("aria-current"), "page");
    // The view is not made either.
    const viewOff = await off.load("pages/generatorView.mjs");
    assert.equal(viewOff.createGeneratorView({ texts: off.texts("en"), flow: {}, store: {}, tabId: 1 }), null);
    // And the popup page asks FEATURES before it builds either (the check of a build with the feature off lists a page that does not).
    assert.match(release.files.get("pages/popup.mjs")?.toString("utf8") ?? "", /FEATURES\.save/);
    assert.match(release.files.get("pages/popupTabs.mjs")?.toString("utf8") ?? "", /FEATURES\.save/);
    assert.match(release.files.get("pages/generatorView.mjs")?.toString("utf8") ?? "", /FEATURES\.save/);
  } finally {
    env.cleanup();
  }
});

test("options_are_kept_in_storage_local_and_never_the_value", async () => {
  useDocument();
  const pack = packageOf((await pkg()).dir);
  const mod = await pack.load("pages/generatorView.mjs");
  const area = fakeArea({ generator_options: { kind: "password", length: 33, lower: true, upper: false, digits: true, symbols: false, min_each: 1, avoid_ambiguous: true, words: 7, separator: ".", capitalize: false, number: true } });
  const background = fakeBackground();
  const view = mod.createGeneratorView({
    texts: pack.texts("en"),
    flow: mod.createGeneratorFlow(background.request),
    store: mod.createOptionsStore(area),
    tabId: 7,
  });
  await view.ready;
  await settle();
  // The stored options were used for the first value, and the page shows them.
  assert.deepEqual(background.requests.map((r) => r.type), ["generate", "generate"]);
  assert.deepEqual(background.requests[0].body, { current: true });
  assert.deepEqual(background.requests[1].body, { kind: "password", length: 33, lower: true, upper: false, digits: true, symbols: false, min_each: 1, avoid_ambiguous: true });
  assert.equal(/** @type {any} */ (one(view.root, "option-length")).value, "33");
  assert.equal(/** @type {any} */ (one(view.root, "option-upper")).checked, false);
  assert.equal(/** @type {any} */ (one(view.root, "option-avoid_ambiguous")).checked, true);
  assert.equal(one(view.root, "generated-value")?.textContent, `${SENTINEL}-1`);
  assert.equal(area.writes.length, 0, "showing the options writes nothing");

  // A change is kept, as options, and makes a new value.
  const symbols = /** @type {any} */ (one(view.root, "option-symbols"));
  symbols.checked = true;
  fire(symbols, "change");
  await settle();
  const length = /** @type {any} */ (one(view.root, "option-length"));
  length.value = "40";
  fire(length, "change");
  await settle();
  await click(one(view.root, "kind-passphrase"));
  assert.ok(area.writes.length >= 3);
  assert.deepEqual(JSON.parse(/** @type {string} */ (area.writes.at(-1))), { generator_options: { kind: "passphrase", length: 40, lower: true, upper: false, digits: true, symbols: true, min_each: 1, avoid_ambiguous: true, words: 7, separator: ".", capitalize: false, number: true } });
  // What went into storage is the options and nothing the background answered with, whatever it was.
  for (const write of area.writes) {
    assert.deepEqual(Object.keys(JSON.parse(write)), ["generator_options"]);
    assert.equal(write.includes(SENTINEL), false);
  }
  assert.equal(JSON.stringify([...area.data]).includes(SENTINEL), false);
  // The passphrase request has the options of a passphrase only.
  assert.deepEqual(background.requests.at(-1)?.body, { kind: "passphrase", words: 7, separator: ".", capitalize: false, number: true });

  // A stored value is never trusted: out of range, the wrong type or a key it should not have gives the default.
  const sane = mod.readOptions({ kind: "x", length: 5000, lower: "yes", upper: 1, digits: null, symbols: "no", words: 1, separator: "ab", surprise: 1 });
  assert.deepEqual(sane, mod.readOptions(null));
  assert.deepEqual(Object.keys(sane).sort(), Object.keys(mod.DEFAULT_OPTIONS).sort());
  assert.deepEqual({ ...mod.DEFAULT_OPTIONS }, { kind: "password", length: 20, lower: true, upper: true, digits: true, symbols: true, min_each: 1, avoid_ambiguous: false, words: 5, separator: "-", capitalize: true, number: false });
  // At least one class stays on: turning the last one off turns them all on.
  assert.equal(mod.readOptions({ lower: false, upper: false, digits: false, symbols: false }).lower, true);
  // A storage that fails costs the options, not the generator.
  const broken = mod.createOptionsStore({ get: async () => Promise.reject(new Error("no")), set: async () => Promise.reject(new Error("no")) });
  assert.deepEqual(await broken.load(), mod.readOptions(null));
  await broken.save(mod.readOptions(null));
  // A positive control: the spy on the storage does see a write that is not an option.
  await area.set({ other: SENTINEL });
  assert.ok(area.writes.some((w) => w.includes(SENTINEL)));
});

test("the_view_shows_what_the_background_still_holds_and_never_sends_the_value_back", async () => {
  useDocument();
  const pack = packageOf((await pkg()).dir);
  const mod = await pack.load("pages/generatorView.mjs");
  const background = fakeBackground();
  const area = fakeArea();
  /** @type {any[]} */
  const views = [];
  const open = async (/** @type {number | null} */ tabId) => {
    const view = mod.createGeneratorView({ texts: pack.texts("en"), flow: mod.createGeneratorFlow(background.request), store: mod.createOptionsStore(area), tabId, onOffer: () => views.push("offer") });
    await view.ready;
    await settle();
    return view;
  };
  const first = await open(7);
  assert.equal(one(first.root, "generated-value")?.textContent, `${SENTINEL}-1`);
  assert.match(one(first.root, "generator-strength")?.textContent ?? "", /Very strong: about 120 bits/);
  // Opened again (the popup was closed): the value the background holds is shown, not a new one.
  const again = await open(7);
  assert.equal(one(again.root, "generated-value")?.textContent, `${SENTINEL}-1`);
  assert.equal(background.requests.filter((r) => r.type === "generate" && r.body.current !== true).length, 1);

  // "Fill in the page" and "Copy" send the generation and the tab; the value never goes back.
  await click(one(again.root, "fill"));
  await click(one(again.root, "copy"));
  const sent = background.requests.filter((r) => r.type === "fill_generated" || r.type === "generate_copy");
  assert.deepEqual(sent.map((r) => [r.type, r.body]), [
    ["fill_generated", { generation_id: GENERATION, tab_id: 7 }],
    ["generate_copy", { generation_id: GENERATION }],
  ]);
  assert.equal(JSON.stringify(sent).includes(SENTINEL), false);
  assert.match(one(again.root, "generator-status")?.textContent ?? "", /Copied/);

  // "Make a new one" asks the core again with the options.
  await click(one(again.root, "regenerate"));
  assert.equal(one(again.root, "generated-value")?.textContent, `${SENTINEL}-2`);
  // The strength follows the estimate the core gave, in whole bits.
  await click(one(again.root, "kind-passphrase"));
  assert.match(one(again.root, "generator-strength")?.textContent ?? "", /Strong: about 65 bits/);
  assert.deepEqual([mod.strengthOf(10), mod.strengthOf(40), mod.strengthOf(64), mod.strengthOf(100)], ["weak", "fair", "strong", "very_strong"]);

  // No page (the popup is about no tab): the value can be copied, not filled.
  const nowhere = await open(null);
  assert.equal(nowhere.root.getAttribute("data-feature"), "save");
  assert.equal(one(nowhere.root, "fill")?.hasAttribute("disabled"), true);
  assert.equal(one(nowhere.root, "copy")?.hasAttribute("disabled"), false);
  assert.ok(one(nowhere.root, "generator-no-page"));

  // A field that took fewer characters: the view asks what the background holds now and says why it is shorter.
  const shortened = {
    request: async (/** @type {string} */ type, /** @type {any} */ body) => {
      if (type === "fill_generated") return { ok: true, length: 5, offer: true };
      const value = type === "generate" && body.current === true && shortened.filled ? "Short" : "Longer-value-here";
      if (type === "generate" && body.current === true && !shortened.filled) return { ok: false, reason: "nothing_kept" };
      return { ok: true, generation_id: GENERATION, value, kind: "password", bits: 80, expires_at: 99 };
    },
    filled: false,
  };
  const view2 = mod.createGeneratorView({
    texts: pack.texts("en"),
    flow: mod.createGeneratorFlow(async (/** @type {string} */ type, /** @type {any} */ body) => {
      const reply = await shortened.request(type, body);
      if (type === "fill_generated") shortened.filled = true;
      return reply;
    }),
    store: mod.createOptionsStore(fakeArea()),
    tabId: 7,
    onOffer: () => views.push("offer"),
  });
  await view2.ready;
  await settle();
  assert.equal(one(view2.root, "generated-value")?.textContent, "Longer-value-here");
  await click(one(view2.root, "fill"));
  assert.equal(one(view2.root, "generated-value")?.textContent, "Short");
  assert.match(one(view2.root, "generator-status")?.textContent ?? "", /at most 5 characters/);
  assert.ok(views.includes("offer"), "the offer was announced");

  // A refusal shows its text and never the code.
  const refused = fakeBackground({ answer: (type) => (type === "fill_generated" ? { ok: false, reason: "field_too_short" } : undefined) });
  const view3 = mod.createGeneratorView({ texts: pack.texts("en"), flow: mod.createGeneratorFlow(refused.request), store: mod.createOptionsStore(fakeArea()), tabId: 7 });
  await view3.ready;
  await settle();
  await click(one(view3.root, "fill"));
  const status = one(view3.root, "generator-status");
  assert.equal(status?.hidden, false);
  assert.equal(status?.getAttribute("data-tone"), "bad");
  assert.match(status?.textContent ?? "", /at least 8 characters and fits the field/);
  assert.equal((status?.textContent ?? "").includes("field_too_short"), false);
});

test("every_reason_the_generator_can_give_has_a_text_in_both_languages", async () => {
  const pack = packageOf((await pkg()).dir);
  const mod = await pack.load("pages/generatorView.mjs");
  const handler = await pack.load("background/handlers/generator.handler.mjs");
  assert.deepEqual([...mod.ERROR_REASONS].sort(), [...handler.REASONS, "frame_unchecked"].sort());
  for (const lang of ["en", "nb"]) {
    const catalog = pack.catalog(lang);
    for (const reason of mod.ERROR_REASONS) assert.equal(typeof catalog[`generator.error.${reason}`], "string", `${lang} ${reason}`);
    for (const key of Object.keys(catalog).filter((k) => k.startsWith("generator."))) {
      assert.notEqual(catalog[key].trim(), "", `${lang} ${key}`);
    }
  }
  const en = Object.keys(pack.catalog("en")).filter((k) => k.startsWith("generator.")).sort();
  const nb = Object.keys(pack.catalog("nb")).filter((k) => k.startsWith("generator.")).sort();
  assert.deepEqual(nb, en, "the two languages have the same texts");
  // What the handler maps: an unknown code is "unknown", the fill script's own words are the page's words.
  assert.equal(handler.reasonOf("surprise"), "unknown");
  assert.equal(handler.reasonOf("hidden"), "covered");
  assert.equal(handler.reasonOf("gone"), "frame_gone");
  assert.equal(handler.reasonOf("worker_failed"), "vault_locked");
  assert.equal(mod.errorKey("surprise"), "generator.error.unknown");
  // Every reason a fill can end with is one the page has a text for.
  for (const reason of ["not_offered", "origin_changed", "busy", "frame_gone", "no_report", "no_fields", "no_answer", "value_too_long", "wrong_kind", "covered", "frame_hidden", "field_too_short", "insecure_page", "vault_locked"]) {
    assert.ok(mod.ERROR_REASONS.includes(reason), reason);
  }
});

test("a_partial_fill_that_still_holds_an_offer_tells_the_popup_so_the_card_shows", async () => {
  useDocument();
  const pack = packageOf((await pkg()).dir);
  const mod = await pack.load("pages/generatorView.mjs");
  /** @type {string[]} */
  const told = [];
  // One field took the value and the next was covered: the fill refuses, and the background still holds the offer.
  const partial = fakeBackground({ answer: (type) => (type === "fill_generated" ? { ok: false, reason: "covered", offer: true } : undefined) });
  const view = mod.createGeneratorView({ texts: pack.texts("en"), flow: mod.createGeneratorFlow(partial.request), store: mod.createOptionsStore(fakeArea()), tabId: 7, onOffer: () => told.push("offer") });
  await view.ready;
  await settle();
  await click(one(view.root, "fill"));
  assert.deepEqual(told, ["offer"], "the popup is told of the offer");
  assert.equal(one(view.root, "generator-status")?.getAttribute("data-tone"), "bad", "the refusal is still shown");
  // A refusal with no offer does not announce one.
  const plain = fakeBackground({ answer: (type) => (type === "fill_generated" ? { ok: false, reason: "covered" } : undefined) });
  const other = mod.createGeneratorView({ texts: pack.texts("en"), flow: mod.createGeneratorFlow(plain.request), store: mod.createOptionsStore(fakeArea()), tabId: 7, onOffer: () => told.push("offer") });
  await other.ready;
  await settle();
  await click(one(other.root, "fill"));
  assert.deepEqual(told, ["offer"]);
});
