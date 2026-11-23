// The settings page: the one options page of the add-on, opened in a tab, with
// the one setting "Lock after" as a select of the fixed choices. The steps of
// the page have no DOM, so the tests run them as they are.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { join as joinPath } from "node:path";
import { pathToFileURL } from "node:url";
import { build } from "../../scripts/build.mjs";
import { LOCK_CHOICES, captureErrorKey, choiceKey, createSettingsFlow, errorKey } from "../../src/pages/settingsFlow.mjs";
import { UiError } from "../../src/pages/ui.mjs";
import { UI_TYPES, encode } from "../../src/shared/protocol.mjs";
import { extensionRoot, makeRoot } from "./buildHelpers.mjs";
import { importsOf } from "./importGraph.mjs";
import { byRole, one, textsOf, useDocument } from "./pageDom.mjs";

/** A `request` that records what the page asks and answers from `answer`. */
function recorder(/** @type {(body: any) => any} */ answer = (body) => ({ lock_seconds: body.lock_seconds ?? 900 })) {
  /** @type {Array<[string, any]>} */
  const sent = [];
  /** @type {import("../../src/pages/ui.mjs").Request} */
  const request = async (type, body) => {
    // What a page sends must pass the protocol.
    encode(type, body);
    sent.push([type, body]);
    return answer(body);
  };
  return { request, sent };
}

test("settings_open_in_a_tab", async () => {
  for (const manifest of ["mv3", "mv2"]) {
    for (const variant of ["release", "test"]) {
      const env = makeRoot();
      try {
        const result = await build({ root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath, manifest, variant });
        const json = JSON.parse(readFileSync(join(result.dir, "manifest.json"), "utf8"));
        const where = `${manifest} ${variant}`;
        // The options page is the settings page, and the browser opens it in a tab of its own (not inside about:addons).
        assert.deepEqual(json.options_ui, { open_in_tab: true, page: "pages/settings.html" }, where);
        // The page is in the package, with one script (its own module) and nothing inline.
        const html = result.files.get("pages/settings.html")?.toString("utf8") ?? "";
        assert.ok(html.length > 0, `${where}: pages/settings.html`);
        assert.deepEqual([...html.matchAll(/<script\b([^>]*)>/g)].map((m) => m[1].trim()), ['type="module" src="settings.mjs"'], where);
        assert.doesNotMatch(html, /\son[a-z]+\s*=|\sstyle\s*=|<style|javascript:/i, where);
        // Like the other pages it is never reachable from a web page, and it reaches nothing of the background.
        assert.equal("web_accessible_resources" in json, false, where);
        for (const file of ["pages/settings.mjs", "pages/settingsFlow.mjs"]) {
          const module = result.files.get(file)?.toString("utf8") ?? "";
          assert.ok(module.length > 0, `${where}: ${file}`);
          for (const specifier of importsOf(module).specifiers) assert.doesNotMatch(specifier, /background\//, `${where}: ${file} imports ${specifier}`);
        }
        // The settings handler is in the register of the build, and so is the lock handler.
        const register = result.files.get("background/handlers.gen.mjs")?.toString("utf8") ?? "";
        assert.ok(register.includes("./handlers/settings.handler.mjs") && register.includes("./handlers/lock.handler.mjs"), where);
      } finally {
        env.cleanup();
      }
    }
  }
});

test("the_settings_page_reads_and_saves_only_the_listed_choices", async () => {
  const { request, sent } = recorder();
  const flow = createSettingsFlow(request);
  assert.deepEqual(await flow.load(), { ok: true, seconds: 900 });
  assert.deepEqual(sent, [["settings", {}]]);
  for (const seconds of LOCK_CHOICES) {
    assert.deepEqual(await flow.setLockSeconds(seconds), { ok: true, seconds });
    assert.deepEqual(sent.at(-1), ["settings", { lock_seconds: seconds }]);
  }
  // Anything else is refused on the page and never sent.
  const count = sent.length;
  for (const bad of [0, 14, 16, 45, 90, 1000, 86_401, 1.5, -15, NaN, Infinity, "300", null, undefined, true, {}]) {
    assert.deepEqual(await flow.setLockSeconds(bad), { ok: false, reason: "invalid_input" }, String(bad));
  }
  assert.equal(sent.length, count, "nothing went out");
});

test("the_settings_page_shows_a_refusal_or_an_odd_answer_as_a_reason_and_never_a_value", async () => {
  const refusing = createSettingsFlow(async () => Promise.reject(new UiError("internal_error")));
  assert.deepEqual(await refusing.setLockSeconds(60), { ok: false, reason: "internal_error" });
  const gone = createSettingsFlow(async () => Promise.reject(new UiError("disconnected")));
  assert.deepEqual(await gone.load(), { ok: false, reason: "disconnected" });
  // A background that answers with a value outside the list is not believed.
  for (const answer of [{ lock_seconds: 45 }, { lock_seconds: "900" }, {}, null, { lock_seconds: 0 }]) {
    const odd = createSettingsFlow(async () => answer);
    assert.deepEqual(await odd.load(), { ok: false, reason: "internal_error" }, JSON.stringify(answer));
  }
  assert.equal(errorKey("invalid_input"), "settings.error.invalid_input");
  assert.equal(errorKey("<script>"), "settings.error.unknown");
  assert.equal(errorKey(undefined), "settings.error.unknown");
});

test("every_settings_text_is_there_in_both_languages", () => {
  const read = (/** @type {string} */ lang) => JSON.parse(readFileSync(join(extensionRoot, "src", "locales", lang, "settings.json"), "utf8"));
  const [en, nb] = [read("en"), read("nb")];
  assert.deepEqual(Object.keys(en).sort(), Object.keys(nb).sort(), "the same keys in en and nb");
  const keys = [
    "settings.title",
    "settings.lock.label",
    "settings.lock.hint",
    "settings.saved",
    ...LOCK_CHOICES.map(choiceKey),
    ...["invalid_input", "internal_error", "disconnected", "unknown"].map(errorKey),
  ];
  for (const key of keys) {
    for (const [lang, texts] of [["en", en], ["nb", nb]]) assert.ok(typeof texts[key] === "string" && texts[key].length > 0, `${lang}: ${key}`);
  }
  // Exactly the choices of the list have a text; the two languages say different things.
  const choiceTexts = Object.keys(en).filter((k) => k.startsWith("settings.lock.choice."));
  assert.equal(choiceTexts.length, LOCK_CHOICES.length);
  assert.equal(en["settings.lock.choice.900"], "15 minutes");
  assert.equal(nb["settings.lock.choice.900"], "15 minutter");
  assert.equal(nb["settings.lock.label"], "Lås etter");
});

test("the_settings_request_has_the_bounds_of_the_choices", () => {
  assert.ok(UI_TYPES.settings);
  for (const seconds of LOCK_CHOICES) assert.doesNotThrow(() => encode("settings", { lock_seconds: seconds }), String(seconds));
  assert.throws(() => encode("settings", { lock_minutes: 15 }), "the old key is not known any more");
});

test("turning_on_offer_to_save_asks_for_https_access_in_the_settings_tab_and_explains_why", async () => {
  /** @type {string[]} */
  const order = [];
  /** @type {Array<{ origins: string[] }>} */
  const asked = [];
  const answer = (/** @type {any} */ body) => {
    order.push(`request ${JSON.stringify(body)}`);
    return { ok: true, on: body.enable === true, permission: true, never: [] };
  };
  const make = (/** @type {boolean} */ grant) =>
    createSettingsFlow(
      async (type, body) => {
        encode(type, body);
        return answer(body);
      },
      {
        requestPermission: async (wanted) => {
          order.push("permission");
          asked.push(wanted);
          return grant;
        },
      },
    );

  // Off until the user turns it on: reading the setting asks the browser for nothing.
  const flow = make(true);
  assert.deepEqual(await flow.capture.load(), { ok: true, on: false, permission: true, never: [] });
  assert.deepEqual(asked, []);
  // Turning it on asks for https pages, first and in the click, and only then tells the background.
  assert.deepEqual(await flow.capture.turnOn(), { ok: true, on: true, permission: true, never: [] });
  assert.deepEqual(asked, [{ origins: ["https://*/*"] }]);
  assert.deepEqual(order.slice(-2), ["permission", 'request {"enable":true}']);
  // The user says no: the background is only asked what is true (nothing is switched on) and the reason is shown.
  order.length = 0;
  const refused = await make(false).capture.turnOn();
  assert.equal(refused.ok, false);
  assert.equal(/** @type {any} */ (refused).reason, "permission_refused");
  assert.equal(order.some((line) => line.includes('"enable":true')), false);
  // No way to ask (the page was given no request function): the same, nothing is switched on.
  const none = await createSettingsFlow(async () => ({ ok: true, on: false, permission: false, never: [] })).capture.turnOn();
  assert.equal(/** @type {any} */ (none).reason, "permission_refused");
  // A permission request that fails is a refusal too.
  const failing = createSettingsFlow(async () => ({ ok: true, on: false, permission: false, never: [] }), { requestPermission: async () => Promise.reject(new Error("x")) });
  assert.equal(/** @type {any} */ (await failing.capture.turnOn()).reason, "permission_refused");
  // A background that answers with something odd is not believed; a refusal shows its reason.
  const odd = createSettingsFlow(async () => ({ on: "yes" }), {});
  assert.deepEqual(await odd.capture.load(), { ok: false, reason: "unknown" });
  const gone = createSettingsFlow(async () => Promise.reject(new UiError("not_available")), {});
  assert.deepEqual(await gone.capture.load(), { ok: false, reason: "not_available" });
  assert.equal(captureErrorKey("not_available"), "capture.error.not_available");
  assert.equal(captureErrorKey("<b>"), "capture.error.unknown");

  // The texts explain why in both languages: what is asked for, what is read, how long it is kept, that nothing is saved
  // without a click, and that open tabs need a reload.
  const read = (/** @type {string} */ lang) => JSON.parse(readFileSync(join(extensionRoot, "src", "locales", lang, "capture.json"), "utf8"));
  const [en, nb] = [read("en"), read("nb")];
  assert.deepEqual(Object.keys(en).sort(), Object.keys(nb).sort());
  for (const [lang, texts] of [["en", en], ["nb", nb]]) {
    for (const key of Object.keys(texts)) assert.ok(typeof texts[key] === "string" && texts[key].length > 0, `${lang}: ${key}`);
    for (const key of ["capture.title", "capture.switch", "capture.why", "capture.reload", "capture.on", "capture.off", "capture.never.title", "capture.never.empty", "capture.never.hint", "capture.never.remove", "capture.never.remove.label", "capture.never.clear"]) {
      assert.ok(texts[key], `${lang}: ${key}`);
    }
    for (const reason of ["disconnected", "not_available", "permission_missing", "permission_refused", "register_failed", "unknown"]) {
      assert.ok(texts[captureErrorKey(reason)], `${lang}: ${reason}`);
    }
  }
  assert.match(en["capture.why"], /https/);
  assert.match(en["capture.why"], /five minutes/);
  assert.match(en["capture.why"], /without your click/);
  assert.match(en["capture.reload"], /reload/);
  assert.match(nb["capture.why"], /https/);
  assert.match(nb["capture.why"], /fem minutter/);
  assert.match(nb["capture.reload"], /laster dem på nytt/);
});

test("a_release_build_with_save_off_shows_the_eff_word_list_credit_on_the_settings_page", async () => {
  // The list is in the WASM file of every package, so the credit is in every build: no flag, a page the settings tab shows.
  const env = makeRoot();
  try {
    for (const variant of /** @type {const} */ (["release", "test"])) {
      const result = await build({ root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, out: joinPath(env.out, variant), manifest: "mv2", variant, features: [] });
      assert.deepEqual(result.features, [], "saving is off");
      const settings = result.files.get("pages/settings.mjs")?.toString("utf8") ?? "";
      assert.ok(settings.includes("createCredits(texts)"), "the page shows the credits");
      assert.equal(settings.includes("features.mjs"), false, "the settings page asks no flag");
      assert.equal((result.files.get("pages/credits.mjs")?.toString("utf8") ?? "").includes("features.mjs"), false, "nor does the credits module");
      useDocument();
      const mod = await import(pathToFileURL(joinPath(result.dir, "pages", "credits.mjs")).href);
      for (const lang of ["en", "nb"]) {
        const catalog = JSON.parse(result.files.get(`locales.${lang}.json`)?.toString("utf8") ?? "{}");
        const section = mod.createCredits(textsOf(catalog, lang));
        const text = one(section, "credits-eff")?.textContent ?? "";
        assert.match(text, /EFF/, lang);
        assert.match(text, /Electronic Frontier Foundation/, lang);
        assert.match(text, /CC BY 3[.]0 US/, lang);
        assert.ok(text.includes("https://creativecommons.org/licenses/by/3.0/us/"), `${lang}: the licence address is text`);
        assert.ok(text.includes("https://www.eff.org/dice"), `${lang}: the source address is text`);
        assert.equal(byRole(section, "credits").length, 1);
      }
    }
  } finally {
    env.cleanup();
  }
});
