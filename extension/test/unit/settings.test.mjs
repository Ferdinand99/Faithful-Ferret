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
import { LOCK_CHOICES, captureErrorKey, choiceKey, createSettingsFlow, errorKey, passkeyErrorKey } from "../../src/pages/settingsFlow.mjs";
import { UiError } from "../../src/pages/ui.mjs";
import { UI_TYPES, encode } from "../../src/shared/protocol.mjs";
import { extensionRoot, makeRoot } from "./buildHelpers.mjs";
import { importsOf } from "./importGraph.mjs";
import { byRole, click, fire, one, settle, textsOf, useDocument, withAttribute } from "./pageDom.mjs";

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
        for (const file of ["pages/settings.mjs", "pages/settingsFlow.mjs", "pages/settingsView.mjs"]) {
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
    "settings.back",
    "settings.more",
    "settings.on",
    "settings.off",
    "settings.group.fill",
    "settings.group.unlock",
    "settings.group.security",
    "settings.group.about",
    "settings.lock.title",
    "settings.lock.label",
    "settings.lock.short",
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
  // The words of the switches and of the rows are short, and each language has its own.
  assert.deepEqual([en["settings.on"], en["settings.off"], nb["settings.on"], nb["settings.off"]], ["On", "Off", "På", "Av"]);
  assert.equal(nb["settings.group.fill"], "Fylling og lagring");
  assert.equal(nb["settings.more"], "Mer om dette");
  for (const key of ["settings.lock.short", "settings.group.fill", "settings.lock.title"]) assert.ok(en[key].length <= 60, key);
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
  assert.deepEqual(order.slice(-3), ["permission", 'request {"pending":true}', 'request {"enable":true}']);
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
    for (const key of ["capture.title", "capture.switch", "capture.switch.desc", "capture.why", "capture.idle", "capture.reload", "capture.auto_open.switch", "capture.auto_open.desc", "capture.auto_open.hint", "capture.never.row", "capture.never.short", "capture.never.empty", "capture.never.hint", "capture.never.remove", "capture.never.remove.label", "capture.never.clear"]) {
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

test("the_eff_word_list_credit_is_on_the_settings_page_with_saving_on_and_off", async () => {
  // The list is in the WASM file of every package, so the credit is in every build, with the feature on or off: no flag,
  // a page the settings tab shows.
  const env = makeRoot();
  try {
    for (const [name, variant, features] of /** @type {[string, "release" | "test", string[] | undefined][]} */ ([["release", "release", undefined], ["test", "test", undefined], ["off", "test", []]])) {
      const result = await build({ root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, out: joinPath(env.out, name), manifest: "mv2", variant, ...(features ? { features } : {}) });
      const settings = result.files.get("pages/settingsView.mjs")?.toString("utf8") ?? "";
      assert.ok(settings.includes("createCredits(texts)"), "the settings view shows the credits");
      assert.ok((result.files.get("pages/settings.mjs")?.toString("utf8") ?? "").includes("createSettingsView("), "the page shows the view");
      assert.equal(settings.includes("features.mjs"), false, "the settings view asks no flag");
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

test("turning_offer_to_save_off_leaves_the_access_to_the_background", async () => {
  /** @type {string[]} */
  const order = [];
  const make = (/** @type {{ refuse?: boolean }} */ { refuse = false } = {}) =>
    createSettingsFlow(async (type, body) => {
      encode(type, body);
      order.push(`request ${JSON.stringify(body)}`);
      return refuse && body.enable === false ? { ok: false, reason: "unknown", on: true, permission: true, never: [] } : { ok: true, on: body.enable !== false, permission: body.enable !== false, never: [] };
    });
  // The page only says "off": the background switches capture off and takes the access back itself, unless the passkeys need it
  // (the permission is shared). The page never removes it.
  const off = await make().capture.turnOff();
  assert.deepEqual(order, ['request {"enable":false}']);
  assert.equal(off.ok, true);
  // A background that refuses is shown as it is.
  order.length = 0;
  const refused = await make({ refuse: true }).capture.turnOff();
  assert.deepEqual(order, ['request {"enable":false}']);
  assert.equal(refused.ok, false);
  // The same for the passkeys' switch.
  /** @type {string[]} */
  const seen = [];
  const passkeys = createSettingsFlow(async (type, body) => {
    encode(type, body);
    seen.push(`${type} ${JSON.stringify(body)}`);
    return { ok: true, on: body.enable === true, permission: true, signed_in: true, never: [], recent_unlock: true };
  }).passkeys;
  assert.equal((await passkeys.turnOff()).ok, true);
  assert.deepEqual(seen, ['passkey_settings {"enable":false}']);
});

/** The settings view of a built package, with a flow over a fake background that keeps what it is told. */
async function viewOf(/** @type {string} */ dir, /** @type {{ permission?: boolean, grant?: boolean, lock?: number, on?: boolean, lang?: string }} */ { permission = false, grant = true, lock = 900, on = false, lang = "en" } = {}) {
  const doc = useDocument();
  const flowModule = await import(pathToFileURL(joinPath(dir, "pages", "settingsFlow.mjs")).href);
  const viewModule = await import(pathToFileURL(joinPath(dir, "pages", "settingsView.mjs")).href);
  const catalog = JSON.parse(readFileSync(joinPath(dir, `locales.${lang}.json`), "utf8"));
  const state = { lock, on, permission, never: ["shop.example.net"], autoOpen: true, pk: { on: false, never: ["bank.example"], recent: true } };
  /** @type {string[]} */
  const log = [];
  const flow = flowModule.createSettingsFlow(
    async (/** @type {string} */ type, /** @type {any} */ body) => {
      log.push(`${type} ${JSON.stringify(body)}`);
      if (type === "settings") {
        if (typeof body.lock_seconds === "number") state.lock = body.lock_seconds;
        return { lock_seconds: state.lock };
      }
      if (type === "passkey_settings") {
        if (body.enable === true) state.pk.on = state.permission;
        if (body.enable === false) state.pk.on = false;
        if (typeof body.recent_unlock === "boolean") state.pk.recent = body.recent_unlock;
        if (typeof body.never_remove === "string") state.pk.never = state.pk.never.filter((h) => h !== body.never_remove);
        if (body.never_clear === true) state.pk.never = [];
        return { ok: true, on: state.pk.on, permission: state.permission, signed_in: true, never: state.pk.never, recent_unlock: state.pk.recent };
      }
      if (body.enable === true) state.on = state.permission;
      if (body.enable === false) state.on = false;
      if (typeof body.auto_open === "boolean") state.autoOpen = body.auto_open;
      if (typeof body.never_remove === "string") state.never = state.never.filter((h) => h !== body.never_remove);
      return { ok: true, on: state.on, permission: state.permission, never: state.never, auto_open: state.autoOpen, auto_open_state: "unknown" };
    },
    {
      requestPermission: async () => {
        log.push("permission request");
        if (grant) state.permission = true;
        return grant;
      },
    },
  );
  const view = viewModule.createSettingsView({ texts: textsOf(catalog, lang), flow });
  const root = doc.createElement("div");
  root.append(...view.nodes);
  await view.ready;
  return { root, log, state, view, doc };
}

test("the_settings_view_is_one_module_for_the_page_and_the_popup_and_works_in_every_build", async () => {
  const env = makeRoot();
  try {
    for (const [name, variant, features] of /** @type {[string, "release" | "test", string[] | undefined][]} */ ([["release", "release", undefined], ["test", "test", undefined], ["off", "test", []]])) {
      const result = await build({ root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, out: joinPath(env.out, `view-${name}`), manifest: "mv2", variant, ...(features ? { features } : {}) });
      const withSaving = name !== "off";
      const { root, log } = await viewOf(result.dir, { lock: 1800 });
      // The title, the lock choice with its saved value, the credits; the saving section only where the feature is on.
      assert.equal(one(root, "settings-title")?.textContent, "Settings", name);
      const select = /** @type {any} */ (one(root, "lock-after"));
      assert.equal(select.childNodes.length, LOCK_CHOICES.length, name);
      assert.equal(select.value, "1800", `${name}: the saved choice is shown`);
      assert.equal(byRole(root, "credits").length, 1, name);
      assert.equal(byRole(root, "capture-section").length, withSaving ? 1 : 0, name);
      assert.equal(log.filter((line) => line.startsWith("capture_settings")).length, withSaving ? 1 : 0, `${name}: the saving state is read only where there is a section`);
      // A change sends exactly the chosen value and says "Saved.".
      select.value = "60";
      fire(select, "change");
      await settle();
      assert.ok(log.includes('settings {"lock_seconds":60}'), name);
      assert.equal(one(root, "saved")?.textContent, "Saved.", name);
      // The popup opens no page for the settings: the page is a view of the popup now, and the options page shows the same view.
      const popup = result.files.get("pages/popup.mjs")?.toString("utf8") ?? "";
      assert.equal(popup.includes("openOptionsPage"), false, `${name}: the popup opens no page for the settings`);
      assert.equal(/tabs\.create\([^)]*settings/.test(popup), false, name);
      assert.ok(popup.includes("createSettingsView("), name);
      assert.equal(result.files.has("pages/popupSettings.mjs"), false, name);
      assert.ok(result.files.has("pages/settings.html"), name);
    }
  } finally {
    env.cleanup();
  }
});

test("the_settings_view_turns_offer_to_save_on_and_off_with_the_permission_asked_in_the_click", async () => {
  const env = makeRoot();
  try {
    const result = await build({ root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, out: joinPath(env.out, "view-save"), manifest: "mv2", variant: "test" });
    // Turning it on: the access is asked for first, in the click itself (before anything is awaited), then the background is told.
    const on = await viewOf(result.dir);
    const toggle = /** @type {any} */ (one(on.root, "capture-switch"));
    assert.equal(toggle.getAttribute("aria-checked"), "false");
    assert.equal(one(on.root, "capture-state")?.textContent, "Off");
    assert.equal(toggle.getAttribute("role"), "switch");
    on.log.length = 0;
    fire(toggle, "click");
    assert.deepEqual(on.log, ["permission request", 'capture_settings {"pending":true}'], "the request is made first, in the click, then the mark");
    await settle();
    // The switch marks that it asked (the permission is shared with the passkeys), the grant lands, and the background is told to turn on.
    assert.deepEqual(on.log, ["permission request", 'capture_settings {"pending":true}', 'capture_settings {"enable":true}']);
    assert.equal(toggle.getAttribute("aria-checked"), "true");
    assert.equal(one(on.root, "capture-state")?.textContent, "On");
    assert.equal(one(on.root, "capture-summary")?.textContent, "On", "the row of the main screen says it too");
    assert.equal(one(on.root, "never-host")?.textContent.includes("shop.example.net"), true, "the never list is shown");
    // Turning it off: only the background is told (it takes the access back unless the passkeys need it).
    on.log.length = 0;
    await click(toggle);
    assert.deepEqual(on.log, ['capture_settings {"enable":false}']);
    assert.equal(toggle.getAttribute("aria-checked"), "false");
    // The user says no in the prompt: nothing is switched on.
    const refused = await viewOf(result.dir, { grant: false });
    await click(/** @type {any} */ (one(refused.root, "capture-switch")));
    assert.equal(refused.state.on, false);
    assert.equal(refused.log.some((line) => line.includes('"enable":true')), false);
    assert.ok(refused.log.includes('capture_settings {"pending":false}'), "the mark is cleared when the person says no");
    // The prompt closed the popup that asked and the user said yes: the next time the view is built it says the access is there, and
    // the next press turns it on (a request for an access that is held is answered at once, with no prompt).
    const closed = await viewOf(result.dir, { permission: true });
    assert.match(one(closed.root, "capture-note")?.textContent ?? "", /already given/);
    assert.equal(one(closed.root, "capture-note")?.hidden, false);
    await click(/** @type {any} */ (one(closed.root, "capture-switch")));
    assert.equal(closed.state.on, true);
    assert.equal(one(closed.root, "capture-switch")?.getAttribute("aria-checked"), "true");
    assert.equal(one(closed.root, "capture-state")?.textContent, "On");
    assert.equal(one(closed.root, "capture-note")?.hidden, true, "the note goes when it is on");
  } finally {
    env.cleanup();
  }
});

test("the_access_given_text_exists_in_both_languages", () => {
  for (const lang of ["en", "nb"]) {
    const catalog = JSON.parse(readFileSync(join(extensionRoot, "src", "locales", lang, "capture.json"), "utf8"));
    assert.ok(typeof catalog["capture.off_access_given"] === "string" && catalog["capture.off_access_given"].length > 0, lang);
  }
});

/** The ids of the rows of the main screen, in order, and the texts of the group headings. @param {any} root */
function outline(root) {
  const rows = withAttribute(root, "data-role").map((n) => n.getAttribute("data-role") ?? "").filter((role) => role.startsWith("settings-row-")).map((role) => role.slice("settings-row-".length));
  const groups = withAttribute(root, "class").filter((n) => (n.getAttribute("class") ?? "").split(/\s+/).includes("ff-sgroup-title")).map((n) => n.textContent);
  return { rows, groups };
}

/** Walks up from a node to see whether a <details> holds it. @param {any} node */
function inDisclosure(node) {
  for (let at = node; at; at = at.parentNode) if (at.tagName === "DETAILS") return true;
  return false;
}

test("the_settings_view_groups_its_rows_and_a_group_goes_with_its_flag", async () => {
  const env = makeRoot();
  try {
    const cases = /** @type {const} */ ([
      ["all", undefined, ["capture", "never", "pin", "passkeys", "provider", "provider-never", "lock", "credits"], ["Filling and saving", "Unlocking", "Passkeys on websites", "Security", "About"]],
      ["only-provider", ["passkeys"], ["provider", "provider-never", "lock", "credits"], ["Passkeys on websites", "Security", "About"]],
      ["no-unlock", ["save"], ["capture", "never", "lock", "credits"], ["Filling and saving", "Security", "About"]],
      ["no-save", ["unlock"], ["pin", "passkeys", "lock", "credits"], ["Unlocking", "Security", "About"]],
      ["none", [], ["lock", "credits"], ["Security", "About"]],
    ]);
    for (const [name, features, rows, groups] of cases) {
      const result = await build({ root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, out: joinPath(env.out, `groups-${name}`), manifest: "mv2", variant: "test", ...(features ? { features } : {}) });
      const { root } = await viewOf(result.dir);
      assert.deepEqual(outline(root), { rows, groups }, name);
      // One page for each row, each with its own back button and heading.
      assert.equal(byRole(root, "settings-page").length, rows.length, name);
      assert.equal(byRole(root, "settings-back").length, rows.length, name);
      assert.equal(byRole(root, "settings-page-title").length, rows.length, name);
      // Nothing of a flag that is off is left in the view.
      assert.equal(withAttribute(root, "data-feature").some((n) => n.getAttribute("data-feature") === "save"), rows.includes("capture"), name);
      assert.equal(withAttribute(root, "data-feature").some((n) => n.getAttribute("data-feature") === "unlock"), rows.includes("pin"), name);
      assert.equal(withAttribute(root, "data-feature").some((n) => n.getAttribute("data-feature") === "passkeys"), rows.includes("provider"), name);
      // No inline style anywhere (the page's content security policy has none).
      assert.deepEqual(withAttribute(root, "style"), [], name);
    }
  } finally {
    env.cleanup();
  }
});

test("a_row_opens_its_page_and_back_returns_to_the_row_with_the_focus", async () => {
  const env = makeRoot();
  try {
    const result = await build({ root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, out: joinPath(env.out, "nav"), manifest: "mv2", variant: "test" });
    const { root, doc, view } = await viewOf(result.dir);
    const main = one(root, "settings-main");
    const pages = byRole(root, "settings-page");
    assert.equal(main?.hidden, false, "the main screen is shown first");
    assert.ok(pages.every((page) => page.hidden), "no page is shown first");
    assert.equal(view.current(), null);
    for (const page of pages) {
      const id = page.getAttribute("data-page") ?? "";
      const row = /** @type {any} */ (one(root, `settings-row-${id}`));
      await click(row);
      assert.equal(view.current(), id);
      assert.equal(main?.hidden, true, `${id}: the main screen is out of the way`);
      assert.deepEqual(pages.filter((p) => !p.hidden).map((p) => p.getAttribute("data-page")), [id], `${id}: one page at a time`);
      assert.equal(doc.activeElement, one(page, "settings-page-title"), `${id}: the focus is on the page's heading`);
      assert.equal(page.getAttribute("aria-labelledby"), one(page, "settings-page-title")?.getAttribute("id"), id);
      // The back button reads "Settings" and says where it goes.
      const back = one(page, "settings-back");
      assert.equal(back?.textContent, "Settings", id);
      assert.equal(back?.getAttribute("aria-label"), "Back to settings", id);
      await click(back);
      assert.equal(view.current(), null);
      assert.equal(main?.hidden, false, `${id}: back to the main screen`);
      assert.ok(pages.every((p) => p.hidden), id);
      assert.equal(doc.activeElement, row, `${id}: the focus is back on the row that opened the page`);
    }
    // What is chosen in a page is there when the page is opened again, and the row says it.
    await click(one(root, "settings-row-lock"));
    const select = /** @type {any} */ (one(root, "lock-after"));
    select.value = "300";
    fire(select, "change");
    await settle();
    const lockPage = pages.find((p) => p.getAttribute("data-page") === "lock");
    await click(one(lockPage, "settings-back"));
    assert.equal(one(root, "lock-summary")?.textContent, "5 minutes");
    await click(one(root, "settings-row-lock"));
    assert.equal(select.value, "300");
  } finally {
    env.cleanup();
  }
});

test("every_setting_that_is_on_or_off_is_a_switch_that_says_so_in_words", async () => {
  const env = makeRoot();
  try {
    const result = await build({ root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, out: joinPath(env.out, "switches"), manifest: "mv2", variant: "test" });
    for (const lang of ["en", "nb"]) {
      const { root } = await viewOf(result.dir, { lang });
      const [on, off] = lang === "en" ? ["On", "Off"] : ["På", "Av"];
      for (const [role, state] of /** @type {const} */ ([["capture-switch", "capture-state"], ["auto-open-switch", "auto-open-state"], ["passkeys-switch", "passkeys-state"], ["passkeys-recent-switch", "passkeys-recent-state"]])) {
        const row = /** @type {any} */ (one(root, role));
        assert.equal(row.tagName, "BUTTON", role);
        assert.equal(row.getAttribute("type"), "button", role);
        assert.equal(row.getAttribute("role"), "switch", role);
        assert.ok(["true", "false"].includes(row.getAttribute("aria-checked")), role);
        // The name and the description of the control are the title and the one line under it.
        const named = (/** @type {string} */ attribute) => {
          const id = row.getAttribute(attribute);
          return withAttribute(root, "id").find((n) => n.getAttribute("id") === id)?.textContent ?? "";
        };
        assert.ok(named("aria-labelledby").length > 0, role);
        // (The recent-unlock choice has a title and the "More" text only: its description repeated the title.)
        if (role !== "passkeys-recent-switch") assert.ok(named("aria-describedby").length > 0, role);
        assert.ok(named("aria-describedby").length <= 80, `${role}: one short sentence`);
        // The state is in words, not in colour alone, and it follows the switch.
        const word = /** @type {any} */ (one(root, state));
        assert.equal(word.textContent, row.getAttribute("aria-checked") === "true" ? on : off, role);
        await click(row);
        assert.equal(word.textContent, row.getAttribute("aria-checked") === "true" ? on : off, `${role} after a click`);
      }
    }
  } finally {
    env.cleanup();
  }
});

test("the_long_explanations_are_behind_more_about_this_and_still_there", async () => {
  const env = makeRoot();
  try {
    const result = await build({ root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, out: joinPath(env.out, "more"), manifest: "mv2", variant: "test" });
    const { root } = await viewOf(result.dir);
    const catalog = JSON.parse(readFileSync(joinPath(result.dir, "locales.en.json"), "utf8"));
    for (const [role, key] of /** @type {const} */ ([
      ["capture-why", "capture.why"],
      ["capture-reload", "capture.reload"],
      ["capture-idle", "capture.idle"],
      ["auto-open-hint", "capture.auto_open.hint"],
      ["never-hint", "capture.never.hint"],
      ["passkeys-why", "passkeys.settings.why"],
      ["passkeys-shared", "passkeys.settings.shared"],
      ["passkeys-recent-hint", "passkeys.settings.recent.hint"],
      ["passkeys-reload", "passkeys.settings.reload"],
      ["lock-hint", "settings.lock.hint"],
      ["unlock-pin-about", "settings.unlock.pin.about"],
      ["unlock-lead", "settings.unlock.lead"],
      ["unlock-passkey-about", "settings.unlock.passkey.about"],
    ])) {
      const node = one(root, role);
      assert.equal(node?.textContent, catalog[key], `${role}: the whole text`);
      assert.ok(inDisclosure(node), `${role}: behind "More about this"`);
    }
    // Each disclosure is a native one, named by one short line, and the credits (a licence's condition) are in plain sight.
    for (const more of byRole(root, "more")) {
      assert.equal(more.tagName, "DETAILS");
      assert.equal(/** @type {any} */ (more.childNodes[0]).tagName, "SUMMARY");
      assert.equal(more.childNodes[0].textContent, "More about this");
    }
    assert.equal(inDisclosure(one(root, "credits-eff")), false);
    // What the user reads on the page itself is the state in one short line.
    for (const role of ["unlock-pin-status", "unlock-passkey-count"]) assert.equal(inDisclosure(one(root, role)), false, role);
  } finally {
    env.cleanup();
  }
});

test("the_settings_view_speaks_norwegian_with_the_new_words", async () => {
  const env = makeRoot();
  try {
    const result = await build({ root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, out: joinPath(env.out, "nb"), manifest: "mv2", variant: "test" });
    const { root } = await viewOf(result.dir, { lang: "nb" });
    assert.deepEqual(outline(root).groups, ["Fylling og lagring", "Opplåsing", "Passkeys på nettsteder", "Sikkerhet", "Om"]);
    assert.equal(one(root, "settings-title")?.textContent, "Innstillinger");
    assert.equal(one(root, "capture-state")?.textContent, "Av");
    assert.equal(one(byRole(root, "settings-page")[0], "settings-back")?.getAttribute("aria-label"), "Tilbake til innstillinger");
  } finally {
    env.cleanup();
  }
});

test("the_auto_open_note_keeps_the_badge_sentence_and_a_page_does_not_repeat_its_heading_in_its_card", async () => {
  const read = (/** @type {string} */ lang, /** @type {string} */ file) => JSON.parse(readFileSync(join(extensionRoot, "src", "locales", lang, file), "utf8"));
  assert.match(read("en", "capture.json")["capture.auto_open.hint"], /badge on Ferret's button always shows that an offer waits/);
  assert.match(read("nb", "capture.json")["capture.auto_open.hint"], /Merket på Ferret-knappen viser alltid at et tilbud venter/);
  const env = makeRoot();
  try {
    const result = await build({ root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, out: joinPath(env.out, "cards"), manifest: "mv2", variant: "test" });
    const { root } = await viewOf(result.dir);
    for (const [card, id] of [["unlock-pin-card", "pin"], ["unlock-passkey-card", "passkeys"]]) {
      const page = byRole(root, "settings-page").find((p) => p.getAttribute("data-page") === id);
      const heading = one(page, "settings-page-title")?.textContent;
      const title = withAttribute(one(root, card), "class").find((n) => (n.getAttribute("class") ?? "").includes("ff-scard-title"))?.textContent;
      assert.ok(heading && title && heading !== title, `${id}: "${heading}" and "${title}" are not the same`);
    }
  } finally {
    env.cleanup();
  }
});

test("the_passkeys_pages_turn_the_feature_on_with_the_permission_asked_in_the_click_and_list_the_never_sites", async () => {
  const env = makeRoot();
  try {
    const result = await build({ root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, out: joinPath(env.out, "view-passkeys"), manifest: "mv2", variant: "test" });
    const on = await viewOf(result.dir);
    const toggle = /** @type {any} */ (one(on.root, "passkeys-switch"));
    assert.equal(toggle.getAttribute("role"), "switch");
    assert.equal(toggle.getAttribute("aria-checked"), "false");
    assert.equal(one(on.root, "passkeys-state")?.textContent, "Off");
    // The access is asked for in the click itself, the switch marks its grant, and only then is the background told to turn on.
    on.log.length = 0;
    fire(toggle, "click");
    assert.deepEqual(on.log, ["permission request", 'passkey_settings {"pending":true}'], "the request is made first, in the click, then the mark");
    await settle();
    assert.deepEqual(on.log, ["permission request", 'passkey_settings {"pending":true}', 'passkey_settings {"enable":true}']);
    assert.equal(toggle.getAttribute("aria-checked"), "true");
    assert.equal(one(on.root, "passkeys-summary")?.textContent, "On", "the row of the main screen says it too");
    // Off: only the background is told; the permission is not the page's to take back.
    on.log.length = 0;
    await click(toggle);
    assert.deepEqual(on.log, ['passkey_settings {"enable":false}']);
    assert.equal(toggle.getAttribute("aria-checked"), "false");
    // The recent-unlock choice is on to begin with, and a click turns it off and on.
    const recent = /** @type {any} */ (one(on.root, "passkeys-recent-switch"));
    assert.equal(recent.getAttribute("aria-checked"), "true");
    on.log.length = 0;
    await click(recent);
    assert.deepEqual(on.log, ['passkey_settings {"recent_unlock":false}']);
    assert.equal(recent.getAttribute("aria-checked"), "false");
    await click(recent);
    assert.equal(recent.getAttribute("aria-checked"), "true");
    // The recent-unlock choice is there only while the feature is on, and the sentences about the list only while it has sites.
    assert.equal(/** @type {any} */ (one(on.root, "passkeys-recent-switch")).hidden, true, "off: the choice means nothing");
    assert.equal(/** @type {any} */ (one(on.root, "passkeys-never-short")).hidden, false);
    assert.equal(/** @type {any} */ (one(on.root, "passkeys-never-hint")).hidden, false);
    // The never list: the sites, how many on the row, remove one, remove all.
    assert.equal(byRole(on.root, "passkeys-never-host").length, 1);
    assert.equal(one(on.root, "passkeys-never-host")?.textContent.includes("bank.example"), true);
    assert.equal(one(on.root, "passkeys-never-summary")?.textContent, "1");
    on.log.length = 0;
    await click(/** @type {any} */ (one(on.root, "passkeys-never-remove")));
    assert.deepEqual(on.log, ['passkey_settings {"never_remove":"bank.example"}']);
    assert.equal(byRole(on.root, "passkeys-never-host").length, 0);
    assert.equal(byRole(on.root, "passkeys-never-empty").length, 1);
    assert.equal(/** @type {any} */ (one(on.root, "passkeys-never-clear")).hidden, true);
    assert.equal(/** @type {any} */ (one(on.root, "passkeys-never-short")).hidden, true, "an empty list says what it is for itself");
    assert.equal(/** @type {any} */ (one(on.root, "passkeys-never-hint")).hidden, true);
    // The person says no in the prompt: nothing is switched on and the mark is cleared.
    const refused = await viewOf(result.dir, { grant: false });
    await click(/** @type {any} */ (one(refused.root, "passkeys-switch")));
    assert.equal(refused.state.pk.on, false);
    assert.equal(refused.log.some((line) => line.includes('"enable":true')), false);
    assert.ok(refused.log.includes('passkey_settings {"pending":false}'));
    // Norwegian says "passkey".
    const nb = await viewOf(result.dir, { lang: "nb" });
    assert.equal(one(nb.root, "passkeys-state")?.textContent, "Av");
    assert.equal(one(nb.root, "passkeys-switch")?.textContent.includes("Bruk Ferret til passkeys"), true);
    assert.equal(one(nb.root, "passkeys-recent-switch")?.textContent.includes("Godta opplåsing de siste 5 minuttene som verifisering"), true);
  } finally {
    env.cleanup();
  }
});

test("the_passkeys_texts_exist_in_both_languages_and_the_pages_are_gone_without_the_feature", async () => {
  const read = (/** @type {string} */ lang) => JSON.parse(readFileSync(join(extensionRoot, "src", "locales", lang, "passkeys.json"), "utf8"));
  const [en, nb] = [read("en"), read("nb")];
  assert.deepEqual(Object.keys(en).sort(), Object.keys(nb).sort(), "the same keys in en and nb");
  for (const key of Object.keys(en).filter((k) => k.startsWith("passkeys.settings."))) {
    assert.ok(typeof nb[key] === "string" && nb[key].length > 0, key);
  }
  for (const reason of ["disconnected", "not_available", "permission_missing", "permission_refused", "unknown"]) assert.ok(en[passkeyErrorKey(reason)], reason);
  assert.equal(passkeyErrorKey("odd"), "passkeys.settings.error.unknown");
  const env = makeRoot();
  try {
    const result = await build({ root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, out: joinPath(env.out, "view-no-passkeys"), manifest: "mv2", variant: "test", features: ["save", "unlock"] });
    const { root, log } = await viewOf(result.dir);
    assert.equal(byRole(root, "passkeys-section").length, 0);
    assert.equal(withAttribute(root, "data-feature").some((n) => n.getAttribute("data-feature") === "passkeys"), false);
    assert.equal(log.some((line) => line.startsWith("passkey_settings")), false, "nothing is asked of the background");
  } finally {
    env.cleanup();
  }
});

test("a_hidden_card_is_not_drawn_because_the_stylesheet_says_so", () => {
  // The recent-unlock row is a card that is hidden while the passkeys are off; `.ff-scard { display: flex }` would override `hidden`.
  const css = readFileSync(join(extensionRoot, "src", "styles", "settings.css"), "utf8");
  const at = css.indexOf(".ff-scard[hidden]");
  assert.ok(at > 0 && /^[^}]*display: none/.test(css.slice(at)), "the rule hides it");
});
