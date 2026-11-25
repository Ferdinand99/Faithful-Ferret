// The "Unlock" part of the settings view: the PIN's state and buttons, the dialog that sets or changes a PIN (the master
// password again, the PIN twice, the "123" button, the restart choice, the warning every time and the acknowledgement), and
// the passkeys. The steps have no DOM and run as they are; the view runs over the DOM stand-in against a fake background that
// keeps what it is told. The package is built twice: with unlock on (the test variant) and off (a release).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { pathToFileURL } from "node:url";
import { build } from "../../scripts/build.mjs";
import { PIN_FLOOR, checkPin, createUnlockFlow, pinLength, readUnlockState, unlockErrorKey, vaultAccountUrl } from "../../src/pages/unlockFlow.mjs";
import { UiError } from "../../src/pages/ui.mjs";
import { extensionRoot, makeRoot } from "./buildHelpers.mjs";
import { byRole, click, fire, one, settle, submit, textsOf, useDocument, withAttribute } from "./pageDom.mjs";

/** @type {ReturnType<typeof makeRoot>} */
let env;
/** @type {Awaited<ReturnType<typeof build>>} */
let on;
/** @type {Awaited<ReturnType<typeof build>>} */
let off;
before(async () => {
  env = makeRoot();
  const options = { root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, manifest: "mv2" };
  on = await build({ ...options, out: join(env.out, "on"), variant: "test" });
  off = await build({ ...options, out: join(env.out, "off"), variant: "release" });
});
after(() => env?.cleanup());

const SERVER = "https://ferret.example.net";
const SENTINEL_PIN = "sentinel-pin-7391";
const SENTINEL_PASSWORD = "sentinel-master-password-5528";

/**
 * A background that keeps what it is told: the policy and the PIN, a vault that is open or locked, and the replies a test
 * sets. Every request is logged (a copy, so what the page sends later cannot change an entry).
 * @param {{ pin?: Record<string, unknown>, prf?: Record<string, unknown>, server?: string, passkeys?: number | "unavailable" }} [init]
 */
function backend(init = {}) {
  const state = {
    pin: { allowed: true, after_restart: true, min_length: 6, set: false, location: null, failures_left: 5, wait_ms: 0, offline_ok: true, ...init.pin },
    prf: { enabled: true, count: 2, ...init.prf },
    server: init.server ?? SERVER,
    /** What the server's list says (prf_options): a count, or undefined for "cannot say". */
    passkeys: init.passkeys,
    vault: "unlocked",
    /** @type {any} */
    reply: null,
    /** @type {Promise<void> | null} */
    hold: null,
    /** @type {any} */
    offReply: null,
  };
  /** @type {Array<[string, any]>} */
  const log = [];
  /** @type {import("../../src/pages/ui.mjs").Request} */
  const request = async (type, body) => {
    log.push([type, JSON.parse(JSON.stringify(body))]);
    switch (type) {
      case "unlock_policy":
        return { pin: { ...state.pin }, prf: { ...state.prf } };
      case "pin_set":
        if (state.hold) await state.hold;
        if (state.reply) return state.reply;
        state.pin.set = true;
        state.pin.location = body.location;
        return { ok: true };
      case "pin_off":
        if (state.offReply) return state.offReply;
        state.pin.set = false;
        state.pin.location = null;
        return { ok: true };
      case "state":
        return { state: state.vault, server: state.server };
      case "prf_options":
        if (state.passkeys === undefined) throw new UiError("not_available");
        if (state.passkeys === "unavailable") return { ok: false, reason: "prf_unavailable" };
        return state.passkeys === 0 ? { ok: true, rp_id: "ferret.example.net", credentials: [] } : { ok: true, rp_id: "ferret.example.net", credentials: Array.from({ length: state.passkeys }, () => ({ id: "AQID", salt: "a".repeat(43) })) };
      default:
        throw new UiError("not_available");
    }
  };
  return { state, log, request };
}

/** The section of a built package over a fake background. */
async function sectionOf(/** @type {Awaited<ReturnType<typeof build>>} */ built, /** @type {Parameters<typeof backend>[0] & { lang?: string }} */ init = {}) {
  const doc = useDocument();
  const flowModule = await import(pathToFileURL(join(built.dir, "pages", "settingsFlow.mjs")).href);
  const sectionModule = await import(pathToFileURL(join(built.dir, "pages", "unlockSettings.mjs")).href);
  const lang = init.lang ?? "en";
  const catalog = JSON.parse(readFileSync(join(built.dir, `locales.${lang}.json`), "utf8"));
  const fake = backend(init);
  /** @type {string[]} */
  const opened = [];
  const flow = flowModule.createSettingsFlow(fake.request, {
    openTab: async (/** @type {string} */ url) => {
      opened.push(url);
    },
  });
  const texts = textsOf(catalog, lang);
  const section = sectionModule.createUnlockSection(flow, texts, { pollMs: 0 });
  const root = doc.createElement("div");
  if (section !== null) {
    root.append(section.node);
    await section.refresh();
  }
  return { doc, section, root, texts, catalog, opened, ...fake };
}

/** Types into the dialog: the master password, the PIN twice. */
function fill(/** @type {any} */ root, { password = "correct horse", pin = "123456", again = pin, secret = "" } = {}) {
  /** @type {any} */ (one(root, "pin-password")).value = password;
  /** @type {any} */ (one(root, "pin-secret")).value = secret;
  /** @type {any} */ (one(root, "pin-pin")).value = pin;
  /** @type {any} */ (one(root, "pin-again")).value = again;
}
const field = (/** @type {any} */ root, /** @type {string} */ role) => /** @type {any} */ (one(root, role));
const values = (/** @type {any} */ root) => ["pin-password", "pin-secret", "pin-pin", "pin-again"].map((role) => field(root, role).value);
const dialogOf = (/** @type {any} */ root) => field(root, "pin-dialog");
const setRequests = (/** @type {Array<[string, any]>} */ log) => log.filter(([type]) => type === "pin_set");
const errorText = (/** @type {any} */ root) => {
  const box = field(root, "pin-error");
  return box.hidden ? null : box.textContent;
};
/** Presses a key on an element for its own listeners. */
function press(/** @type {any} */ target, /** @type {string} */ key) {
  const event = { type: "keydown", key, target, defaultPrevented: false, preventDefault() { event.defaultPrevented = true; }, stopPropagation() {} };
  for (const [type, fn] of target.listeners) if (type === "keydown") fn(event);
  return event;
}

// ------------------------------------------------------------------------------------------------ the steps, no DOM

test("the_unlock_flow_reads_only_an_answer_of_the_right_shape", async () => {
  const good = { pin: { allowed: true, after_restart: true, min_length: 6, set: true, location: "disk", failures_left: 3, wait_ms: 5000, offline_ok: false, last_contact_at: 1_700_000_000_000 }, prf: { enabled: true, count: 2 } };
  const read = readUnlockState(good);
  assert.deepEqual(read?.pin, { allowed: true, afterRestart: true, minLength: 6, set: true, location: "disk", failuresLeft: 3, waitMs: 5000, offlineOk: false, lastContactAt: 1_700_000_000_000 });
  assert.deepEqual(read?.prf, { enabled: true, count: 2 });
  for (const odd of [null, {}, { pin: null, prf: {} }, { ...good, pin: { ...good.pin, allowed: "yes" } }, { ...good, pin: { ...good.pin, min_length: 3 } }, { ...good, pin: { ...good.pin, min_length: 65 } }, { ...good, pin: { ...good.pin, set: true, location: "tape" } }, { ...good, prf: { enabled: true, count: -1 } }, { ...good, prf: { enabled: 1, count: 0 } }]) {
    assert.equal(readUnlockState(odd), null, JSON.stringify(odd));
  }
  const flow = createUnlockFlow(async () => ({ nonsense: true }));
  assert.deepEqual(await flow.load(), { ok: false, reason: "unknown" });
  assert.deepEqual(await createUnlockFlow(async () => Promise.reject(new UiError("disconnected"))).load(), { ok: false, reason: "disconnected" });
  assert.deepEqual(await createUnlockFlow(async () => good).load(), { ok: true, state: read });
});

test("the_unlock_flow_sends_a_pin_only_in_one_request_and_refuses_what_needs_no_request", async () => {
  /** @type {Array<[string, any]>} */
  const sent = [];
  const flow = createUnlockFlow(async (type, body) => {
    sent.push([type, body]);
    return { ok: true };
  });
  const base = { password: "pw", pin: "123456", location: "session", acknowledged: false };
  assert.deepEqual(await flow.setPin(base), { ok: true });
  assert.deepEqual(sent[0], ["pin_set", { mp: "pw", pin: "123456", location: "session", acknowledged: false }]);
  assert.deepEqual(await flow.setPin({ ...base, secretKey: "sk-1", location: "disk", acknowledged: true }), { ok: true });
  assert.deepEqual(sent[1], ["pin_set", { mp: "pw", sk: "sk-1", pin: "123456", location: "disk", acknowledged: true }]);
  const count = sent.length;
  // On disk without the acknowledgement, a missing password, an empty PIN and an odd place: nothing goes out.
  assert.deepEqual(await flow.setPin({ ...base, location: "disk", acknowledged: false }), { ok: false, reason: "not_acknowledged" });
  assert.deepEqual(await flow.setPin({ ...base, location: "disk", acknowledged: /** @type {any} */ ("true") }), { ok: false, reason: "not_acknowledged" });
  assert.deepEqual(await flow.setPin({ ...base, password: "" }), { ok: false, reason: "password_missing" });
  assert.deepEqual(await flow.setPin({ ...base, pin: "" }), { ok: false, reason: "too_short" });
  assert.deepEqual(await flow.setPin({ ...base, location: "tape" }), { ok: false, reason: "invalid_input" });
  assert.equal(sent.length, count);
  // The background's refusals and a refused request are reasons, never values.
  assert.deepEqual(await createUnlockFlow(async () => ({ ok: false, reason: "pin_rule" })).setPin(base), { ok: false, reason: "pin_rule" });
  assert.deepEqual(await createUnlockFlow(async () => Promise.reject(new UiError("vault_locked"))).setPin(base), { ok: false, reason: "vault_locked" });
  assert.deepEqual(await createUnlockFlow(async () => ({})).setPin(base), { ok: false, reason: "unknown" });
  // Turning it off sends no secret at all.
  sent.length = 0;
  assert.deepEqual(await flow.turnOff(), { ok: true });
  assert.deepEqual(sent, [["pin_off", {}]]);
});

test("the_rule_counts_characters_the_way_the_core_does", () => {
  assert.equal(PIN_FLOOR, 4);
  assert.equal(pinLength("abcd"), 4);
  // NFKD: the ligature "fi" is two characters, "é" written as one letter is two after the split.
  assert.equal(pinLength("ﬁx"), 3);
  assert.equal(pinLength("é"), 2);
  assert.deepEqual(checkPin("1234", 4), { ok: true });
  assert.deepEqual(checkPin("123", 4), { ok: false, reason: "too_short" });
  assert.deepEqual(checkPin("12345", 6), { ok: false, reason: "too_short" });
  // The fixed floor holds even when a rule says less.
  assert.deepEqual(checkPin("123", 1), { ok: false, reason: "too_short" });
  assert.deepEqual(checkPin("x".repeat(64), 6), { ok: true });
  assert.deepEqual(checkPin("x".repeat(65), 6), { ok: false, reason: "too_long" });
  // Characters that take four bytes each: 64 of them are at the byte limit and still fit.
  assert.deepEqual(checkPin("😀".repeat(64), 6), { ok: true });
});

test("the_vault_address_is_built_from_the_server_address_and_nothing_else", () => {
  assert.equal(vaultAccountUrl("https://ferret.example.net"), "https://ferret.example.net/#/account");
  assert.equal(vaultAccountUrl("https://ferret.example.net/"), "https://ferret.example.net/#/account");
  assert.equal(vaultAccountUrl("https://ferret.example.net/vault/?x=1#y"), "https://ferret.example.net/vault/#/account");
  assert.equal(vaultAccountUrl("http://172.30.237.5:8080"), "http://172.30.237.5:8080/#/account");
  for (const bad of ["javascript:alert(1)", "data:text/html,x", "file:///etc/passwd", "ftp://x.example", "https://user:pw@ferret.example.net", "", "not a url", null, undefined, 5]) {
    assert.equal(vaultAccountUrl(bad), null, String(bad));
  }
});

test("every_reason_of_the_unlock_part_has_a_key_and_an_odd_one_is_unknown", () => {
  assert.equal(unlockErrorKey("pin_rule"), "settings.unlock.error.pin_rule");
  assert.equal(unlockErrorKey("<script>"), "settings.unlock.error.unknown");
  assert.equal(unlockErrorKey(undefined), "settings.unlock.error.unknown");
});

// ------------------------------------------------------------------------------------------------ the section

test("the_unlock_section_exists_only_with_unlock_on", async () => {
  // On: the view has the section and reads the policy.
  const doc = useDocument();
  for (const [name, built, expected] of /** @type {const} */ ([["on", on, 1], ["off", off, 0]])) {
    const flowModule = await import(pathToFileURL(join(built.dir, "pages", "settingsFlow.mjs")).href);
    const viewModule = await import(pathToFileURL(join(built.dir, "pages", "settingsView.mjs")).href);
    const catalog = JSON.parse(readFileSync(join(built.dir, "locales.en.json"), "utf8"));
    const fake = backend();
    const view = viewModule.createSettingsView({ texts: textsOf(catalog, "en"), flow: flowModule.createSettingsFlow(fake.request) });
    const root = doc.createElement("div");
    root.append(...view.nodes);
    await view.ready;
    assert.equal(byRole(root, "unlock-section").length, expected, name);
    assert.equal(fake.log.filter(([type]) => type === "unlock_policy").length, expected, `${name}: the policy is read only where there is a section`);
    assert.equal(withAttribute(root, "data-feature").some((node) => node.getAttribute("data-feature") === "unlock"), expected === 1, name);
    // Nothing of the PIN is sent without a click, in either build.
    assert.deepEqual(fake.log.filter(([type]) => type.startsWith("pin_")), [], name);
    assert.ok(byRole(root, "settings-title").length === 1 && byRole(root, "credits").length === 1, `${name}: the rest of the view is there`);
  }
  // The module of the section gives nothing when the flag is off, whatever the flow holds.
  const off2 = await sectionOf(off);
  assert.equal(off2.section, null);
  const on2 = await sectionOf(on);
  assert.ok(on2.section !== null);
});

test("the_section_shows_what_is_true_of_the_pin_and_the_passkeys", async () => {
  // No PIN: one button, the rule in plain text.
  const none = await sectionOf(on, { pin: { min_length: 8 } });
  assert.equal(one(none.root, "unlock-pin-status")?.textContent, "No PIN is set.");
  assert.ok(one(none.root, "unlock-pin-on") && !one(none.root, "unlock-pin-change") && !one(none.root, "unlock-pin-off"));
  assert.equal(one(none.root, "unlock-pin-rule")?.textContent, "Rule from your administrator: at least 8 characters.");
  // A PIN on disk with a count, a wait, a contact time and the offline window.
  const set = await sectionOf(on, { pin: { set: true, location: "disk", failures_left: 3, wait_ms: 4200, last_contact_at: Date.UTC(2026, 10, 20, 12, 0), offline_ok: true } });
  assert.match(one(set.root, "unlock-pin-status")?.textContent ?? "", /kept encrypted on this computer and works after a restart/);
  assert.equal(one(set.root, "unlock-attempts")?.textContent, "3 tries left before the PIN is deleted.");
  assert.equal(one(set.root, "unlock-wait")?.textContent, "The next try is possible in 5 seconds.");
  assert.match(one(set.root, "unlock-contact")?.textContent ?? "", /^Last contact with the server: .*2026/);
  assert.match(one(set.root, "unlock-offline")?.textContent ?? "", /works for 7 days/);
  assert.ok(one(set.root, "unlock-pin-change") && one(set.root, "unlock-pin-off") && !one(set.root, "unlock-pin-on"));
  // Five tries left says nothing about tries; an expired window says the server is needed.
  const fresh = await sectionOf(on, { pin: { set: true, location: "session", failures_left: 5, offline_ok: false } });
  assert.match(one(fresh.root, "unlock-pin-status")?.textContent ?? "", /in memory only/);
  assert.equal(one(fresh.root, "unlock-attempts"), null);
  assert.match(one(fresh.root, "unlock-offline")?.textContent ?? "", /more than 7 days/);
  // The administrator turned PIN off: no button.
  const forbidden = await sectionOf(on, { pin: { allowed: false } });
  assert.match(one(forbidden.root, "unlock-pin-status")?.textContent ?? "", /turned PIN off/);
  assert.equal(byRole(forbidden.root, "unlock-pin-actions")[0].childNodes.length, 0);
  // The passkeys: a count, none, and off.
  assert.equal(one(none.root, "unlock-passkey-count")?.textContent, "Passkeys set up: 2.");
  assert.ok(one(none.root, "unlock-manage"));
  // The policy's count is 0 (the background does not read the list for it): the server's list decides, and when it cannot be
  // read the text does not claim there is none.
  const zero = await sectionOf(on, { prf: { count: 0 }, passkeys: 0 });
  assert.equal(one(zero.root, "unlock-passkey-count")?.textContent, "No passkey is set up for unlocking.");
  const listed = await sectionOf(on, { prf: { count: 0 }, passkeys: 3 });
  assert.equal(one(listed.root, "unlock-passkey-count")?.textContent, "Passkeys set up: 3.");
  // A refusal that says nothing about the account (no server, a device whose state is not known, a pinned record that is
  // missing) does not make the page claim there is no passkey.
  const refused = await sectionOf(on, { prf: { count: 0 }, passkeys: "unavailable" });
  assert.equal(one(refused.root, "unlock-passkey-count")?.textContent, "Passkeys are listed in the web vault.");
  const unknown = await sectionOf(on, { prf: { count: 0 } });
  assert.equal(one(unknown.root, "unlock-passkey-count")?.textContent, "Passkeys are listed in the web vault.");
  const noPrf = await sectionOf(on, { prf: { enabled: false, count: 0 } });
  assert.match(one(noPrf.root, "unlock-passkey-count")?.textContent ?? "", /not turned on/);
  assert.equal(one(noPrf.root, "unlock-manage"), null);
  // The explanation names the difference between a synced passkey and one that stays on this device.
  assert.match(one(none.root, "unlock-passkey-about")?.textContent ?? "", /Synced passkey.*This device only/);
});

test("the_restart_choice_defaults_to_off", async () => {
  const world = await sectionOf(on);
  await click(one(world.root, "unlock-pin-on"));
  const restart = field(world.root, "pin-restart");
  assert.equal(restart.checked, false);
  assert.equal(restart.hasAttribute("disabled"), false);
  assert.equal(restart.getAttribute("type"), "checkbox");
  assert.equal(field(world.root, "pin-restart-hint").textContent, world.catalog["settings.unlock.restart.hint"]);
  // Not remembered: ticked, closed and opened again, it is off again.
  restart.checked = true;
  await click(field(world.root, "pin-cancel"));
  await click(one(world.root, "unlock-pin-on"));
  assert.equal(field(world.root, "pin-restart").checked, false);
  // The label is the one the warning names.
  assert.match(world.catalog["settings.unlock.warning.body"], new RegExp(world.catalog["settings.unlock.restart.label"]));
});

test("the_warning_is_shown_every_time_a_pin_is_set_or_changed", async () => {
  const world = await sectionOf(on);
  const body = world.catalog["settings.unlock.warning.body"];
  assert.match(body, /five-attempt limit does not apply/);
  const seen = async (/** @type {string} */ opener) => {
    assert.equal(dialogOf(world.root).hidden, true, "closed until it is asked for");
    await click(one(world.root, opener));
    assert.equal(dialogOf(world.root).hidden, false);
    const warning = field(world.root, "pin-warning");
    assert.equal(field(world.root, "pin-warning-text").textContent, body);
    assert.equal(warning.getAttribute("id"), "unlock-pin-warning");
    // The dialog is described by the warning, so it is read out when the dialog is entered.
    assert.equal(dialogOf(world.root).getAttribute("aria-describedby"), "unlock-pin-warning");
    assert.equal(dialogOf(world.root).getAttribute("role"), "dialog");
  };
  // A new PIN.
  await seen("unlock-pin-on");
  // With the restart choice on (memory) the warning is still there.
  field(world.root, "pin-restart").checked = true;
  fire(field(world.root, "pin-restart"), "change");
  assert.equal(field(world.root, "pin-warning").hidden, false);
  assert.equal(field(world.root, "pin-warning-text").textContent, body);
  // Set, and the dialog is gone.
  field(world.root, "pin-restart").checked = false;
  fire(field(world.root, "pin-restart"), "change");
  fill(world.root);
  field(world.root, "pin-ack").checked = true;
  await submit(dialogOf(world.root));
  assert.equal(dialogOf(world.root).hidden, true);
  assert.equal(setRequests(world.log).length, 1);
  // A change shows it again, then a second change, and so does a dialog that was cancelled.
  await seen("unlock-pin-change");
  await click(field(world.root, "pin-cancel"));
  await seen("unlock-pin-change");
  assert.equal(setRequests(world.log).length, 1);
});

test("the_pin_is_not_saved_to_disk_without_the_acknowledgement", async () => {
  const world = await sectionOf(on);
  await click(one(world.root, "unlock-pin-on"));
  fill(world.root, { password: SENTINEL_PASSWORD, pin: SENTINEL_PIN });
  await submit(dialogOf(world.root));
  assert.deepEqual(setRequests(world.log), [], "nothing was sent");
  assert.equal(errorText(world.root), world.catalog["settings.unlock.error.not_acknowledged"]);
  assert.equal(world.doc.activeElement, field(world.root, "pin-ack"), "the acknowledgement has the focus");
  // What was typed is still there to fix.
  assert.equal(field(world.root, "pin-pin").value, SENTINEL_PIN);
  // Ticked: it goes, on disk, with the acknowledgement.
  field(world.root, "pin-ack").checked = true;
  await submit(dialogOf(world.root));
  const sent = setRequests(world.log);
  assert.equal(sent.length, 1);
  assert.deepEqual(sent[0][1], { mp: SENTINEL_PASSWORD, pin: SENTINEL_PIN, location: "disk", acknowledged: true });
  assert.equal(world.state.pin.location, "disk");
  // In memory only, no acknowledgement is asked or sent.
  const memory = await sectionOf(on);
  await click(one(memory.root, "unlock-pin-on"));
  field(memory.root, "pin-restart").checked = true;
  fire(field(memory.root, "pin-restart"), "change");
  assert.equal(field(memory.root, "pin-ack-row").hidden, true);
  fill(memory.root);
  await submit(dialogOf(memory.root));
  assert.deepEqual(setRequests(memory.log).map(([, body]) => [body.location, body.acknowledged]), [["session", false]]);
  // A box that was ticked and then hidden does not count as an acknowledgement.
  const hidden = await sectionOf(on);
  await click(one(hidden.root, "unlock-pin-on"));
  field(hidden.root, "pin-ack").checked = true;
  field(hidden.root, "pin-restart").checked = true;
  fire(field(hidden.root, "pin-restart"), "change");
  fill(hidden.root);
  await submit(dialogOf(hidden.root));
  assert.deepEqual(setRequests(hidden.log).map(([, body]) => body.acknowledged), [false]);
});

test("the_acknowledgement_is_not_preticked", async () => {
  const world = await sectionOf(on);
  await click(one(world.root, "unlock-pin-on"));
  const ack = field(world.root, "pin-ack");
  assert.equal(ack.checked, false);
  assert.equal(ack.getAttribute("type"), "checkbox");
  assert.equal(ack.hasAttribute("checked"), false);
  assert.equal(world.catalog["settings.unlock.warning.acknowledge"], "I understand");
  // Ticked and cancelled: unticked the next time. A refused answer unticks it too.
  ack.checked = true;
  await click(field(world.root, "pin-cancel"));
  await click(one(world.root, "unlock-pin-on"));
  assert.equal(field(world.root, "pin-ack").checked, false);
  world.state.reply = { ok: false, reason: "wrong_credentials" };
  fill(world.root);
  field(world.root, "pin-ack").checked = true;
  await submit(dialogOf(world.root));
  assert.equal(setRequests(world.log).length, 1);
  assert.equal(field(world.root, "pin-ack").checked, false);
  // The same after the change of an existing PIN.
  world.state.reply = null;
  world.state.pin.set = true;
  world.state.pin.location = "disk";
  await world.section.refresh();
  await click(field(world.root, "pin-cancel"));
  await click(one(world.root, "unlock-pin-change"));
  assert.equal(field(world.root, "pin-ack").checked, false);
});

test("moving_to_disk_asks_for_the_password", async () => {
  // A PIN kept in memory, moved to disk: the dialog asks for the master password again, and nothing goes without it.
  const world = await sectionOf(on, { pin: { set: true, location: "session" } });
  await click(one(world.root, "unlock-pin-change"));
  assert.equal(field(world.root, "pin-password").getAttribute("type"), "password");
  // The dialog starts from memory; moving to disk is the user's own choice.
  assert.equal(field(world.root, "pin-restart").checked, true);
  field(world.root, "pin-restart").checked = false;
  fire(field(world.root, "pin-restart"), "change");
  fill(world.root, { password: "" });
  field(world.root, "pin-ack").checked = true;
  await submit(dialogOf(world.root));
  assert.deepEqual(setRequests(world.log), []);
  assert.equal(errorText(world.root), world.catalog["settings.unlock.error.password_missing"]);
  assert.equal(world.doc.activeElement, field(world.root, "pin-password"));
  field(world.root, "pin-password").value = "the master password";
  await submit(dialogOf(world.root));
  assert.deepEqual(setRequests(world.log).map(([, body]) => [body.mp, body.location]), [["the master password", "disk"]]);
  // The secret key goes along only when it was typed (the PIN is on disk now, so the change starts from disk).
  await click(one(world.root, "unlock-pin-change"));
  fill(world.root, { secret: "A3-SECRET" });
  field(world.root, "pin-ack").checked = true;
  await submit(dialogOf(world.root));
  assert.equal(setRequests(world.log)[1][1].sk, "A3-SECRET");
  assert.equal("sk" in setRequests(world.log)[0][1], false);
});

test("admin_forbidding_after_restart_locks_the_choice_on_and_says_why", async () => {
  const world = await sectionOf(on, { pin: { after_restart: false } });
  await click(one(world.root, "unlock-pin-on"));
  const restart = field(world.root, "pin-restart");
  assert.equal(restart.checked, true);
  assert.equal(restart.hasAttribute("disabled"), true);
  assert.equal(field(world.root, "pin-restart-hint").textContent, world.catalog["settings.unlock.restart.locked"]);
  assert.match(field(world.root, "pin-restart-hint").textContent, /administrator requires the master password after a restart/);
  // No acknowledgement is asked for: nothing is kept on disk. The PIN goes in memory only.
  assert.equal(field(world.root, "pin-ack-row").hidden, true);
  fill(world.root);
  await submit(dialogOf(world.root));
  assert.deepEqual(setRequests(world.log).map(([, body]) => [body.location, body.acknowledged]), [["session", false]]);
  // A background that still refuses the choice is believed and said.
  const refused = await sectionOf(on);
  refused.state.reply = { ok: false, reason: "after_restart_not_allowed" };
  await click(one(refused.root, "unlock-pin-on"));
  fill(refused.root);
  field(refused.root, "pin-ack").checked = true;
  await submit(dialogOf(refused.root));
  assert.equal(errorText(refused.root), refused.catalog["settings.unlock.error.after_restart_not_allowed"]);
});

test("the_rule_is_shown_and_enforced_in_the_dialog", async () => {
  const world = await sectionOf(on, { pin: { min_length: 8 } });
  await click(one(world.root, "unlock-pin-on"));
  assert.equal(field(world.root, "pin-rule").textContent, "Rule: at least 8 characters and at most 64. Digits, letters and symbols all work. A longer PIN with letters is much harder to guess.");
  field(world.root, "pin-ack").checked = true;
  // One short of the rule: refused on the page, nothing sent, the PIN field has the focus.
  fill(world.root, { pin: "1234567" });
  await submit(dialogOf(world.root));
  assert.deepEqual(setRequests(world.log), []);
  assert.equal(errorText(world.root), "That PIN is too short. Use at least 8 characters.");
  assert.equal(world.doc.activeElement, field(world.root, "pin-pin"));
  // Too long.
  fill(world.root, { pin: "x".repeat(65) });
  await submit(dialogOf(world.root));
  assert.deepEqual(setRequests(world.log), []);
  assert.equal(errorText(world.root), "That PIN is too long. Use at most 64 characters.");
  // Exactly the rule: it goes. Letters are as good as digits.
  fill(world.root, { pin: "abcd1234" });
  await submit(dialogOf(world.root));
  assert.equal(setRequests(world.log).length, 1);
  // The background's own refusal of a PIN is said too.
  const other = await sectionOf(on);
  other.state.reply = { ok: false, reason: "pin_rule" };
  await click(one(other.root, "unlock-pin-on"));
  fill(other.root);
  field(other.root, "pin-ack").checked = true;
  await submit(dialogOf(other.root));
  assert.equal(errorText(other.root), other.catalog["settings.unlock.error.pin_rule"]);
});

test("the_two_pin_fields_must_match", async () => {
  const world = await sectionOf(on);
  await click(one(world.root, "unlock-pin-on"));
  field(world.root, "pin-ack").checked = true;
  fill(world.root, { pin: "123456", again: "123457" });
  await submit(dialogOf(world.root));
  assert.deepEqual(setRequests(world.log), []);
  assert.equal(errorText(world.root), "The two PINs are not the same.");
  assert.equal(world.doc.activeElement, field(world.root, "pin-again"));
  fill(world.root, { pin: "123456", again: "123456" });
  await submit(dialogOf(world.root));
  assert.equal(setRequests(world.log).length, 1);
});

test("fields_are_emptied_on_close_lock_and_answer", async () => {
  const typed = () => ({ password: SENTINEL_PASSWORD, pin: SENTINEL_PIN, secret: "A3-SECRET" });
  const empty = (/** @type {any} */ root) => assert.deepEqual(values(root), ["", "", "", ""]);

  // Close: the Cancel button, and Escape.
  const world = await sectionOf(on);
  await click(one(world.root, "unlock-pin-on"));
  fill(world.root, typed());
  field(world.root, "pin-ack").checked = true;
  await click(field(world.root, "pin-cancel"));
  empty(world.root);
  assert.equal(dialogOf(world.root).hidden, true);
  await click(one(world.root, "unlock-pin-on"));
  fill(world.root, typed());
  const escape = press(dialogOf(world.root), "Escape");
  assert.equal(escape.defaultPrevented, true);
  await settle();
  empty(world.root);
  assert.equal(dialogOf(world.root).hidden, true);
  // Another key does nothing.
  await click(one(world.root, "unlock-pin-on"));
  fill(world.root, typed());
  press(dialogOf(world.root), "a");
  assert.equal(dialogOf(world.root).hidden, false);

  // Lock: the vault closes while the dialog is open; the next look closes and empties it, and says why.
  world.state.vault = "locked";
  await world.section.checkLock();
  empty(world.root);
  assert.equal(dialogOf(world.root).hidden, true);
  assert.equal(one(world.root, "unlock-pin-status")?.textContent, world.catalog["settings.unlock.locked_closed"]);
  // An open vault, or an answer that is none, leaves the dialog alone.
  world.state.vault = "unlocked";
  await click(one(world.root, "unlock-pin-on"));
  fill(world.root, typed());
  await world.section.checkLock();
  assert.equal(dialogOf(world.root).hidden, false);
  assert.equal(values(world.root)[2], SENTINEL_PIN);

  // The page goes away: emptied.
  world.section.wipe();
  empty(world.root);
  assert.equal(dialogOf(world.root).hidden, true);

  // Answer: the fields are empty while the request is out (nothing waits in the page), and after the answer, whichever it is.
  const slow = await sectionOf(on);
  let release = () => {};
  slow.state.hold = new Promise((resolve) => {
    release = () => resolve();
  });
  await click(one(slow.root, "unlock-pin-on"));
  fill(slow.root, typed());
  field(slow.root, "pin-ack").checked = true;
  await click(field(slow.root, "pin-password-toggle"));
  assert.equal(field(slow.root, "pin-password").getAttribute("type"), "text");
  fire(dialogOf(slow.root), "submit");
  await settle();
  assert.equal(setRequests(slow.log).length, 1, "the request is out");
  empty(slow.root);
  assert.equal(field(slow.root, "pin-password").getAttribute("type"), "password", "a shown field is hidden again");
  assert.equal(field(slow.root, "pin-submit").getAttribute("aria-busy"), "true");
  slow.state.reply = { ok: false, reason: "wrong_credentials" };
  release();
  await settle();
  empty(slow.root);
  assert.equal(errorText(slow.root), slow.catalog["settings.unlock.error.wrong_credentials"]);
  assert.equal(field(slow.root, "pin-submit").hasAttribute("aria-busy"), false);
  assert.equal(field(slow.root, "pin-submit").hasAttribute("disabled"), false);
  assert.equal(slow.doc.activeElement, field(slow.root, "pin-password"), "the focus is where the user types again");
  // A good answer closes the dialog, emptied, and the status says what was done.
  slow.state.hold = null;
  slow.state.reply = null;
  fill(slow.root, typed());
  field(slow.root, "pin-ack").checked = true;
  await submit(dialogOf(slow.root));
  empty(slow.root);
  assert.equal(dialogOf(slow.root).hidden, true);
  assert.equal(one(slow.root, "unlock-pin-status")?.textContent, "PIN is on.");
  assert.ok(one(slow.root, "unlock-pin-change"), "the buttons are those of a PIN that is set");

  // A dialog closed while the request is out: the late answer is not shown and nothing is filled in again.
  const late = await sectionOf(on);
  late.state.hold = new Promise((resolve) => {
    release = () => resolve();
  });
  late.state.reply = { ok: false, reason: "wrong_credentials" };
  await click(one(late.root, "unlock-pin-on"));
  fill(late.root, typed());
  field(late.root, "pin-ack").checked = true;
  fire(dialogOf(late.root), "submit");
  await settle();
  await click(field(late.root, "pin-cancel"));
  release();
  await settle();
  empty(late.root);
  assert.equal(errorText(late.root), null);
  assert.equal(dialogOf(late.root).hidden, true);
});

test("the_change_dialog_starts_from_where_the_pin_is", async () => {
  // A PIN kept in memory is changed in memory: moving it to disk is the user's own choice.
  const memory = await sectionOf(on, { pin: { set: true, location: "session" } });
  await click(one(memory.root, "unlock-pin-change"));
  assert.equal(field(memory.root, "pin-restart").checked, true);
  assert.equal(field(memory.root, "pin-restart").hasAttribute("disabled"), false, "it can still be changed");
  assert.equal(field(memory.root, "pin-ack-row").hidden, true);
  // A PIN on disk is changed with the choice off, and a new PIN starts off too.
  const disk = await sectionOf(on, { pin: { set: true, location: "disk" } });
  await click(one(disk.root, "unlock-pin-change"));
  assert.equal(field(disk.root, "pin-restart").checked, false);
  assert.equal(field(disk.root, "pin-ack-row").hidden, false);
  const none = await sectionOf(on);
  await click(one(none.root, "unlock-pin-on"));
  assert.equal(field(none.root, "pin-restart").checked, false);
});

test("a_locked_vault_gets_no_pin_dialog", async () => {
  const world = await sectionOf(on);
  world.state.vault = "locked";
  await click(one(world.root, "unlock-pin-on"));
  assert.equal(dialogOf(world.root).hidden, true);
  assert.equal(one(world.root, "unlock-error")?.hidden, false);
  assert.equal(one(world.root, "unlock-error")?.textContent, world.catalog["settings.unlock.error.vault_locked"]);
  assert.equal(byRole(world.root, "unlock-pin-actions")[0].hidden, false, "the button stays");
  // Unlocked again: the dialog opens and the note is gone.
  world.state.vault = "unlocked";
  await click(one(world.root, "unlock-pin-on"));
  assert.equal(dialogOf(world.root).hidden, false);
  assert.equal(one(world.root, "unlock-error")?.hidden, true);
});

test("a_pin_saved_after_the_dialog_was_closed_is_read_again", async () => {
  const world = await sectionOf(on);
  let release = () => {};
  world.state.hold = new Promise((resolve) => {
    release = () => resolve();
  });
  await click(one(world.root, "unlock-pin-on"));
  fill(world.root);
  field(world.root, "pin-ack").checked = true;
  fire(dialogOf(world.root), "submit");
  await settle();
  await click(field(world.root, "pin-cancel"));
  assert.ok(one(world.root, "unlock-pin-on"), "the section still says there is no PIN");
  release();
  await settle();
  assert.equal(world.state.pin.set, true, "the background did save it");
  assert.ok(one(world.root, "unlock-pin-change") && !one(world.root, "unlock-pin-on"), "the section reads what is true");
  assert.match(one(world.root, "unlock-pin-status")?.textContent ?? "", /PIN is on/);
});

test("the_rule_and_the_keyboard_note_are_read_with_the_pin_fields", async () => {
  const world = await sectionOf(on);
  await click(one(world.root, "unlock-pin-on"));
  for (const role of ["pin-pin", "pin-again"]) {
    const ids = (field(world.root, role).getAttribute("aria-describedby") ?? "").split(" ");
    assert.deepEqual(ids, ["unlock-pin-rule", "unlock-pin-hint"], role);
    for (const id of ids) assert.ok(withAttribute(world.root, "id").some((node) => node.getAttribute("id") === id), id);
  }
  assert.equal(field(world.root, "pin-ack").getAttribute("aria-describedby"), "unlock-pin-warning-title");
});

test("the_popup_empties_the_settings_view_when_it_is_torn_down", () => {
  for (const built of [on, off]) {
    const popup = built.files.get("pages/popup.mjs")?.toString("utf8") ?? "";
    assert.match(popup, /settingsView\?\.wipe\(\)/, "the lock of the popup reaches the view");
  }
});

test("the_pin_and_the_passwords_are_never_in_the_page_after_use", async () => {
  // The sentinel goes out in one request and is in no attribute or text of the page, before, during and after.
  const world = await sectionOf(on);
  await click(one(world.root, "unlock-pin-on"));
  fill(world.root, { password: SENTINEL_PASSWORD, pin: SENTINEL_PIN, secret: "sentinel-secret-key" });
  field(world.root, "pin-ack").checked = true;
  const leaks = () => {
    /** @type {string[]} */
    const found = [];
    const walk = (/** @type {any} */ node) => {
      for (const [name, value] of node.attributes ?? []) if (/sentinel/.test(`${name}=${value}`)) found.push(`attribute ${name}`);
      if (node.nodeType === 3 && /sentinel/.test(node.data)) found.push("text");
      for (const child of node.childNodes ?? []) walk(child);
    };
    walk(world.root);
    return found;
  };
  assert.deepEqual(leaks(), []);
  await submit(dialogOf(world.root));
  assert.deepEqual(leaks(), []);
  assert.equal(setRequests(world.log).length, 1);
  // Only `pin_set` carried a secret; the rest of the traffic is the policy, the state and the off request.
  for (const [type, body] of world.log) if (type !== "pin_set") assert.doesNotMatch(JSON.stringify(body), /sentinel/, type);
  await click(one(world.root, "unlock-pin-off"));
  assert.deepEqual(world.log.at(-2), ["pin_off", {}]);
  assert.deepEqual(leaks(), []);
  // The modules write nothing to a store and nothing to a log.
  for (const file of ["unlockFlow.mjs", "unlockDialog.mjs", "unlockSettings.mjs"]) {
    const text = readFileSync(join(extensionRoot, "src", "pages", file), "utf8");
    assert.doesNotMatch(text, /console\s*\.|localStorage|sessionStorage|indexedDB|browser\s*\.\s*storage|\.cookie\b|postMessage|\balert\(/, file);
    assert.doesNotMatch(text, /\sstyle\s*[:=]|\.style\b|innerHTML|insertAdjacentHTML|eval\(|new Function/, file);
  }
});

test("the_show_buttons_keep_their_name_and_flip_aria_pressed_and_the_123_button_only_changes_the_keyboard", async () => {
  const world = await sectionOf(on);
  await click(one(world.root, "unlock-pin-on"));
  for (const [toggle, input, label] of /** @type {const} */ ([
    ["pin-password-toggle", "pin-password", "Show master password"],
    ["pin-secret-toggle", "pin-secret", "Show secret key"],
    ["pin-pin-toggle", "pin-pin", "Show PIN"],
  ])) {
    const button = field(world.root, toggle);
    assert.equal(button.getAttribute("aria-label"), label);
    assert.equal(button.getAttribute("aria-pressed"), "false");
    assert.equal(field(world.root, input).getAttribute("type"), "password");
    await click(button);
    assert.equal(button.getAttribute("aria-label"), label, "the name does not flip");
    assert.equal(button.getAttribute("aria-pressed"), "true");
    assert.equal(field(world.root, input).getAttribute("type"), "text");
    await click(button);
    assert.equal(button.getAttribute("aria-pressed"), "false");
    assert.equal(field(world.root, input).getAttribute("type"), "password");
  }
  // The PIN's button shows or hides both PIN fields.
  await click(field(world.root, "pin-pin-toggle"));
  assert.equal(field(world.root, "pin-again").getAttribute("type"), "text");
  // "123": the keyboard only. The type, the length and the value stay as they were.
  const numeric = field(world.root, "pin-numeric");
  assert.equal(numeric.getAttribute("aria-pressed"), "false");
  assert.match(numeric.getAttribute("aria-label"), /123/);
  assert.equal(field(world.root, "pin-pin").getAttribute("inputmode"), "text");
  fill(world.root, { pin: "abc123" });
  await click(numeric);
  assert.equal(numeric.getAttribute("aria-pressed"), "true");
  for (const role of ["pin-pin", "pin-again"]) {
    assert.equal(field(world.root, role).getAttribute("inputmode"), "numeric");
    assert.equal(field(world.root, role).getAttribute("maxlength"), null);
  }
  assert.equal(field(world.root, "pin-pin").value, "abc123");
  // Not remembered.
  await click(field(world.root, "pin-cancel"));
  await click(one(world.root, "unlock-pin-on"));
  assert.equal(field(world.root, "pin-numeric").getAttribute("aria-pressed"), "false");
  assert.equal(field(world.root, "pin-pin").getAttribute("inputmode"), "text");
  assert.equal(field(world.root, "pin-pin-toggle").getAttribute("aria-pressed"), "false");
});

test("the_dialog_moves_the_focus_in_and_back_out", async () => {
  const world = await sectionOf(on);
  const opener = one(world.root, "unlock-pin-on");
  await click(opener);
  assert.equal(world.doc.activeElement, field(world.root, "pin-title"), "the title has the focus when the dialog opens");
  assert.equal(field(world.root, "pin-title").getAttribute("tabindex"), "-1");
  assert.equal(dialogOf(world.root).getAttribute("aria-labelledby"), "unlock-pin-title");
  assert.equal(field(world.root, "pin-title").getAttribute("id"), "unlock-pin-title");
  assert.equal(field(world.root, "pin-title").textContent, "Turn on PIN");
  // The buttons that opened it are out of the way while it is open, and back after.
  assert.equal(byRole(world.root, "unlock-pin-actions")[0].hidden, true);
  await click(field(world.root, "pin-cancel"));
  assert.equal(byRole(world.root, "unlock-pin-actions")[0].hidden, false);
  assert.equal(world.doc.activeElement, one(world.root, "unlock-pin-on"), "the focus is back on the button");
  // A change has its own title; turning the PIN off puts the focus on a button that is there.
  world.state.pin.set = true;
  world.state.pin.location = "disk";
  await world.section.refresh();
  await click(one(world.root, "unlock-pin-change"));
  assert.equal(field(world.root, "pin-title").textContent, "Change PIN");
  await click(field(world.root, "pin-cancel"));
  await click(one(world.root, "unlock-pin-off"));
  assert.equal(world.state.pin.set, false);
  assert.equal(one(world.root, "unlock-pin-status")?.textContent, "PIN turned off.");
  assert.equal(world.doc.activeElement, one(world.root, "unlock-pin-on"));
  // Every field has a label that names it, and the live line is polite.
  for (const [input, id] of [["pin-password", "unlock-pin-password"], ["pin-secret", "unlock-pin-secret"], ["pin-pin", "unlock-pin-pin"], ["pin-again", "unlock-pin-again"], ["pin-restart", "unlock-pin-restart"], ["pin-ack", "unlock-pin-ack"]]) {
    assert.equal(field(world.root, input).getAttribute("id"), id);
  }
  assert.equal(one(world.root, "unlock-pin-status")?.getAttribute("aria-live"), "polite");
  assert.equal(field(world.root, "pin-error").getAttribute("role"), "alert");
});

test("turning_the_pin_off_needs_no_password_and_a_refusal_is_said", async () => {
  const world = await sectionOf(on, { pin: { set: true, location: "disk" } });
  await click(one(world.root, "unlock-pin-off"));
  assert.deepEqual(world.log.filter(([type]) => type === "pin_off"), [["pin_off", {}]]);
  assert.equal(one(world.root, "unlock-pin-status")?.textContent, "PIN turned off.");
  assert.ok(one(world.root, "unlock-pin-on"));
  // A background that refuses: the reason is said, and the buttons of what is still true are there.
  const refused = await sectionOf(on, { pin: { set: true, location: "disk" } });
  refused.state.offReply = { ok: false, reason: "internal_error" };
  await click(one(refused.root, "unlock-pin-off"));
  assert.equal(one(refused.root, "unlock-error")?.hidden, false);
  assert.equal(one(refused.root, "unlock-error")?.textContent, refused.catalog["settings.unlock.error.internal_error"]);
  assert.ok(one(refused.root, "unlock-pin-off"));
  assert.equal(one(refused.root, "unlock-pin-off")?.hasAttribute("disabled"), false);
});

test("manage_in_the_web_vault_opens_the_vault_page", async () => {
  const world = await sectionOf(on);
  await click(one(world.root, "unlock-manage"));
  assert.deepEqual(world.opened, ["https://ferret.example.net/#/account"]);
  assert.equal(one(world.root, "unlock-error")?.hidden, true);
  // A server address that is no web address opens nothing and says so.
  const odd = await sectionOf(on, { server: "javascript:alert(1)" });
  await click(one(odd.root, "unlock-manage"));
  assert.deepEqual(odd.opened, []);
  assert.equal(one(odd.root, "unlock-error")?.hidden, false);
  assert.equal(one(odd.root, "unlock-error")?.textContent, odd.catalog["settings.unlock.error.not_available"]);
  // A page with no way to open a tab (no `openTab`) opens nothing.
  const flow = createUnlockFlow(async () => ({ state: "unlocked", server: SERVER }));
  assert.deepEqual(await flow.openVault(), { ok: false, reason: "not_available" });
  // The button is a button, with the name of the text.
  assert.equal(one(world.root, "unlock-manage")?.getAttribute("type"), "button");
  assert.equal(one(world.root, "unlock-manage")?.textContent, "Manage in the web vault");
});

test("texts_exist_in_en_and_nb", async () => {
  const read = (/** @type {string} */ lang) => Object.fromEntries(Object.entries(JSON.parse(readFileSync(join(extensionRoot, "src", "locales", lang, "settings.json"), "utf8"))).filter(([key]) => key.startsWith("settings.unlock.")));
  const [en, nb] = [read("en"), read("nb")];
  assert.deepEqual(Object.keys(en).sort(), Object.keys(nb).sort(), "the same keys in en and nb");
  for (const [lang, texts] of [["en", en], ["nb", nb]]) for (const [key, text] of Object.entries(texts)) assert.ok(typeof text === "string" && text.length > 0, `${lang}: ${key}`);
  // Every text the modules ask for is there, in both languages (a key written as a literal, and the reasons).
  const wanted = new Set();
  for (const file of ["unlockFlow.mjs", "unlockDialog.mjs", "unlockSettings.mjs"]) {
    const text = readFileSync(join(extensionRoot, "src", "pages", file), "utf8");
    for (const [, key] of text.matchAll(/["'`](settings\.unlock\.[a-z_.]+)["'`]/g)) wanted.add(key);
  }
  for (const reason of ["wrong_credentials", "pin_rule", "pin_not_allowed", "after_restart_not_allowed", "not_acknowledged", "out_of_memory", "too_slow", "network", "too_short", "too_long", "mismatch", "password_missing", "vault_locked", "not_available", "invalid_input", "internal_error", "disconnected", "unknown"]) wanted.add(unlockErrorKey(reason));
  for (const key of wanted) {
    assert.ok(en[key], `en: ${key}`);
    assert.ok(nb[key], `nb: ${key}`);
  }
  // No key that nobody asks for (the two lists are the same).
  for (const key of Object.keys(en)) assert.ok(wanted.has(key), `unused: ${key}`);
  // The two languages say different things, and the warning is the one that was written for the default (disk).
  for (const key of Object.keys(en)) if (!["settings.unlock.dialog.pin.numeric", "settings.unlock.dialog.pin.label", "settings.unlock.pin.title", "settings.unlock.passkey.title"].includes(key)) assert.notEqual(en[key], nb[key], key);
  assert.match(en["settings.unlock.warning.body"], /Your PIN is kept on this computer, encrypted, so it works after a restart and without a network/);
  assert.match(en["settings.unlock.warning.body"], /the five-attempt limit does not apply there/);
  // Two plain sentences more: a revoked device stays usable offline for up to 7 days, and a removed PIN may stay on disk.
  assert.match(en["settings.unlock.warning.body"], /A device that has been revoked can still be opened with its PIN for up to 7 days while it stays offline\./);
  assert.match(en["settings.unlock.warning.body"], /A PIN you remove may remain in your browser profile's files on disk\./);
  assert.match(nb["settings.unlock.warning.body"], /tilbakekalt, kan fortsatt åpnes med PIN-en i opptil 7 dager/);
  assert.match(nb["settings.unlock.warning.body"], /En PIN du fjerner, kan bli liggende i filene i nettleserprofilen din på disken\./);
  assert.match(nb["settings.unlock.warning.body"], /PIN-en din lagres kryptert på denne datamaskinen/);
  assert.match(nb["settings.unlock.warning.body"], /grensen på fem forsøk gjelder ikke der/);
  assert.equal(nb["settings.unlock.warning.acknowledge"], "Jeg forstår");
  assert.equal(nb["settings.unlock.restart.label"], "Krev hovedpassord etter omstart av nettleseren");
  // The label the warning names is the label of the choice, in both languages.
  assert.ok(en["settings.unlock.warning.body"].includes(en["settings.unlock.restart.label"]));
  assert.ok(nb["settings.unlock.warning.body"].includes(nb["settings.unlock.restart.label"]));
  // The built packages carry them, and the section speaks Norwegian when it is asked to.
  for (const built of [on, off]) {
    const catalog = JSON.parse(readFileSync(join(built.dir, "locales.nb.json"), "utf8"));
    assert.equal(catalog["settings.unlock.pin.on"], nb["settings.unlock.pin.on"]);
  }
  const world = await sectionOf(on, { lang: "nb", pin: { min_length: 8 } });
  assert.equal(one(world.root, "unlock-pin-status")?.textContent, "Ingen PIN er satt.");
  assert.equal(one(world.root, "unlock-pin-rule")?.textContent, "Regel fra administratoren din: minst 8 tegn.");
  await click(one(world.root, "unlock-pin-on"));
  assert.equal(field(world.root, "pin-warning-text").textContent, nb["settings.unlock.warning.body"]);
});

test("the_unlock_page_modules_use_no_inline_style_and_the_build_has_the_stylesheet", () => {
  for (const built of [on, off]) {
    const css = built.files.get("assets/app.css")?.toString("utf8") ?? "";
    assert.match(css, /\.ff-pin-dialog\[hidden\]/);
    assert.match(css, /\.ff-pin-warning\b/);
  }
  const css = readFileSync(join(extensionRoot, "src", "styles", "unlock.css"), "utf8");
  // Only the tokens of session.css: no colour written out.
  assert.doesNotMatch(css, /#[0-9a-fA-F]{3,8}\b|rgba?\(|hsla?\(/);
});
