// The popup page itself (pages/popup.mjs of a built package) with a PIN on its locked view, over the real protocol: the page
// talks to a fake background through the real UI port code (`connectUi`), and every request and every reply goes through
// `encode` and `decode` of the extension's protocol, so a body or a reply that the real handlers could not send or that the
// page could not read fails here. What this checks that the part's own tests do not: the wiring in the page (the master
// password's form first, the PIN added when the answer comes, however late), what a refusal that ends the PIN shows, what
// the page empties when it goes away, and that a build with unlock off asks the background nothing about a PIN.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { pathToFileURL } from "node:url";
import { build } from "../../scripts/build.mjs";
import { UI_TYPES, decode, encode, encodeRefusal } from "../../src/shared/protocol.mjs";
import { PIN_ENDED_REASONS, pinResultOf } from "../../src/pages/popupFlow.mjs";
import { readUnlockState } from "../../src/pages/unlockFlow.mjs";
import { makeRoot } from "./buildHelpers.mjs";
import { byRole, click, one, settle, submit, useDocument } from "./pageDom.mjs";

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
let worlds = 0;

/** The answer of `unlock_policy` for a PIN that is set. @param {Record<string, unknown>} [pin] */
const policy = (pin = {}) => ({
  pin_state: { allowed: true, after_restart: true, min_length: 6, set: true, location: "disk", failures_left: 5, wait_ms: 0, offline_ok: true, ...pin },
  prf: { enabled: false },
});

/**
 * Runs the popup page of a built package against a fake background. `answers` gives the reply body of a request type (a
 * function gets the request body, and may return a promise that a test holds back); a reply is encoded with the real
 * schema, a thrown error with a `code` is sent as the router's refusal.
 * @param {Awaited<ReturnType<typeof build>>} built
 * @param {Record<string, (body: any) => unknown>} answers
 */
async function popupOf(built, answers) {
  const doc = /** @type {any} */ (useDocument());
  const elements = new Map();
  for (const id of ["root", "lock", "popout", "avatar"]) elements.set(id, doc.createElement(id === "root" ? "main" : "button"));
  doc.getElementById = (/** @type {string} */ id) => elements.get(id) ?? null;
  doc.body = doc.createElement("body");
  doc.body.classList.toggle = () => {};
  doc.documentElement = { lang: "" };
  doc.querySelectorAll = () => [];
  /** @type {Array<() => void>} */
  const pagehide = [];
  /** @type {Array<{ type: string, body: any }>} */
  const requests = [];
  const catalog = JSON.parse(readFileSync(join(built.dir, "locales.en.json"), "utf8"));
  /** @type {Array<(raw: unknown) => void>} */
  const listeners = [];
  const port = {
    postMessage(/** @type {string} */ raw) {
      const { id, type, body } = decode(raw, UI_TYPES);
      requests.push({ type, body: JSON.parse(JSON.stringify(body)) });
      void (async () => {
        let reply;
        try {
          const answer = answers[type];
          if (!answer) throw Object.assign(new Error("not_available"), { code: "not_available" });
          reply = encode(type, await answer(body), { id, reply: true });
        } catch (error) {
          reply = encodeRefusal(id, /** @type {any} */ (error)?.code ?? "internal_error");
        }
        for (const fn of listeners) fn(reply);
      })();
    },
    disconnect() {},
    onMessage: { addListener: (/** @type {(raw: unknown) => void} */ fn) => listeners.push(fn) },
    onDisconnect: { addListener() {} },
  };
  const saved = Object.fromEntries(["window", "location", "browser", "fetch"].map((key) => [key, /** @type {any} */ (globalThis)[key]]));
  Object.assign(globalThis, {
    window: { addEventListener: (/** @type {string} */ type, /** @type {() => void} */ fn) => type === "pagehide" && pagehide.push(fn), close() {} },
    location: { search: "" },
    fetch: async () => ({ ok: true, json: async () => catalog }),
    browser: {
      runtime: { getURL: (/** @type {string} */ path) => `moz-extension://test/${path}`, connect: () => port },
      tabs: { getCurrent: async () => undefined, query: async () => [], create: async () => ({}) },
      windows: { create: async () => ({}) },
      storage: { local: { get: async () => ({}), set: async () => {} } },
      permissions: { request: async () => true, remove: async () => true },
    },
  });
  worlds += 1;
  await import(`${pathToFileURL(join(built.dir, "pages", "popup.mjs")).href}?world=${worlds}`);
  const root = elements.get("root");
  for (let i = 0; i < 200 && doc.body.dataset.ready !== "1"; i += 1) await new Promise((resolve) => setTimeout(resolve, 5));
  assert.equal(doc.body.dataset.ready, "1", "the popup is ready");
  await settle();
  return {
    doc,
    root,
    requests,
    catalog,
    pagehide,
    elements,
    cleanup() {
      for (const [key, value] of Object.entries(saved)) /** @type {any} */ (globalThis)[key] = value;
    },
  };
}

/** The answers of a locked device, and what a test adds. @param {Record<string, (body: any) => unknown>} [more] */
const locked = (more = {}) => ({
  state: () => ({ state: "locked", server: SERVER, account: "ola@example.net" }),
  ...more,
});

const hidden = (/** @type {any} */ node) => node === null || node.hasAttribute("hidden");
const text = (/** @type {any} */ root, /** @type {string} */ role) => one(root, role)?.textContent ?? null;

test("the_master_password_form_is_there_at_once_and_a_late_policy_answer_adds_the_pin", async () => {
  /** @type {() => void} */
  let release = () => {};
  const held = new Promise((resolve) => {
    release = () => resolve(undefined);
  });
  const world = await popupOf(on, locked({ unlock_policy: async () => (await held, policy()) }));
  try {
    // The policy has not answered: the master password's form is shown, nothing is blank, and the PIN is not there yet.
    assert.ok(one(world.root, "locked-view"));
    assert.equal(hidden(one(world.root, "unlock-form")), false);
    assert.equal(one(world.root, "pin-unlock-form"), null);
    assert.equal(world.doc.activeElement, one(world.root, "password"));
    release();
    await settle();
    // The answer came late, and the PIN is offered: its field has the place, the master password's form is a click away.
    assert.ok(one(world.root, "pin-unlock-form"));
    assert.equal(hidden(one(world.root, "pin-unlock-form")), false);
    assert.equal(hidden(one(world.root, "unlock-form")), true);
    assert.equal(world.doc.activeElement, one(world.root, "pin-input"));
    await click(one(world.root, "use-master"));
    assert.equal(hidden(one(world.root, "unlock-form")), false);
    assert.equal(hidden(one(world.root, "pin-unlock-form")), true);
    assert.equal(world.doc.activeElement, one(world.root, "password"));
    await click(one(world.root, "use-pin"));
    assert.equal(hidden(one(world.root, "unlock-form")), true);
    assert.equal(hidden(one(world.root, "pin-unlock-form")), false);
    assert.equal(world.doc.activeElement, one(world.root, "pin-input"));
  } finally {
    world.cleanup();
  }
});

test("a_person_who_has_started_typing_the_master_password_keeps_that_form", async () => {
  /** @type {() => void} */
  let release = () => {};
  const held = new Promise((resolve) => {
    release = () => resolve(undefined);
  });
  const world = await popupOf(on, locked({ unlock_policy: async () => (await held, policy()) }));
  try {
    /** @type {any} */ (one(world.root, "password")).value = "half a master pass";
    release();
    await settle();
    // The PIN is offered but does not take the form away: "Use PIN instead" is there, and the part waits hidden.
    assert.equal(hidden(one(world.root, "unlock-form")), false);
    assert.equal(hidden(one(world.root, "pin-unlock-form")), true);
    assert.equal(/** @type {any} */ (one(world.root, "password")).value, "half a master pass");
    assert.ok(one(world.root, "use-pin"));
    // Going to the PIN empties what was typed in the master password's form.
    await click(one(world.root, "use-pin"));
    assert.equal(/** @type {any} */ (one(world.root, "password")).value, "");
    assert.equal(hidden(one(world.root, "pin-unlock-form")), false);
  } finally {
    world.cleanup();
  }
});

test("a_policy_answer_in_the_middle_of_a_master_password_unlock_keeps_the_form_for_its_error", async () => {
  /** @type {() => void} */
  let releasePolicy = () => {};
  const heldPolicy = new Promise((resolve) => {
    releasePolicy = () => resolve(undefined);
  });
  /** @type {() => void} */
  let releaseUnlock = () => {};
  const heldUnlock = new Promise((resolve) => {
    releaseUnlock = () => resolve(undefined);
  });
  const world = await popupOf(
    on,
    locked({
      unlock_policy: async () => (await heldPolicy, policy()),
      unlock: async () => (await heldUnlock, { ok: false, reason: "wrong_credentials" }),
    }),
  );
  try {
    // The master password is sent: the submit empties the fields before it awaits the answer, so the fields say nothing.
    /** @type {any} */ (one(world.root, "password")).value = "a master password";
    const sent = submit(one(world.root, "unlock-form"));
    await settle();
    assert.equal(/** @type {any} */ (one(world.root, "password")).value, "");
    assert.equal(one(world.root, "unlock-form")?.getAttribute("aria-busy"), "true");
    // The policy answers now, in the middle of that unlock: the form stays, and only "Use PIN instead" is added.
    releasePolicy();
    await settle();
    assert.equal(hidden(one(world.root, "unlock-form")), false);
    assert.equal(hidden(one(world.root, "pin-unlock-form")), true);
    assert.ok(one(world.root, "use-pin"));
    // The unlock fails: its error is in the form the person can see.
    releaseUnlock();
    await sent;
    await settle();
    const error = /** @type {any} */ (byRole(one(world.root, "unlock-form"), "error")[0]);
    assert.equal(error.hidden, false);
    assert.notEqual(error.textContent, "");
    assert.equal(hidden(one(world.root, "unlock-form")), false);
  } finally {
    world.cleanup();
  }
});

test("a_pin_that_is_gone_shows_the_master_password_form_with_the_reason_in_the_alert", async () => {
  for (const [reply, expected] of /** @type {Array<[any, (c: Record<string, string>) => string]>} */ ([
    [{ ok: false, reason: "pin_wiped" }, (c) => c["unlock.pin.error.pin_wiped"]],
    [{ ok: false, reason: "pin_stale" }, (c) => c["pin.error.pin_stale"]],
    [{ ok: false, reason: "pin_unavailable" }, (c) => c["unlock.pin.error.pin_unavailable"]],
    [{ ok: false, reason: "attack_warning" }, (c) => `${c["session.error.attack_warning"]} ${c["unlock.pin.error.removed_note"]}`],
  ])) {
    const world = await popupOf(on, locked({ unlock_policy: () => policy(), pin_unlock: () => reply }));
    try {
      const input = /** @type {any} */ (one(world.root, "pin-input"));
      input.value = "a-pin-of-length";
      await submit(one(world.root, "pin-unlock-form"));
      assert.deepEqual(world.requests.filter((r) => r.type === "pin_unlock").map((r) => r.body), [{ pin: "a-pin-of-length" }], reply.reason);
      const error = /** @type {any} */ (byRole(one(world.root, "unlock-form"), "error")[0]);
      assert.equal(error.textContent, expected(world.catalog), reply.reason);
      assert.equal(error.hidden, false, reply.reason);
      assert.equal(hidden(one(world.root, "unlock-form")), false, reply.reason);
      assert.equal(hidden(one(world.root, "pin-unlock-form")), true, reply.reason);
      assert.equal(hidden(one(world.root, "use-pin")), true, `${reply.reason}: nothing offers the PIN again in this view`);
      assert.equal(/** @type {any} */ (one(world.root, "pin-input")).value, "", reply.reason);
      assert.equal(world.doc.activeElement, one(world.root, "password"), reply.reason);
    } finally {
      world.cleanup();
    }
  }
});

test("the_page_empties_a_typed_pin_when_it_goes_away_and_sends_nothing_for_a_short_one", async () => {
  const world = await popupOf(on, locked({ unlock_policy: () => policy(), pin_unlock: () => ({ ok: false, reason: "wrong_pin", left: 4, wait_ms: 0 }) }));
  try {
    const input = /** @type {any} */ (one(world.root, "pin-input"));
    // A PIN shorter than the rule is not sent at all.
    input.value = "abc";
    await submit(one(world.root, "pin-unlock-form"));
    assert.equal(world.requests.filter((r) => r.type === "pin_unlock").length, 0);
    assert.equal(text(world.root, "pin-error"), "The PIN has at least 6 characters.");
    // A PIN typed and not sent is gone when the page goes away.
    input.value = "typed and never sent";
    assert.ok(world.pagehide.length >= 1);
    for (const fn of world.pagehide) fn();
    assert.equal(input.value, "");
    // The answer to a PIN that went out: the real reply shape is read (left, wait), the text is the wrong-PIN text.
    input.value = "wrong-but-long-enough";
    await submit(one(world.root, "pin-unlock-form"));
    assert.equal(text(world.root, "pin-error"), "That PIN is not right. 4 tries left before the PIN is deleted.");
    assert.equal(input.value, "");
  } finally {
    world.cleanup();
  }
});

test("a_build_with_unlock_off_asks_nothing_about_a_pin_and_keeps_the_old_form", async () => {
  const world = await popupOf(off, locked({ unlock_policy: () => policy(), pin_unlock: () => ({ ok: true }) }));
  try {
    await settle();
    assert.deepEqual([...new Set(world.requests.map((r) => r.type))].filter((type) => type.startsWith("pin_") || type === "unlock_policy"), []);
    assert.equal(one(world.root, "pin-unlock-form"), null);
    assert.equal(one(world.root, "use-pin"), null);
    assert.equal(hidden(one(world.root, "unlock-form")), false);
    // The form is as it was: the button is a direct child of the form (no row for a second button).
    const form = /** @type {any} */ (one(world.root, "unlock-form"));
    assert.ok(form.childNodes.includes(one(world.root, "unlock")));
    assert.equal(byRole(world.root, "use-master").length, 0);
  } finally {
    world.cleanup();
  }
});

// -------------------------------------------------------------------------------------------------- the contract

test("every_reason_the_pin_handlers_send_goes_through_the_protocol_and_has_its_text", async () => {
  const en = JSON.parse(readFileSync(join(on.dir, "locales.en.json"), "utf8"));
  // The handlers of the built package (the sources ask the build's feature module, which only a package has).
  const { PIN_REASONS: HANDLER_PIN_REASONS } = await import(pathToFileURL(join(on.dir, "background", "handlers", "unlock.handler.mjs")).href);
  const { REASONS: SESSION_REASONS } = await import(pathToFileURL(join(on.dir, "background", "handlers", "session.handler.mjs")).href);
  /** What `pin_unlock` can answer: the PIN host's own reasons, `pin_rule` among them, and the session's. */
  const unlockReasons = ["wrong_pin", "pin_wait", "out_of_memory", "pin_wiped", "pin_stale", "pin_offline_expired", "pin_unavailable", "pin_rule"];
  const sessionReasons = ["attack_warning", "signed_out", "busy", "vault_locked", "network", "throttled"];
  // They are reasons the handlers know (the page cannot have a text for a code the background never sends).
  for (const reason of unlockReasons) assert.ok(HANDLER_PIN_REASONS.includes(reason), reason);
  for (const reason of sessionReasons) assert.ok(SESSION_REASONS.includes(reason), reason);
  for (const reason of [...unlockReasons, ...sessionReasons]) {
    for (const extra of [{}, { left: 3, wait_ms: 5000 }]) {
      const sent = encode("pin_unlock", { ok: false, reason, ...extra }, { id: "c1", reply: true });
      const body = decode(sent, UI_TYPES, { reply: true }).body;
      const result = pinResultOf(body);
      assert.equal(result.ok, false, reason);
      if (result.ok) continue;
      // Each reason has a text of its own and none falls back to the general one.
      for (const key of result.keys) assert.ok(typeof en[key] === "string" && en[key].length > 0, `${reason}: ${key}`);
      assert.notEqual(result.keys[0], "session.error.unknown", reason);
      assert.equal(result.ended, PIN_ENDED_REASONS.includes(reason), reason);
      assert.equal(result.left, "left" in extra ? 3 : null, reason);
      assert.equal(result.waitMs, "wait_ms" in extra ? 5000 : 0, reason);
    }
  }
  // The uncounted refusal for a PIN outside the rule keeps the PIN and says that it did not count.
  const rule = pinResultOf({ ok: false, reason: "pin_rule", left: 4, wait_ms: 0 });
  assert.equal(rule.ok === false && rule.ended, false);
  assert.match(en["unlock.pin.error.pin_rule"], /did not count as a try/);
  // The success reply, and the request that carries only the PIN.
  assert.equal(decode(encode("pin_unlock", { ok: true, account_email: "ola@example.net", server: SERVER }, { id: "c2", reply: true }), UI_TYPES, { reply: true }).body.ok, true);
  assert.deepEqual(decode(encode("pin_unlock", { pin: "a pin" }, { id: "c3" }), UI_TYPES).body, { pin: "a pin" });
  assert.throws(() => encode("pin_unlock", { pin: "a pin", mp: "no" }, { id: "c4" }));
  // `unlock_policy`: the reply of the handlers reads as an offer, and one without a PIN does not.
  for (const body of [policy(), policy({ location: "session", failures_left: 2, wait_ms: 15_000, offline_ok: false })]) {
    const read = readUnlockState(decode(encode("unlock_policy", body, { id: "c5", reply: true }), UI_TYPES, { reply: true }).body);
    assert.ok(read !== null && read.pin.set && read.pin.allowed);
  }
  const none = { pin_state: { allowed: true, after_restart: true, min_length: 6, set: false, failures_left: 5, wait_ms: 0, offline_ok: true }, prf: { enabled: false } };
  assert.equal(readUnlockState(decode(encode("unlock_policy", none, { id: "c6", reply: true }), UI_TYPES, { reply: true }).body)?.pin.set, false);
});
