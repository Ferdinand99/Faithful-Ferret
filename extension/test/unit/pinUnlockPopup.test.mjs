// The PIN on the popup's locked view: when the field shows, the "123" button, the texts of every refusal (a wrong PIN with the
// tries left, the wait, the PIN deleted after five, a stale PIN, a device without the memory for it, the offline window, the
// attack warning), and what happens to the typed PIN. The steps have no DOM and run as they are; the part runs over the DOM
// stand-in against a fake background that answers as the real one is told to, with a clock and a timer of the test's own. The
// package is built twice: with unlock on (the test variant) and off (a release).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { pathToFileURL } from "node:url";
import { build } from "../../scripts/build.mjs";
import { PIN_ENDED_REASONS, PIN_REASONS, pinResultOf } from "../../src/pages/popupFlow.mjs";
import { UiError } from "../../src/pages/ui.mjs";
import { extensionRoot, makeRoot } from "./buildHelpers.mjs";
import { click, one, settle, submit, useDocument, withAttribute } from "./pageDom.mjs";

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
  off = await build({ ...options, out: join(env.out, "off"), variant: "test", features: ["save"] });
});
after(() => env?.cleanup());

const SENTINEL = "sentinel-pin-4417-xyz";

/** The state of a PIN as the background's `unlock_policy` says it. @param {Record<string, unknown>} [pin] */
const policy = (pin = {}) => ({
  pin_state: { allowed: true, after_restart: true, min_length: 6, set: true, location: "disk", failures_left: 5, wait_ms: 0, offline_ok: true, ...pin },
  prf: { enabled: false },
});

/**
 * Texts as a page gets them: `{name}` filled, and the key itself for a key the catalog lacks (as the real catalog does).
 * @param {Record<string, string>} catalog @param {string} lang
 */
function textsOf(catalog, lang) {
  return {
    lang,
    t: (/** @type {string} */ key, /** @type {Record<string, string | number>} */ vars = {}) =>
      Object.hasOwn(catalog, key) ? catalog[key].replace(/\{(\w+)\}/g, (all, name) => (name in vars ? String(vars[name]) : all)) : key,
  };
}

/**
 * A background that answers `unlock_policy`, `pin_unlock` (from a script a test sets) and `state`, and logs every request (a
 * copy, so what the page sends later cannot change an entry).
 * @param {Record<string, unknown>} [pin]
 */
function backend(pin = {}) {
  const state = {
    policy: policy(pin),
    vault: "locked",
    /** @type {any[]} */
    replies: [],
    /** @type {Promise<void> | null} */
    hold: null,
    /** @type {any} */
    policyThrows: null,
  };
  /** @type {Array<[string, any]>} */
  const log = [];
  /** @type {import("../../src/pages/ui.mjs").Request} */
  const request = async (type, body) => {
    log.push([type, JSON.parse(JSON.stringify(body))]);
    switch (type) {
      case "unlock_policy":
        if (state.policyThrows) throw state.policyThrows;
        return state.policy;
      case "pin_unlock": {
        if (state.hold) await state.hold;
        const reply = state.replies.shift();
        if (reply instanceof Error) throw reply;
        if (reply?.ok === true) state.vault = "unlocked";
        return reply ?? { ok: false, reason: "wrong_pin" };
      }
      case "state":
        return { state: state.vault, server: "https://ferret.example.net", account: "ola@example.net" };
      case "sync_state":
        return { running: false };
      default:
        throw new UiError("not_available");
    }
  };
  return { state, log, request };
}

/** A clock and a timer that only move when the test says so. */
function clock() {
  let time = 1_000_000;
  /** @type {Array<{ at: number, fn: () => void, off: boolean }>} */
  const timers = [];
  return {
    now: () => time,
    schedule: (/** @type {() => void} */ fn, /** @type {number} */ ms) => {
      const timer = { at: time + ms, fn, off: false };
      timers.push(timer);
      return timer;
    },
    cancel: (/** @type {{ off: boolean }} */ timer) => {
      timer.off = true;
    },
    /** @param {number} ms */
    advance(ms) {
      const target = time + ms;
      for (;;) {
        const due = timers.filter((timer) => !timer.off && timer.at <= target).sort((a, b) => a.at - b.at)[0];
        if (!due) break;
        due.off = true;
        time = Math.max(time, due.at);
        due.fn();
      }
      time = target;
    },
    pending: () => timers.filter((timer) => !timer.off).length,
  };
}

/**
 * The part of a built package over a fake background.
 * @param {Awaited<ReturnType<typeof build>>} built
 * @param {{ lang?: string, pin?: Record<string, unknown>, offer?: Record<string, unknown> | null }} [init]
 */
async function partOf(built, init = {}) {
  const doc = useDocument();
  /** @type {Array<[string, () => void]>} */
  const pagehide = [];
  const previous = /** @type {any} */ (globalThis).addEventListener;
  /** @type {any} */ (globalThis).addEventListener = (/** @type {string} */ type, /** @type {() => void} */ fn) => pagehide.push([type, fn]);
  try {
    const flowModule = await import(pathToFileURL(join(built.dir, "pages", "popupFlow.mjs")).href);
    const viewModule = await import(pathToFileURL(join(built.dir, "pages", "pinUnlockView.mjs")).href);
    const lang = init.lang ?? "en";
    const catalog = JSON.parse(readFileSync(join(built.dir, `locales.${lang}.json`), "utf8"));
    const fake = backend(init.pin);
    const flow = flowModule.createPopupFlow(fake.request);
    const time = clock();
    const offer = init.offer === undefined ? await flow.pinPolicy() : init.offer;
    /** @type {PopupView[]} */
    const done = [];
    /** @type {string[]} */
    const ended = [];
    let useMaster = 0;
    const part = offer === null ? null : viewModule.createPinUnlockPart({
      texts: textsOf(catalog, lang),
      flow,
      offer,
      onDone: (/** @type {any} */ view) => done.push(view),
      onEnded: (/** @type {string} */ message) => ended.push(message),
      onUseMaster: () => {
        useMaster += 1;
      },
      schedule: time.schedule,
      cancel: time.cancel,
      now: time.now,
    });
    return { doc, part, flow, offer, catalog, time, done, ended, useMasterCount: () => useMaster, pagehide, viewModule, flowModule, ...fake };
  } finally {
    /** @type {any} */ (globalThis).addEventListener = previous;
  }
}
/** @typedef {import("../../src/pages/popupFlow.mjs").PopupView} PopupView */

const root = (/** @type {any} */ world) => world.part.root;
const input = (/** @type {any} */ world) => /** @type {any} */ (one(root(world), "pin-input"));
const live = (/** @type {any} */ world) => /** @type {any} */ (one(root(world), "pin-error"));
const unlockButton = (/** @type {any} */ world) => /** @type {any} */ (one(root(world), "pin-unlock"));
const pinRequests = (/** @type {Array<[string, any]>} */ log) => log.filter(([type]) => type === "pin_unlock");

/** Types a PIN and submits the form. @param {any} world @param {string} [pin] */
async function enter(world, pin = SENTINEL) {
  input(world).value = pin;
  await submit(root(world));
}

// ------------------------------------------------------------------------------------------------------ the steps

test("the_pin_field_shows_only_when_a_pin_is_set_and_unlock_is_on", async () => {
  // What the background says decides: a PIN that is set and allowed is offered, anything else is not.
  const offered = await partOf(on);
  assert.equal(offered.offer?.set, true);
  assert.deepEqual(offered.log, [["unlock_policy", {}]]);
  for (const [what, pin] of /** @type {Array<[string, Record<string, unknown>]>} */ ([["no PIN set", { set: false, location: null }], ["the administrator forbids PIN", { allowed: false }]])) {
    const world = await partOf(on, { pin });
    assert.equal(world.offer, null, what);
    assert.equal(world.part, null, what);
  }
  for (const reply of [null, {}, { pin_state: null, prf: {} }, { pin: policy().pin_state, prf: { enabled: false } }, { pin_state: { ...policy().pin_state, min_length: 3 }, prf: { enabled: false } }]) {
    const world = await partOf(on, { offer: null });
    world.state.policy = /** @type {any} */ (reply);
    assert.equal(await world.flow.pinPolicy(), null, JSON.stringify(reply));
  }
  const broken = await partOf(on, { offer: null });
  broken.state.policyThrows = new UiError("disconnected");
  assert.equal(await broken.flow.pinPolicy(), null, "a background that does not answer offers no PIN");
  broken.state.policyThrows = new UiError("not_available");
  assert.equal(await broken.flow.pinPolicy(), null, "a server or a build without the feature offers no PIN");

  // The field: one labelled field for a secret, "Unlock with PIN", and "Use master password instead", all marked as the feature's.
  assert.ok(offered.part);
  const field = input(offered);
  assert.equal(field.getAttribute("type"), "password");
  assert.equal(field.getAttribute("autocomplete"), "off");
  const label = withAttribute(root(offered), "for").find((node) => node.getAttribute("for") === field.getAttribute("id"));
  assert.equal(label?.textContent, "PIN", "the label names the field");
  assert.equal(unlockButton(offered).textContent, "Unlock with PIN");
  assert.equal(one(root(offered), "use-master")?.textContent, "Use master password instead");
  assert.equal(root(offered).getAttribute("data-feature"), "unlock");
  assert.equal(one(root(offered), "use-master")?.getAttribute("data-feature"), "unlock");

  // A build with unlock off gives no part at all, whatever the background says.
  const viewOff = await import(pathToFileURL(join(off.dir, "pages", "pinUnlockView.mjs")).href);
  const absent = viewOff.createPinUnlockPart({ texts: textsOf({}, "en"), flow: {}, offer: offered.offer, onDone() {}, onEnded() {}, onUseMaster() {} });
  assert.equal(absent, null);

  // The popup asks the background about a PIN only in a build with the feature on, and only after it asked the flag.
  const code = readFileSync(join(extensionRoot, "src", "pages", "popup.mjs"), "utf8");
  // The master password's form is built first and shown at once; the PIN is added when the answer comes, and no timer gives up on it.
  const flag = code.indexOf("if (!FEATURES.unlock) return;");
  assert.ok(flag !== -1);
  assert.ok(code.indexOf("const mounted = mountLocked(view);") < flag);
  assert.ok(flag < code.indexOf("flow.pinPolicy()"));
  assert.doesNotMatch(code, /PIN_OFFER_WAIT|giveUp|Promise\.race/);
  assert.match(code, /mounted\.addPin\(offer\)/);
  assert.equal(code.match(/pinPolicy\(/g)?.length, 1, "one place asks");
});

test("the_123_toggle_only_changes_inputmode_and_is_not_remembered", async () => {
  const world = await partOf(on);
  const button = /** @type {any} */ (one(root(world), "pin-numeric"));
  assert.equal(button.getAttribute("aria-pressed"), "false");
  input(world).value = "abc123";
  await click(button);
  assert.equal(input(world).getAttribute("inputmode"), "numeric");
  assert.equal(button.getAttribute("aria-pressed"), "true");
  // Only the keyboard changes: the field stays a field for any text, and what was typed stays.
  assert.equal(input(world).getAttribute("type"), "password");
  assert.equal(input(world).value, "abc123");
  assert.equal(button.textContent, "123");
  assert.equal(button.getAttribute("aria-label"), "123 keyboard", "a fixed name; the state is aria-pressed");
  await click(button);
  assert.equal(input(world).getAttribute("inputmode"), "text");
  assert.equal(button.getAttribute("aria-pressed"), "false");
  // Not remembered: the next time the part is made (the next unlock), and after a wipe, the keyboard is the plain one.
  await click(button);
  world.part.wipe();
  assert.equal(input(world).getAttribute("inputmode"), "text");
  assert.equal(button.getAttribute("aria-pressed"), "false");
  const next = await partOf(on);
  assert.equal(/** @type {any} */ (one(root(next), "pin-numeric")).getAttribute("aria-pressed"), "false");
  assert.equal(input(next).getAttribute("inputmode"), null);
  // The toggle is not kept anywhere: the part and its flow never touch a storage area.
  for (const file of ["pinUnlockView.mjs", "popupFlow.mjs"]) {
    const text = readFileSync(join(extensionRoot, "src", "pages", file), "utf8");
    assert.doesNotMatch(text, /localStorage|sessionStorage|indexedDB|storage\.(local|session|sync)|browser\.storage/, file);
  }
  // The "show PIN" button is a button with one name; it shows the text and hides it again.
  const eye = /** @type {any} */ (one(root(world), "pin-toggle"));
  assert.equal(eye.getAttribute("aria-label"), "Show PIN");
  await click(eye);
  assert.equal(input(world).getAttribute("type"), "text");
  assert.equal(eye.getAttribute("aria-pressed"), "true");
  assert.equal(eye.getAttribute("aria-label"), "Show PIN");
  await click(eye);
  assert.equal(input(world).getAttribute("type"), "password");
});

test("five_wrong_pins_wipe_and_the_popup_asks_for_the_password_and_says_why", async () => {
  const world = await partOf(on);
  const waits = [0, 5000, 15000, 30000];
  world.state.replies = [4, 3, 2, 1].map((left, i) => ({ ok: false, reason: "wrong_pin", left, wait_ms: waits[i] }));
  world.state.replies.push({ ok: false, reason: "pin_wiped" });
  const said = [];
  for (let i = 0; i < 4; i += 1) {
    await enter(world, `wrong-${i}`);
    said.push(live(world).textContent);
    // The wait runs out before the next try (the clock is the test's).
    world.time.advance(waits[i] + 1);
    await settle();
  }
  assert.match(said[0], /^That PIN is not right\. 4 tries left before the PIN is deleted\./);
  assert.match(said[1], /^That PIN is not right\. 3 tries left/);
  assert.match(said[2], /^That PIN is not right\. 2 tries left/);
  assert.match(said[3], /^That PIN is not right\. This is your last try\. After that the PIN is deleted and you need your master password\./);
  assert.equal(world.ended.length, 0, "the PIN is still offered until the fifth");
  assert.equal(/** @type {any} */ (one(root(world), "pin-attempts")).textContent, "Tries left before the PIN is deleted: 1");
  // The fifth: the part ends, and the popup is told the text that says why (the master password stays, never the PIN).
  await enter(world, "wrong-4");
  assert.deepEqual(world.ended, [world.catalog["unlock.pin.error.pin_wiped"]]);
  assert.match(world.ended[0], /deleted: after five wrong tries, because the administrator changed or turned off the PIN rule, or because it no longer matched your account\. Use your master password/);
  assert.equal(world.done.length, 0);
  // Every try carried the PIN in one request and nothing else.
  assert.deepEqual(pinRequests(world.log).map(([, body]) => Object.keys(body)), [["pin"], ["pin"], ["pin"], ["pin"], ["pin"]]);
  // The other ways a PIN ends: stale (its text is the one the PIN's background owns), and not usable on this device.
  for (const reason of ["pin_stale", "pin_unavailable"]) {
    const other = await partOf(on);
    other.state.replies = [{ ok: false, reason }];
    await enter(other);
    const key = reason === "pin_stale" ? "pin.error.pin_stale" : `unlock.pin.error.${reason}`;
    assert.deepEqual(other.ended, [other.catalog[key]], reason);
  }
  assert.match((await partOf(on)).catalog["pin.error.pin_stale"], /no longer fits the vault/);
  // "Use master password instead" is always there, also with tries left, and it empties the field.
  const again = await partOf(on);
  input(again).value = "half typed";
  await click(one(root(again), "use-master"));
  assert.equal(again.useMasterCount(), 1);
  assert.equal(input(again).value, "");
});

test("the_wait_is_shown_and_enter_does_nothing_during_it", async () => {
  const world = await partOf(on);
  world.state.replies = [{ ok: false, reason: "wrong_pin", left: 3, wait_ms: 5000 }, { ok: true }];
  await enter(world, "first-try");
  const countdown = /** @type {any} */ (one(root(world), "pin-countdown"));
  assert.equal(countdown.hidden, false);
  assert.equal(countdown.textContent, "Next try in 5 s");
  assert.equal(countdown.getAttribute("aria-hidden"), "true", "the countdown is for the eye, not read out every second");
  assert.match(live(world).textContent, /3 tries left before the PIN is deleted\. Wait 5 seconds\./);
  assert.equal(unlockButton(world).hasAttribute("disabled"), true);
  assert.equal(world.part.waiting(), true);
  // Enter (a submit of the form) during the wait sends nothing, and the typed PIN stays.
  input(world).value = "second-try";
  await submit(root(world));
  assert.equal(pinRequests(world.log).length, 1);
  assert.equal(input(world).value, "second-try");
  // The countdown runs in whole seconds.
  world.time.advance(2000);
  assert.equal(countdown.textContent, "Next try in 3 s");
  world.time.advance(2500);
  assert.equal(countdown.textContent, "Next try in 1 s");
  assert.equal(unlockButton(world).hasAttribute("disabled"), true);
  await submit(root(world));
  assert.equal(pinRequests(world.log).length, 1);
  // The wait is over: the button is back, the page says so once, politely, and the focus is on the field.
  world.time.advance(600);
  assert.equal(world.part.waiting(), false);
  assert.equal(unlockButton(world).hasAttribute("disabled"), false);
  assert.equal(countdown.hidden, true);
  assert.equal(live(world).textContent, "You can try again now.");
  assert.equal(live(world).getAttribute("aria-live"), "polite");
  assert.equal(world.doc.activeElement, input(world));
  assert.equal(world.time.pending(), 0, "no timer is left running");
  // And a try after the wait goes through.
  await submit(root(world));
  assert.equal(pinRequests(world.log).length, 2);
  assert.equal(world.done.length, 1);
  assert.equal(world.done[0].view, "unlocked");
  // A wait that was already running when the view was built (the background says so) starts at once.
  const waiting = await partOf(on, { pin: { wait_ms: 15000, failures_left: 3 } });
  assert.equal(unlockButton(waiting).hasAttribute("disabled"), true);
  assert.equal(/** @type {any} */ (one(root(waiting), "pin-countdown")).textContent, "Next try in 15 s");
  assert.match(live(waiting).textContent, /^You have to wait before the next try\. Wait 15 seconds\./);
  assert.equal(/** @type {any} */ (one(root(waiting), "pin-attempts")).textContent, "Tries left before the PIN is deleted: 3");
  await submit(root(waiting));
  assert.equal(pinRequests(waiting.log).length, 0);
  // The background can say "wait" itself (a second popup, a try that came too early): that is shown the same way.
  const early = await partOf(on);
  early.state.replies = [{ ok: false, reason: "pin_wait", wait_ms: 30000, left: 1 }];
  await enter(early);
  assert.match(live(early).textContent, /^You have to wait before the next try\. Wait 30 seconds\./);
  assert.equal(unlockButton(early).hasAttribute("disabled"), true);
});

test("out_of_memory_is_not_called_a_wrong_pin", async () => {
  const world = await partOf(on);
  world.state.replies = [{ ok: false, reason: "out_of_memory", left: 3 }];
  await enter(world);
  const text = live(world).textContent;
  assert.equal(text, world.catalog["unlock.pin.error.out_of_memory"]);
  assert.match(text, /did not have enough memory/);
  assert.doesNotMatch(text, /not right/, "it does not say the PIN was wrong");
  assert.match(text, /It is not a wrong PIN/);
  assert.match(text, /still counts as one of the five/, "and it says honestly that the try counted");
  assert.equal(world.ended.length, 0, "the PIN stays");
  assert.equal(/** @type {any} */ (one(root(world), "pin-attempts")).textContent, "Tries left before the PIN is deleted: 3");
  assert.equal(pinResultOf({ ok: false, reason: "out_of_memory" }).ok, false);
  // In Norwegian too, and with the words of the brief.
  const nb = await partOf(on, { lang: "nb" });
  nb.state.replies = [{ ok: false, reason: "out_of_memory", left: 3 }];
  await enter(nb);
  assert.match(live(nb).textContent, /fikk ikke nok minne/);
  assert.doesNotMatch(live(nb).textContent, /stemmer ikke/);
});

test("the_offline_window_text_is_shown_after_seven_days", async () => {
  // The background says the window is over: the text is there before a try, and the field is still usable (the background
  // reaches the server first).
  const world = await partOf(on, { pin: { offline_ok: false } });
  const hint = /** @type {any} */ (one(root(world), "pin-offline"));
  assert.equal(hint.hidden, false);
  // Before a try it says that the PIN reaches the server first: it is not a refusal yet.
  assert.equal(hint.textContent, world.catalog["unlock.pin.offline_first"]);
  assert.match(hint.textContent, /Unlock with PIN tries that now/);
  assert.match(hint.textContent, /more than 7 days since the last contact/);
  const fine = await partOf(on);
  assert.equal(/** @type {any} */ (one(root(fine), "pin-offline")).hidden, true);
  // And after a try the background refuses: the text is in the live line, the PIN is kept, and the master password is a click away.
  const refused = await partOf(on);
  refused.state.replies = [{ ok: false, reason: "pin_offline_expired" }];
  await enter(refused);
  assert.equal(live(refused).textContent, refused.catalog["unlock.pin.error.pin_offline_expired"]);
  assert.equal(refused.ended.length, 0);
  assert.equal(unlockButton(refused).hasAttribute("disabled"), false);
  assert.ok(one(root(refused), "use-master"));
  assert.ok(!PIN_ENDED_REASONS.includes("pin_offline_expired"));
  // Norwegian.
  const nb = await partOf(on, { lang: "nb", pin: { offline_ok: false } });
  assert.match(/** @type {any} */ (one(root(nb), "pin-offline")).textContent, /mer enn 7 dager siden sist/);
});

test("the_pin_field_is_emptied_after_every_answer_and_on_close", async () => {
  const world = await partOf(on);
  /** @type {() => void} */
  let release = () => {};
  world.state.hold = new Promise((resolve) => {
    release = resolve;
  });
  world.state.replies = [{ ok: false, reason: "wrong_pin", left: 4 }, { ok: false, reason: "out_of_memory", left: 3 }, { ok: false, reason: "pin_offline_expired" }, new UiError("disconnected"), { ok: true }];
  input(world).value = SENTINEL;
  const pending = submit(root(world));
  await settle();
  // The request is out and the field is already empty: nothing waits in the page for the answer.
  assert.equal(input(world).value, "");
  assert.deepEqual(pinRequests(world.log), [["pin_unlock", { pin: SENTINEL }]]);
  assert.equal(unlockButton(world).hasAttribute("disabled"), true);
  // A second submit while the answer is out does nothing.
  input(world).value = "typed meanwhile";
  await submit(root(world));
  assert.equal(pinRequests(world.log).length, 1);
  release();
  await pending;
  await settle();
  assert.equal(input(world).value, "", "emptied when the answer came");
  // After every kind of answer: wrong, no memory, offline, a background that went away, and the one that opens the vault.
  world.state.hold = null;
  for (const [i, pin] of ["p-b", "p-c", "p-d", "p-e"].entries()) {
    world.time.advance(100_000);
    input(world).setAttribute("type", "text");
    await enter(world, `${SENTINEL}-${pin}`);
    assert.equal(input(world).value, "", `after answer ${i + 2}`);
    assert.equal(input(world).getAttribute("type"), "password", "and the field is hidden again");
  }
  assert.equal(world.done.length, 1);
  // The disconnected answer got its text and not the code.
  assert.equal(pinResultOf({ ok: false, reason: "disconnected" }).ok, false);
  // The PIN is in no attribute, no text and no message but the one request.
  const hits = [];
  const walk = (/** @type {any} */ node) => {
    for (const [key, value] of node.attributes ?? []) if (String(value).includes(SENTINEL)) hits.push(`${node.tagName}@${key}`);
    if (node.nodeType === 3 && node.data.includes(SENTINEL)) hits.push("text");
    for (const child of node.childNodes) walk(child);
  };
  walk(root(world));
  assert.deepEqual(hits, []);
  // On close: a PIN that was typed and not sent is gone, also when the page goes away (`pagehide`), and a late answer is dropped.
  const closing = await partOf(on);
  input(closing).value = SENTINEL;
  input(closing).setAttribute("type", "text");
  closing.part.wipe();
  assert.equal(input(closing).value, "");
  assert.equal(input(closing).getAttribute("type"), "password");
  const pageGone = await partOf(on);
  input(pageGone).value = SENTINEL;
  const handlers = pageGone.pagehide.filter(([type]) => type === "pagehide");
  assert.equal(handlers.length, 1, "the part listens for the page going away");
  handlers[0][1]();
  assert.equal(input(pageGone).value, "");
  // A late answer: the part is wiped while the request is out; nothing is shown and nobody is told.
  const late = await partOf(on);
  /** @type {() => void} */
  let go = () => {};
  late.state.hold = new Promise((resolve) => {
    go = resolve;
  });
  late.state.replies = [{ ok: true }];
  input(late).value = SENTINEL;
  const out = submit(root(late));
  await settle();
  late.part.wipe();
  go();
  await out;
  await settle();
  assert.equal(late.done.length, 0);
  assert.equal(late.ended.length, 0);
  assert.equal(live(late).textContent, "");
  // Escape does not matter here: the popup closes on it; the page-gone path above is the one that empties.
  // Nothing of the PIN reaches a log: no console in the part or the flow, and the flow's request is the only place it goes.
  for (const file of ["pinUnlockView.mjs", "popupFlow.mjs"]) {
    const text = readFileSync(join(extensionRoot, "src", "pages", file), "utf8");
    assert.doesNotMatch(text, /console\./, file);
  }
});

test("the_unlock_refusal_after_an_accepted_restore_shows_the_attack_warning", async () => {
  const world = await partOf(on);
  world.state.replies = [{ ok: false, reason: "attack_warning" }];
  await enter(world);
  // The part ends, and what the popup shows is the attack warning of the master-password unlock, word for word, and that the PIN is gone.
  assert.equal(world.ended.length, 1);
  assert.ok(world.ended[0].startsWith(world.catalog["session.error.attack_warning"]));
  assert.ok(world.ended[0].endsWith(world.catalog["unlock.pin.error.removed_note"]));
  assert.match(world.ended[0], /This can be an attack\. Nothing was opened\./);
  assert.doesNotMatch(world.ended[0], /not right/, "it is not called a wrong PIN");
  assert.equal(world.done.length, 0);
  // It is a reason that ends the PIN, and a reason of the master-password unlock, so it needs no text of its own twice.
  assert.ok(PIN_ENDED_REASONS.includes("attack_warning"));
  assert.ok(!PIN_REASONS.includes("attack_warning"));
  const result = pinResultOf({ ok: false, reason: "attack_warning" });
  assert.deepEqual(result.ok === false && result.keys, ["session.error.attack_warning", "unlock.pin.error.removed_note"]);
  // A reason the popup has no text for never shows as a code.
  const odd = await partOf(on);
  odd.state.replies = [{ ok: false, reason: "pinned_something_new" }];
  await enter(odd);
  assert.equal(live(odd).textContent, odd.catalog["session.error.unknown"]);
  for (const reply of [null, {}, { ok: false }, { ok: false, reason: 5 }, { ok: false, reason: "Not A Code" }]) {
    const read = pinResultOf(reply);
    assert.equal(read.ok, false);
    assert.deepEqual(/** @type {any} */ (read).keys, ["session.error.unknown"], JSON.stringify(reply));
  }
  // A sign-out answered at the same time ends the popup's locked view: the part hands the view over.
  const out = await partOf(on);
  out.state.replies = [{ ok: false, reason: "signed_out" }];
  out.state.vault = "signed_out";
  await enter(out);
  assert.equal(out.done.length, 1);
  assert.equal(out.done[0].view, "signed_out");
});

// ------------------------------------------------------------------------------------------------------ the flow

test("a_pin_shorter_than_the_rule_is_not_sent", async () => {
  const world = await partOf(on, { pin: { min_length: 6, failures_left: 4 } });
  // Too short: nothing is sent, so it is not a try; the page says the rule, not "wrong"; the typed value stays; the counter is as it was.
  input(world).value = "abc12";
  await submit(root(world));
  assert.equal(pinRequests(world.log).length, 0);
  assert.equal(live(world).textContent, "The PIN has at least 6 characters.");
  assert.doesNotMatch(live(world).textContent, /not right/);
  assert.equal(input(world).value, "abc12");
  assert.equal(world.doc.activeElement, input(world));
  assert.equal(unlockButton(world).hasAttribute("disabled"), false);
  assert.equal(world.part.waiting(), false);
  assert.equal(/** @type {any} */ (one(root(world), "pin-attempts")).textContent, "Tries left before the PIN is deleted: 4");
  // The fixed floor of 4 holds even when the rule says less, and the ceiling of 64 characters too.
  const low = await partOf(on, { pin: { min_length: 4 } });
  await enter(low, "abc");
  assert.equal(pinRequests(low.log).length, 0);
  await enter(low, "x".repeat(65));
  assert.equal(pinRequests(low.log).length, 0);
  assert.equal(live(low).textContent, "The PIN has at most 64 characters.");
  // A PIN of exactly the minimum goes out; so does a PIN of letters counted as characters, not bytes.
  await enter(world, "abc123");
  assert.deepEqual(pinRequests(world.log), [["pin_unlock", { pin: "abc123" }]]);
  await enter(low, "åäöå");
  assert.equal(pinRequests(low.log).length, 1);
  const nb = await partOf(on, { lang: "nb", pin: { min_length: 8 } });
  await enter(nb, "abc");
  assert.equal(live(nb).textContent, "PIN-en har minst 8 tegn.");
  assert.equal(pinRequests(nb.log).length, 0);
});

test("the_flow_sends_the_pin_in_one_request_and_reads_the_view_after_it", async () => {
  const world = await partOf(on);
  world.state.replies = [{ ok: false, reason: "wrong_pin", left: 4, wait_ms: 0 }, { ok: true, account_email: "ola@example.net", server: "https://ferret.example.net" }];
  world.log.length = 0;
  const wrong = await world.flow.pinUnlock("not it");
  assert.deepEqual(wrong.result, { ok: false, reason: "wrong_pin", keys: ["unlock.pin.error.wrong_pin"], left: 4, waitMs: 0, ended: false });
  assert.equal(wrong.view.view, "locked");
  const right = await world.flow.pinUnlock("it");
  assert.deepEqual(right.result, { ok: true });
  assert.equal(right.view.view, "unlocked");
  assert.deepEqual(world.log.map(([type]) => type), ["pin_unlock", "state", "pin_unlock", "state", "sync_state"]);
  assert.deepEqual(world.log.filter(([type]) => type === "pin_unlock").map(([, body]) => body), [{ pin: "not it" }, { pin: "it" }]);
  // A background that threw: the code is read as a reason.
  world.state.replies = [new UiError("vault_locked")];
  const gone = await world.flow.pinUnlock("x");
  assert.equal(gone.result.ok, false);
  assert.deepEqual(/** @type {any} */ (gone.result).keys, ["session.error.vault_locked"]);
  // What the background sends is bounded: the tries left, the wait.
  const odd = pinResultOf({ ok: false, reason: "wrong_pin", left: 99, wait_ms: 10 ** 9 });
  assert.equal(odd.ok === false && odd.left, null);
  assert.equal(odd.ok === false && odd.waitMs, 0);
  assert.deepEqual(odd.ok === false && odd.keys, ["unlock.pin.error.wrong_pin_plain"]);
  const last = pinResultOf({ ok: false, reason: "wrong_pin", left: 1, wait_ms: 30000 });
  assert.deepEqual(last.ok === false && [last.keys, last.left, last.waitMs], [["unlock.pin.error.wrong_pin_last"], 1, 30000]);
});

// ------------------------------------------------------------------------------------------------------ texts and form

test("texts_exist_in_en_and_nb", async () => {
  const read = (/** @type {string} */ lang) => JSON.parse(readFileSync(join(extensionRoot, "src", "locales", lang, "unlock.json"), "utf8"));
  const [en, nb] = [read("en"), read("nb")];
  assert.deepEqual(Object.keys(en).sort(), Object.keys(nb).sort(), "the same keys in en and nb");
  for (const [lang, texts] of [["en", en], ["nb", nb]]) for (const [key, text] of Object.entries(texts)) assert.ok(typeof text === "string" && text.length > 0 && key.startsWith("unlock."), `${lang}: ${key}`);
  // Every text the modules ask for is there, in both languages, and no text stays that nobody asks for.
  const wanted = new Set();
  for (const file of ["pinUnlockView.mjs", "popupFlow.mjs", "popup.mjs"]) {
    const text = readFileSync(join(extensionRoot, "src", "pages", file), "utf8");
    for (const [, key] of text.matchAll(/["'`](unlock\.pin\.[a-z_.]+)["'`]/g)) wanted.add(key);
  }
  // The text of a stale PIN is the PIN background's (pin.json), reused; every other reason has a text here.
  for (const reason of PIN_REASONS) if (reason !== "pin_stale") wanted.add(`unlock.pin.error.${reason}`);
  const shared = (/** @type {string} */ lang) => JSON.parse(readFileSync(join(extensionRoot, "src", "locales", lang, "pin.json"), "utf8"));
  assert.ok(shared("en")["pin.error.pin_stale"] && shared("nb")["pin.error.pin_stale"]);
  assert.equal(PIN_REASONS.length, 8);
  for (const key of wanted) {
    if (key.endsWith(".error.")) continue;
    assert.ok(en[key], `en: ${key}`);
    assert.ok(nb[key], `nb: ${key}`);
  }
  for (const key of Object.keys(en)) assert.ok(wanted.has(key), `unused: ${key}`);
  // The texts of the master-password unlock that the part reuses are there too.
  const session = (/** @type {string} */ lang) => JSON.parse(readFileSync(join(extensionRoot, "src", "locales", lang, "session.json"), "utf8"));
  for (const lang of ["en", "nb"]) for (const key of ["session.error.attack_warning", "session.error.unknown", "session.error.disconnected", "session.error.vault_locked"]) assert.ok(session(lang)[key], `${lang}: ${key}`);
  // The two languages say different things (but for the labels that are the same word), and the words of the brief are there.
  for (const key of Object.keys(en)) if (!["unlock.pin.label", "unlock.pin.numeric"].includes(key)) assert.notEqual(en[key], nb[key], key);
  assert.match(nb["unlock.pin.error.out_of_memory"], /fikk ikke nok minne/);
  assert.match(nb["unlock.pin.error.pin_offline_expired"], /mer enn 7 dager siden sist/);
  assert.match(nb["unlock.pin.error.pin_wiped"], /fem gale forsøk/);
  assert.equal(nb["unlock.pin.use_password"], "Bruk hovedpassordet i stedet");
  // The built packages carry them, in both variants (a release has the strings, as it has those of the settings).
  for (const built of [on, off]) {
    assert.equal(JSON.parse(readFileSync(join(built.dir, "locales.nb.json"), "utf8"))["unlock.pin.submit"], nb["unlock.pin.submit"]);
    assert.equal(JSON.parse(readFileSync(join(built.dir, "locales.en.json"), "utf8"))["unlock.pin.submit"], en["unlock.pin.submit"]);
  }
  // The part speaks Norwegian when it is asked to.
  const world = await partOf(on, { lang: "nb" });
  assert.equal(unlockButton(world).textContent, "Lås opp med PIN");
  assert.equal(one(root(world), "use-master")?.textContent, "Bruk hovedpassordet i stedet");
  world.state.replies = [{ ok: false, reason: "wrong_pin", left: 2 }];
  await enter(world);
  assert.equal(live(world).textContent, "PIN-en stemmer ikke. 2 forsøk igjen før PIN-en slettes.");
});

test("the_pin_part_is_polite_labelled_and_uses_no_inline_style", async () => {
  const world = await partOf(on);
  // The refusal is read out politely and is not an alert; the line is always in the page.
  assert.equal(live(world).getAttribute("aria-live"), "polite");
  assert.equal(live(world).hidden, false);
  assert.equal(live(world).hasAttribute("role"), false);
  assert.equal(live(world).getAttribute("aria-atomic"), "true");
  // After a refusal the focus is on the field.
  world.state.replies = [{ ok: false, reason: "wrong_pin", left: 4 }];
  await enter(world);
  assert.equal(world.doc.activeElement, input(world));
  // The field is described by the hint and the lines that change.
  const described = String(input(world).getAttribute("aria-describedby")).split(" ");
  for (const id of described) assert.ok(withAttribute(root(world), "id").some((node) => node.getAttribute("id") === id), `aria-describedby points at #${id}`);
  // No inline style, no markup from strings, in the part, the flow and the popup.
  for (const file of ["pinUnlockView.mjs", "popupFlow.mjs", "popup.mjs"]) {
    const text = readFileSync(join(extensionRoot, "src", "pages", file), "utf8");
    for (const sink of ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "style="]) assert.equal(text.includes(sink), false, `${file}: ${sink}`);
  }
  // The stylesheet is in the build, uses the tokens only, and hides what the attribute hides.
  for (const built of [on, off]) {
    const css = built.files.get("assets/app.css")?.toString("utf8") ?? "";
    assert.match(css, /\.ff-pin-live\b/);
    assert.match(css, /\.ff-form\[hidden\]/);
  }
  const css = readFileSync(join(extensionRoot, "src", "styles", "unlock.css"), "utf8");
  assert.doesNotMatch(css, /#[0-9a-fA-F]{3,8}\b|rgba?\(|hsla?\(/);
  // The popup builds the PIN's part only through the one function that asks the flag, and marks what it adds.
  const popup = readFileSync(join(extensionRoot, "src", "pages", "popup.mjs"), "utf8");
  assert.match(popup, /createPinUnlockPart\(/);
  assert.doesNotMatch(popup, /createPinUnlock\(/);
  assert.match(popup, /from "\.\.\/shared\/features\.mjs"/);
});
