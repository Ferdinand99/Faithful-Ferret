// "Fill in the page" with a generated value, through the real background (core host, lock, router and the handlers of
// the built package) with a fake core, a fake page matching and pages whose fill script answers through the router:
//
// - the popup names a generation id and a tab, never the value; the value goes from the background to the one frame;
// - only the new and the confirm field of a sign-up, change or reset form are filled, never a password in use, and
//   never a sign-in form;
// - the frame rules of a fill hold: a frame the page matching does not offer, a hidden or covered one, one the
//   background could not check, a changed origin, and a plain `http` page get nothing;
// - a field's `maxlength` shortens a password (never below 8), and a passphrase is never cut;
// - after the fill the store of offers is told, with the value and the frame, and the popup's view shows its save card
//   at once.
import assert from "node:assert/strict";
import { test } from "node:test";
import { generatorFrames } from "../../src/background/frames.mjs";
import { LOGIN_ORIGIN, LOGIN_URL, TAB, itemWorld } from "./itemHelpers.mjs";
import { FakeElement, one, settle, useDocument } from "./pageDom.mjs";
import { pkg } from "./sessionHelpers.mjs";

const PASSWORD_OPTIONS = Object.freeze({ kind: "password", length: 20, lower: true, upper: true, digits: true, symbols: true, min_each: 1, avoid_ambiguous: false });
const PASSPHRASE_OPTIONS = Object.freeze({ kind: "passphrase", words: 5, separator: "-", capitalize: true, number: false });

/** A world with the vault open, a page that has a sign-up form, a popup and one generated value. @param {Parameters<typeof itemWorld>[0]} [options] */
async function signUpWorld(options = {}) {
  const world = await itemWorld({ generated: true, ...options });
  await world.open();
  const popup = world.popup();
  const made = await popup.request("generate", PASSWORD_OPTIONS);
  return { world, popup, made };
}

/** What the popup sent the background, text by text (after its first request has opened the port). @param {ReturnType<typeof itemWorld> extends Promise<infer W> ? W : never} world */
function spyOnPopupPort(world) {
  /** @type {string[]} */
  const sent = [];
  const page = world.ports[0].page;
  const original = page.postMessage.bind(page);
  page.postMessage = (/** @type {string} */ raw) => {
    sent.push(raw);
    return original(raw);
  };
  return sent;
}

test("fill_generated_sends_a_generation_id_never_the_value", async () => {
  const { world, popup, made } = await signUpWorld();
  const sent = spyOnPopupPort(world);
  const reply = await popup.request("fill_generated", { generation_id: made.generation_id, tab_id: TAB });
  assert.deepEqual(reply, { ok: true, length: 20, offer: true });

  // What the popup sent: the id, the tab, nothing else.
  assert.equal(sent.length, 1);
  assert.deepEqual(JSON.parse(sent[0]).body, { generation_id: made.generation_id, tab_id: TAB });
  assert.equal(sent.join("\n").includes(made.value), false);
  // The value went to the page from the background, to the new and the confirm field of the one document, once each.
  assert.deepEqual(world.pushed.map((p) => [p.tabId, p.message.body.field, p.message.body.value, p.options]), [
    [TAB, "new_password", made.value, { documentId: "doc-1" }],
    [TAB, "confirm_password", made.value, { documentId: "doc-1" }],
  ]);
  for (const { message } of world.pushed) assert.deepEqual(message.body.expect, { origin: LOGIN_ORIGIN, frameUrl: LOGIN_URL });
  assert.deepEqual(world.page.filled, { new_password: made.value, confirm_password: made.value });
  // Nothing the background answered the popup with after the generation carries it.
  const afterwards = popup.received().filter((text) => text.includes('"type":"fill_generated"'));
  assert.equal(afterwards.length, 1);
  assert.equal(afterwards[0].includes(made.value), false);
  // The script went into the frame in the mode of a generated fill, pinned to its document.
  assert.deepEqual(world.begins().map((i) => [i.target, i.args.slice(1)]), [[{ tabId: TAB, documentIds: ["doc-1"] }, ["generated"]]]);
  // No item was opened, no value of the vault was read, and the fill context was not told about an item.
  assert.deepEqual(world.opens, []);
  assert.deepEqual(world.client.calls.filter((c) => ["reveal_item_field", "totp_code"].includes(c.method)), []);
  // The request must say which generation: an id that is not held fills nothing.
  assert.deepEqual(await popup.request("fill_generated", { generation_id: "e".repeat(32), tab_id: TAB }), { ok: false, reason: "not_offered" });
  assert.equal(world.pushed.length, 2);
});

test("fill_generated_fills_new_and_confirm_and_never_the_current_password", async () => {
  // A change form: the page reports the new and the confirm field to a generated fill; the password in use is not
  // among them (the fill script decides that, see fillDom.test.mjs), and what a frame reports beyond them is dropped.
  const { world, popup, made } = await signUpWorld();
  world.page.fields = ["username", "password"];
  world.page.generatedFields = ["password", "new_password", "username", "confirm_password", "totp"];
  assert.deepEqual(await popup.request("fill_generated", { generation_id: made.generation_id, tab_id: TAB }), { ok: true, length: 20, offer: true });
  assert.deepEqual(world.pushed.map((p) => p.message.body.field), ["new_password", "confirm_password"]);
  assert.deepEqual(Object.keys(world.page.filled), ["new_password", "confirm_password"]);

  // Only a new password field (a sign-up with one box): one value.
  const single = await signUpWorld();
  single.world.page.generatedFields = ["new_password"];
  assert.deepEqual(await single.popup.request("fill_generated", { generation_id: single.made.generation_id, tab_id: TAB }), { ok: true, length: 20, offer: true });
  assert.deepEqual(single.world.pushed.map((p) => p.message.body.field), ["new_password"]);

  // A confirm field with no new field is not a form Ferret fills.
  const lonely = await signUpWorld();
  lonely.world.page.generatedFields = ["confirm_password"];
  assert.deepEqual(await lonely.popup.request("fill_generated", { generation_id: lonely.made.generation_id, tab_id: TAB }), { ok: false, reason: "no_fields" });
  assert.deepEqual(lonely.world.pushed, []);

  // The other way round: a sign-in "Fill" of an item never takes a new or a confirm field a frame reports.
  const login = await itemWorld({ generated: true });
  await login.open();
  login.page.fields = ["new_password", "confirm_password", "username", "password"];
  const loginPopup = login.popup();
  const row = (await loginPopup.list.page(TAB)).rows[0];
  assert.deepEqual(await loginPopup.list.fill(row, TAB), { ok: true });
  assert.deepEqual(login.pushed.map((p) => p.message.body.field), ["username", "password"]);
});

test("fill_generated_refuses_a_login_group_and_a_cross_site_frame", async () => {
  // A sign-in form reports nothing to a generated fill: no field, nothing pushed, and the value is still held.
  const login = await signUpWorld();
  login.world.page.generatedFields = [];
  assert.deepEqual(await login.popup.request("fill_generated", { generation_id: login.made.generation_id, tab_id: TAB }), { ok: false, reason: "no_fields" });
  assert.deepEqual(login.world.pushed, []);
  assert.deepEqual(login.world.offered.calls, []);
  assert.equal((await login.popup.request("generate", { current: true })).value, login.made.value);

  // A page that is not encrypted gets nothing; the loopback is secure (the page matching says which is which).
  const plain = await signUpWorld({ frames: [{ frameId: 0, documentId: "doc-1", url: "http://login.example.net/signup", origin: "http://login.example.net", insecure: true, itemIds: [] }] });
  assert.deepEqual(await plain.popup.request("fill_generated", { generation_id: plain.made.generation_id, tab_id: TAB }), { ok: false, reason: "insecure_page" });
  assert.deepEqual(plain.world.injections, []);

  // Another tab than the page matching knows: no page, no field.
  const other = await signUpWorld();
  assert.deepEqual(await other.popup.request("fill_generated", { generation_id: other.made.generation_id, tab_id: TAB + 1 }), { ok: false, reason: "no_fields" });
  assert.deepEqual(other.world.injections, []);

  // A frame below the top: a field the frame shows goes in; one that is hidden, covered or cannot be checked does not.
  const framed = await signUpWorld({
    frames: [
      { frameId: 0, documentId: "doc-1", url: LOGIN_URL, origin: LOGIN_ORIGIN, itemIds: [] },
      { frameId: 5, documentId: "doc-5", url: "https://login.example.net/frame", origin: LOGIN_ORIGIN, itemIds: [] },
    ],
  });
  framed.world.page.generatedFields = [];
  const child = framed.world.addFrame({ url: "https://login.example.net/frame", frameId: 5, documentId: "doc-5", selfOrigin: LOGIN_ORIGIN });
  assert.deepEqual(await framed.popup.request("fill_generated", { generation_id: framed.made.generation_id, tab_id: TAB }), { ok: true, length: 20, offer: true });
  assert.deepEqual(framed.world.pushed.map((p) => [p.options, p.message.body.field]), [
    [{ documentId: "doc-5" }, "new_password"],
    [{ documentId: "doc-5" }, "confirm_password"],
  ]);
  assert.deepEqual(child.filled, { new_password: framed.made.value, confirm_password: framed.made.value });
  // The frame was asked whether it is shown in the document above it, before each value.
  assert.deepEqual(framed.world.frameShown.kinds, ["new_password", "new_password", "confirm_password"]);

  for (const [verdict, reason] of /** @type {const} */ ([["hidden", "frame_hidden"], ["covered", "frame_hidden"]])) {
    const hidden = await signUpWorld({
      frames: [
        { frameId: 0, documentId: "doc-1", url: LOGIN_URL, origin: LOGIN_ORIGIN, itemIds: [] },
        { frameId: 5, documentId: "doc-5", url: "https://login.example.net/frame", origin: LOGIN_ORIGIN, itemIds: [] },
      ],
    });
    hidden.world.page.generatedFields = [];
    hidden.world.addFrame({ url: "https://login.example.net/frame", frameId: 5, documentId: "doc-5", selfOrigin: LOGIN_ORIGIN });
    hidden.world.frameShown.verdict = () => verdict;
    assert.deepEqual(await hidden.popup.request("fill_generated", { generation_id: hidden.made.generation_id, tab_id: TAB }), { ok: false, reason }, verdict);
    assert.deepEqual(hidden.world.pushed, [], verdict);
  }

  const unchecked = await signUpWorld({
    frames: [
      { frameId: 0, documentId: "doc-1", url: LOGIN_URL, origin: LOGIN_ORIGIN, itemIds: [] },
      { frameId: 5, documentId: "doc-5", url: "https://login.example.net/frame", origin: LOGIN_ORIGIN, unchecked: true, itemIds: [] },
    ],
  });
  unchecked.world.page.generatedFields = [];
  unchecked.world.addFrame({ url: "https://login.example.net/frame", frameId: 5, documentId: "doc-5", selfOrigin: LOGIN_ORIGIN });
  assert.deepEqual(await unchecked.popup.request("fill_generated", { generation_id: unchecked.made.generation_id, tab_id: TAB }), { ok: false, reason: "frame_unchecked" });
  assert.deepEqual(unchecked.world.pushed, []);

  // A frame whose origin is not the one the browser named (the script's own origin is a sandbox's): dropped.
  const sandboxed = await signUpWorld();
  sandboxed.world.page.sender.selfOrigin = "null";
  assert.deepEqual(await sandboxed.popup.request("fill_generated", { generation_id: sandboxed.made.generation_id, tab_id: TAB }), { ok: false, reason: "origin_changed" });
  assert.deepEqual(sandboxed.world.pushed, []);

  // The page changes between the report and the value: the fill script says so and the fill stops.
  const moved = await signUpWorld();
  moved.world.page.answer = () => ({ ok: false, reason: "origin_changed" });
  assert.deepEqual(await moved.popup.request("fill_generated", { generation_id: moved.made.generation_id, tab_id: TAB }), { ok: false, reason: "origin_changed" });
  assert.equal(moved.world.pushed.length, 1, "the second value was not sent after the first was refused");
  assert.deepEqual(moved.world.offered.calls, [], "no offer for a fill that failed");

  // A lock between the click and the value: nothing is pushed.
  const locking = await signUpWorld();
  locking.world.matching.before = async () => {
    await locking.world.coreHost.lock("manual");
  };
  const reply = await locking.popup.request("fill_generated", { generation_id: locking.made.generation_id, tab_id: TAB }).catch((/** @type {any} */ error) => ({ ok: false, reason: error.code }));
  assert.equal(reply.ok, false);
  assert.deepEqual(locking.world.pushed, []);
});

test("generated_frames_follow_the_fill_frame_rules", async () => {
  // The frames a generated password may go into, from the browser's frames and the core's answers (no item, no match).
  const core = {
    page_origin: async (/** @type {string} */ url) => new URL(url).origin,
    same_site: async (/** @type {string} */ a, /** @type {string} */ b) => new URL(a).hostname.split(".").slice(-2).join(".") === new URL(b).hostname.split(".").slice(-2).join("."),
  };
  /** @param {Array<[number, number, string]>} rows */
  const navigation = (rows) => ({
    getAllFrames: async () => rows.map(([frameId, parentFrameId, url]) => ({ frameId, parentFrameId, url, documentId: `doc-${frameId}` })),
  });
  const { fillableFrames } = await import("../../src/background/frames.mjs");
  /** @param {Array<[number, number, string]>} rows @param {string[]} [granted] @param {number} [frameId] */
  const frames = async (rows, granted = [], frameId) => {
    const nav = navigation(rows);
    const reply = await generatorFrames(TAB, {
      coreHost: { call: async (op, args) => (op === "display_host" ? { a_label: new URL(/** @type {any} */ (args).url).hostname, unicode: new URL(/** @type {any} */ (args).url).hostname } : undefined) },
      frames: (id) => fillableFrames(id, { webNavigation: nav, core }),
      permissions: { contains: async ({ origins }) => origins.some((o) => granted.includes(o)) },
      ...(frameId !== undefined ? { frameId } : {}),
    });
    return reply;
  };
  const top = [0, -1, "https://login.example.net/signup"];
  // The top and a frame of the same origin; a cross-site frame is not offered at all.
  const same = await frames([/** @type {any} */ (top), [1, 0, "https://login.example.net/frame"], [2, 0, "https://ads.evil.test/x"]]);
  assert.deepEqual(same.frames.map((f) => f.frameId), [0, 1]);
  assert.equal(same.insecure, false);
  assert.deepEqual(same.host, { a_label: "login.example.net", unicode: "login.example.net" });
  // A frame of the same site with another origin waits for its host permission, as for a fill.
  const rows = [/** @type {any} */ (top), [1, 0, "https://auth.example.net/frame"]];
  assert.deepEqual((await frames(rows)).frames.map((f) => f.frameId), [0]);
  assert.deepEqual((await frames(rows, ["https://auth.example.net/*"])).frames.map((f) => f.frameId), [0, 1]);
  // A frame below a middle frame of another origin is marked unchecked without that origin's permission.
  const deep = [/** @type {any} */ (top), [1, 0, "https://auth.example.net/frame"], [2, 1, "https://login.example.net/inner"]];
  const unchecked = await frames(deep, ["https://login.example.net/*"]);
  assert.deepEqual(unchecked.frames.map((f) => [f.frameId, f.unchecked === true]), [[0, false], [2, true]]);
  // The menu's frame only.
  assert.deepEqual((await frames([/** @type {any} */ (top), [1, 0, "https://login.example.net/frame"]], [], 1)).frames.map((f) => f.frameId), [1]);
  // A plain http page is said to be insecure (the fill flow then refuses), and has no frame from a cross-site chain.
  const plain = await frames([[0, -1, "http://login.example.net/signup"]]);
  assert.equal(plain.insecure, true);
  // No top: nothing.
  assert.deepEqual(await frames([[1, 0, "https://login.example.net/frame"]]), { host: null, insecure: false, frames: [] });
});

test("fill_generated_respects_maxlength_and_refuses_below_8", async () => {
  // The shortest limit of the two fields: the core makes the password again at that length, same generation.
  const { world, popup, made } = await signUpWorld();
  world.page.limits = { new_password: 14, confirm_password: 12 };
  const reply = await popup.request("fill_generated", { generation_id: made.generation_id, tab_id: TAB });
  assert.deepEqual(reply, { ok: true, length: 12, offer: true });
  assert.deepEqual(world.made.map((m) => m.options.length), [20, 12], "the core made the second at the limit");
  const shown = await popup.request("generate", { current: true });
  assert.equal(shown.generation_id, made.generation_id, "the same generation");
  assert.equal(shown.value.length, 12);
  assert.notEqual(shown.value, made.value);
  assert.deepEqual(world.pushed.map((p) => p.message.body.value), [shown.value, shown.value]);
  assert.deepEqual(world.offered.calls.map((c) => c.password), [shown.value], "the offer holds what went into the page");

  // The same options as the first value (the generator keeps them), with the length of the limit only.
  assert.deepEqual({ ...world.made[1].options, length: 20 }, world.made[0].options);

  // 8 is the shortest Ferret fills; 7 and below it refuses and changes nothing.
  const eight = await signUpWorld();
  eight.world.page.limits = { new_password: 8 };
  assert.deepEqual(await eight.popup.request("fill_generated", { generation_id: eight.made.generation_id, tab_id: TAB }), { ok: true, length: 8, offer: true });
  const seven = await signUpWorld();
  seven.world.page.limits = { new_password: 7 };
  assert.deepEqual(await seven.popup.request("fill_generated", { generation_id: seven.made.generation_id, tab_id: TAB }), { ok: false, reason: "field_too_short" });
  assert.deepEqual(seven.world.pushed, []);
  assert.equal(seven.world.made.length, 1, "the core was not asked for a shorter one");
  assert.equal((await seven.popup.request("generate", { current: true })).value, seven.made.value);
  const zero = await signUpWorld();
  zero.world.page.limits = { confirm_password: 0 };
  assert.deepEqual(await zero.popup.request("fill_generated", { generation_id: zero.made.generation_id, tab_id: TAB }), { ok: false, reason: "field_too_short" });

  // A limit that is not below the length changes nothing.
  const roomy = await signUpWorld();
  roomy.world.page.limits = { new_password: 64, confirm_password: 20 };
  assert.deepEqual(await roomy.popup.request("fill_generated", { generation_id: roomy.made.generation_id, tab_id: TAB }), { ok: true, length: 20, offer: true });
  assert.equal(roomy.world.made.length, 1);

  // A passphrase is never cut: too long for the field, it is refused.
  const phrase = await itemWorld({ generated: true });
  await phrase.open();
  const spoken = await phrase.popup().request("generate", PASSPHRASE_OPTIONS);
  phrase.page.limits = { new_password: 20 };
  assert.ok(spoken.value.length > 20);
  assert.deepEqual(await phrase.popup().request("fill_generated", { generation_id: spoken.generation_id, tab_id: TAB }), { ok: false, reason: "field_too_short" });
  assert.deepEqual(phrase.pushed, []);
  assert.equal(phrase.made.length, 1);

  // The core cannot make a shorter one with those options: refused, not filled.
  const strict = await signUpWorld();
  strict.world.page.limits = { new_password: 10 };
  strict.world.generatorCore.refuses = "generator_options";
  assert.deepEqual(await strict.popup.request("fill_generated", { generation_id: strict.made.generation_id, tab_id: TAB }), { ok: false, reason: "field_too_short" });
  assert.deepEqual(strict.world.pushed, []);
});

test("fill_generated_leaves_out_the_classes_a_field_refuses", async () => {
  // A field that refuses symbols: the core makes the password again with symbols off, same generation, length kept.
  const { world, popup, made } = await signUpWorld();
  world.page.forbid = { new_password: ["symbol"], confirm_password: ["symbol"] };
  const reply = await popup.request("fill_generated", { generation_id: made.generation_id, tab_id: TAB });
  assert.deepEqual(reply, { ok: true, length: 20, offer: true });
  assert.equal(world.made.length, 2);
  assert.deepEqual(world.made[1].options, { ...world.made[0].options, symbols: false });
  const shown = await popup.request("generate", { current: true });
  assert.equal(shown.generation_id, made.generation_id, "the same generation");
  assert.deepEqual(world.pushed.map((p) => p.message.body.value), [shown.value, shown.value]);

  // The classes of both fields count, and a limit goes with them.
  const both = await signUpWorld();
  both.world.page.forbid = { new_password: ["symbol"], confirm_password: ["upper", "digit"] };
  both.world.page.limits = { new_password: 12 };
  assert.deepEqual(await both.popup.request("fill_generated", { generation_id: both.made.generation_id, tab_id: TAB }), { ok: true, length: 12, offer: true });
  assert.deepEqual(both.world.made[1].options, { ...both.world.made[0].options, length: 12, symbols: false, upper: false, digits: false });

  // A field that says nothing changes nothing; a passphrase is as it is.
  const quiet = await signUpWorld();
  assert.deepEqual(await quiet.popup.request("fill_generated", { generation_id: quiet.made.generation_id, tab_id: TAB }), { ok: true, length: 20, offer: true });
  assert.equal(quiet.world.made.length, 1);
  const phrase = await itemWorld({ generated: true });
  await phrase.open();
  const spoken = await phrase.popup().request("generate", PASSPHRASE_OPTIONS);
  phrase.page.forbid = { new_password: ["symbol"] };
  assert.equal((await phrase.popup().request("fill_generated", { generation_id: spoken.generation_id, tab_id: TAB })).ok, true);
  assert.equal(phrase.made.length, 1);

  // Nothing left to make a password of (the page refuses a class the user switched on, and the user had only that one): refused.
  const poor = await itemWorld({ generated: true });
  await poor.open();
  const digits = await poor.popup().request("generate", { ...PASSWORD_OPTIONS, lower: false, upper: false, symbols: false });
  poor.page.forbid = { new_password: ["digit"] };
  assert.deepEqual(await poor.popup().request("fill_generated", { generation_id: digits.generation_id, tab_id: TAB }), { ok: false, reason: "field_too_short" });
  assert.deepEqual(poor.pushed, []);
});

test("fill_generated_creates_an_offer_marked_generated_and_shows_the_save_card_at_once", async () => {
  const { world, popup, made } = await signUpWorld();
  assert.deepEqual(world.offered.calls, [], "nothing is offered by making a value");
  const reply = await popup.request("fill_generated", { generation_id: made.generation_id, tab_id: TAB });
  assert.equal(reply.offer, true);
  // The store of offers was told what went into the page, where, and for how long the value is held.
  assert.deepEqual(world.offered.calls, [
    { tabId: TAB, frameId: 0, documentId: "doc-1", frameUrl: LOGIN_URL, kind: "signup", password: made.value, expiresAt: made.expires_at },
  ]);
  // It is told once per fill, and not for a fill that put nothing in.
  await popup.request("fill_generated", { generation_id: made.generation_id, tab_id: TAB });
  assert.equal(world.offered.calls.length, 2);
  world.page.generatedFields = [];
  await popup.request("fill_generated", { generation_id: made.generation_id, tab_id: TAB });
  assert.equal(world.offered.calls.length, 2);

  // An offer that cannot be made leaves the fill as it was: the value is in the page, and the popup is told no offer.
  const full = await signUpWorld();
  full.world.offered.failing = true;
  assert.deepEqual(await full.popup.request("fill_generated", { generation_id: full.made.generation_id, tab_id: TAB }), { ok: true, length: 20, offer: false });

  // The popup's view shows the save card at once: it is told right after the reply, before anything is submitted.
  const doc = useDocument();
  assert.ok(doc);
  const { Texts } = await texts();
  const { createGeneratorFlow, createGeneratorView, readOptions } = await (await pkg()).load("pages/generatorView.mjs");
  const events = /** @type {string[]} */ ([]);
  const view = createGeneratorView({
    texts: Texts,
    flow: createGeneratorFlow(async (/** @type {string} */ type, /** @type {any} */ body) => {
      events.push(type);
      if (type === "generate") return body.current === true ? { ok: false, reason: "nothing_kept" } : { ok: true, generation_id: "a".repeat(32), value: "Zq9!sample", kind: "password", bits: 100, expires_at: 1 };
      return { ok: true, length: 10, offer: true };
    }),
    store: { load: async () => readOptions(null), save: async () => {} },
    tabId: TAB,
    onOffer: () => events.push("offer"),
  });
  assert.ok(view);
  await view.ready;
  await settle();
  const fill = one(view.root, "fill");
  assert.ok(fill instanceof FakeElement);
  for (const [type, fn] of fill.listeners) if (type === "click") fn({});
  await settle();
  assert.deepEqual(events.slice(-2), ["fill_generated", "offer"]);
});

/** The texts of the built package's English catalog. */
async function texts() {
  const { dir } = await pkg();
  const { readFileSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { textsOf } = await import("./pageDom.mjs");
  const catalog = JSON.parse(readFileSync(join(dir, "locales.en.json"), "utf8"));
  return { Texts: textsOf(catalog, "en") };
}

test("a_generated_password_under_8_characters_is_never_filled_whatever_the_field_says", async () => {
  // The popup can make a password of 4 characters; the core allows it, Ferret does not put it into a page.
  for (const limits of /** @type {Array<Record<string, number>>} */ ([{}, { new_password: 6 }, { new_password: 64 }])) {
    const world = await itemWorld({ generated: true });
    await world.open();
    const popup = world.popup();
    const made = await popup.request("generate", { ...PASSWORD_OPTIONS, length: 6 });
    assert.equal(made.value.length, 6);
    world.page.limits = limits;
    assert.deepEqual(await popup.request("fill_generated", { generation_id: made.generation_id, tab_id: TAB }), { ok: false, reason: "field_too_short" }, JSON.stringify(limits));
    assert.deepEqual(world.pushed, []);
    assert.deepEqual(world.offered.calls, []);
    // It can still be shown and copied.
    assert.equal((await popup.request("generate", { current: true })).value, made.value);
    assert.deepEqual(await popup.request("generate_copy", { generation_id: made.generation_id }), { ok: true });
  }
  // 8 is the shortest that is filled; the floor is the one the generator makes a password fit a field with.
  const eight = await itemWorld({ generated: true });
  await eight.open();
  const made = await eight.popup().request("generate", { ...PASSWORD_OPTIONS, length: 8 });
  assert.deepEqual(await eight.popup().request("fill_generated", { generation_id: made.generation_id, tab_id: TAB }), { ok: true, length: 8, offer: true });
  const pack = await pkg();
  assert.equal((await pack.load("background/fillFlow.mjs")).MIN_GENERATED_FILL, (await pack.load("background/generator.mjs")).MIN_FIT);
});

test("a_value_that_landed_in_one_field_and_was_refused_by_the_next_still_gets_its_offer", async () => {
  const { world, popup, made } = await signUpWorld();
  world.page.answer = (/** @type {string} */ kind) => (kind === "confirm_password" ? { ok: false, reason: "hidden" } : { ok: true });
  assert.deepEqual(await popup.request("fill_generated", { generation_id: made.generation_id, tab_id: TAB }), { ok: false, reason: "covered", offer: true });
  assert.deepEqual(world.page.filled, { new_password: made.value });
  assert.deepEqual(world.offered.calls.map((c) => c.password), [made.value], "the page holds the value, so the offer does too");

  // Nothing landed: no offer. And an offer that cannot be made says so.
  const none = await signUpWorld();
  none.world.page.answer = () => ({ ok: false, reason: "hidden" });
  assert.deepEqual(await none.popup.request("fill_generated", { generation_id: none.made.generation_id, tab_id: TAB }), { ok: false, reason: "covered" });
  assert.deepEqual(none.world.offered.calls, []);
  const full = await signUpWorld();
  full.world.offered.failing = true;
  full.world.page.answer = (/** @type {string} */ kind) => (kind === "confirm_password" ? { ok: false, reason: "hidden" } : { ok: true });
  assert.deepEqual(await full.popup.request("fill_generated", { generation_id: full.made.generation_id, tab_id: TAB }), { ok: false, reason: "covered" });
});

test("the_store_of_offers_is_told_the_kind_of_form_and_a_refusal_means_no_offer", async () => {
  // The kind of the form comes from the fill script's report: a change form and a reset form say so.
  for (const group of ["change", "reset"]) {
    const { world, popup, made } = await signUpWorld();
    world.page.group = group;
    assert.equal((await popup.request("fill_generated", { generation_id: made.generation_id, tab_id: TAB })).offer, true);
    assert.deepEqual(world.offered.calls.map((c) => c.kind), [group]);
  }
  // A report that names no kind gives no offer (the value is in the page, the store is not asked).
  const unnamed = await signUpWorld();
  unnamed.world.page.group = null;
  assert.deepEqual(await unnamed.popup.request("fill_generated", { generation_id: unnamed.made.generation_id, tab_id: TAB }), { ok: true, length: 20, offer: false });
  assert.deepEqual(unnamed.world.offered.calls, []);
  // The store answers null: no offer, and the reply says so.
  const refused = await signUpWorld();
  refused.world.offered.refusing = true;
  assert.deepEqual(await refused.popup.request("fill_generated", { generation_id: refused.made.generation_id, tab_id: TAB }), { ok: true, length: 20, offer: false });
  // The offer ends with the value: a fill at minute 14 passes the generator's own end, not a new 15 minutes.
  const late = await signUpWorld();
  late.world.clock.advance(14 * 60_000);
  await late.popup.request("fill_generated", { generation_id: late.made.generation_id, tab_id: TAB });
  assert.equal(late.world.offered.calls[0].expiresAt, late.made.expires_at);
  assert.ok(late.world.offered.calls[0].expiresAt - late.world.clock.now() <= 60_000);
});
