// The generator's part of the background (generator.mjs and its handler), through the real core host, lock, router and
// handlers of the built package with a fake core:
//
// - the only source of a generated value is the core's `generate` call; no code outside the core makes one;
// - the background holds the value under a random generation id until the vault locks or 15 minutes have passed
//   (wall clock), and never writes it anywhere;
// - "Copy" goes through the clipboard of the background, which clears it 30 seconds later;
// - nothing works while the vault is locked, and a build without the feature refuses every type.
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { test } from "node:test";
import { ALARM_PREFIX, CLEAR_AFTER_MS } from "../../src/background/clipboard.mjs";
import { build } from "../../scripts/build.mjs";
import { itemWorld } from "./itemHelpers.mjs";
import { makeRoot } from "./buildHelpers.mjs";
import { pkg } from "./sessionHelpers.mjs";

const PASSWORD_OPTIONS = Object.freeze({ kind: "password", length: 20, lower: true, upper: true, digits: true, symbols: true, min_each: 1, avoid_ambiguous: false });
const PASSPHRASE_OPTIONS = Object.freeze({ kind: "passphrase", words: 5, separator: "-", capitalize: true, number: false });
const MINUTE = 60_000;

/** Every .mjs file under `dir`, as package-relative path -> text. @param {string} dir @returns {Map<string, string>} */
function sourcesOf(dir) {
  /** @type {Map<string, string>} */
  const out = new Map();
  const walk = (/** @type {string} */ at) => {
    for (const name of readdirSync(at)) {
      const path = join(at, name);
      if (statSync(path).isDirectory()) walk(path);
      else if (name.endsWith(".mjs")) out.set(relative(dir, path).split("\\").join("/"), readFileSync(path, "utf8"));
    }
  };
  walk(dir);
  return out;
}

/** The text of one function of a source, from its first line to the line that closes it at the same indent. @param {string} text @param {string} head */
function functionText(text, head) {
  const start = text.indexOf(head);
  assert.ok(start >= 0, `${head} is in the source`);
  const indent = /^ */.exec(text.slice(text.lastIndexOf("\n", start) + 1))?.[0] ?? "";
  const end = text.indexOf(`\n${indent}}\n`, start);
  return text.slice(start, end + indent.length + 2);
}

test("no_code_outside_the_core_makes_a_password_value", async () => {
  const { dir } = await pkg();
  const files = sourcesOf(dir);
  // No source of randomness in the files that hold, show, fill or offer a generated value (ids and nonces are made by
  // the entry point and handed in).
  const RANDOM = /getRandomValues|Math\.random|randomUUID|\bcrypto\b|randomBytes/;
  for (const path of ["background/generator.mjs", "background/handlers/generator.handler.mjs", "pages/generatorView.mjs", "pages/popupTabs.mjs"]) {
    assert.ok(files.has(path), `${path} is in the package`);
    assert.equal(RANDOM.test(/** @type {string} */ (files.get(path))), false, `${path} imports no randomness`);
  }
  // The generated fill in the fill flow too (its request ids are made by `random`, outside this function).
  const fillFlow = /** @type {string} */ (files.get("background/fillFlow.mjs"));
  const fillGenerated = functionText(fillFlow, "async function fillGenerated(");
  assert.equal(RANDOM.test(fillGenerated.replace("random(new Uint8Array(16))", "")), false, "fill_generated makes no value");
  // The offers (when the background has a store of them) import no randomness for a value either: they hold the value
  // they were given. Its own ids are the only ones it may make.
  if (files.has("background/offers.mjs")) {
    const offers = /** @type {string} */ (files.get("background/offers.mjs"));
    assert.equal(/Math\.random|generate_pass/.test(offers), false, "the offers make no password");
  }
  // The core's generate functions are called in one place only.
  const callers = [...files].filter(([, text]) => /generate_password|generate_passphrase/.test(text)).map(([path]) => path);
  assert.deepEqual(callers, ["background/generator.mjs"]);
  // The one source of a value, in the running code: the core. What the popup is given and what goes into the page is
  // what the fake core made, and nothing else.
  const world = await itemWorld({ generated: true });
  await world.open();
  const popup = world.popup();
  const first = await popup.request("generate", PASSWORD_OPTIONS);
  const second = await popup.request("generate", PASSPHRASE_OPTIONS);
  assert.deepEqual([first.value, second.value], world.made.map((m) => m.value));
  assert.deepEqual(world.made.map((m) => m.kind), ["password", "passphrase"]);
  await popup.request("fill_generated", { generation_id: first.generation_id, tab_id: 7 });
  assert.deepEqual(world.pushed.map((p) => p.message.body.value), [first.value, first.value]);
  // The spy sees a value that is not the core's too (a positive control for the comparison above).
  assert.notEqual(first.value, "something-else-entirely");
});

test("a_generate_request_names_the_options_of_one_kind_and_the_core_checks_them", async () => {
  const world = await itemWorld({ generated: true });
  await world.open();
  const popup = world.popup();
  // The core gets exactly the options of the kind (no key of the other kind, none of the request's own).
  await popup.request("generate", { ...PASSWORD_OPTIONS, length: 33 });
  await popup.request("generate", PASSPHRASE_OPTIONS);
  assert.deepEqual(world.client.calls.filter((c) => c.method.startsWith("generate")).map((c) => [c.method, Object.keys(/** @type {any} */ (c.args[0])).sort()]), [
    ["generate_password", ["avoid_ambiguous", "digits", "length", "lower", "min_each", "symbols", "upper"]],
    ["generate_passphrase", ["capitalize", "number", "separator", "words"]],
  ]);
  assert.equal(world.made[0].options.length, 33);
  // A request without the options of its kind is refused, and so is one without a kind.
  assert.deepEqual(await popup.request("generate", { kind: "password", length: 20 }), { ok: false, reason: "invalid_input" });
  assert.deepEqual(await popup.request("generate", { length: 20 }), { ok: false, reason: "invalid_input" });
  assert.equal(world.made.length, 2, "the core was not asked");
  // The core's own refusal of options out of range reaches the page as a bad request.
  const refusing = await itemWorld({ generated: true });
  await refusing.open();
  refusing.generatorCore.refuses = "generator_options";
  const refused = await refusing.popup().request("generate", PASSWORD_OPTIONS);
  assert.deepEqual(refused, { ok: false, reason: "invalid_input" });
});

test("the_generated_value_lives_in_the_background_until_lock_or_15_minutes", async () => {
  const world = await itemWorld({ generated: true });
  await world.open();
  const popup = world.popup();
  /** Everything the page could write that a value might land in. */
  const spies = [];
  const logged = /** @type {string[]} */ ([]);
  for (const name of /** @type {const} */ (["log", "info", "warn", "error", "debug"])) {
    const original = console[name];
    console[name] = (/** @type {unknown[]} */ ...args) => logged.push(JSON.stringify(args));
    spies.push(() => { console[name] = original; });
  }
  try {
    const made = await popup.request("generate", PASSWORD_OPTIONS);
    assert.equal(made.ok, true);
    assert.match(made.generation_id, /^[A-Za-z0-9_-]{1,64}$/);
    assert.equal(made.expires_at, world.clock.now() + 15 * MINUTE);
    const value = made.value;

    // The popup was closed and opened again: the value is still there, and is the same.
    const again = await world.popup().request("generate", { current: true });
    assert.deepEqual({ ...again }, { ...made });
    assert.equal(world.made.length, 1, "no new value was made");

    // 14 minutes 59 seconds: still held. A copy of it works.
    world.clock.advance(15 * MINUTE - 1000);
    assert.equal((await popup.request("generate", { current: true })).value, value);
    assert.deepEqual(await popup.request("generate_copy", { generation_id: made.generation_id }), { ok: true });
    assert.deepEqual(world.written, [value]);

    // 15 minutes of wall clock, with no timer that ran: gone.
    world.clock.advance(1000);
    assert.deepEqual(await popup.request("generate", { current: true }), { ok: false, reason: "nothing_kept" });
    assert.deepEqual(await popup.request("generate_copy", { generation_id: made.generation_id }), { ok: false, reason: "not_offered" });
    assert.deepEqual(await popup.request("fill_generated", { generation_id: made.generation_id, tab_id: 7 }), { ok: false, reason: "not_offered" });
    assert.deepEqual(world.pushed, []);

    // A lock takes every value, however young.
    const young = await popup.request("generate", PASSWORD_OPTIONS);
    assert.equal(world.generatorHost.generations.size(), 1);
    await world.coreHost.lock("manual");
    assert.equal(world.generatorHost.generations.size(), 0);
    await world.open();
    assert.deepEqual(await world.popup().request("generate", { current: true }), { ok: false, reason: "nothing_kept" });
    assert.deepEqual(await world.popup().request("generate_copy", { generation_id: young.generation_id }), { ok: false, reason: "not_offered" });

    // At most eight are held; the oldest goes first.
    const ids = [];
    for (let i = 0; i < 10; i += 1) ids.push((await popup.request("generate", PASSWORD_OPTIONS)).generation_id);
    assert.equal(world.generatorHost.generations.size(), 8);
    assert.equal(world.generatorHost.get(ids[0]), null);
    assert.notEqual(world.generatorHost.get(ids[9]), null);

    // Never written anywhere the background writes: not the session storage, not a log, and the replies of the other
    // types do not carry it (a positive control: the clipboard mark and the logs the spies would have seen exist).
    const everyValue = world.made.map((m) => m.value);
    const stored = JSON.stringify([...world.sessionStorage.data]);
    assert.ok(stored.includes("clipboard_mark"), "the spy on the storage saw the clipboard's mark");
    for (const secret of everyValue) {
      assert.equal(stored.includes(secret), false, "no value in the storage");
      assert.equal(logged.join("\n").includes(secret), false, "no value in the log");
    }
    console.log("positive control");
    assert.ok(logged.some((line) => line.includes("positive control")), "the log spy sees a log");
    const received = popup.received().filter((text) => /"type":"(generate_copy|fill_generated)"/.test(text)).join("\n");
    for (const secret of everyValue) assert.equal(received.includes(secret), false, "no reply of another type carries a value");
  } finally {
    for (const restore of spies) restore();
  }
});

test("generator_needs_an_unlocked_vault", async () => {
  const world = await itemWorld({ generated: true });
  // Locked: every type is refused before anything reaches the core.
  const popup = world.popup();
  for (const [type, body] of /** @type {Array<[string, any]>} */ ([
    ["generate", PASSWORD_OPTIONS],
    ["generate", { current: true }],
    ["generate_copy", { generation_id: "a".repeat(32) }],
    ["fill_generated", { generation_id: "a".repeat(32), tab_id: 7 }],
  ])) {
    await assert.rejects(popup.request(type, body), (/** @type {any} */ error) => error?.name === "UiError" && error.code === "vault_locked", type);
  }
  assert.deepEqual(world.made, []);
  assert.deepEqual(world.client.calls.filter((c) => c.method.startsWith("generate")), []);
  // The page is not told what the vault holds, and a value made once is gone after the lock.
  await world.open();
  const made = await popup.request("generate", PASSWORD_OPTIONS);
  await world.coreHost.lock("timeout");
  await assert.rejects(popup.request("generate", { current: true }), (/** @type {any} */ error) => error?.name === "UiError" && error.code === "vault_locked");
  assert.equal(popup.received().join("\n").includes(made.value) && popup.received().filter((t) => t.includes(made.value)).length, 1, "the value was sent once");
});

test("copy_of_a_generated_value_uses_the_30_second_clear", async () => {
  const world = await itemWorld({ generated: true });
  await world.open();
  const popup = world.popup();
  const made = await popup.request("generate", PASSWORD_OPTIONS);
  // The popup names the generation; the background writes the clipboard itself.
  assert.deepEqual(await popup.request("generate_copy", { generation_id: made.generation_id }), { ok: true });
  assert.deepEqual(world.written, [made.value]);
  const mark = await world.clipboard.mark();
  assert.match(String(mark), /^[0-9a-f]{32}$/);
  // The same alarm and the same 30 seconds as the copy of an item's password.
  assert.equal(world.events.alarmList.get(`${ALARM_PREFIX}${mark}`)?.when, world.clock.now() + CLEAR_AFTER_MS);
  assert.equal(CLEAR_AFTER_MS, 30_000);
  await world.events.fireAlarm(`${ALARM_PREFIX}${mark}`);
  assert.deepEqual(world.written, [made.value, ""], "the alarm cleared the clipboard");
  // An unknown generation copies nothing.
  assert.deepEqual(await popup.request("generate_copy", { generation_id: "f".repeat(32) }), { ok: false, reason: "not_offered" });
  assert.deepEqual(world.written, [made.value, ""]);
  // A clipboard that fails and one that cannot be cleared are told apart, as for an item.
  world.clipboardState.fails = true;
  assert.deepEqual(await popup.request("generate_copy", { generation_id: made.generation_id }), { ok: false, reason: "clipboard" });
  world.clipboardState.fails = false;
  world.clipboardState.timerFails = true;
  world.events.alarms.create = () => {
    throw new Error("no alarm");
  };
  assert.deepEqual(await popup.request("generate_copy", { generation_id: made.generation_id }), { ok: false, reason: "not_cleared" });
});

test("a_build_without_the_feature_refuses_every_generator_type_and_has_no_generator_operation", async () => {
  const env = makeRoot();
  try {
    const release = await build({ root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, out: env.out, manifest: "mv2", variant: "release" });
    const { pathToFileURL } = await import("node:url");
    const load = (/** @type {string} */ path) => import(pathToFileURL(join(release.dir, ...path.split("/"))).href);
    const handler = (await load("background/handlers/generator.handler.mjs")).default;
    assert.deepEqual([...handler.types], ["generate", "generate_copy", "fill_generated"]);
    for (const type of handler.types) {
      await assert.rejects(handler.handle({}, { channel: "ui", type, state: () => "unlocked" }), (/** @type {any} */ error) => error?.code === "not_available", type);
    }
    // The generator's own operations refuse too, if someone builds the host without asking the flag first.
    const { createGeneratorHost } = await load("background/generator.mjs");
    const host = createGeneratorHost({ newId: () => "a".repeat(32), clipboard: { copy: async () => {} } });
    for (const name of ["generate", "generate_copy"]) {
      await assert.rejects(host.ops[name].run({ vault: {} }, { kind: "password", generation_id: "a".repeat(32) }, {}), (/** @type {any} */ error) => error?.code === "not_available", name);
    }
    assert.deepEqual(await host.fit("a".repeat(32), 12).catch((/** @type {any} */ error) => error.code), "not_available");
    // The fill flow without a generator has no `fill_generated` to give.
    const { createFillHost } = await load("background/fillFlow.mjs");
    const fillHost = createFillHost({ syncHost: { engine: () => null }, clipboard: { copy: async () => {} }, scripting: { executeScript: async () => [] }, tabs: { sendMessage: async () => undefined, create: async () => ({}) }, source: null });
    await assert.rejects(fillHost.ops.fill_generated.run({}, { session: "0".repeat(32), generation_id: "a".repeat(32), tab_id: 7 }, {}), (/** @type {any} */ error) => error?.code === "not_available");
  } finally {
    env.cleanup();
  }
});
