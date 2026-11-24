// The generator's options and the handoff to the form of a new item: what is read from a stored value, what the core is asked,
// that the stored options never hold a value, and that a handed-over value can be taken once.
import assert from "node:assert/strict";
import { test } from "node:test";
import { GENERATOR_PREFS_KEY, createOptionsStore } from "../../src/generatorPrefs.mjs";
import {
  DEFAULT_OPTIONS, HANDOFF_TTL_MS, createHandoff, makeValue, readOptions, requestOf, strengthOf,
} from "../../src/views/generatorModel.mjs";
import { coded } from "./vaultHelpers.mjs";

/** A storage that holds strings, like localStorage. */
function memory(initial = {}) {
  const map = new Map(Object.entries(initial));
  return {
    map,
    getItem: (key) => map.get(key) ?? null,
    setItem: (key, value) => void map.set(key, String(value)),
    removeItem: (key) => void map.delete(key),
  };
}

test("nothing_stored_gives_the_defaults_of_the_extension", () => {
  assert.deepEqual(readOptions(null), DEFAULT_OPTIONS);
  assert.deepEqual(readOptions(undefined), DEFAULT_OPTIONS);
  assert.deepEqual(readOptions("text"), DEFAULT_OPTIONS);
  assert.deepEqual(readOptions([1, 2]), DEFAULT_OPTIONS);
  assert.equal(DEFAULT_OPTIONS.length, 20);
  assert.equal(DEFAULT_OPTIONS.words, 5);
});

test("a_stored_value_is_checked_key_by_key_and_never_trusted", () => {
  const read = readOptions({ kind: "passphrase", length: 500, words: 2, separator: "x", lower: "yes", min_each: 9, avoid_ambiguous: 1, capitalize: null, number: true, extra: "x" });
  assert.deepEqual(read, { ...DEFAULT_OPTIONS, kind: "passphrase", number: true });
  assert.ok(!("extra" in read), "only the known keys come out");
  assert.equal(readOptions({ length: 4 }).length, 4);
  assert.equal(readOptions({ length: 128 }).length, 128);
  assert.equal(readOptions({ length: 3 }).length, 20);
  assert.equal(readOptions({ length: 12.5 }).length, 20);
  assert.equal(readOptions({ words: 3 }).words, 3);
  assert.equal(readOptions({ words: 20 }).words, 20);
  assert.equal(readOptions({ words: 21 }).words, 5);
  for (const separator of ["-", ".", "_", " "]) assert.equal(readOptions({ separator }).separator, separator);
  assert.equal(readOptions({ kind: "other" }).kind, "password");
});

test("at_least_one_class_of_characters_stays_on", () => {
  const read = readOptions({ lower: false, upper: false, digits: false, symbols: false });
  assert.deepEqual([read.lower, read.upper, read.digits, read.symbols], [true, true, true, true]);
  const some = readOptions({ lower: false, upper: false, digits: true, symbols: false });
  assert.deepEqual([some.lower, some.upper, some.digits, some.symbols], [false, false, true, false]);
});

test("the_core_is_given_every_key_of_the_kind_and_no_other", () => {
  assert.deepEqual(requestOf(readOptions({ kind: "password", length: 24, symbols: false, avoid_ambiguous: true })), {
    length: 24, lower: true, upper: true, digits: true, symbols: false, min_each: 1, avoid_ambiguous: true,
  });
  assert.deepEqual(requestOf(readOptions({ kind: "passphrase", words: 7, separator: ".", capitalize: false, number: true })), {
    words: 7, separator: ".", capitalize: false, number: true,
  });
});

test("strength_names_a_range_of_the_cores_estimate", () => {
  assert.deepEqual([0, 39, 40, 63, 64, 99, 100, 300].map(strengthOf), ["weak", "weak", "fair", "fair", "strong", "strong", "very_strong", "very_strong"]);
});

test("a_value_comes_only_from_the_cores_call_for_the_kind_and_the_estimate_is_rounded", async () => {
  const calls = [];
  const client = { vault: {
    generate_password: async (o) => (calls.push(["password", o]), { value: "pw-1", bits: 119.6 }),
    generate_passphrase: async (o) => (calls.push(["passphrase", o]), { value: "a-b-c", bits: 64.4 }),
  } };
  assert.deepEqual(await makeValue(client, readOptions({ kind: "password" })), { value: "pw-1", bits: 120 });
  assert.deepEqual(await makeValue(client, readOptions({ kind: "passphrase" })), { value: "a-b-c", bits: 64 });
  assert.deepEqual(calls.map(([kind]) => kind), ["password", "passphrase"]);
  assert.deepEqual(Object.keys(calls[1][1]), ["words", "separator", "capitalize", "number"]);
});

test("a_refusal_of_the_core_passes_on_with_its_code_and_an_empty_answer_is_an_error", async () => {
  const refuse = { vault: { generate_password: async () => { throw coded("generator_options"); } } };
  await assert.rejects(makeValue(refuse, readOptions(null)), (error) => error.code === "generator_options");
  const empty = { vault: { generate_password: async () => ({ value: "", bits: 1 }) } };
  await assert.rejects(makeValue(empty, readOptions(null)), (error) => error.code === "unknown");
});

test("the_options_are_kept_and_read_back_and_the_stored_text_holds_options_only", () => {
  const storage = memory();
  const store = createOptionsStore(storage);
  assert.deepEqual(store.read(), DEFAULT_OPTIONS);
  const chosen = readOptions({ kind: "passphrase", words: 8, separator: "_", number: true, length: 33 });
  store.save(chosen);
  assert.deepEqual(createOptionsStore(storage).read(), chosen);
  const text = storage.map.get(GENERATOR_PREFS_KEY);
  assert.deepEqual(Object.keys(JSON.parse(text)).sort(), Object.keys(DEFAULT_OPTIONS).sort());
  assert.deepEqual([...storage.map.keys()], [GENERATOR_PREFS_KEY], "one key");
});

test("a_bad_or_blocked_store_only_means_the_choice_is_not_remembered", () => {
  assert.deepEqual(createOptionsStore(memory({ [GENERATOR_PREFS_KEY]: "{not json" })).read(), DEFAULT_OPTIONS);
  assert.deepEqual(createOptionsStore(memory({ [GENERATOR_PREFS_KEY]: "x".repeat(5000) })).read(), DEFAULT_OPTIONS);
  assert.deepEqual(createOptionsStore(null).read(), DEFAULT_OPTIONS);
  createOptionsStore(null).save(DEFAULT_OPTIONS);
  const blocked = {
    getItem() { throw new Error("blocked"); },
    setItem() { throw new Error("blocked"); },
    removeItem() { throw new Error("blocked"); },
  };
  const store = createOptionsStore(blocked);
  assert.deepEqual(store.read(), DEFAULT_OPTIONS);
  store.save(DEFAULT_OPTIONS);
});

test("a_handed_over_value_is_taken_once_and_only_while_it_is_fresh", () => {
  let now = 1_000;
  const handoff = createHandoff({ now: () => now });
  assert.equal(handoff.take(), null);
  handoff.put("v1");
  assert.equal(handoff.take(), "v1");
  assert.equal(handoff.take(), null, "taken once");
  handoff.put("v2");
  now += HANDOFF_TTL_MS - 1;
  assert.equal(handoff.take(), "v2");
  handoff.put("v3");
  now += HANDOFF_TTL_MS;
  assert.equal(handoff.take(), null, "too old");
  handoff.put("v4");
  handoff.clear();
  assert.equal(handoff.take(), null, "cleared");
  handoff.put("v5");
  now -= 10_000;
  assert.equal(handoff.take(), null, "a clock that went back");
});
