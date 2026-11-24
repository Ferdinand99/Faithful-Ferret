// The generator page: the value comes from the core's call and from nowhere else, the options are kept without the value, the value
// goes with a lock, a sign-out, a change of page and "Use as new item", and the page makes no random number of its own.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createWipeScope } from "../../src/views/common.mjs";
import { generatorView } from "../../src/views/generator.mjs";
import { GENERATOR_PREFS_KEY, createOptionsStore } from "../../src/generatorPrefs.mjs";
import { createHandoff } from "../../src/views/generatorModel.mjs";
import { web } from "./helpers.mjs";
import { all, click, coded, find, fire, settle, t, textOf, withDom } from "./vaultHelpers.mjs";

function memory(initial = {}) {
  const map = new Map(Object.entries(initial));
  return {
    map,
    getItem: (key) => map.get(key) ?? null,
    setItem: (key, value) => void map.set(key, String(value)),
    removeItem: (key) => void map.delete(key),
  };
}

/** A client whose values are numbered ("PW-1"), so a test can tell which call a shown value came from. The calls are kept. */
function fakeCore({ bits = 130 } = {}) {
  const calls = [];
  let n = 0;
  let held = null;
  const make = (kind) => async (options) => {
    calls.push([kind, structuredClone(options)]);
    n += 1;
    const answer = { value: `${kind === "password" ? "PW" : "PP"}-${n}`, bits };
    if (held === null) return answer;
    return new Promise((resolve, reject) => held.push({ answer, resolve, reject }));
  };
  return {
    calls,
    client: { vault: { generate_password: make("password"), generate_passphrase: make("passphrase") } },
    /** The next calls wait until `release()`. */
    hold() {
      held = [];
    },
    release(index = 0) {
      held[index].resolve(held[index].answer);
    },
  };
}

function fakeWindow(hash = "#/generator") {
  const listeners = new Set();
  const win = {
    location: { hash },
    addEventListener: (type, fn) => type === "hashchange" && listeners.add(fn),
    removeEventListener: (type, fn) => type === "hashchange" && listeners.delete(fn),
    get listening() {
      return listeners.size;
    },
    go(next) {
      win.location.hash = next;
      for (const fn of [...listeners]) fn();
    },
  };
  return win;
}

async function open({ core = fakeCore(), storage = memory(), clipboard, touch, handoff = createHandoff(), go, win = fakeWindow(), scope = createWipeScope() } = {}) {
  const moves = [];
  const written = [];
  const root = generatorView({
    t, client: core.client, store: createOptionsStore(storage), handoff, scope, touch, win,
    go: go ?? ((path) => moves.push(path)),
    clipboard: clipboard === undefined ? { writeText: async (text) => void written.push(text) } : clipboard,
  });
  await settle();
  return { core, storage, root, scope, win, handoff, moves, written };
}

const valueOf = (root) => textOf(find(root, "generated-value")).trim();

/** Sets a box or a list and tells the page, as a change in the browser does. */
async function change(root, role, props) {
  const node = find(root, role);
  Object.assign(node, props);
  await fire(node, "change");
  await settle();
  return node;
}

test("the_page_makes_one_password_with_the_default_options_when_it_opens", async () => {
  await withDom(async () => {
    const { root, core } = await open();
    assert.deepEqual(core.calls, [["password", { length: 20, lower: true, upper: true, digits: true, symbols: true, min_each: 1, avoid_ambiguous: false }]]);
    assert.equal(valueOf(root), "PW-1");
    assert.equal(find(root, "generator-strength").getAttribute("data-level"), "very_strong");
    assert.ok(textOf(find(root, "generator-strength")).includes('"bits":130'));
    assert.equal(find(root, "copy").disabled, false);
  });
});

test("the_value_is_in_a_polite_live_region_with_a_name_and_the_controls_have_names", async () => {
  await withDom(async () => {
    const { root } = await open();
    const box = find(root, "generated-value");
    assert.equal(box.tagName, "output");
    assert.equal(box.getAttribute("aria-live"), "polite");
    assert.equal(box.getAttribute("aria-atomic"), "true");
    assert.equal(box.getAttribute("aria-label"), "generator.value_label");
    assert.equal(box.getAttribute("dir"), "ltr");
    assert.equal(find(root, "generator-status").getAttribute("role"), "status");
    assert.equal(find(root, "generator-error").getAttribute("role"), "alert");
    for (const role of ["copy", "regenerate", "use-as-new", "kind-password", "kind-passphrase"]) {
      assert.equal(find(root, role).tagName, "button", role);
      assert.equal(find(root, role).getAttribute("type"), "button", role);
    }
    // Every field has a label tied to it by `for`; the sliders have a name of their own.
    const labelled = new Set();
    const walkNodes = (node) => {
      if (node.tagName === "label") labelled.add(node.getAttribute("for"));
      for (const child of node.childNodes) walkNodes(child);
    };
    walkNodes(root);
    for (const [role, id] of [["option-length", "gen-length"], ["option-words", "gen-words"], ["option-separator", "gen-separator"], ["option-upper", "gen-upper"], ["option-min_each", "gen-min_each"]]) {
      assert.equal(find(root, role).getAttribute("id"), id);
      assert.ok(labelled.has(id), `a label for ${id}`);
    }
    assert.equal(find(root, "option-length-range").getAttribute("aria-label"), "generator.options.length_slider");
    assert.equal(find(root, "option-words-range").getAttribute("aria-label"), "generator.options.words_slider");
    assert.equal(find(root, "generator-kinds").getAttribute("role"), "group");
    assert.ok(find(root, "generator-kinds").getAttribute("aria-label"));
  });
});

test("regenerate_makes_a_new_value_and_a_late_reply_of_an_older_call_is_dropped", async () => {
  await withDom(async () => {
    const core = fakeCore();
    const { root } = await open({ core });
    assert.equal(valueOf(root), "PW-1");
    core.hold();
    await click(find(root, "regenerate"));
    await click(find(root, "regenerate"));
    await settle();
    assert.equal(core.calls.length, 3);
    core.release(1); // the newer one answers first
    await settle();
    assert.equal(valueOf(root), "PW-3");
    core.release(0); // the older one answers late
    await settle();
    assert.equal(valueOf(root), "PW-3", "the late reply does not replace the newer value");
  });
});

test("a_change_of_options_asks_the_core_again_with_the_options_and_keeps_them", async () => {
  await withDom(async () => {
    const storage = memory();
    const { root, core } = await open({ storage });
    await change(root, "option-length", { value: "32" });
    assert.equal(core.calls.at(-1)[1].length, 32);
    assert.equal(find(root, "option-length-range").value, "32", "the slider and the box say the same");
    await change(root, "option-symbols", { checked: false });
    assert.equal(core.calls.at(-1)[1].symbols, false);
    await change(root, "option-avoid_ambiguous", { checked: true });
    assert.equal(core.calls.at(-1)[1].avoid_ambiguous, true);
    await change(root, "option-min_each", { checked: false });
    assert.equal(core.calls.at(-1)[1].min_each, 0);
    assert.deepEqual(JSON.parse(storage.map.get(GENERATOR_PREFS_KEY)), {
      kind: "password", length: 32, lower: true, upper: true, digits: true, symbols: false, min_each: 0, avoid_ambiguous: true,
      words: 5, separator: "-", capitalize: true, number: false,
    });
  });
});

test("a_number_out_of_range_is_held_to_the_range_and_text_that_is_no_number_changes_nothing", async () => {
  await withDom(async () => {
    const { root, core } = await open();
    await change(root, "option-length", { value: "500" });
    assert.equal(core.calls.at(-1)[1].length, 128);
    assert.equal(find(root, "option-length").value, "128");
    await change(root, "option-length", { value: "1" });
    assert.equal(core.calls.at(-1)[1].length, 4);
    await change(root, "option-length", { value: "abc" });
    assert.equal(core.calls.at(-1)[1].length, 4);
    assert.equal(find(root, "option-length").value, "4");
    const slider = find(root, "option-length-range");
    slider.value = "40";
    await fire(slider, "input");
    assert.equal(find(root, "option-length").value, "40", "the box follows the slider while it moves");
    assert.equal(core.calls.at(-1)[1].length, 4, "the core is asked when the slider is let go");
    await fire(slider, "change");
    await settle();
    assert.equal(core.calls.at(-1)[1].length, 40);
  });
});

test("the_last_class_that_is_on_cannot_be_switched_off", async () => {
  await withDom(async () => {
    const { root } = await open();
    for (const name of ["upper", "lower", "digits"]) await change(root, `option-${name}`, { checked: false });
    assert.equal(find(root, "option-symbols").disabled, true);
    for (const name of ["upper", "lower", "digits"]) assert.equal(find(root, `option-${name}`).disabled, false);
    // Even a change that gets through (a script) cannot leave a password with no class.
    await change(root, "option-symbols", { checked: false });
    assert.equal(find(root, "option-symbols").checked, true);
  });
});

test("a_passphrase_asks_the_core_for_a_passphrase_with_its_own_options", async () => {
  await withDom(async () => {
    const { root, core } = await open();
    await click(find(root, "kind-passphrase"));
    await settle();
    assert.deepEqual(core.calls.at(-1), ["passphrase", { words: 5, separator: "-", capitalize: true, number: false }]);
    assert.equal(valueOf(root), "PP-2");
    assert.equal(find(root, "kind-passphrase").getAttribute("aria-pressed"), "true");
    assert.equal(find(root, "kind-password").getAttribute("aria-pressed"), "false");
    assert.equal(find(root, "options-passphrase").hidden, false);
    assert.equal(find(root, "options-password").hidden, true);
    await change(root, "option-words", { value: "9" });
    await change(root, "option-separator", { value: "." });
    await change(root, "option-capitalize", { checked: false });
    await change(root, "option-number", { checked: true });
    assert.deepEqual(core.calls.at(-1), ["passphrase", { words: 9, separator: ".", capitalize: false, number: true }]);
    await click(find(root, "kind-password"));
    await settle();
    assert.equal(core.calls.at(-1)[0], "password");
    assert.equal(find(root, "options-password").hidden, false);
  });
});

test("the_options_are_remembered_by_the_next_page_and_the_value_never_is", async () => {
  await withDom(async () => {
    const storage = memory();
    const first = await open({ storage });
    await click(find(first.root, "kind-passphrase"));
    await settle();
    await change(first.root, "option-words", { value: "11" });
    const shown = valueOf(first.root);
    assert.ok(shown.startsWith("PP-"));
    const stored = [...storage.map.entries()];
    assert.deepEqual(stored.map(([key]) => key), [GENERATOR_PREFS_KEY]);
    assert.ok(!JSON.stringify(stored).includes(shown), "the value is not in the storage");
    assert.ok(!JSON.stringify(stored).includes("PP-"));
    const second = await open({ storage });
    assert.equal(find(second.root, "kind-passphrase").getAttribute("aria-pressed"), "true");
    assert.equal(find(second.root, "option-words").value, "11");
    assert.equal(second.core.calls[0][0], "passphrase");
    assert.equal(second.core.calls[0][1].words, 11);
  });
});

test("copy_hands_the_value_to_the_clipboard_like_the_item_page_and_says_so", async () => {
  await withDom(async () => {
    const { root, written } = await open();
    await click(find(root, "copy"));
    await settle();
    assert.deepEqual(written, ["PW-1"]);
    assert.ok(textOf(find(root, "generator-status")).includes("vault.item.copied"));
    assert.ok(textOf(find(root, "generator-status")).includes("vault.edit.password"), "named as the password");
    assert.ok(!textOf(find(root, "generator-status")).includes("PW-1"), "the value is not repeated in the message");
    await click(find(root, "kind-passphrase"));
    await settle();
    await click(find(root, "copy"));
    await settle();
    assert.deepEqual(written, ["PW-1", "PP-2"]);
    assert.ok(textOf(find(root, "generator-status")).includes("generator.mode.passphrase"));
  });
});

test("a_clipboard_that_refuses_or_is_missing_is_said_in_words", async () => {
  await withDom(async () => {
    for (const clipboard of [{ writeText: async () => { throw new Error("denied"); } }, null]) {
      const { root } = await open({ clipboard });
      await click(find(root, "copy"));
      await settle();
      assert.equal(find(root, "generator-error").hidden, false);
      assert.ok(textOf(find(root, "generator-error")).includes("vault.error.clipboard"));
      assert.equal(textOf(find(root, "generator-status")).trim(), "");
    }
  });
});

test("the_core_refusing_the_options_is_said_and_leaves_no_value", async () => {
  await withDom(async () => {
    const core = fakeCore();
    const { root } = await open({ core });
    core.client.vault.generate_password = async () => {
      throw coded("generator_options");
    };
    await click(find(root, "regenerate"));
    await settle();
    assert.equal(valueOf(root), "");
    assert.equal(find(root, "generator-error").hidden, false);
    assert.ok(textOf(find(root, "generator-error")).includes("generator.error.options"));
    assert.equal(find(root, "copy").disabled, true);
    assert.equal(find(root, "use-as-new").disabled, true);
    // Another failure has the vault's own text.
    core.client.vault.generate_password = async () => {
      throw coded("worker_failed");
    };
    await click(find(root, "regenerate"));
    await settle();
    assert.ok(textOf(find(root, "generator-error")).includes("vault.error.worker_failed"));
  });
});

test("use_as_new_item_leaves_the_value_for_the_form_once_wipes_the_page_and_opens_the_form", async () => {
  await withDom(async () => {
    const { root, handoff, moves } = await open();
    await click(find(root, "use-as-new"));
    assert.deepEqual(moves, ["/items/new"]);
    assert.equal(valueOf(root), "", "the page no longer shows it");
    assert.equal(find(root, "copy").disabled, true);
    assert.equal(handoff.take(), "PW-1");
    assert.equal(handoff.take(), null);
    assert.ok(!JSON.stringify(moves).includes("PW-"), "the value is not in the address");
  });
});

test("the_value_goes_when_the_vault_locks_and_a_reply_that_was_on_its_way_is_dropped", async () => {
  await withDom(async () => {
    const core = fakeCore();
    const { root, scope } = await open({ core });
    core.hold();
    await click(find(root, "regenerate"));
    await settle();
    scope.run(); // lock, sign-out or another tab taking the vault
    assert.equal(valueOf(root), "");
    core.release(0);
    await settle();
    assert.equal(valueOf(root), "", "the late reply is not shown after the wipe");
    assert.equal(find(root, "copy").disabled, true);
    await click(find(root, "regenerate"));
    await settle();
    assert.equal(core.calls.length, 2, "a wiped page makes no more values");
  });
});

test("the_value_goes_when_the_address_leaves_the_page_and_the_listener_with_it", async () => {
  await withDom(async () => {
    const { root, win } = await open();
    assert.equal(win.listening, 1);
    win.go("#/generator?x=1");
    assert.equal(valueOf(root), "PW-1", "the same page");
    win.go("#/items");
    assert.equal(valueOf(root), "");
    assert.equal(win.listening, 0);
  });
});

test("the_value_is_not_in_the_page_outside_the_value_box_and_not_in_the_address_or_the_storage", async () => {
  await withDom(async () => {
    const { root, storage, win } = await open();
    const value = valueOf(root);
    assert.equal(value, "PW-1");
    let elsewhere = "";
    const walkNodes = (node) => {
      for (const child of node.childNodes) walkNodes(child);
      if (node.attributes) for (const [name, text] of node.attributes) if (text.includes(value)) elsewhere += `${name}=${text} `;
    };
    walkNodes(root);
    assert.equal(elsewhere, "", "no attribute holds the value");
    assert.equal(all(root, "generated-value").length, 1);
    assert.ok(!win.location.hash.includes(value));
    assert.ok(![...storage.map.values()].some((text) => text.includes(value)));
  });
});

test("every_action_moves_the_idle_clock_and_does_nothing_when_the_vault_has_locked", async () => {
  await withDom(async () => {
    let live = true;
    let touches = 0;
    const touch = () => {
      touches += 1;
      return live;
    };
    const { root, core, written } = await open({ touch });
    live = false;
    const before = core.calls.length;
    await click(find(root, "regenerate"));
    await click(find(root, "copy"));
    await click(find(root, "use-as-new"));
    await click(find(root, "kind-passphrase"));
    await change(root, "option-length", { value: "30" });
    assert.equal(core.calls.length, before);
    assert.deepEqual(written, []);
    assert.ok(touches >= 5);
  });
});

// --------------------------------------------------------------- no randomness

test("the_page_makes_no_random_number_of_its_own_while_it_runs", async () => {
  const savedRandom = Math.random;
  const savedCrypto = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  const trap = (name) => () => {
    throw new Error(`${name} was called by the generator page`);
  };
  try {
    await withDom(async () => {
      Math.random = trap("Math.random");
      Object.defineProperty(globalThis, "crypto", {
        configurable: true,
        value: { getRandomValues: trap("crypto.getRandomValues"), randomUUID: trap("crypto.randomUUID"), subtle: new Proxy({}, { get: trap("crypto.subtle") }) },
      });
      const core = fakeCore();
      const { root } = await open({ core });
      await click(find(root, "regenerate"));
      await click(find(root, "kind-passphrase"));
      await change(root, "option-words", { value: "6" });
      await click(find(root, "copy"));
      await settle();
      assert.ok(core.calls.length >= 4);
      assert.ok(valueOf(root).startsWith("PP-"));
    });
  } finally {
    Math.random = savedRandom;
    if (savedCrypto) Object.defineProperty(globalThis, "crypto", savedCrypto);
  }
});

test("no_file_of_the_generator_imports_or_calls_a_source_of_random_numbers", () => {
  const files = ["views/generator.mjs", "views/generatorModel.mjs", "routes/generator.route.mjs", "views/edit.mjs", "routes/new.route.mjs"];
  const forbidden = [/Math\s*\.\s*random/, /getRandomValues/, /randomUUID/, /randomBytes/, /randomInt/, /\bcrypto\s*\./, /node:crypto/, /\bimport\b[^;]*\b(?:random|crypto)\b[^;]*;/];
  for (const file of files) {
    const source = readFileSync(join(web, "src", file), "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
    for (const pattern of forbidden) assert.ok(!pattern.test(source), `${file}: ${pattern}`);
  }
  // The values come from the two calls of the core.
  const model = readFileSync(join(web, "src", "views", "generatorModel.mjs"), "utf8");
  assert.ok(model.includes("client.vault.generate_passphrase") && model.includes("client.vault.generate_password"));
});

// ------------------------------------------------------------------- the texts

test("every_text_the_generator_asks_for_is_in_both_languages", () => {
  const catalog = (lang) => {
    const out = {};
    for (const name of readdirSync(join(web, "src", "locales", lang))) Object.assign(out, JSON.parse(readFileSync(join(web, "src", "locales", lang, name), "utf8")));
    return out;
  };
  const en = catalog("en");
  const nb = catalog("nb");
  const source = readFileSync(join(web, "src", "views", "generator.mjs"), "utf8") + readFileSync(join(web, "src", "views", "edit.mjs"), "utf8");
  const keys = new Set([...source.matchAll(/\bt\(\s*"((?:generator|vault\.edit)\.[A-Za-z0-9_.]+)"/g)].map((m) => m[1]));
  for (const name of ["hyphen", "period", "underscore", "space"]) keys.add(`generator.options.separator.${name}`);
  for (const level of ["weak", "fair", "strong", "very_strong"]) keys.add(`generator.strength.${level}`);
  for (const kind of ["password", "passphrase"]) keys.add(`generator.mode.${kind}`);
  for (const name of ["upper", "lower", "digits", "symbols"]) keys.add(`generator.options.${name}`);
  assert.ok(keys.size > 20);
  for (const key of keys) {
    assert.ok(typeof en[key] === "string" && en[key] !== "", `en: ${key}`);
    assert.ok(typeof nb[key] === "string" && nb[key] !== "", `nb: ${key}`);
  }
  assert.equal(en["shell.nav.generator"], "Generator");
});
