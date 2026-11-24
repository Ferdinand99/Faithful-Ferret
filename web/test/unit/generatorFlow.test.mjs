// The generator in the vault: its route and its place in the menu, "Use as new item" (the password goes to the new item form once, in
// memory only), and "Generate a password" in the item form (the value goes in the password input and nowhere else).
import assert from "node:assert/strict";
import { test } from "node:test";
import { autoLockFor } from "../../src/lock.mjs";
import generatorRoute from "../../src/routes/generator.route.mjs";
import newRoute from "../../src/routes/new.route.mjs";
import { createWipeScope } from "../../src/views/common.mjs";
import { editView } from "../../src/views/edit.mjs";
import { GENERATOR_PREFS_KEY, createOptionsStore } from "../../src/generatorPrefs.mjs";
import { generatedHandoff } from "../../src/views/generatorModel.mjs";
import { sidebarModel } from "../../src/views/sidebarModel.mjs";
import { click, coded, fakeEngine, fakeSession, find, fire, settle, submit, t, textOf, withDom } from "./vaultHelpers.mjs";

const ENTRY = {
  id: "11".repeat(16), name: "Bank", type: "login", favorite: false, urls: [], username: "ada", rev: 1, pending: false, damaged: false,
  quarantined: false, missingOnServer: false, blocked: false, blockedReason: null, readOnly: false,
};

function memory(initial = {}) {
  const map = new Map(Object.entries(initial));
  return {
    map,
    getItem: (key) => map.get(key) ?? null,
    setItem: (key, value) => void map.set(key, String(value)),
    removeItem: (key) => void map.delete(key),
  };
}

/** A client that makes numbered values, like the core would answer. */
function generatingClient() {
  const calls = [];
  let n = 0;
  let held = null;
  const make = (kind) => async (options) => {
    calls.push([kind, options]);
    n += 1;
    const answer = { value: `${kind === "password" ? "GEN" : "PHR"}-${n}`, bits: 120 };
    return held === null ? answer : new Promise((resolve) => held.push(() => resolve(answer)));
  };
  return {
    calls,
    locked: 0,
    vault: { generate_password: make("password"), generate_passphrase: make("passphrase") },
    hold() {
      held = [];
    },
    release(index = 0) {
      held[index]();
    },
  };
}

function rig({ open = true } = {}) {
  const engine = fakeEngine({ items: [ENTRY], views: {} });
  const client = generatingClient();
  const session = fakeSession({ client, open });
  const sync = { engine, current: () => engine, start: async () => engine, stop: () => engine.stop(), discard: engine.discard, discardMissing: engine.discardMissing };
  const moves = [];
  const ctx = (path, params = {}) => ({
    params, path, i18n: { t, lang: "en", missing: [] }, client, services: { crypto: session, sync }, go: (p) => moves.push(p), routes: [generatorRoute, newRoute],
  });
  return { engine, client, session, sync, moves, ctx, done: () => autoLockFor(session, sync).stop() };
}

const valueOf = (root) => textOf(find(root, "generated-value")).trim();

test("the_generator_route_is_listed_in_the_tools_section_and_is_no_longer_a_planned_page", () => {
  assert.equal(generatorRoute.path, "/generator");
  assert.equal(generatorRoute.title, "generator.title");
  const sections = sidebarModel({ routes: [generatorRoute] });
  const tools = sections.find((s) => s.id === "tools");
  assert.deepEqual(tools.entries.map((e) => [e.id, e.kind, e.href, e.role]), [
    ["/generator", "link", "#/generator", "nav-generator"],
    ["health", "soon", null, "nav-health"],
  ]);
  assert.equal(tools.entries[0].label, "shell.nav.generator");
});

test("a_locked_vault_shows_the_unlock_screen_and_no_generator", async () => {
  await withDom(async () => {
    const r = rig({ open: false });
    try {
      const node = await generatorRoute.load(r.ctx("/generator"));
      await settle();
      assert.ok(find(node, "unlock"));
      assert.equal(find(node, "generator-page"), null);
      assert.deepEqual(r.client.calls, [], "nothing is made for a locked vault");
    } finally {
      r.done();
    }
  });
});

test("an_open_vault_shows_the_generator_in_the_frame_and_the_lock_wipes_it", async () => {
  await withDom(async () => {
    const r = rig();
    try {
      const node = await generatorRoute.load(r.ctx("/generator"));
      await settle();
      assert.ok(find(node, "shell"));
      assert.ok(find(node, "generator-page"));
      assert.equal(valueOf(node), "GEN-1");
      await r.session.lock();
      await settle();
      assert.equal(find(node, "generator-page"), null, "the frame is replaced by the unlock screen");
      assert.ok(!textOf(node).includes("GEN-1"), "the value is nowhere on the screen");
    } finally {
      r.done();
    }
  });
});

test("opening_the_generator_clears_a_value_that_was_left_for_a_form_and_never_taken", async () => {
  await withDom(async () => {
    const r = rig();
    try {
      generatedHandoff.put("LEFT-OVER");
      await generatorRoute.load(r.ctx("/generator"));
      assert.equal(generatedHandoff.take(), null);
    } finally {
      r.done();
    }
  });
});

test("use_as_new_item_opens_the_new_form_with_the_password_filled_in_once_and_in_memory_only", async () => {
  await withDom(async () => {
    const storage = memory();
    const r = rig();
    try {
      const page = await generatorRoute.load(r.ctx("/generator"));
      await settle();
      assert.equal(valueOf(page), "GEN-1");
      await click(find(page, "use-as-new"));
      assert.deepEqual(r.moves, ["/items/new"]);
      assert.ok(!r.moves.join("").includes("GEN-"), "not in the address");
      assert.equal(valueOf(page), "");
      // The route of the new item takes it.
      const fresh = await newRoute.load(r.ctx("/items/new"));
      assert.equal(find(fresh, "password").value, "GEN-1");
      assert.equal(find(fresh, "password").getAttribute("type"), "password", "it starts hidden");
      assert.ok(textOf(find(fresh, "status")).includes("vault.edit.generated_prefill"));
      assert.ok(!textOf(fresh).includes("GEN-1"), "the value is in the password input only");
      // A second visit to the form finds nothing left.
      const again = await newRoute.load(r.ctx("/items/new"));
      assert.equal(find(again, "password").value, "");
      assert.deepEqual([...storage.map.keys()], []);
      // Saving sends it to the engine as the item's password.
      find(fresh, "name").value = "Bank";
      await submit(find(fresh, "edit-form"));
      const created = r.engine.calls.find(([name]) => name === "create")[1];
      assert.deepEqual(created.fields, [{ id: "password", label: "vault.edit.password", kind: "password", value: "GEN-1" }]);
      assert.equal(find(fresh, "password").value, "", "the form is emptied when it is saved");
    } finally {
      r.done();
    }
  });
});

test("a_value_that_waits_for_the_form_is_dropped_when_the_vault_is_locked_by_then", async () => {
  await withDom(async () => {
    const r = rig();
    try {
      generatedHandoff.put("GEN-9");
      await r.session.lock();
      const node = await newRoute.load(r.ctx("/items/new"));
      await settle();
      assert.ok(find(node, "unlock"));
      assert.equal(generatedHandoff.take(), null, "the locked screen took it and nobody can read it");
    } finally {
      r.done();
    }
  });
});

// ---------------------------------------------------------- the item form's button

async function form({ id = null, storage = memory(), client = generatingClient(), scope = createWipeScope(), initialPassword = null, touch } = {}) {
  const engine = fakeEngine({ items: [ENTRY], views: { [ENTRY.id]: { item_type: "login", name: "Bank", fields: [{ id: "username", value: "ada" }, { id: "password", value: null }], urls: [], has_notes: false, favorite: false, read_only: false } } });
  const moves = [];
  const root = await editView({
    engine, client, id, t, go: (p) => moves.push(p), scope, touch, initialPassword, generatorStore: createOptionsStore(storage),
  });
  return { engine, client, root, scope, moves, storage };
}

test("the_form_has_a_generate_button_beside_the_password_only_where_the_client_can_make_one", async () => {
  await withDom(async () => {
    const { root } = await form();
    const button = find(root, "password-generate");
    assert.equal(button.tagName, "button");
    assert.equal(button.getAttribute("type"), "button", "it never submits the form");
    assert.ok(textOf(button).includes("vault.edit.generate"));
    const bare = await form({ client: { vault: {} } });
    assert.equal(find(bare.root, "password-generate"), null);
  });
});

test("generate_fills_the_password_input_from_the_core_with_the_options_of_the_page_and_shows_it", async () => {
  await withDom(async () => {
    const client = generatingClient();
    const { root } = await form({ client });
    assert.equal(find(root, "password").getAttribute("type"), "password");
    await click(find(root, "password-generate"));
    await settle();
    assert.equal(client.calls.length, 1);
    assert.deepEqual(client.calls[0], ["password", { length: 20, lower: true, upper: true, digits: true, symbols: true, min_each: 1, avoid_ambiguous: false }]);
    assert.equal(find(root, "password").value, "GEN-1");
    assert.equal(find(root, "password").getAttribute("type"), "text", "shown through the toggle of the form");
    assert.equal(find(root, "password-toggle").getAttribute("aria-pressed"), "true");
    assert.equal(find(root, "password-toggle").getAttribute("aria-label"), "vault.edit.password_hide");
    assert.ok(textOf(find(root, "status")).includes("vault.edit.generated"));
    assert.ok(!textOf(find(root, "status")).includes("GEN-1"), "the message does not repeat the value");
    // The toggle hides it again, and a new click makes a new one.
    await click(find(root, "password-toggle"));
    assert.equal(find(root, "password").getAttribute("type"), "password");
    await click(find(root, "password-generate"));
    await settle();
    assert.equal(find(root, "password").value, "GEN-2");
  });
});

test("generate_uses_the_options_the_generator_page_kept_and_never_writes_them_or_a_value", async () => {
  await withDom(async () => {
    const stored = JSON.stringify({ kind: "passphrase", words: 7, separator: "_", capitalize: false, number: true });
    const storage = memory({ [GENERATOR_PREFS_KEY]: stored });
    const client = generatingClient();
    const { root } = await form({ client, storage });
    await click(find(root, "password-generate"));
    await settle();
    assert.deepEqual(client.calls[0], ["passphrase", { words: 7, separator: "_", capitalize: false, number: true }]);
    assert.equal(find(root, "password").value, "PHR-1");
    assert.equal(storage.map.get(GENERATOR_PREFS_KEY), stored, "the form does not write the options");
    assert.equal(storage.map.size, 1);
  });
});

test("a_generated_password_is_saved_as_the_password_and_an_edit_keeps_the_old_one_in_the_history", async () => {
  await withDom(async () => {
    const { root, engine } = await form({ id: ENTRY.id });
    await click(find(root, "password-generate"));
    await settle();
    await submit(find(root, "edit-form"));
    const [, , draft] = engine.calls.find(([name]) => name === "update");
    assert.equal(draft.keep_password_history, true);
    assert.equal(draft.fields.find((f) => f.id === "password").value, "GEN-1");
    assert.equal(find(root, "password").value, "");
    assert.equal(find(root, "password").getAttribute("type"), "password");
  });
});

test("generate_that_the_core_refuses_says_so_and_changes_nothing", async () => {
  await withDom(async () => {
    const client = generatingClient();
    client.vault.generate_password = async () => {
      throw coded("generator_options");
    };
    const { root } = await form({ client });
    find(root, "password").value = "typed";
    await click(find(root, "password-generate"));
    await settle();
    assert.equal(find(root, "password").value, "typed");
    assert.equal(find(root, "error").hidden, false);
    assert.ok(textOf(find(root, "error")).includes("generator.error.options"));
  });
});

test("a_lock_while_the_core_is_working_leaves_the_form_empty_when_the_reply_comes", async () => {
  await withDom(async () => {
    const client = generatingClient();
    const scope = createWipeScope();
    const { root } = await form({ client, scope });
    client.hold();
    const pending = click(find(root, "password-generate")); // the click is done when the core has answered
    await settle();
    scope.run();
    client.release(0);
    await pending;
    await settle();
    assert.equal(find(root, "password"), null, "the form was wiped and emptied from the screen");
  });
  await withDom(async () => {
    const client = generatingClient();
    const { root } = await form({ client });
    client.hold();
    const first = click(find(root, "password-generate"));
    const second = click(find(root, "password-generate"));
    await settle();
    client.release(1);
    await settle();
    client.release(0);
    await Promise.all([first, second]);
    await settle();
    assert.equal(find(root, "password").value, "GEN-2", "an older reply does not replace the newer one");
  });
});

test("generate_does_nothing_when_the_vault_has_locked_or_the_form_is_read_only", async () => {
  await withDom(async () => {
    const client = generatingClient();
    const { root } = await form({ client, touch: () => false });
    await click(find(root, "password-generate"));
    await settle();
    assert.deepEqual(client.calls, []);
    assert.equal(find(root, "password").value, "");
  });
});

test("a_form_with_a_password_from_the_generator_counts_as_having_edits_and_a_wipe_empties_it", async () => {
  await withDom(async () => {
    const scope = createWipeScope();
    const { root } = await form({ initialPassword: "GEN-5", scope });
    assert.equal(find(root, "password").value, "GEN-5");
    scope.run();
    assert.equal(find(root, "password"), null);
  });
  await withDom(async () => {
    // An edit never takes a password from the generator page: its password input starts empty.
    const { root } = await form({ id: ENTRY.id, initialPassword: "GEN-5" });
    assert.equal(find(root, "password").value, "");
  });
});

test("the_button_is_disabled_with_the_rest_of_a_form_that_is_frozen", async () => {
  await withDom(async () => {
    let frozen = null;
    const tracker = { trackUnsaved: (f) => ((frozen = f), () => {}) };
    const engine = fakeEngine({ items: [ENTRY], views: {} });
    const client = generatingClient();
    const root = await editView({ engine, client, id: null, t, tracker, generatorStore: createOptionsStore(memory()) });
    frozen.freeze();
    assert.equal(find(root, "password-generate").disabled, true);
    await fire(find(root, "password-generate"), "click");
    await settle();
    assert.deepEqual(client.calls, []);
  });
});
