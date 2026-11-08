// The page for a restored server: the preview comes first, the older state is accepted
// only after the typed word, and only once.
import assert from "node:assert/strict";
import { test } from "node:test";
import { restoredView } from "../../src/views/restored.mjs";
import { click, find, settle, submit, textOf, withDom } from "./vaultHelpers.mjs";
import { EN, NB, fakeWarningsEngine, textFor, translator } from "./syncWarningsHelpers.mjs";

/** The page for an engine that is stopped because the server was restored. */
async function page(options = {}, lang = "en") {
  const engine = fakeWarningsEngine({ halted: "server_restored", ...options.start });
  Object.assign(engine, options.engine);
  const went = [];
  const root = restoredView({ engine, t: translator(lang), router: { go: (path) => went.push(path) } });
  await settle();
  return { engine, root, went };
}

const type = (root, text) => {
  find(root, "restored-word").value = text;
};

test("restored_view_shows_the_preview_counts", async () => {
  await withDom(async () => {
    for (const [lang, catalog] of [["en", EN], ["nb", NB]]) {
      const { engine, root } = await page({ engine: { previewResult: { reupload: 3, conflicts: 2 } } }, lang);
      assert.deepEqual(engine.calls, ["restorePreview"], "the preview is asked for once, before anything is accepted");
      assert.equal(textOf(find(root, "preview-reupload")).trim(), textFor(catalog, "syncwarnings.restored.preview_reupload", { count: 3 }));
      assert.equal(textOf(find(root, "preview-conflicts")).trim(), textFor(catalog, "syncwarnings.restored.preview_conflicts", { count: 2 }));
      assert.equal(find(root, "restored-preview").hidden, false);
      // The page says what is certain, and what accepting does, before it asks.
      const text = textOf(root);
      assert.ok(text.includes(catalog["syncwarnings.restored.intro_safe"]));
      assert.ok(text.includes(catalog["syncwarnings.restored.intro_choice"]));
      assert.ok(text.includes(catalog["syncwarnings.restored.intro_warn"]));
      assert.ok(!engine.calls.includes("acceptOlderState"));
    }
    // Counts of zero are shown as zero.
    const { root } = await page({ engine: { previewResult: { reupload: 0, conflicts: 0 } } });
    assert.match(textOf(find(root, "preview-reupload")), /: 0/);
  });
});

test("accept_older_state_needs_the_typed_word_and_calls_the_engine_once", async () => {
  await withDom(async () => {
    for (const [lang, word] of [["en", "accept"], ["nb", "godta"]]) {
      const { engine, root } = await page({}, lang);
      const form = find(root, "restored-form");
      assert.equal(find(root, "restored-word").getAttribute("aria-describedby"), "restored-word-help");
      // The label names the word to type.
      assert.match(textOf(root), new RegExp(`${word}`));
      // Nothing typed, or the wrong word: the engine is not called, and the page says so.
      await submit(form);
      type(root, "yes");
      await submit(form);
      type(root, `${word}x`);
      await submit(form);
      assert.ok(!engine.calls.includes("acceptOlderState"), `${lang}: no call without the word`);
      assert.equal(find(root, "restored-error").hidden, false);
      assert.match(textOf(find(root, "restored-error")), lang === "en" ? /not the word/ : /ikke ordet/);
      // The word, in any case and with spaces around, is accepted; a double press calls the engine once.
      let release;
      engine.gate = new Promise((resolve) => (release = resolve));
      type(root, `  ${word.toUpperCase()} `);
      const first = submit(form);
      await settle(2);
      assert.equal(find(root, "restored-accept").disabled, true, "disabled while it runs");
      await submit(form);
      release();
      await first;
      await settle();
      assert.deepEqual(engine.calls.filter((call) => call === "acceptOlderState"), ["acceptOlderState"], `${lang}: once`);
      const done = find(root, "restored-done");
      assert.ok(done, "the result is shown");
      assert.equal(textOf(done).trim(), textFor(lang === "en" ? EN : NB, "syncwarnings.restored.done", { reuploaded: 2, conflicts: 1 }));
      assert.ok(find(root, "restored-conflicts"), "a conflict is pointed out");
      assert.equal(find(root, "restored-word"), null, "the form is gone");
    }
  });
});

test("accept_older_state_that_fails_says_so_stays_stopped_and_can_be_tried_again", async () => {
  await withDom(async () => {
    const { engine, root } = await page({ engine: { acceptError: Object.assign(new Error("secret detail"), { code: "checkpoint_forged" }) } });
    type(root, "accept");
    await submit(find(root, "restored-form"));
    await settle();
    assert.match(textOf(find(root, "restored-error")), /could not be accepted/);
    assert.doesNotMatch(textOf(root), /secret detail|checkpoint_forged/);
    assert.equal(find(root, "restored-accept").disabled, false);
    assert.equal(find(root, "restored-word").value, "", "the word must be typed again");
    engine.acceptError = null;
    type(root, "accept");
    await submit(find(root, "restored-form"));
    await settle();
    assert.ok(find(root, "restored-done"));
    assert.equal(engine.calls.filter((call) => call === "acceptOlderState").length, 2);
  });
});

test("the_page_cannot_accept_before_the_preview_is_there_and_the_preview_can_be_read_again", async () => {
  await withDom(async () => {
    const { engine, root } = await page({ engine: { previewError: new Error("no") } });
    assert.equal(find(root, "restored-accept").disabled, true);
    assert.equal(find(root, "restored-preview").hidden, true);
    assert.match(textOf(find(root, "restored-error")), /cannot be shown yet/);
    type(root, "accept");
    await submit(find(root, "restored-form"));
    assert.ok(!engine.calls.includes("acceptOlderState"), "no accepting without seeing the effect");
    engine.previewError = null;
    await click(find(root, "preview-retry"));
    await settle();
    assert.equal(find(root, "restored-accept").disabled, false);
    assert.equal(find(root, "restored-error").hidden, true);
    assert.equal(find(root, "restored-preview").hidden, false);
  });
});

test("the_page_has_nothing_to_decide_unless_the_engine_stopped_for_a_restored_server", async () => {
  await withDom(async () => {
    for (const start of [{ halted: null }, { halted: "rollback_suspected" }]) {
      const { engine, root, went } = await page({ start });
      assert.ok(find(root, "restored-na"));
      assert.equal(find(root, "restored-form"), null);
      assert.deepEqual(engine.calls, [], "no preview, nothing to accept");
      await click(find(root, "restored-back"));
      assert.deepEqual(went, ["/items"]);
    }
  });
});

test("the_page_offers_to_forget_the_server_instead_and_shows_no_item_names", async () => {
  await withDom(async () => {
    const { root, went } = await page();
    await click(find(root, "restored-forget"));
    assert.deepEqual(went, ["/forget"]);
    await click(find(root, "restored-back"));
    assert.deepEqual(went, ["/forget", "/items"]);
    // Counts only: the preview gives no names and the page reads none.
    assert.doesNotMatch(textOf(root), /undefined|\[object/);
  });
});
