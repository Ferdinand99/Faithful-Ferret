// The page for a restored server: the preview comes first, the older state is accepted
// only after the typed word, and only once.
import assert from "node:assert/strict";
import { test } from "node:test";
import { restoredView } from "../../src/views/restored.mjs";
import { click, find, settle, submit, textOf, withDom } from "./vaultHelpers.mjs";
import { EN, NB, fakeWarningsEngine, textFor, translator, withFocus } from "./syncWarningsHelpers.mjs";

/** The page for an engine that is stopped because the server was restored. */
async function page(options = {}, lang = "en") {
  const engine = fakeWarningsEngine({ halted: "server_restored", ...options.start });
  Object.assign(engine, options.engine);
  const went = [];
  const reloads = [];
  const root = restoredView({ engine, t: translator(lang), router: { go: (path) => went.push(path) }, reload: () => reloads.push(1) });
  await settle();
  return { engine, root, went, reloads };
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

const problem = (code, reason = null) => Object.assign(new Error("a detail that must not be shown"), { code, ...(reason ? { reason } : {}) });

test("restore_not_verified_says_the_older_state_does_not_check_out_and_does_not_invite_a_retry", async () => {
  await withDom(() => withFocus(async () => {
    for (const [lang, catalog] of [["en", EN], ["nb", NB]]) {
      for (const phase of ["accept", "preview"]) {
        for (const reason of ["no_checkpoint", "checkpoint_bad_mac"]) {
          const engine = phase === "preview" ? { previewError: problem("restore_not_verified", reason) } : { acceptError: problem("restore_not_verified", reason) };
          const { engine: e, root, went } = await page({ engine }, lang);
          if (phase === "accept") {
            type(root, catalog["syncwarnings.restored.word"]);
            await submit(find(root, "restored-form"));
            await settle();
          }
          const text = textOf(find(root, "restored-error"));
          assert.ok(text.includes(catalog["syncwarnings.restored.not_verified"]), `${lang} ${phase} ${reason}`);
          // The reason has a sentence of its own only when the page knows it; a code is never shown.
          assert.equal(text.includes(catalog["syncwarnings.restored.not_verified_no_checkpoint"]), reason === "no_checkpoint");
          assert.doesNotMatch(textOf(root), /checkpoint_bad_mac|a detail that must not be shown/);
          // Nothing to press again: no form, no retry, no accept. The way on is to leave it stopped or to forget the server.
          assert.equal(find(root, "restored-form"), null);
          assert.equal(find(root, "preview-retry"), null);
          assert.equal(find(root, "restored-accept"), null);
          const exit = find(find(root, "restored-exits"), "restored-forget");
          assert.ok(exit);
          assert.equal(globalThis.document.activeElement, exit, "the focus goes to the way out");
          await click(exit);
          assert.deepEqual(went, ["/forget"]);
          assert.equal(e.calls.filter((call) => call === "acceptOlderState").length, phase === "accept" ? 1 : 0, "asked once, not again");
        }
      }
    }
  }));
});

test("invalid_state_offers_to_let_sync_try_again_or_to_reload", async () => {
  await withDom(() => withFocus(async () => {
    for (const [lang, catalog] of [["en", EN], ["nb", NB]]) {
      const { engine, root, reloads } = await page({ engine: { acceptError: problem("invalid_state") } }, lang);
      type(root, catalog["syncwarnings.restored.word"]);
      await submit(find(root, "restored-form"));
      await settle();
      assert.ok(textOf(find(root, "restored-error")).includes(catalog["syncwarnings.restored.invalid_state"]));
      assert.equal(find(root, "restored-form"), null);
      assert.equal(globalThis.document.activeElement, find(root, "restored-resume"));
      assert.equal(textOf(find(root, "restored-resume")).trim(), catalog["syncwarnings.restored.resume"]);
      assert.equal(textOf(find(root, "restored-reload")).trim(), catalog["syncwarnings.restored.reload"]);
      // Reload reloads the page.
      await click(find(root, "restored-reload"));
      assert.equal(reloads.length, 1);
      // Let sync try again: the cause is still there, so it says so and keeps the button and the focus.
      engine.stillStopped = true;
      engine.halted = "server_restored";
      await click(find(root, "restored-resume"));
      await settle();
      assert.deepEqual(engine.calls.filter((call) => call === "resumeAfterHalt"), ["resumeAfterHalt"]);
      assert.ok(textOf(find(root, "restored-error")).includes(catalog["syncwarnings.restored.resume_still"]));
      assert.equal(globalThis.document.activeElement, find(root, "restored-resume"));
      // And when the cause is gone, the page says sync runs again.
      engine.stillStopped = false;
      engine.halted = "server_restored";
      await click(find(root, "restored-resume"));
      await settle();
      assert.equal(textOf(find(root, "restored-resumed")).trim(), catalog["syncwarnings.restored.resumed"]);
    }
  }));
});

test("busy_says_to_wait_and_keeps_the_form_with_the_focus_in_the_field", async () => {
  await withDom(() => withFocus(async () => {
    for (const [lang, catalog, wait] of [["en", EN, /Wait a moment/], ["nb", NB, /Vent litt/]]) {
      const { engine, root } = await page({ engine: { acceptError: problem("busy") } }, lang);
      type(root, catalog["syncwarnings.restored.word"]);
      await submit(find(root, "restored-form"));
      await settle();
      assert.match(textOf(find(root, "restored-error")), wait);
      assert.ok(find(root, "restored-form"), "the form stays");
      assert.equal(find(root, "restored-accept").disabled, false);
      assert.equal(globalThis.document.activeElement, find(root, "restored-word"), "the focus is back in the field");
      // Wait, then it works.
      engine.acceptError = null;
      type(root, catalog["syncwarnings.restored.word"]);
      await submit(find(root, "restored-form"));
      await settle();
      assert.ok(find(root, "restored-done"));
    }
    // A preview that is busy keeps the retry, with the focus on it.
    const { root } = await page({ engine: { previewError: problem("busy") } });
    assert.match(textOf(find(root, "restored-error")), /Wait a moment/);
    assert.equal(globalThis.document.activeElement, find(root, "preview-retry"));
  }));
});

test("a_failed_accept_without_a_name_gives_the_focus_back_to_the_field", async () => {
  await withDom(() => withFocus(async () => {
    const { root } = await page({ engine: { acceptError: problem("something_else") } });
    type(root, "accept");
    find(root, "restored-word").focus();
    await submit(find(root, "restored-form"));
    await settle();
    assert.match(textOf(find(root, "restored-error")), /could not be accepted/);
    assert.equal(globalThis.document.activeElement, find(root, "restored-word"));
    // A locked vault is its own message and has no form to go back to.
    const stopped = await page({ engine: { acceptError: problem("stopped") } });
    type(stopped.root, "accept");
    await submit(find(stopped.root, "restored-form"));
    await settle();
    assert.match(textOf(find(stopped.root, "restored-error")), /vault was locked/);
    assert.equal(find(stopped.root, "restored-form"), null);
  }));
});

test("an_older_manifest_is_said_in_the_preview_and_in_the_result_and_conflicts_have_their_own_line", async () => {
  await withDom(async () => {
    for (const [lang, catalog] of [["en", EN], ["nb", NB]]) {
      const { engine, root } = await page({ engine: { previewResult: { reupload: 1, conflicts: 7, manifestOlder: true }, acceptResult: { reuploaded: 1, conflicts: 7, manifestOlder: true } } }, lang);
      assert.ok(textOf(find(root, "restored-manifest-older")).includes(catalog["syncwarnings.restored.manifest_older"]));
      assert.ok(textOf(find(root, "restored-conflicts-note")).includes(catalog["syncwarnings.restored.conflicts_note"]), "every existing item comes back as a conflict, and the preview says so");
      // Unreadable items are counted from the engine's events, by number, never by name.
      type(root, catalog["syncwarnings.restored.word"]);
      let release;
      engine.gate = new Promise((resolve) => (release = resolve));
      const accepting = submit(find(root, "restored-form"));
      await settle(2);
      engine.emit("error", { code: "restore_item_unreadable", id: "ab".repeat(16), name: "Secret bank item" });
      engine.emit("error", { code: "restore_item_unreadable", id: "cd".repeat(16) });
      engine.emit("error", { code: "restore_item_unreadable", id: "cd".repeat(16) });
      release();
      await accepting;
      await settle();
      assert.equal(textOf(find(root, "restored-conflicts")).trim(), textFor(catalog, "syncwarnings.restored.done_conflicts", { count: 7 }), "the count is stated, with the way to the conflicts");
      assert.equal(textOf(find(root, "restored-unreadable")).trim(), textFor(catalog, "syncwarnings.restored.unreadable", { count: 2 }));
      assert.ok(find(root, "restored-manifest-older"), "the result says it too");
      assert.doesNotMatch(textOf(root), /Secret bank item|abab|cdcd/);
      assert.equal(engine.listening, 0, "the page stops listening when it is done");
    }
    // Nothing older, no conflicts, nothing unreadable: none of the lines.
    const { root } = await page({ engine: { previewResult: { reupload: 1, conflicts: 0 }, acceptResult: { reuploaded: 1, conflicts: 0 } } });
    assert.equal(find(root, "restored-manifest-older"), null);
    assert.equal(find(root, "restored-conflicts-note"), null);
    type(root, "accept");
    await submit(find(root, "restored-form"));
    await settle();
    assert.equal(find(root, "restored-conflicts"), null);
    assert.equal(find(root, "restored-unreadable"), null);
  });
});

test("a_lying_listing_in_the_preview_or_the_accept_says_bad_feed_and_can_be_tried_again", async () => {
  await withDom(() => withFocus(async () => {
    const { engine, root } = await page({ engine: { previewError: problem("bad_feed") } });
    assert.ok(textOf(find(root, "restored-error")).includes(EN["syncwarnings.banner.bad_feed"]));
    assert.ok(find(root, "preview-retry"), "a bad feed may be gone the next time");
    engine.previewError = null;
    await click(find(root, "preview-retry"));
    await settle();
    assert.equal(find(root, "restored-accept").disabled, false);
    engine.acceptError = problem("bad_feed");
    type(root, "accept");
    await submit(find(root, "restored-form"));
    await settle();
    assert.ok(textOf(find(root, "restored-error")).includes(EN["syncwarnings.banner.bad_feed"]));
    assert.ok(find(root, "restored-form"), "the form stays, and the word has to be typed again");
    assert.equal(globalThis.document.activeElement, find(root, "restored-word"));
  }));
});

test("the_conflict_text_prepares_a_device_that_was_behind_for_many_conflicts", async () => {
  for (const [lang, catalog, behind] of [["en", EN, /was behind can have many/], ["nb", NB, /lå etter kan få mange/]]) {
    assert.match(catalog["syncwarnings.restored.conflicts_note"], behind, `${lang}: the preview says it`);
    assert.match(catalog["syncwarnings.restored.done_conflicts"], lang === "en" ? /can be many, also for items that nobody changed/ : /Det kan være mange, også for elementer ingen endret/, `${lang}: the result says it`);
  }
});
