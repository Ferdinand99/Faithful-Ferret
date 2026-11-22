// "Accept the older state" in the popup (design document, section 8.6,
// "Legitimate rollbacks"): a stop because the server was restored offers it
// first; the panel shows what accepting would do (counts only) before anything
// is done, and accepts only after the user typed the word, as the web vault
// does. The background is the real one with the sync wired in; the engine is a
// fake that counts what is asked of it; the panel runs on a small stand-in for
// the DOM, with the texts of the built package.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { byRole, click, one, submit, textsOf, useDocument } from "./pageDom.mjs";
import { fakeEngines, pkg } from "./sessionHelpers.mjs";
import { syncWorld } from "./syncWorld.mjs";

/** The texts of the built package in `lang`. @param {string} lang */
async function texts(lang) {
  const { dir } = await pkg();
  return textsOf(JSON.parse(await readFile(join(dir, `locales.${lang}.json`), "utf8")), lang);
}

/**
 * A device whose sync stopped because the server was restored, with the popup's flows and a panel builder.
 * @param {Parameters<typeof fakeEngines>[0]} behaviour
 */
async function restoredWorld(behaviour) {
  const engines = fakeEngines(behaviour);
  const sync = await syncWorld({ engines });
  await sync.signIn();
  const [engine] = engines.made;
  engine.halt("server_restored");
  const { load } = await pkg();
  const [{ createOlderPanel }, flowModule] = await Promise.all([load("pages/olderState.mjs"), load("pages/popupFlow.mjs")]);
  const request = sync.world.page("pages/popup.html").request;
  /** @param {string} lang */
  const panel = async (lang = "en") => {
    useDocument();
    let closed = 0;
    const made = createOlderPanel({ texts: await texts(lang), flow: flowModule.createOlderFlow(request), onClose: () => (closed += 1) });
    await made.loaded;
    return { root: made.root, closed: () => closed };
  };
  return { ...sync, engine, panel, request, flowModule };
}

test("accept_older_state_needs_the_typed_confirmation_and_shows_the_counts", async () => {
  const { engine, popup, panel, request, flowModule } = await restoredWorld({
    preview: () => ({ reupload: 3, conflicts: 2, manifestOlder: false }),
    accept: () => ({ reuploaded: 3, conflicts: 2, manifestOlder: false }),
  });
  const en = await texts("en");

  // The stop offers accepting the older state first, then "Try again" and "Forget this server".
  const view = await popup.load();
  assert.equal(view.sync?.halted, "server_restored");
  assert.deepEqual(view.sync?.actions, ["accept_older", "try_again", "forget"]);

  // The panel reads the preview at once and shows its counts, with the note that conflicts can be many.
  const { root, closed } = await panel();
  assert.equal(engine.previews, 1);
  assert.equal(one(root, "older-preview")?.hidden, false);
  assert.equal(one(root, "older-reupload")?.textContent, en.t("sync.older.preview_reupload", { count: 3 }));
  assert.equal(one(root, "older-conflicts")?.textContent, en.t("sync.older.preview_conflicts", { count: 2 }));
  assert.equal(one(root, "older-conflicts-note")?.textContent, en.t("sync.older.conflicts_note"));
  assert.equal(one(root, "older-manifest"), null, "the unlock methods did not go back");
  // The web vault's words.
  const web = JSON.parse(await readFile(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "web", "src", "locales", "en", "syncwarnings.json"), "utf8"));
  assert.equal(en.t("sync.older.preview_reupload"), web["syncwarnings.restored.preview_reupload"]);
  assert.equal(en.t("sync.older.word"), web["syncwarnings.restored.word"]);

  // No word, then a wrong one: nothing is accepted, and the background is not even asked.
  const input = /** @type {any} */ (one(root, "older-word"));
  const form = one(root, "older-form");
  const accept = one(root, "older-accept");
  assert.equal(accept?.hasAttribute("disabled"), false, "the accept is there once the counts are");
  for (const typed of ["", "   ", "yes", "accep", "godta"]) {
    input.value = typed;
    await submit(form);
    assert.equal(engine.accepts, 0, JSON.stringify(typed));
    assert.equal(one(root, "older-error")?.hidden, false, JSON.stringify(typed));
    assert.equal(one(root, "older-error")?.textContent, en.t("sync.older.error.word_wrong"));
    assert.equal(input.value, "", "the field is emptied for another try");
  }
  // The background refuses an accept that does not say it was confirmed.
  assert.deepEqual(await request("sync_accept_older", { confirmed: false }), { ok: false, reason: "not_confirmed" });
  assert.equal(engine.accepts, 0);

  // The word (case and spaces do not matter): accepted once, and the counts of what was done are shown.
  input.value = "  Accept ";
  await submit(form);
  assert.equal(engine.accepts, 1);
  assert.equal(one(root, "older-form"), null, "the form is gone");
  assert.equal(one(root, "older-done")?.textContent, en.t("sync.older.done", { reuploaded: 3, conflicts: 2 }));
  assert.equal(one(root, "older-done-conflicts")?.textContent, en.t("sync.older.done_conflicts", { count: 2 }));
  assert.equal(closed(), 0);
  await click(one(root, "older-close"));
  assert.equal(closed(), 1, "done goes back to the popup");

  // The flow alone: a wrong word never reaches the background.
  const flow = flowModule.createOlderFlow(async () => assert.fail("the background was asked"));
  assert.deepEqual(await flow.accept("nope", "accept"), { ok: false, reason: "word_wrong" });
  assert.deepEqual(await flow.accept("", ""), { ok: false, reason: "word_wrong" });
});

test("accept_older_state_asks_for_the_word_of_the_page_language", async () => {
  const { engine, panel } = await restoredWorld({
    preview: () => ({ reupload: 0, conflicts: 0, manifestOlder: true }),
    accept: () => ({ reuploaded: 0, conflicts: 0, manifestOlder: true }),
  });
  const nb = await texts("nb");
  const { root } = await panel("nb");
  // The unlock methods went back with the server: the panel says so before and after.
  assert.equal(one(root, "older-manifest")?.textContent, nb.t("sync.older.manifest_older"));
  assert.equal(one(root, "older-conflicts-note"), null, "no conflicts, no note about them");
  const input = /** @type {any} */ (one(root, "older-word"));
  input.value = "accept";
  await submit(one(root, "older-form"));
  assert.equal(engine.accepts, 0, "the English word is not the Norwegian page's word");
  input.value = "Godta";
  await submit(one(root, "older-form"));
  assert.equal(engine.accepts, 1);
  assert.equal(byRole(root, "older-manifest").length, 1);
});

test("an_older_state_that_does_not_check_out_is_not_offered_to_accept", async () => {
  const { engine, panel, request } = await restoredWorld({
    preview: () => {
      throw Object.assign(new Error("no"), { code: "restore_not_verified", reason: "no_checkpoint" });
    },
  });
  const en = await texts("en");
  const { root } = await panel();
  assert.equal(one(root, "older-form"), null, "nothing to type a word into");
  assert.equal(one(root, "older-error")?.textContent, en.t("sync.older.error.not_verified_no_checkpoint"));
  assert.equal(one(root, "older-back")?.hidden, false, "the way back stays");
  assert.deepEqual(await request("sync_older_preview", {}), { ok: false, reason: "not_verified_no_checkpoint" });
  assert.equal(engine.accepts, 0);
});

test("a_preview_that_failed_can_be_read_again_and_a_busy_engine_says_so", async () => {
  let fail = true;
  const { engine, panel } = await restoredWorld({
    preview: () => {
      if (fail) throw Object.assign(new Error("busy"), { code: "busy" });
      return { reupload: 1, conflicts: 0, manifestOlder: false };
    },
  });
  const en = await texts("en");
  const { root } = await panel();
  assert.equal(one(root, "older-error")?.textContent, en.t("sync.older.error.busy"));
  assert.equal(one(root, "older-accept")?.hasAttribute("disabled"), true, "nothing to accept before the counts");
  assert.equal(one(root, "older-retry")?.hidden, false);
  fail = false;
  await click(one(root, "older-retry"));
  assert.equal(engine.previews, 2);
  assert.equal(one(root, "older-reupload")?.textContent, en.t("sync.older.preview_reupload", { count: 1 }));
  assert.equal(one(root, "older-accept")?.hasAttribute("disabled"), false);
});
