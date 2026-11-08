// The restored page when the server's unlock methods went back with it (`manifestOlder`): the preview and the
// result say what that means, a restore without it says nothing about unlock methods, and a successful accept
// hands the result on once so that a note can be kept.
import assert from "node:assert/strict";
import { test } from "node:test";
import restoredRoute from "../../src/routes/restored.route.mjs";
import { loadRestoreNote } from "../../src/store/restoreNote.mjs";
import { restoredView } from "../../src/views/restored.mjs";
import { SERVER, freshStore } from "./idbHelpers.mjs";
import { autoLockFor } from "../../src/lock.mjs";
import { fakeClient, fakeEngine, fakeSession, find, settle, submit, textOf, withDom } from "./vaultHelpers.mjs";
import { loadSyncState, saveSyncState } from "../../src/store/syncState.mjs";
import { loadPinned } from "../../src/store/pinned.mjs";
import { deleteRestoreNote, saveRestoreNote } from "../../src/store/restoreNote.mjs";
import { EN, NB, fakeWarningsEngine, translator } from "./syncWarningsHelpers.mjs";

const KEY = "syncwarnings.restored.manifest_older";

async function page({ preview = {}, accept = {}, engine: more = {}, onAccepted } = {}, lang = "en") {
  const engine = fakeWarningsEngine({ halted: "server_restored" });
  engine.previewResult = { reupload: 2, conflicts: 1, ...preview };
  engine.acceptResult = { reuploaded: 2, conflicts: 1, ...accept };
  Object.assign(engine, more);
  const root = restoredView({ engine, t: translator(lang), router: { go() {} }, onAccepted });
  await settle();
  return { engine, root };
}

const acceptNow = async (root, word = "accept") => {
  find(root, "restored-word").value = word;
  await submit(find(root, "restored-form"));
  await settle();
};

test("preview_and_result_explain_an_older_manifest_and_say_the_old_password_works_again", async () => {
  await withDom(async () => {
    for (const [lang, catalog, word] of [["en", EN, "accept"], ["nb", NB, "godta"]]) {
      const { root } = await page({ preview: { manifestOlder: true }, accept: { manifestOlder: true } }, lang);
      // Before anything is confirmed: the box is on the page, and the form is below it.
      const box = find(root, "restored-manifest-older");
      assert.ok(box, `${lang}: the box is in the preview`);
      assert.equal(textOf(box).trim(), catalog[KEY]);
      assert.ok(textOf(root).indexOf(catalog[KEY]) < textOf(root).indexOf(catalog["syncwarnings.restored.accept"]), `${lang}: the box comes before the confirmation`);
      assert.equal(find(root, "restored-done"), null);
      await acceptNow(root, word);
      // In the result as well.
      assert.ok(find(root, "restored-done"), `${lang}: accepted`);
      assert.equal(textOf(find(root, "restored-manifest-older")).trim(), catalog[KEY]);
    }
    // The wording the design asks for, both languages.
    assert.equal(
      EN[KEY],
      "The server was restored from before you last changed your unlock methods. Methods you added after the backup are gone, methods you removed are back, and the old password works again on the server. This device will refuse the older password at the next unlock.",
    );
    assert.equal(
      NB[KEY],
      "Tjeneren er gjenopprettet fra før du sist endret opplåsingsmåter. Måter du la til etter backupen er borte, måter du fjernet er tilbake, og det gamle passordet virker igjen på tjeneren. Denne enheten vil nekte det eldre passordet ved neste opplåsing.",
    );
  });
});

test("without_manifest_older_no_unlock_method_text_is_shown", async () => {
  await withDom(async () => {
    for (const [lang, catalog, word] of [["en", EN, "accept"], ["nb", NB, "godta"]]) {
      for (const flag of [{}, { manifestOlder: false }]) {
        const { root } = await page({ preview: flag, accept: flag }, lang);
        assert.equal(find(root, "restored-manifest-older"), null, `${lang}: nothing in the preview`);
        assert.ok(!textOf(root).includes(catalog[KEY]));
        await acceptNow(root, word);
        assert.ok(find(root, "restored-done"));
        assert.equal(find(root, "restored-manifest-older"), null, `${lang}: nothing in the result`);
        assert.ok(!textOf(root).includes(catalog[KEY]));
      }
    }
  });
});

test("a_successful_accept_with_manifest_older_hands_the_result_on_once_for_the_note", async () => {
  await withDom(async () => {
    const seen = [];
    const { root, engine } = await page({ preview: { manifestOlder: true }, accept: { manifestOlder: true }, onAccepted: (result) => seen.push(result) });
    assert.deepEqual(seen, [], "nothing is kept before the user accepts");
    // The wrong word accepts nothing, and keeps nothing.
    await acceptNow(root, "no");
    assert.deepEqual(seen, []);
    await acceptNow(root);
    assert.deepEqual(seen, [{ reuploaded: 2, conflicts: 1, manifestOlder: true }]);
    assert.equal(engine.calls.filter((call) => call === "acceptOlderState").length, 1);
  });
});

test("a_failed_accept_keeps_no_note_and_a_note_that_fails_changes_nothing_on_the_page", async () => {
  await withDom(async () => {
    const seen = [];
    const failing = await page({
      preview: { manifestOlder: true },
      engine: { acceptError: Object.assign(new Error("x"), { code: "restore_not_verified" }) },
      onAccepted: (result) => seen.push(result),
    });
    await acceptNow(failing.root);
    assert.deepEqual(seen, [], "a refused accept leaves no note");

    for (const throwing of [() => { throw new Error("disk"); }, async () => { throw new Error("disk"); }]) {
      const { root } = await page({ preview: { manifestOlder: true }, accept: { manifestOlder: true }, onAccepted: throwing });
      await acceptNow(root);
      assert.ok(find(root, "restored-done"), "the result is shown although the note could not be kept");
      assert.ok(find(root, "restored-manifest-older"));
      assert.equal(find(root, "restored-error"), null, "no error is shown");
    }
  });
});

/** The restored route over fakes: an open vault whose engine is stopped for a restored server, and a real store. */
async function routeRig({ info } = {}) {
  const db = await freshStore();
  const engine = fakeEngine();
  Object.assign(engine, {
    health: () => ({ halted: "server_restored", warnings: [] }),
    restorePreview: async () => ({ reupload: 0, conflicts: 0, manifestOlder: true }),
    acceptOlderState: async () => ({ reuploaded: 0, conflicts: 0, manifestOlder: true }),
  });
  const client = fakeClient(engine);
  const session = fakeSession({ client, ...(info === undefined ? {} : { info }) });
  session.serverUrl = SERVER;
  const sync = { current: () => engine, start: async () => engine, stop() {}, discard() {}, discardMissing() {} };
  const store = {
    open: async () => db.store,
    loadSyncState,
    pinHintForEmail: loadPinned,
    restoreNote: { save: saveRestoreNote, load: loadRestoreNote, delete: deleteRestoreNote },
  };
  const ctx = {
    params: {}, path: "/restored", i18n: { t: translator("en"), lang: "en", missing: [] }, client, go() {},
    services: { crypto: session, sync, store },
  };
  return { db, ctx, session, sync, done: () => autoLockFor(session, sync).stop() };
}

test("the_restored_route_keeps_the_note_for_the_open_account_after_an_accept", async () => {
  await withDom(async () => {
    const r = await routeRig();
    try {
      await saveSyncState(r.db.store, SERVER, "aa".repeat(16), { memory: new Uint8Array(8), restoreEpoch: 5, verifiedAt: 1, verifiedSeq: 1, uploadedAt: 1, uploadedSeq: 1, hardWarning: null, restore: null });
      const node = await restoredRoute.load(r.ctx);
      await settle();
      await acceptNow(node);
      assert.ok(find(node, "restored-done"));
      await settle();
      const kept = await loadRestoreNote(r.db.store, SERVER, "aa".repeat(16), Date.now());
      assert.equal(kept?.manifestOlder, true);
      assert.equal(kept?.restoreEpoch, 5);
    } finally {
      r.done();
    }
  });
});

test("the_restored_route_says_so_on_the_page_when_no_account_id_is_there_and_the_accept_still_works", async () => {
  await withDom(async () => {
    const r = await routeRig({ info: { accountId: undefined, email: "ada@example.test" } });
    try {
      const node = await restoredRoute.load(r.ctx);
      await settle();
      assert.equal(find(node, "restored-note-not-kept"), null, "nothing before the accept");
      await acceptNow(node);
      await settle();
      assert.ok(find(node, "restored-done"), "the accept itself is not stopped");
      assert.equal(textOf(find(node, "restored-note-not-kept")).trim(), EN["syncwarnings.restored.note_not_kept"]);
    } finally {
      r.done();
    }
  });
});

test("the_page_says_the_note_was_not_kept_only_when_the_hook_says_so_in_both_languages", async () => {
  await withDom(async () => {
    for (const [lang, catalog] of [["en", EN], ["nb", NB]]) {
      const word = lang === "en" ? "accept" : "godta";
      const missed = await page({ preview: { manifestOlder: true }, accept: { manifestOlder: true }, onAccepted: () => "not_kept" }, lang);
      await acceptNow(missed.root, word);
      await settle();
      assert.equal(textOf(find(missed.root, "restored-note-not-kept")).trim(), catalog["syncwarnings.restored.note_not_kept"]);
      for (const answer of ["kept", "none", undefined]) {
        const fine = await page({ preview: { manifestOlder: true }, accept: { manifestOlder: true }, onAccepted: () => answer }, lang);
        await acceptNow(fine.root, word);
        await settle();
        assert.equal(find(fine.root, "restored-note-not-kept"), null, String(answer));
      }
    }
  });
});
