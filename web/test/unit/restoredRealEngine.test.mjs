// The restored-server page and the warning banner driven by the REAL sync engine (over the fake server, the fake core and the
// real stores of the engine tests), not by a stand-in: the preview and the accept of a restored server, and "Try again" after a
// stop. What the stand-in engine cannot show is how the real one orders its events: `resumeAfterHalt` clears the stop and says
// `syncing` at once, and halts again if the cause is still there.
import assert from "node:assert/strict";
import { test } from "node:test";
import { restoredView } from "../../src/views/restored.mjs";
import { syncBanner } from "../../src/views/syncBanner.mjs";
import { accountDocument } from "./accountHelpers.mjs";
import { all, click, find, submit, textOf } from "./vaultHelpers.mjs";
import { EN, textFor, translator, withFocus } from "./syncWarningsHelpers.mjs";
import { createFakeClient, Model, syncDevice, until } from "./syncHelpers.mjs";

const ID_A = "11".repeat(16);
const ID_B = "22".repeat(16);
const ID_C = "33".repeat(16);
const ID_D = "44".repeat(16);

const setRow = (model, client, id, rev, name, extra = {}) => model.set(id, { rev, ...client.wireRow(id, rev, { item_type: "login", name }), ...extra });
const setTomb = (model, client, id, rev, extra = {}) => model.set(id, { rev, deleted: true, tomb: client.wireTomb(id, rev), ...extra });

/** Runs a test body with a fake document whose elements start with the properties a real one has, and a focus. */
const withDom = (body) => {
  const saved = globalThis.document;
  globalThis.document = accountDocument();
  return withFocus(body).finally(() => {
    if (saved === undefined) delete globalThis.document;
    else globalThis.document = saved;
  });
};

/** A device whose server was restored from a backup: it has stopped with `server_restored` (the world of the engine tests). */
async function restoredWorld() {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 3, "A");
  setRow(model, client, ID_B, 3, "B");
  setTomb(model, client, ID_C, 4);
  setRow(model, client, ID_D, 1, "D");
  const d = await syncDevice({ model, client });
  await d.engine.start();
  model.items.clear();
  setRow(model, client, ID_A, 2, "A old", { seq: 1 });
  setTomb(model, client, ID_B, 2, { seq: 2 });
  setRow(model, client, ID_C, 3, "C old", { seq: 3 });
  model.restoreEpoch = 1;
  await d.engine.syncNow();
  assert.equal(d.engine.health().halted, "server_restored");
  return d;
}

/** A device that has stopped with `rollback_suspected`: the server claims a position below what it showed before. */
async function suspectWorld() {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A", { seq: 5 });
  const d = await syncDevice({ model, client });
  await d.engine.start();
  model.latestSeqLie = 2;
  await d.engine.syncNow();
  assert.equal(d.engine.health().halted, "rollback_suspected");
  return d;
}

const bannerOf = (root, code) => all(root, "sync-banner").find((node) => node.getAttribute("data-code") === code) ?? null;
const type = (root, text) => {
  find(root, "restored-word").value = text;
};

test("the_restored_page_previews_and_accepts_with_the_real_engine", async () => {
  await withDom(async () => {
    const d = await restoredWorld();
    const t = translator();
    const went = [];
    const router = { go: (path) => went.push(path) };
    const banner = syncBanner({ engine: d.engine, router, t });
    // The banner of the stop, and its way to the page.
    const node = bannerOf(banner, "server_restored");
    assert.ok(node, "the stop has its banner");
    await click(find(node, "banner-action"));
    assert.deepEqual(went, ["/restored"]);

    // The page: the real preview, with its counts, before anything is done.
    const view = restoredView({ engine: d.engine, t, router });
    await until(() => find(view, "preview-reupload") && textOf(find(view, "preview-reupload")).trim() !== "", "the preview is shown");
    assert.equal(textOf(find(view, "preview-reupload")).trim(), textFor(EN, "syncwarnings.restored.preview_reupload", { count: 1 }));
    assert.equal(textOf(find(view, "preview-conflicts")).trim(), textFor(EN, "syncwarnings.restored.preview_conflicts", { count: 3 }));
    assert.equal(find(view, "restored-manifest-older"), null, "the restored manifest is not older here");
    assert.ok(find(view, "restored-conflicts-note"));
    assert.equal(d.api.puts.length, 0, "a preview sends nothing");
    assert.equal(d.engine.health().halted, "server_restored");
    assert.equal(find(view, "restored-accept").disabled, false);

    // The wrong word calls nothing; the right word accepts, once.
    type(view, "yes");
    await submit(find(view, "restored-form"));
    assert.equal(d.engine.health().halted, "server_restored");
    type(view, "accept");
    await submit(find(view, "restored-form"));
    const done = find(view, "restored-done");
    assert.ok(done, "the result is shown");
    assert.equal(textOf(done).trim(), textFor(EN, "syncwarnings.restored.done", { reuploaded: 1, conflicts: 3 }));
    // The three items that exist on the server are conflicts for the user to decide: the count has its own line.
    assert.equal(textOf(find(view, "restored-conflicts")).trim(), textFor(EN, "syncwarnings.restored.done_conflicts", { count: 3 }));
    assert.equal(find(view, "restored-form"), null);
    // The engine runs again, the banner of the stop is gone, and the one item the server had no row for went up.
    assert.equal(d.engine.health().halted, null);
    assert.equal(bannerOf(banner, "server_restored"), null, "the stop's banner follows the engine's all-clear");
    await until(() => d.model.items.get(ID_D)?.rev === 1, "D is on the server");
    assert.equal(d.events.error.filter((e) => e.code === "conflict").length, 3);
    d.engine.stop();
  });
});

test("the_restored_page_with_the_real_engine_says_when_the_page_is_out_of_date", async () => {
  await withDom(async () => {
    const d = await restoredWorld();
    const t = translator("nb");
    const view = restoredView({ engine: d.engine, t, router: { go() {} }, reload: () => {} });
    await until(() => find(view, "preview-reupload") && textOf(find(view, "preview-reupload")).trim() !== "", "the preview is shown");
    // Another tab accepted meanwhile: this engine is no longer halted for a restored server, so accepting is `invalid_state`.
    await d.engine.acceptOlderState();
    type(view, "godta");
    await submit(find(view, "restored-form"));
    assert.ok(textOf(find(view, "restored-error")).includes("utdatert"));
    assert.ok(find(view, "restored-resume"));
    assert.ok(find(view, "restored-reload"));
    d.engine.stop();
  });
});

test("try_again_with_the_real_engine_keeps_the_banner_its_note_and_its_focus_and_goes_when_the_cause_is_gone", async () => {
  await withDom(async () => {
    const d = await suspectWorld();
    const banner = syncBanner({ engine: d.engine, router: { go() {} }, t: translator() });
    const node = bannerOf(banner, "rollback_suspected");
    assert.ok(node);
    const button = all(node, "banner-action").find((b) => b.getAttribute("data-action") === "try_again");
    button.focus();
    const halted = d.events.state.filter((s) => s.kind === "halted").length;

    // The real engine lifts the stop and says `syncing`, finds the cause, and halts again: one banner, the same node, the focus.
    await click(button);
    await until(() => d.events.state.filter((s) => s.kind === "halted").length > halted && textOf(find(node, "banner-note")).includes("still there"), "stopped again, and said so");
    assert.equal(d.engine.health().halted, "rollback_suspected");
    assert.equal(all(banner, "sync-banner").length, 1);
    assert.equal(bannerOf(banner, "rollback_suspected"), node, "the same banner, not a new one");
    assert.equal(globalThis.document.activeElement, button, "the focus stayed on the button");
    assert.equal(button.getAttribute("aria-disabled"), "false");

    // The cause is gone: the next try takes the banner away.
    d.model.latestSeqLie = null;
    await click(button);
    await until(() => d.engine.health().halted === null && bannerOf(banner, "rollback_suspected") === null, "the stop is lifted and its banner is gone");
    d.engine.stop();
  });
});
