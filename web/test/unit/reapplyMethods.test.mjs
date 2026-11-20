// "Reapply the unlock methods" after an accepted restore: offered only for a note that says the unlock
// methods went back, for the restore epoch the sync state stored, and only while the server's recovery key is
// below this device's floor; it renews over that wrap through the core's after-restore entry, with the
// generation above every floor, and no floor ever goes down. No other module of the web vault names that entry.
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { test } from "node:test";
import { restoreNoteTools } from "../../src/flows/restoreNote.mjs";
import { loadPinned } from "../../src/store/pinned.mjs";
import { loadRestoreNote } from "../../src/store/restoreNote.mjs";
import { unlockScreen } from "../../src/views/unlock.mjs";
import { saveSyncState } from "../../src/store/syncState.mjs";
import { renewRecoveryView } from "../../src/views/renewRecovery.mjs";
import { restoredView } from "../../src/views/restored.mjs";
import { byRole, fire, settle, textOf } from "./accountHelpers.mjs";
import { web } from "./helpers.mjs";
import { fakeWarningsEngine } from "./syncWarningsHelpers.mjs";
import { find, submit } from "./vaultHelpers.mjs";
import { ACCOUNT, EMAIL, RK_CODE, SERVER, catalog, filled, i18n, keysWorld, reauthWith, storedFloor, typing, withDom } from "./keysHelpers.mjs";

const DAY = 24 * 60 * 60 * 1000;

/**
 * A world after an accepted restore: this device saw the given floors, the server shows the given generations,
 * the sync state stored `stateEpoch`, and the note (if any) is kept.
 */
async function restoredWorld({ floors = { password: 1, recovery: 3 }, server = { password: 1, recovery: 1 }, note = {}, stateEpoch = 5, handlers } = {}) {
  const world = await keysWorld({ server, handlers });
  const record = await loadPinned(world.db.store, SERVER, EMAIL);
  await world.store.savePinned(world.db.store, SERVER, ACCOUNT, EMAIL, {
    ...record,
    kek_generation_max: record.kek_generation_max.map((f) => ({ ...f, generation: floors[f.type] ?? f.generation })),
  });
  if (stateEpoch !== null) {
    await saveSyncState(world.db.store, SERVER, ACCOUNT, {
      memory: new Uint8Array(8), restoreEpoch: stateEpoch, verifiedAt: 1, verifiedSeq: 1, uploadedAt: 1, uploadedSeq: 1, hardWarning: null, restore: null,
    });
  }
  if (note !== null) {
    world.note = { acceptedAt: Date.now() - 1000, restoreEpoch: 5, manifestOlder: true, ...note };
    await world.store.restoreNote.save(world.db.store, SERVER, ACCOUNT, world.note);
  }
  world.log.length = 0;
  world.requests.length = 0;
  world.client.calls.length = 0;
  return world;
}

const writes = (world) => world.requests.filter((r) => r.method !== "GET");
const floorsOf = async (world) => Object.fromEntries((await loadPinned(world.db.store, SERVER, EMAIL)).kek_generation_max.map((f) => [f.type, f.generation]));

test("reapply_after_an_accepted_restore_with_an_older_manifest_renews_the_recovery_key", async () => {
  const world = await restoredWorld();
  // The offer: the note applies and the server's recovery key is below this device's floor.
  const offer = await world.session.reapplyOffer();
  assert.deepEqual(offer.note, world.note);
  assert.deepEqual(offer.below, ["recovery"]);

  const back = await world.session.reapplyMethods({ note: offer.note, reauth: reauthWith(world), confirmNewRk: typing(world, RK_CODE) });
  assert.deepEqual(back, ["recovery"]);
  // The after-restore entry, never the default one; the generation is above the floor (max(3, 1) + 1).
  assert.equal(world.client.called("renew_recovery_after_restore").length, 1);
  assert.equal(world.client.called("renew_recovery").length, 0);
  assert.equal(world.recoveryPuts.length, 1);
  assert.equal(world.recoveryPuts[0].body.kek_generation, 4);
  assert.equal(await storedFloor(world, "recovery"), 4);
  assert.equal(world.core.held, null, "the new key left the worker");
  // The order: the password check, then the methods, then the key; the sheet before anything is sent.
  const order = world.log.filter((line) => ["reauth", "sheet", "vault.renew_recovery_after_restore", "PUT /api/vault/unlock-methods/recovery"].includes(line));
  assert.deepEqual(order, ["reauth", "vault.renew_recovery_after_restore", "sheet", "PUT /api/vault/unlock-methods/recovery"]);

  // On the page: the part shows, the button runs it through the sheet, and the result says the key is back.
  for (const lang of ["en", "nb"]) {
    await withDom(async () => {
      const w = await restoredWorld();
      const texts = catalog(lang);
      const page = renewRecoveryView({
        t: i18n(lang).t,
        renew: () => assert.fail("the plain renewal is not used here"),
        offer: () => w.session.reapplyOffer(),
        reapply: ({ note, confirmNewRk }) => w.session.reapplyMethods({ note, confirmNewRk, reauth: reauthWith(w) }),
        win: {},
        locale: lang,
      });
      await settle();
      assert.equal(byRole(page, "reapply-slot").hidden, false, lang);
      assert.equal(byRole(page, "reapply-password"), null, "the password is not below its floor here");
      await fire(byRole(page, "reapply-button"), "click");
      await settle();
      byRole(page, "rk-typed").value = RK_CODE;
      await fire(byRole(page, "confirm-form"), "submit");
      await settle(60);
      assert.equal(w.recoveryPuts.length, 1, lang);
      assert.equal(byRole(page, "renew-done").hidden, false, lang);
      assert.equal(textOf(byRole(page, "renew-done-reapplied")).trim(), texts["keys.reapply.done"]);
      assert.equal(textOf(byRole(page, "renew-keep-old")).trim(), texts["keys.recovery.done_keep_old"]);
      assert.equal(await storedFloor(w, "recovery"), 4);
    });
  }
});

test("reapply_is_hidden_without_manifest_older_and_never_lowers_a_floor", async () => {
  // No offer: no note, a note without manifestOlder, another restore epoch, an expired note, no sync state.
  for (const [label, options] of [
    ["no note", { note: null }],
    ["not older", { note: { manifestOlder: false } }],
    ["other epoch", { note: { restoreEpoch: 4 } }],
    ["expired", { note: { acceptedAt: Date.now() - 31 * DAY } }],
    ["no sync state", { stateEpoch: null }],
  ]) {
    const world = await restoredWorld(options);
    const offer = await world.session.reapplyOffer();
    assert.deepEqual(offer, { note: null, below: [] }, label);
    assert.ok(!world.log.includes("GET /api/vault/unlock-methods"), `${label}: the server is not asked`);
    // Asked anyway, with a note the page made up: refused after the password check, before anything is made.
    const forged = { acceptedAt: Date.now() - 1000, restoreEpoch: 5, manifestOlder: true };
    await assert.rejects(world.session.reapplyMethods({ note: forged, reauth: reauthWith(world), confirmNewRk: typing(world, RK_CODE) }), { code: "reapply_not_offered" }, label);
    assert.equal(world.client.called("renew_recovery_after_restore").length, 0, label);
    assert.equal(writes(world).length, 0, label);
    assert.equal(await storedFloor(world, "recovery"), 3, label);
    await withDom(async () => {
      const page = renewRecoveryView({ t: i18n("en").t, renew: async () => ({ kekGeneration: 2 }), offer: () => world.session.reapplyOffer(), reapply: async () => [], win: {} });
      await settle();
      assert.equal(byRole(page, "reapply-slot").hidden, true, label);
      assert.equal(byRole(page, "reapply-button"), null, label);
    });
  }

  // A note that is not "older" is refused before even the password check.
  const plain = await restoredWorld();
  await assert.rejects(plain.session.reapplyMethods({ note: { ...plain.note, manifestOlder: false }, reauth: reauthWith(plain), confirmNewRk: typing(plain, RK_CODE) }), { code: "reapply_not_offered" });
  assert.deepEqual(plain.log, []);

  // A recovery key that is not below the floor: nothing to reapply, nothing made, nothing sent.
  const level = await restoredWorld({ floors: { password: 1, recovery: 1 } });
  assert.deepEqual((await level.session.reapplyOffer()).below, []);
  assert.deepEqual(await level.session.reapplyMethods({ note: level.note, reauth: reauthWith(level), confirmNewRk: typing(level, RK_CODE) }), []);
  assert.equal(level.client.called("renew_recovery_after_restore").length, 0);
  assert.equal(writes(level).length, 0);

  // A password below its floor is pointed to the password change, never renewed here.
  const password = await restoredWorld({ floors: { password: 2, recovery: 1 } });
  assert.deepEqual((await password.session.reapplyOffer()).below, ["password"]);
  await withDom(async () => {
    const page = renewRecoveryView({ t: i18n("en").t, renew: async () => ({ kekGeneration: 2 }), offer: () => password.session.reapplyOffer(), reapply: async () => assert.fail("not offered"), win: {} });
    await settle();
    assert.equal(byRole(page, "reapply-slot").hidden, false);
    assert.equal(byRole(page, "reapply-button"), null);
    assert.equal(byRole(page, "reapply-password-link").getAttribute("href"), "#/password");
  });

  // No floor goes down: after a reapply every floor is at least what it was, and a core that would lower one is
  // stopped before anything is sent.
  const world = await restoredWorld({ floors: { password: 2, recovery: 3 }, server: { password: 2, recovery: 1 } });
  const before = await floorsOf(world);
  await world.session.reapplyMethods({ note: world.note, reauth: reauthWith(world), confirmNewRk: typing(world, RK_CODE) });
  const after = await floorsOf(world);
  for (const [type, generation] of Object.entries(before)) assert.ok(after[type] >= generation, type);
  assert.ok(after.recovery > before.recovery);

  const lowering = await restoredWorld({
    handlers: {
      renew_recovery_after_restore: (pinned, current) => ({
        wrap: { method_id: current.method_id, kek_generation: 2, method: { type: "recovery" }, wrap: filled(72, 12) },
        pk_r: filled(32, 13),
        manifest: { rev: 2, envelope: filled(80, 14), tag: filled(32, 15) },
        pinned: { ...pinned, kek_generation_max: pinned.kek_generation_max.map((f) => (f.type === "recovery" ? { ...f, generation: 2 } : f)) },
      }),
    },
  });
  await assert.rejects(lowering.session.reapplyMethods({ note: lowering.note, reauth: reauthWith(lowering), confirmNewRk: typing(lowering, RK_CODE) }), { code: "pinned_floor_downgrade" });
  assert.equal(writes(lowering).length, 0);
  assert.equal(await storedFloor(lowering, "recovery"), 3);

  // The restored page leads on to it only for a kept note of a restore that took the unlock methods back.
  await withDom(async () => {
    for (const [answer, older, shown] of [["kept", true, true], ["kept", false, false], ["none", true, false], ["not_kept", true, false], [undefined, true, false]]) {
      const engine = fakeWarningsEngine({ halted: "server_restored" });
      engine.previewResult = { reupload: 0, conflicts: 0, manifestOlder: older };
      engine.acceptResult = { reuploaded: 0, conflicts: 0, manifestOlder: older };
      const went = [];
      const root = restoredView({ engine, t: i18n("en").t, router: { go: (path) => went.push(path) }, onAccepted: () => answer });
      await settle();
      find(root, "restored-word").value = "syncwarnings.restored.word";
      await submit(find(root, "restored-form"));
      await settle();
      const link = find(root, "restored-reapply");
      assert.equal(link !== null, shown, `${answer} ${older}`);
      if (link) {
        await fire(link, "click");
        assert.deepEqual(went, ["/recovery-key"]);
      }
    }
  });
});

test("only_the_reapply_flow_names_the_after_restore_entry", () => {
  /** @param {string} dir @returns {string[]} */
  const files = (dir) => readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? files(path) : [path];
  });
  const naming = ["src", "admin", "types", "scripts"].flatMap((dir) => files(join(web, dir)))
    .filter((path) => /\.(?:[cm]?[jt]s|d\.[cm]?ts|html|json|css)$/.test(path))
    .filter((path) => readFileSync(path, "utf8").includes("renew_recovery_after_restore"))
    .map((path) => relative(web, path).replace(/\\/g, "/"));
  assert.deepEqual(naming, ["src/flows/reapplyMethods.mjs"]);
});

test("the_note_stays_after_a_successful_unlock_and_the_reapply_is_still_offered", async () => {
  // Only the recovery key went back: the password still unlocks.
  let held = null;
  const world = await restoredWorld({ handlers: { unlock_password: async () => ({ pinned: await loadPinned(held.db.store, SERVER, EMAIL) }) } });
  held = world;
  // The unlock and sign-in screens get the finder only.
  const tools = restoreNoteTools({ store: world.store, serverUrl: world.session.serverUrl });
  assert.deepEqual(Object.keys(tools), ["restoreNote"]);

  await world.session.lock();
  await withDom(async () => {
    let unlocked = 0;
    const host = unlockScreen({ session: world.session, t: i18n("en").t, go() {}, onUnlocked: () => (unlocked += 1), ...tools, locale: "en" });
    await settle(60);
    find(host, "password").value = "test-password-for-unit-tests-only";
    await submit(find(host, "unlock-form"));
    await settle(60);
    assert.equal(unlocked, 1, "the unlock went through");
  });
  assert.ok(world.session.current());
  assert.deepEqual(await loadRestoreNote(world.db.store, SERVER, ACCOUNT, Date.now()), world.note);
  const offer = await world.session.reapplyOffer();
  assert.deepEqual(offer.below, ["recovery"]);
  assert.deepEqual(offer.note, world.note);
});

test("a_successful_reapply_removes_the_note_unless_the_password_is_also_below", async () => {
  const only = await restoredWorld();
  assert.deepEqual(await only.session.reapplyMethods({ note: only.note, reauth: reauthWith(only), confirmNewRk: typing(only, RK_CODE) }), ["recovery"]);
  assert.equal(await loadRestoreNote(only.db.store, SERVER, ACCOUNT, Date.now()), null);
  // A later rollback of the same restore is a plain refusal again: nothing is offered.
  assert.deepEqual(await only.session.reapplyOffer(), { note: null, below: [] });

  const both = await restoredWorld({ floors: { password: 2, recovery: 3 } });
  assert.deepEqual(await both.session.reapplyMethods({ note: both.note, reauth: reauthWith(both), confirmNewRk: typing(both, RK_CODE) }), ["recovery"]);
  // The password still goes back at the next unlock; the note stays to explain that refusal.
  assert.deepEqual(await loadRestoreNote(both.db.store, SERVER, ACCOUNT, Date.now()), both.note);

  // Nothing done, nothing removed: a refused or abandoned reapply keeps the note.
  const no = await restoredWorld();
  await assert.rejects(no.session.reapplyMethods({ note: no.note, reauth: reauthWith(no), confirmNewRk: async () => false }), { code: "cancelled" });
  assert.deepEqual(await loadRestoreNote(no.db.store, SERVER, ACCOUNT, Date.now()), no.note);
});
