// A new recovery key: the password check first, the new page 2 shown, nothing sent before the key is
// typed back, the pin raised only after 200, the new key out of the worker on every path, the texts of
// the page (J48), and the rollback text when the core refuses a wrap below the floor.
import assert from "node:assert/strict";
import { test } from "node:test";
import { b64u } from "../../src/b64.mjs";
import { renewRecoveryKey } from "../../src/flows/renewRecovery.mjs";
import { keysErrorText, renewRecoveryView } from "../../src/views/renewRecovery.mjs";
import { byRole, coded, dumpDatabase, fire, settle, textOf } from "./accountHelpers.mjs";
import { NONCE, PROOF } from "./securityHelpers.mjs";
import { loadPinned } from "../../src/store/pinned.mjs";
import { ACCOUNT, EMAIL, OLD_RK_CODE, RK_CODE, SERVER, catalog, filled, i18n, keysWorld, reauthWith, storedFloor, typing, withDom } from "./keysHelpers.mjs";

const renew = (world, extra = {}) =>
  world.session.renewRecoveryKey({ reauth: reauthWith(world), confirmNewRk: typing(world, RK_CODE), ...extra });

const writes = (world) => world.requests.filter((r) => r.method !== "GET");

test("renewal_needs_fresh_reauth_shows_the_new_sheet_and_sends_only_after_the_key_is_typed_back", async () => {
  // A password check that is cancelled stops everything before the first request.
  const cancelled = await keysWorld();
  await assert.rejects(renew(cancelled, { reauth: reauthWith(cancelled, "cancelled") }), { code: "cancelled" });
  assert.deepEqual(cancelled.log, ["reauth"]);
  assert.equal(cancelled.client.called("renew_recovery").length, 0);

  const world = await keysWorld();
  let sentBeforeTyping = null;
  const confirmNewRk = async ({ sheet, verify }) => {
    world.log.push("sheet");
    // Page 2 alone: the new key and nothing of page 1.
    assert.deepEqual(sheet, { access: null, recoveryKeyCode: RK_CODE });
    sentBeforeTyping = writes(world).length;
    // A typo and the old key are refused by the check; the page asks again and nothing goes out meanwhile.
    await assert.rejects(verify("FFR2-TYPO"), { code: "checksum" });
    await assert.rejects(verify(OLD_RK_CODE), { code: "decrypt" });
    assert.equal(writes(world).length, 0);
    await verify(RK_CODE);
    return true;
  };
  const done = await world.session.renewRecoveryKey({ reauth: reauthWith(world), confirmNewRk });
  assert.equal(done.kekGeneration, 2);
  assert.equal(sentBeforeTyping, 0, "nothing was sent while the sheet was up");
  assert.deepEqual(world.log.filter((line) => !line.startsWith("vault.verify_recovery_setup")), [
    "reauth", // the master password again, first
    "GET /api/auth/session",
    "GET /api/vault/unlock-methods",
    "vault.seed_pinned",
    "vault.check_server_methods",
    "vault.clear_setup_secrets", // a key left over from a page left half way is never sent
    "vault.renew_recovery",
    "vault.reveal_recovery_code", // page 2 only: the full sheet is never asked for
    "sheet",
    "POST /api/auth/challenge", // only now
    "vault.auth_sign",
    "PUT /api/vault/unlock-methods/recovery",
    "vault.clear_setup_secrets",
  ]);
  assert.equal(world.client.called("reveal_emergency_sheet").length, 0);
  assert.equal(world.client.called("renew_recovery_after_restore").length, 0);
  // The core was given the record with its floors, the server's recovery wrap and the manifest the server holds.
  const [pinned, current, manifest] = world.client.called("renew_recovery")[0].snapshot;
  assert.equal(pinned.account_id.length, 16);
  assert.equal(current.method.type, "recovery");
  assert.equal(current.kek_generation, 1);
  assert.equal(manifest.rev, 1);
});

test("after_200_the_pin_rises_and_the_new_key_leaves_memory", async () => {
  const world = await keysWorld();
  assert.equal(await storedFloor(world, "recovery"), 1);
  await renew(world);
  // The record this device keeps now has the new floor; the password floor is as it was.
  assert.equal(await storedFloor(world, "recovery"), 2);
  assert.equal(await storedFloor(world, "password"), 1);
  // The worker no longer holds the new key, and it was told to drop it after the write too.
  assert.equal(world.core.held, null);
  assert.equal(world.client.calls.at(-1).method, "clear_setup_secrets");
  // What went to the server: the new wrap, the generation the core made, `pk_r` and the manifest, signed over those bytes.
  const [put] = world.recoveryPuts;
  assert.deepEqual(Object.keys(put.body).sort(), ["kek_generation", "manifest", "pk_r", "wrap"]);
  assert.equal(put.body.kek_generation, 2);
  assert.equal(put.body.wrap, b64u.encode(filled(72, 12)));
  assert.equal(put.body.pk_r, b64u.encode(filled(32, 13)));
  assert.deepEqual(put.body.manifest, { rev: 2, envelope: b64u.encode(filled(80, 14)), tag: b64u.encode(filled(32, 15)) });
  const [op, nonce, body] = world.client.called("auth_sign")[0].snapshot;
  assert.equal(op, "unlock-method.recovery.put");
  assert.deepEqual(nonce, NONCE);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(body)), put.body);
  assert.equal(put.headers["Ferret-Proof"], b64u.encode(PROOF));
  // The vault stays open, nothing was locked, and the key is nowhere in what this device stores.
  assert.ok(world.session.current());
  assert.equal(world.client.locked, 0);
  const stored = await dumpDatabase(world.db.store);
  assert.ok(!stored.includes(RK_CODE));
  for (const request of world.requests) assert.ok(!String(request.url).includes("FFR1"));
});

test("a_password_check_that_ran_out_while_the_key_was_written_down_is_asked_again_once", async () => {
  const world = await keysWorld({ puts: [{ status: 403, body: { error: "reauth_required" } }, { status: 200 }] });
  let checks = 0;
  const reauth = async () => {
    checks += 1;
    return "ok";
  };
  const done = await world.session.renewRecoveryKey({ reauth, confirmNewRk: typing(world, RK_CODE) });
  assert.equal(done.kekGeneration, 2);
  assert.equal(checks, 2);
  // The same signed change went out again, with a new nonce of its own.
  assert.equal(world.recoveryPuts.length, 2);
  assert.deepEqual(world.recoveryPuts[0].body, world.recoveryPuts[1].body);
  assert.equal(world.client.called("auth_sign").length, 2);
  assert.equal(await storedFloor(world, "recovery"), 2);

  // A second refusal is not tried again.
  const twice = await keysWorld({ puts: [{ status: 403, body: { error: "reauth_required" } }] });
  await assert.rejects(renew(twice), { code: "reauth_required" });
  assert.equal(twice.recoveryPuts.length, 2);
  assert.equal(await storedFloor(twice, "recovery"), 1);
});

test("a_refused_renewal_clears_the_new_key_and_keeps_the_pin", async () => {
  // "Do not use the new key": nothing is sent and the key goes.
  const no = await keysWorld();
  await assert.rejects(renew(no, { confirmNewRk: async () => false }), { code: "cancelled" });
  assert.equal(no.core.held, null);
  assert.equal(writes(no).length, 0);
  assert.equal(await storedFloor(no, "recovery"), 1);

  // A page that answers yes without a check that passed is not believed.
  const lying = await keysWorld();
  await assert.rejects(renew(lying, { confirmNewRk: async () => true }), { code: "cancelled" });
  assert.equal(lying.core.held, null);
  assert.equal(writes(lying).length, 0);

  // An explicit refusal of the server: nothing changed, nothing pinned, the key is gone.
  for (const [status, error] of [[409, "write_conflict"], [400, "malformed_recovery_key"], [401, "denied"], [403, "forbidden"]]) {
    const world = await keysWorld({ puts: [{ status, body: { error } }] });
    await assert.rejects(renew(world), { code: error }, error);
    assert.equal(world.core.held, null, error);
    assert.equal(await storedFloor(world, "recovery"), 1, error);
    assert.ok(world.session.current(), error);
  }

  // No answer, a server error or an answer for another generation: it is not known whether the key is in force.
  for (const put of [{ status: 500, body: { error: "internal" } }, { status: 200, body: { kek_generation: 7, seq: 1 } }]) {
    const world = await keysWorld({ puts: [put] });
    await assert.rejects(renew(world), { code: "renew_unconfirmed" });
    assert.equal(world.core.held, null);
    assert.equal(await storedFloor(world, "recovery"), 1);
  }

  // A core that would hand back a lower floor is stopped before anything is sent.
  const lower = await keysWorld({
    handlers: {
      renew_recovery: (pinned, current) => ({
        wrap: { method_id: current.method_id, kek_generation: 2, method: { type: "recovery" }, wrap: filled(72, 12) },
        pk_r: filled(32, 13),
        manifest: { rev: 2, envelope: filled(80, 14), tag: filled(32, 15) },
        pinned: { ...pinned, kek_generation_max: pinned.kek_generation_max.filter((f) => f.type !== "password") },
      }),
    },
  });
  await assert.rejects(renew(lower), { code: "pinned_floor_downgrade" });
  assert.equal(writes(lower).length, 0);
});

test("a_renewal_below_the_floor_without_an_accepted_restore_shows_the_rollback_text", async () => {
  const world = await keysWorld({ server: { password: 1, recovery: 1 } });
  // This device saw recovery generation 3; the server shows 1.
  const record = await loadPinned(world.db.store, SERVER, EMAIL);
  await world.store.savePinned(world.db.store, SERVER, ACCOUNT, EMAIL, {
    ...record,
    kek_generation_max: record.kek_generation_max.map((f) => (f.type === "recovery" ? { ...f, generation: 3 } : f)),
  });
  await assert.rejects(renew(world), { code: "pinned_kek_generation" });
  assert.equal(world.client.called("renew_recovery_after_restore").length, 0, "the after-restore entry is never taken here");
  assert.equal(writes(world).length, 0);
  assert.equal(await storedFloor(world, "recovery"), 3);

  // The page says it is a rollback or a restore, that nothing changed, and where the way on is.
  for (const lang of ["en", "nb"]) {
    const text = keysErrorText(i18n(lang).t, coded("pinned_kek_generation"));
    assert.equal(text, catalog(lang)["keys.error.pinned_kek_generation"]);
    assert.ok(text.includes(lang === "en" ? "Reapply the unlock methods" : "Legg inn opplåsingsmåtene på nytt"));
  }
  await withDom(async () => {
    const page = renewRecoveryView({ t: i18n("en").t, renew: async () => Promise.reject(coded("pinned_kek_generation")), win: {} });
    await fire(byRole(page, "renew-start"), "click");
    await settle();
    const error = byRole(page, "renew-error");
    assert.equal(error.hidden, false);
    assert.equal(textOf(error).trim(), catalog("en")["keys.error.pinned_kek_generation"]);
    assert.equal(byRole(page, "renew-done").hidden, true);
  });
});

test("the_page_says_a_backup_was_taken_and_to_keep_the_old_sheet_until_a_newer_backup", async () => {
  for (const lang of ["en", "nb"]) {
    await withDom(async () => {
      const world = await keysWorld();
      const page = renewRecoveryView({
        t: i18n(lang).t,
        renew: ({ confirmNewRk }) => world.session.renewRecoveryKey({ reauth: reauthWith(world), confirmNewRk }),
        win: {},
      });
      const texts = catalog(lang);
      // Before: what a new key does, and that devices stay signed in.
      assert.ok(textOf(page).includes(texts["keys.recovery.effects"]));
      assert.equal(byRole(page, "renew-done").hidden, true);

      await fire(byRole(page, "renew-start"), "click");
      await settle();
      // The new page 2 is on the page, in the sheet's renew mode, with the way out under it.
      const sheet = byRole(page, "sheet-page");
      assert.ok(sheet, lang);
      assert.ok(textOf(sheet).includes(RK_CODE));
      assert.ok(byRole(page, "renew-cancel"));
      assert.equal(writes(world).length, 0);

      // The key typed back: the check passes, the sheet goes and the change is sent.
      byRole(page, "rk-typed").value = RK_CODE;
      await fire(byRole(page, "confirm-form"), "submit");
      await settle(60);
      assert.equal(world.recoveryPuts.length, 1, lang);
      assert.equal(byRole(page, "sheet-page"), null, "the sheet left the page");
      assert.ok(!textOf(page).includes(RK_CODE), "the key left the page");

      const done = byRole(page, "renew-done");
      assert.equal(done.hidden, false, lang);
      assert.equal(textOf(byRole(page, "renew-done-backup")).trim(), texts["keys.recovery.done_backup"]);
      assert.equal(textOf(byRole(page, "renew-keep-old")).trim(), texts["keys.recovery.done_keep_old"]);
      assert.equal(textOf(byRole(page, "renew-done-old-key")).trim(), texts["keys.recovery.done_old_key"]);
    });
  }
  // J48, word for word.
  assert.equal(catalog("nb")["keys.recovery.done_keep_old"],
    "Gjenopprettes serveren fra en backup fra før i dag, virker den gamle nøkkelen igjen og den nye ikke. Ta vare på det gamle arket til du har sett en ny backup.");
  assert.match(catalog("en")["keys.recovery.done_backup"], /asked to make a new backup/);
  assert.match(catalog("nb")["keys.recovery.done_backup"], /bedt om å ta en ny backup/);
});

test("the_sheet_goes_and_the_key_is_dropped_on_no_on_a_lock_and_when_the_page_is_left", async () => {
  for (const how of ["no", "lock", "leave"]) {
    await withDom(async () => {
      const world = await keysWorld();
      const wipers = new Set();
      const scope = { add: (fn) => (wipers.add(fn), () => wipers.delete(fn)) };
      const listeners = new Map();
      const win = {
        addEventListener: (type, fn) => listeners.set(type, fn),
        removeEventListener: (type) => listeners.delete(type),
      };
      /** @type {Promise<unknown> | null} */
      let running = null;
      const page = renewRecoveryView({
        t: i18n("en").t,
        renew: ({ confirmNewRk }) => (running = world.session.renewRecoveryKey({ reauth: reauthWith(world), confirmNewRk })),
        scope,
        win,
      });
      await fire(byRole(page, "renew-start"), "click");
      await settle();
      assert.ok(byRole(page, "sheet-page"), how);
      assert.equal(world.core.held, RK_CODE);
      if (how === "no") await fire(byRole(page, "renew-cancel"), "click");
      if (how === "lock") for (const fn of [...wipers]) fn();
      if (how === "leave") listeners.get("hashchange")();
      await settle(60);
      await assert.rejects(running, { code: "cancelled" }, how);
      assert.equal(byRole(page, "sheet-page"), null, how);
      assert.ok(!textOf(page).includes(RK_CODE), how);
      assert.equal(world.core.held, null, how);
      assert.equal(writes(world).length, 0, how);
      assert.equal(listeners.size, 0, `${how}: the page stops listening`);
      assert.equal(textOf(byRole(page, "renew-note")).trim(), catalog("en")["keys.error.cancelled"]);
    });
  }
});

test("keys_texts_exist_in_both_languages", async () => {
  const { readFileSync, readdirSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { web } = await import("./helpers.mjs");
  const { KEYS_ERRORS } = await import("../../src/views/renewRecovery.mjs");
  const read = (lang) => JSON.parse(readFileSync(join(web, "src", "locales", lang, "keys.json"), "utf8"));
  const en = read("en");
  const nb = read("nb");
  // The same keys, each a text, with the same placeholders, in both languages.
  assert.deepEqual(Object.keys(nb).sort(), Object.keys(en).sort());
  const holes = (text) => [...text.matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((m) => m[1]).sort();
  for (const key of Object.keys(en)) {
    assert.ok(key.startsWith("keys."), key);
    for (const catalogue of [en, nb]) assert.ok(typeof catalogue[key] === "string" && catalogue[key].trim() !== "", key);
    assert.deepEqual(holes(nb[key]), holes(en[key]), key);
  }
  // Every key the sources name is there, and every error the pages have a text for.
  const sources = ["views/renewRecovery.mjs", "views/secretKey.mjs", "views/restored.mjs", ...readdirSync(join(web, "src", "routes")).map((name) => `routes/${name}`)]
    .map((path) => readFileSync(join(web, "src", path), "utf8"))
    .join("\n");
  const named = new Set([...sources.matchAll(/"(keys\.[a-z_.]+)"/g)].map((m) => m[1]));
  for (const code of KEYS_ERRORS) named.add(`keys.error.${code}`);
  for (const key of named) assert.ok(Object.hasOwn(en, key), `${key} is missing`);
  // The sheet texts the pages borrow exist in both languages.
  for (const lang of ["en", "nb"]) {
    const sheet = JSON.parse(readFileSync(join(web, "src", "locales", lang, "sheet.json"), "utf8"));
    for (const key of ["sheet.new_browser", "sheet.download_continue", "sheet.download_cancel", "sheet.download_done", "sheet.pdf.title_access"]) assert.ok(Object.hasOwn(sheet, key), key);
  }
});
