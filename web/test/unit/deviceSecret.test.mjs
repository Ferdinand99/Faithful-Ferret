// The secret key on the device (D6): sealed under a non-extractable key, bound
// to the server and the account, and never guessed when it is not there.
import assert from "node:assert/strict";
import { test } from "node:test";
import { forgetSecretKey, loadSecretKey, saveSecretKey } from "../../src/flows/deviceSecret.mjs";
import { deviceSecrets } from "../../src/store/settings.mjs";
import { ACCOUNT, EMAIL, PASSWORD, SERVER, SK_CODE, dumpDatabase, scenario } from "./accountHelpers.mjs";

const OTHER_ACCOUNT = "f0e1d2c3b4a5968778695a4b3c2d1e0f";

const firstSignIn = (session, extra = {}) =>
  session.signIn({ email: EMAIL, password: PASSWORD, skBit: true, skCode: SK_CODE, ...extra });

test("sk_is_stored_sealed_and_only_when_the_user_keeps_remember_on", async () => {
  const on = await scenario();
  const unlocked = await firstSignIn(on.session, { rememberSk: true });
  assert.equal(unlocked.secretKey, "saved");
  const row = await deviceSecrets.get(await on.store.open(), SERVER, ACCOUNT);
  assert.ok(row.key instanceof CryptoKey);
  assert.equal(row.key.extractable, false);
  assert.equal(row.iv.length, 12);
  assert.equal(await loadSecretKey(on.db.store, SERVER, ACCOUNT), SK_CODE);

  // The user turned "remember" off: nothing is kept.
  const off = await scenario();
  const second = await firstSignIn(off.session, { rememberSk: false });
  assert.equal(second.secretKey, "forgotten");
  assert.equal(await deviceSecrets.get(off.db.store, SERVER, ACCOUNT), null);

  // A page that did not offer the choice (a device that knows the account) leaves things as they were.
  const unchanged = await firstSignIn((await scenario()).session);
  assert.equal(unchanged.secretKey, "unchanged");
});

test("stored_sk_is_not_readable_as_text_in_indexeddb", async () => {
  const world = await scenario();
  await firstSignIn(world.session, { rememberSk: true });
  const dump = await dumpDatabase(world.db.store);
  // Neither the code nor any group of it is in the database as text or bytes.
  for (const piece of [SK_CODE, "TESTA", "TESTB", Buffer.from(SK_CODE).toString("hex")]) {
    assert.ok(!dump.includes(piece), `found ${piece}`);
  }
  // The sealing key cannot be exported by script.
  const row = await deviceSecrets.get(world.db.store, SERVER, ACCOUNT);
  await assert.rejects(crypto.subtle.exportKey("raw", row.key));
  assert.ok(row.sealed.length > SK_CODE.length);
});

test("sealed_sk_cannot_be_moved_between_accounts_or_servers", async () => {
  const world = await scenario();
  await saveSecretKey(world.db.store, SERVER, ACCOUNT, SK_CODE);
  const row = await deviceSecrets.get(world.db.store, SERVER, ACCOUNT);

  // The same bytes under another account or another server do not open.
  await deviceSecrets.put(world.db.store, SERVER, OTHER_ACCOUNT, row);
  await deviceSecrets.put(world.db.store, "https://other.example", ACCOUNT, row);
  assert.equal(await loadSecretKey(world.db.store, SERVER, OTHER_ACCOUNT), null);
  assert.equal(await loadSecretKey(world.db.store, "https://other.example", ACCOUNT), null);
  // At home it still does; a trailing slash is the same server.
  assert.equal(await loadSecretKey(world.db.store, SERVER, ACCOUNT), SK_CODE);
  assert.equal(await loadSecretKey(world.db.store, `${SERVER}/`, ACCOUNT), SK_CODE);
});

test("unavailable_key_storage_falls_back_to_asking_for_sk_at_every_sign_in_and_never_guesses_sk_bit", async () => {
  // A browser that cannot make or keep the key.
  const subtle = { generateKey: async () => Promise.reject(new Error("no key storage")) };
  assert.equal(await saveSecretKey((await scenario()).db.store, SERVER, ACCOUNT, SK_CODE, { subtle }), "unavailable");

  const world = await scenario({ secrets: { subtle } });
  const unlocked = await firstSignIn(world.session, { rememberSk: true });
  assert.equal(unlocked.secretKey, "unavailable");
  assert.equal(await deviceSecrets.get(world.db.store, SERVER, ACCOUNT), null);

  // The device knows the account has a secret key but holds none: it asks, before anything is sent.
  const before = world.requests.length;
  const startCalls = world.client.called("login_start").length;
  await assert.rejects(world.session.signIn({ email: EMAIL, password: PASSWORD }), { code: "sk_required" });
  assert.equal(world.requests.length, before);
  assert.equal(world.client.called("login_start").length, startCalls);

  // A device that knows nothing does not guess the answer from the server's hint.
  const fresh = await scenario({ skHint: true });
  await assert.rejects(fresh.session.signIn({ email: EMAIL, password: PASSWORD }), { code: "sk_answer_required" });
  assert.equal(fresh.requests.length, 0);
  assert.equal(fresh.client.calls.length, 0);

  // A key that was evicted (the row is gone) is the same as none.
  const kept = await scenario();
  await firstSignIn(kept.session, { rememberSk: true });
  await deviceSecrets.delete(kept.db.store, SERVER, ACCOUNT);
  assert.equal(await loadSecretKey(kept.db.store, SERVER, ACCOUNT), null);
  await assert.rejects(kept.session.signIn({ email: EMAIL, password: PASSWORD }), { code: "sk_required" });
});

test("opting_out_of_remember_asks_for_sk_each_time", async () => {
  const world = await scenario();
  await firstSignIn(world.session, { rememberSk: false });
  await assert.rejects(world.session.signIn({ email: EMAIL, password: PASSWORD }), { code: "sk_required" });
  // Typing it each time works.
  const again = await world.session.signIn({ email: EMAIL, password: PASSWORD, skCode: SK_CODE });
  assert.equal(again.accountId, ACCOUNT);
  assert.equal(world.client.called("login_start").at(-1).snapshot[1], SK_CODE);

  // Signing in once more with "remember" off removes what an earlier choice stored.
  const kept = await scenario();
  await firstSignIn(kept.session, { rememberSk: true });
  assert.equal(await loadSecretKey(kept.db.store, SERVER, ACCOUNT), SK_CODE);
  await firstSignIn(kept.session, { rememberSk: false });
  assert.equal(await loadSecretKey(kept.db.store, SERVER, ACCOUNT), null);
});

test("forgetting_the_device_removes_the_sealed_sk_and_its_key", async () => {
  const world = await scenario();
  await firstSignIn(world.session, { rememberSk: true });
  assert.ok(await deviceSecrets.get(world.db.store, SERVER, ACCOUNT));
  await world.session.forgetSecretKey(ACCOUNT);
  // The row holds both the sealed code and the key: it is gone as a whole.
  assert.equal(await deviceSecrets.get(world.db.store, SERVER, ACCOUNT), null);
  assert.equal(await loadSecretKey(world.db.store, SERVER, ACCOUNT), null);
  // And the function by itself does the same.
  await saveSecretKey(world.db.store, SERVER, ACCOUNT, SK_CODE);
  await forgetSecretKey(world.db.store, SERVER, ACCOUNT);
  assert.equal(await deviceSecrets.get(world.db.store, SERVER, ACCOUNT), null);
});

test("a_stored_sk_is_used_without_asking_and_never_when_the_record_says_there_is_none", async () => {
  const world = await scenario();
  await firstSignIn(world.session, { rememberSk: true });
  // The next sign-in needs no secret key from the page.
  await world.session.signIn({ email: EMAIL, password: PASSWORD });
  assert.equal(world.client.called("login_start").at(-1).snapshot[1], SK_CODE);

  // An account whose record says "no secret key" sends none, even if one is stored for it.
  const plain = await scenario({ skBit: false });
  await plain.session.signIn({ email: EMAIL, password: PASSWORD, skBit: false });
  await saveSecretKey(plain.db.store, SERVER, ACCOUNT, SK_CODE);
  await plain.session.signIn({ email: EMAIL, password: PASSWORD });
  assert.equal(plain.client.called("login_start").at(-1).snapshot[1], null);
});
