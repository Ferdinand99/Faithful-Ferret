// Opening a closed vault with a passkey, from the web vault's side: when it is offered (only with a valid vault session, a
// pinned record on this device and a passkey method), the one WebAuthn call that comes from the click, what that call asks
// for, the checks of the answer, the core's unlock under the pinned record, the checks that follow every unlock, and that
// the PRF result goes nowhere but into the core. The fake core and the fake server are those of the passkey methods tests.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { b64u } from "../../src/b64.mjs";
import { createI18n } from "../../src/i18n.mjs";
import { req, run } from "../../src/store/idb.mjs";
import { evaluateOneOf } from "../../src/flows/passkeyAnswer.mjs";
import { evaluatePasskey } from "../../src/flows/passkeyCeremony.mjs";
import { PASSKEY_UNLOCK_ERRORS, passkeyUnlockErrorText, prepareUnlock, unlockScreen } from "../../src/views/unlock.mjs";
import { describeError } from "../../src/views/form.mjs";
import { ACCOUNT, EMAIL, coded, dumpDatabase, filled, pinnedRecord } from "./accountHelpers.mjs";
import { CREDENTIAL, HOST, ORIGIN, PRF_RESULT, SALT, ceremonyDeps, fakeCredentials, passkeyWorld, sentinelForms } from "./methodsHelpers.mjs";
import { web } from "./helpers.mjs";
import { fakeSession, find, all, fire, settle, t, textOf, walk, withDom } from "./vaultHelpers.mjs";

const hex = (bytes) => Buffer.from(bytes).toString("hex");
/** The pinned record this device keeps of the account. */
const recordOf = async (world) => world.store.pinnedForSignIn(await world.store.open(), world.session.serverUrl, EMAIL, ACCOUNT);

/** The passkey the account has: the one the fake authenticator answers for. */
const PHONE = Object.freeze({ id: "31".repeat(16), credential: CREDENTIAL, salt: SALT, aaguid: "fbfc3007154e4ecc8c0b6e020557d7bd", name: "Phone", synced: true, createdAt: 1_750_000_000 });
/** A second one, with its own credential and salt. */
const KEY = Object.freeze({ id: "32".repeat(16), credential: filled(20, 0x77), salt: filled(32, 0x78), aaguid: "00".repeat(16), name: "Key", synced: false, createdAt: 1_700_000_000 });

/** A world whose vault is closed while the vault session on the server is still valid. */
async function closedWorld(options = {}) {
  const world = await passkeyWorld({ passkeys: [PHONE], ...options });
  await world.session.lock();
  world.log.length = 0;
  world.requests.length = 0;
  world.client.calls.length = 0;
  world.client.locked = 0;
  return world;
}

/** The page's own WebAuthn call over fake credentials, and the dependencies that go with them. */
const how = (credentials, extra = {}) => ({ getAssertion: (publicKey) => credentials.get({ publicKey }), deps: ceremonyDeps(credentials), ...extra });
const unlockWith = (world, offer, credentials) => world.session.unlockWithPasskey(offer, how(credentials));
/** The session as a page sees it: the host is the page's (a test has no `location`) and the WebAuthn call is the fake one. */
const pageSession = (world, credentials) => ({
  ...world.session,
  preparePasskeyUnlock: () => world.session.preparePasskeyUnlock({ rpId: HOST }),
  unlockWithPasskey: (offer) => world.session.unlockWithPasskey(offer, how(credentials)),
});
const phoneKey = (extra = {}) => fakeCredentials({ credential: PHONE.credential, ...extra });

const read = (lang) => {
  const dir = join(web, "src", "locales", lang);
  const out = {};
  for (const name of readdirSync(dir)) Object.assign(out, JSON.parse(readFileSync(join(dir, name), "utf8")));
  return out;
};

// -------------------------------------------------------------------------------------------------- when it is offered

test("prf_unlock_is_offered_only_when_the_session_is_valid_and_a_method_exists", async () => {
  const world = await closedWorld();
  const credentials = phoneKey();
  const offer = await world.session.preparePasskeyUnlock({ rpId: HOST });
  assert.ok(offer, "offered");
  assert.equal(offer.rpId, HOST);
  assert.equal(offer.accountId, ACCOUNT);
  assert.deepEqual(offer.credentials.map((c) => [hex(c.id), hex(c.salt)]), [[hex(PHONE.credential), hex(PHONE.salt)]]);
  // Nothing was asked of the passkey and nothing was written: the offer is only a read.
  assert.equal(credentials.calls.get.length, 0);
  assert.equal(world.client.called("unlock_prf").length, 0);
  assert.deepEqual(world.requests.filter((r) => r.method !== "GET"), []);

  // No method: nothing to offer.
  assert.equal(await (await closedWorld({ passkeys: [] })).session.preparePasskeyUnlock({ rpId: HOST }), null);
  // The server does not offer passkeys.
  assert.equal(await (await closedWorld({ offered: false })).session.preparePasskeyUnlock({ rpId: HOST }), null);
  // The vault session has ended.
  const ended = await closedWorld();
  ended.server.state.signedIn = false;
  assert.equal(await ended.session.preparePasskeyUnlock({ rpId: HOST }), null);
  // This device holds no pinned record of the account: a passkey is never the first unlock of a device.
  const fresh = await closedWorld();
  const db = await fresh.store.open();
  await run(db, ["pinned"], "readwrite", async ([pinned]) => void (await req(pinned.clear())));
  assert.equal(await fresh.session.preparePasskeyUnlock({ rpId: HOST }), null);
  // The vault is open already.
  const open = await passkeyWorld({ passkeys: [PHONE] });
  assert.equal(await open.session.preparePasskeyUnlock({ rpId: HOST }), null);
  // A server that cannot be read offers nothing (the master password is always there).
  const broken = await closedWorld();
  broken.server.state.signedIn = true;
  const original = broken.api.get;
  broken.api.get = async (path, ...rest) => {
    if (path === "/api/vault/unlock-methods") throw coded("network");
    return original(path, ...rest);
  };
  assert.equal(await broken.session.preparePasskeyUnlock({ rpId: HOST }), null);
});

test("an_ended_session_asks_for_the_password_as_before", async () => {
  // The Unlock page of a session that has ended is the remembered account's: no passkey button, only the password.
  await withDom(async () => {
    const session = fakeSession({ info: null });
    session.remembered = async () => ({ accountId: "aa".repeat(16), email: "ada@example.test", skBit: false, skStored: false });
    session.preparePasskeyUnlock = async () => {
      throw new Error("an ended session offers nothing");
    };
    const facts = await prepareUnlock(session);
    assert.equal(facts.signedIn, false);
    assert.equal(facts.passkey, undefined);
  });
  await withDom(async () => {
    const session = fakeSession({ info: null });
    session.unlockWithPasskey = async () => {
      throw new Error("no passkey after the session ended");
    };
    const host = unlockScreen({ session, t, go: () => undefined, onUnlocked: () => undefined });
    await settle();
    assert.equal(find(host, "passkey-section"), null);
    assert.equal(find(host, "passkey-unlock"), null);
  });
  // The session ends between the offer and the click: the call was the click's, nothing opens, and the answer is the
  // ordinary one that sends the user to the sign-in page.
  const world = await closedWorld();
  const offer = await world.session.preparePasskeyUnlock({ rpId: HOST });
  world.server.state.signedIn = false;
  await assert.rejects(unlockWith(world, offer, phoneKey()), { code: "session_ended" });
  assert.equal(world.client.called("unlock_prf").length, 0);
  assert.equal(world.session.current(), null);
});

test("a_removed_method_is_not_offered_and_fails_cleanly", async () => {
  // Removed before the page was shown: not offered.
  const gone = await closedWorld({ passkeys: [] });
  assert.equal(await gone.session.preparePasskeyUnlock({ rpId: HOST }), null);

  // Removed after the page was shown, before the click: the passkey answers, the list no longer has it, nothing is tried.
  const world = await closedWorld({ passkeys: [PHONE, KEY] });
  const offer = await world.session.preparePasskeyUnlock({ rpId: HOST });
  assert.equal(offer.credentials.length, 2);
  world.methods.list = world.methods.list.filter((m) => m.id !== PHONE.id);
  const output = PRF_RESULT.slice();
  await assert.rejects(unlockWith(world, offer, phoneKey({ output })), { code: "method_removed" });
  assert.equal(world.client.called("unlock_prf").length, 0, "the core was not asked");
  assert.equal(world.session.current(), null);
  assert.ok(world.client.locked >= 1, "no vault stays open");

  // Changed (a method with the same credential and another salt): not the key the passkey made.
  const changed = await closedWorld();
  const again = await changed.session.preparePasskeyUnlock({ rpId: HOST });
  changed.methods.list = changed.methods.list.map((m) => ({ ...m, salt: filled(32, 0x99) }));
  await assert.rejects(unlockWith(changed, again, phoneKey()), { code: "method_changed" });
  assert.equal(changed.client.called("unlock_prf").length, 0);
});

// ---------------------------------------------------------------------------------------------- the call and its answer

test("a_record_that_pins_a_server_key_is_given_that_key_because_a_passkey_unlock_shows_none", async () => {
  const world = await closedWorld();
  const db = await world.store.open();
  await run(db, ["pinned"], "readwrite", async ([pinned]) => void (await req(pinned.clear())));
  await world.store.savePinned(db, world.session.serverUrl, ACCOUNT, EMAIL, pinnedRecord({ serverKey: 9 }));
  const offer = await world.session.preparePasskeyUnlock({ rpId: HOST });
  await unlockWith(world, offer, phoneKey());
  const [call] = world.prfUnlocks;
  assert.deepEqual([...call.pinned.server_public_key], [...filled(32, 9)]);
  assert.deepEqual([...call.pinned.record.server_public_key], [...filled(32, 9)]);
  // A record that pins none is given none.
  const plain = await closedWorld();
  await unlockWith(plain, await plain.session.preparePasskeyUnlock({ rpId: HOST }), phoneKey());
  assert.equal("server_public_key" in plain.prfUnlocks[0].pinned, false);
});

test("the_call_asks_for_the_listed_credentials_with_a_salt_each_and_user_verification", async () => {
  const world = await closedWorld({ passkeys: [PHONE, KEY] });
  const offer = await world.session.preparePasskeyUnlock({ rpId: HOST });
  const credentials = phoneKey();
  await unlockWith(world, offer, credentials);
  assert.equal(credentials.calls.get.length, 1, "exactly one WebAuthn call");
  const { publicKey } = credentials.calls.get[0];
  assert.equal(publicKey.rpId, HOST, "the exact host of the vault");
  assert.equal(publicKey.userVerification, "required");
  assert.deepEqual(publicKey.allowCredentials.map((c) => hex(new Uint8Array(c.id))), [hex(PHONE.credential), hex(KEY.credential)]);
  assert.deepEqual(Object.keys(publicKey.extensions.prf), ["evalByCredential"], "no single `eval`: each credential has its own salt");
  const by = publicKey.extensions.prf.evalByCredential;
  assert.deepEqual(Object.keys(by).sort(), [b64u.encode(PHONE.credential), b64u.encode(KEY.credential)].sort());
  assert.equal(hex(by[b64u.encode(PHONE.credential)].first), hex(PHONE.salt));
  assert.equal(hex(by[b64u.encode(KEY.credential)].first), hex(KEY.salt));
  // The core was given the wrap of the passkey that answered, the pinned record and the result.
  assert.equal(world.prfUnlocks.length, 1);
  const [call] = world.prfUnlocks;
  assert.equal(call.pinned.kind, "pinned");
  assert.equal(call.wrap.method.type, "prf");
  assert.equal(hex(call.wrap.method.credential_id), hex(PHONE.credential));
  assert.equal(hex(call.wrap.method.prf_salt), hex(PHONE.salt));
  assert.equal(hex(call.output), hex(PRF_RESULT));
  assert.equal(world.session.current().accountId, offer.accountId);
});

test("a_click_makes_the_webauthn_call_before_anything_is_awaited", async () => {
  const world = await closedWorld();
  const offer = await world.session.preparePasskeyUnlock({ rpId: HOST });
  const credentials = phoneKey();
  const pending = unlockWith(world, offer, credentials);
  // Nothing has been awaited by the caller: the call is already made.
  assert.equal(credentials.calls.get.length, 1);
  await pending;
  assert.equal(credentials.calls.get.length, 1, "and only one");

  // On the page: the click handler hands the call over at once, and a second click while it runs does nothing.
  await withDom(async () => {
    const session = fakeSession();
    let calls = 0;
    let release;
    session.preparePasskeyUnlock = async () => ({ accountId: "aa".repeat(16), email: "ada@example.test", rpId: HOST, credentials: [{ id: CREDENTIAL, salt: SALT }] });
    session.unlockWithPasskey = (given) => {
      calls += 1;
      assert.equal(given.rpId, HOST);
      return new Promise((resolve) => void (release = resolve));
    };
    const host = unlockScreen({ session, t, go: () => undefined, onUnlocked: () => undefined });
    await settle();
    const button = find(host, "passkey-unlock");
    assert.ok(button, "the button is there");
    const clicked = fire(button, "click");
    assert.equal(calls, 1, "the session was called inside the click, before any await");
    await clicked;
    assert.equal(button.disabled, true, "busy");
    assert.equal(find(host, "password").disabled, true);
    assert.ok(textOf(find(host, "status")).includes("vault.unlock.passkey.busy"));
    release();
    await settle();
    assert.equal(button.disabled, false);
  });
});

test("a_wrong_or_missing_prf_result_gives_one_plain_error", async () => {
  const messages = new Set();
  const run1 = async (label, { credentials, handlers }) => {
    const world = await closedWorld({ handlers });
    const offer = await world.session.preparePasskeyUnlock({ rpId: HOST });
    await assert.rejects(unlockWith(world, offer, credentials), (error) => {
      assert.equal(error.code, "passkey_unlock_failed", label);
      messages.add(`${error.code}|${error.message}`);
      return true;
    });
    assert.equal(world.session.current(), null, label);
    return world;
  };
  // The authenticator gave no result.
  await run1("missing", { credentials: phoneKey({ output: null }) });
  // The wrong size, shorter and longer: the core is never asked.
  for (const size of [16, 31, 33, 64]) {
    const world = await run1(`size ${size}`, { credentials: phoneKey({ output: filled(size, 0x5a) }) });
    assert.equal(world.client.called("unlock_prf").length, 0, `size ${size}`);
  }
  // A key that does not open the wrap: the core's one `decrypt`, said in the same words.
  const wrong = await run1("wrong", { credentials: phoneKey(), handlers: { unlock_prf: () => { throw coded("decrypt"); } } });
  assert.equal(wrong.client.called("unlock_prf").length, 1);
  assert.equal(messages.size, 1, "the same error whichever it was");
  // Its text, in both languages, tells nothing about which.
  for (const lang of ["en", "nb"]) assert.ok(read(lang)["vault.unlock.passkey_error.passkey_unlock_failed"].length > 10);

  // The user was not verified: not a result at all, and said so.
  const unverified = await closedWorld();
  const offer = await unverified.session.preparePasskeyUnlock({ rpId: HOST });
  await assert.rejects(unlockWith(unverified, offer, phoneKey({ getUv: false })), { code: "passkey_not_verified" });
  assert.equal(unverified.client.called("unlock_prf").length, 0);
  // Another credential than the ones asked for.
  const other = await closedWorld();
  const again = await other.session.preparePasskeyUnlock({ rpId: HOST });
  await assert.rejects(unlockWith(other, again, phoneKey({ otherId: true })), { code: "passkey_other_credential" });
  // An answer made for another host.
  const elsewhere = await closedWorld();
  const third = await elsewhere.session.preparePasskeyUnlock({ rpId: HOST });
  await assert.rejects(unlockWith(elsewhere, third, phoneKey({ host: "other.example.test" })), { code: "passkey_bad_answer" });
  // The user closes the prompt.
  const closed = await closedWorld();
  const fourth = await closed.session.preparePasskeyUnlock({ rpId: HOST });
  await assert.rejects(unlockWith(closed, fourth, phoneKey({ fail: { get: "NotAllowedError" }, clock: { at: 0 } })), { code: "passkey_blocked" });
});

test("a_refused_answer_still_wipes_the_browsers_own_result_buffer", async () => {
  // The browser's `results.first` is the real PRF output. When the answer is refused before the result is read, the buffer is
  // wiped all the same (best effort: script cannot reach a copy the engine made).
  const keep = (credentials) => {
    const held = PRF_RESULT.slice().buffer;
    const get = credentials.get;
    credentials.get = async (options) => {
      const answer = await get(options);
      const results = { prf: { results: { first: held } } };
      answer.getClientExtensionResults = () => results;
      return answer;
    };
    return held;
  };
  const zero = (buffer) => new Uint8Array(buffer).every((byte) => byte === 0);
  // The unlock: another credential, not verified, another host.
  for (const [extra, code] of [[{ otherId: true }, "passkey_other_credential"], [{ getUv: false }, "passkey_not_verified"], [{ host: "other.example.test" }, "passkey_bad_answer"]]) {
    const world = await closedWorld();
    const offer = await world.session.preparePasskeyUnlock({ rpId: HOST });
    const credentials = phoneKey(extra);
    const held = keep(credentials);
    assert.equal(zero(held), false, "the control: the buffer holds the result before");
    await assert.rejects(unlockWith(world, offer, credentials), { code });
    assert.equal(zero(held), true, `${code}: the browser's buffer is wiped`);
  }
  // The same for the evaluation that registers a passkey.
  for (const [extra, code] of [[{ otherId: true }, "passkey_other_credential"], [{ getUv: false }, "passkey_not_verified"]]) {
    const credentials = phoneKey(extra);
    const held = keep(credentials);
    await assert.rejects(evaluatePasskey({ rpId: HOST, credentialId: PHONE.credential, salt: SALT }, ceremonyDeps(credentials)), { code });
    assert.equal(zero(held), true, `${code}: the browser's buffer is wiped (registration)`);
  }
});

test("a_salt_of_the_wrong_size_gives_the_plain_error_and_not_a_type_error", async () => {
  // The call itself: nothing is asked of the passkey, and the error is the one of an unlock that did not work.
  const credentials = phoneKey();
  await assert.rejects(
    evaluateOneOf({ rpId: HOST, credentials: [{ id: PHONE.credential, salt: filled(16, 0x61) }], getAssertion: (publicKey) => credentials.get({ publicKey }) }, ceremonyDeps(credentials)),
    { code: "passkey_unlock_failed" },
  );
  assert.equal(credentials.calls.get.length, 0);
  // A list with such a row is not read at all (the wire wants 32 bytes), so nothing is offered and the password is the way.
  const world = await closedWorld({ passkeys: [PHONE, { ...KEY, salt: filled(16, 0x61) }] });
  assert.equal(await world.session.preparePasskeyUnlock({ rpId: HOST }), null);
});

test("the_unlock_page_is_drawn_before_the_offer_is_known", async () => {
  await withDom(async () => {
    const session = fakeSession();
    let release;
    session.preparePasskeyUnlock = () => new Promise((resolve) => void (release = resolve));
    session.unlockWithPasskey = async () => undefined;
    const host = unlockScreen({ session, t, go: () => undefined, onUnlocked: () => undefined });
    await settle();
    assert.ok(find(host, "password"), "the password form is there while the offer is still being read");
    assert.equal(find(host, "passkey-section"), null);
    release({ accountId: "aa".repeat(16), email: "ada@example.test", rpId: HOST, credentials: [{ id: CREDENTIAL, salt: SALT }] });
    await settle();
    assert.ok(find(host, "passkey-section"), "the button comes when the offer is known");
    // An offer that fails to read leaves the page as it was.
    const failing = fakeSession();
    failing.preparePasskeyUnlock = async () => {
      throw new Error("no answer");
    };
    const other = unlockScreen({ session: failing, t, go: () => undefined, onUnlocked: () => undefined });
    await settle();
    assert.ok(find(other, "password"));
    assert.equal(find(other, "passkey-section"), null);
  });
});

// ----------------------------------------------------------------------------------------------- the checks after it

test("the_manifest_and_floors_are_checked_after_a_prf_unlock", async () => {
  // The way it goes: the core opens the vault under the pinned record, then the floors of the manifest are added, the
  // server's list is compared with the manifest, the account key is compared, and only then is the record kept.
  const raised = pinnedRecord({ floors: [["password", 4], ["recovery", 3]] });
  const world = await closedWorld({ handlers: { seed_pinned: () => raised } });
  const offer = await world.session.preparePasskeyUnlock({ rpId: HOST });
  const before = await recordOf(world);
  assert.ok(before, "the device has the record");
  await unlockWith(world, offer, phoneKey());
  assert.deepEqual(world.client.calls.map((c) => c.method).filter((m) => ["unlock_prf", "seed_pinned", "check_server_methods"].includes(m)), ["unlock_prf", "seed_pinned", "check_server_methods"]);
  const kept = await recordOf(world);
  assert.notDeepEqual(kept.kek_generation_max, before.kek_generation_max, "the floors of the manifest were kept");
  assert.deepEqual(kept.kek_generation_max.map((f) => [f.type, f.generation]), [["password", 4], ["recovery", 3]]);
  const [call] = world.prfUnlocks;
  assert.equal(call.pinned.kind, "pinned");
  assert.equal(hex(call.pinned.record.account_id), offer.accountId);

  // Each refusal closes the vault, keeps the record as it was and is passed on by its own code.
  /** @type {Array<[string, Record<string, Function>]>} */
  const refusals = [
    ["method_list_changed", { check_server_methods: () => { throw coded("method_list_changed"); } }],
    ["method_list_unknown", { check_server_methods: () => { throw coded("method_list_unknown"); } }],
    ["pinned_auth_key", { seed_pinned: () => pinnedRecord({ pkA: 9 }) }],
    ["pinned_kek_generation", { unlock_prf: () => { throw coded("pinned_kek_generation"); } }],
    ["pinned_floor_downgrade", { unlock_prf: () => { throw coded("pinned_floor_downgrade"); } }],
    ["pinned_epoch_ahead", { unlock_prf: () => { throw coded("pinned_epoch_ahead"); } }],
    ["pinned_vk_epoch", { unlock_prf: () => { throw coded("pinned_vk_epoch"); } }],
  ];
  for (const [code, handlers] of refusals) {
    const bad = await closedWorld({ handlers });
    const asked = await bad.session.preparePasskeyUnlock({ rpId: HOST });
    const was = await recordOf(bad);
    await assert.rejects(unlockWith(bad, asked, phoneKey()), { code }, code);
    assert.equal(bad.session.current(), null, `${code}: no vault is open`);
    assert.ok(bad.client.locked >= 1, `${code}: the vault was closed`);
    const now = await recordOf(bad);
    assert.deepEqual(now, was, `${code}: the record is as it was`);
    assert.deepEqual(bad.requests.filter((r) => r.method !== "GET"), [], `${code}: nothing was written to the server`);
    assert.equal(bad.server.state.signedIn, true, `${code}: the vault session stays (the password still works)`);
  }
  // A passkey is never the first unlock of a device: with no record the core is not asked.
  const none = await closedWorld();
  const offered = await none.session.preparePasskeyUnlock({ rpId: HOST });
  await run(await none.store.open(), ["pinned"], "readwrite", async ([pinned]) => void (await req(pinned.clear())));
  await assert.rejects(unlockWith(none, offered, phoneKey()), { code: "session_ended" });
  assert.equal(none.client.called("unlock_prf").length, 0);
});

test("a_newer_vault_key_epoch_is_the_attack_warning", () => {
  for (const lang of ["en", "nb"]) {
    const texts = read(lang);
    const say = createI18n({ en: read("en"), nb: read("nb") }, lang).t;
    const text = passkeyUnlockErrorText(say, coded("pinned_epoch_ahead"));
    assert.equal(text, describeError(say, coded("pinned_epoch_ahead")));
    assert.equal(text, texts["account.error.pinned_epoch_ahead"]);
  }
  assert.match(read("en")["account.error.pinned_epoch_ahead"], /can be an attack/);
});

// ------------------------------------------------------------------------------------------------------------- the page

test("the_unlock_page_offers_the_passkey_and_opens_the_vault_from_the_click", async () => {
  await withDom(async () => {
    const world = await closedWorld();
    const credentials = phoneKey();
    let unlocked = 0;
    const session = pageSession(world, credentials);
    const host = unlockScreen({ session, t, go: () => undefined, onUnlocked: () => void (unlocked += 1) });
    await settle();
    assert.ok(find(host, "passkey-section"));
    assert.notEqual(find(host, "passkey-section").hidden, true);
    assert.equal(credentials.calls.get.length, 0, "the passkey is not asked for before the click");
    await fire(find(host, "passkey-unlock"), "click");
    await settle(40);
    assert.equal(credentials.calls.get.length, 1);
    assert.equal(unlocked, 1);
    assert.equal(world.session.current().email, "ada@example.test");
    assert.equal(world.requests.some((r) => r.method === "POST" && r.url.includes("/opaque/")), false, "no password sign-in ran");
  });
});

test("a_refusal_at_once_says_what_to_check_and_a_gone_method_is_not_offered_again", async () => {
  for (const lang of ["en", "nb"]) {
    const texts = read(lang);
    const say = createI18n({ en: read("en"), nb: read("nb") }, lang).t;
    await withDom(async () => {
      const failing = (code) => {
        const session = fakeSession();
        session.preparePasskeyUnlock = async () => ({ accountId: "aa".repeat(16), email: "ada@example.test", rpId: HOST, credentials: [{ id: CREDENTIAL, salt: SALT }] });
        session.unlockWithPasskey = async () => {
          throw coded(code);
        };
        return session;
      };
      const moves = [];
      const open = async (code) => {
        const host = unlockScreen({ session: failing(code), t: say, go: (p) => moves.push(p), onUnlocked: () => undefined });
        await settle();
        await fire(find(host, "passkey-unlock"), "click");
        await settle();
        return host;
      };
      const blocked = await open("passkey_blocked");
      assert.equal(textOf(find(blocked, "error")).trim(), texts["vault.unlock.passkey_error.passkey_blocked"]);
      const help = find(blocked, "passkey-blocked-help");
      assert.equal(help.hidden, false);
      assert.ok(textOf(help).includes(texts["methods.blocked.other_manager"]));
      assert.ok(textOf(help).includes(texts["methods.blocked.mac"]));
      assert.ok(textOf(help).includes(texts["methods.blocked.windows"]));
      assert.equal(find(blocked, "passkey-unlock").disabled, false, "another try is possible");

      // A prompt the user closed: no help list, and the same click can be made again.
      const cancelled = await open("passkey_cancelled");
      assert.equal(find(cancelled, "passkey-blocked-help").hidden, true);
      assert.equal(textOf(find(cancelled, "error")).trim(), texts["vault.unlock.passkey_error.passkey_cancelled"]);

      // A method that is gone: said, and the button is out of the way (the password is the way).
      const removed = await open("method_removed");
      assert.equal(find(removed, "passkey-section").hidden, true);
      assert.equal(textOf(find(removed, "error")).trim(), texts["vault.unlock.passkey_error.method_removed"]);

      // The refusals of the pins keep their warning text.
      const ahead = await open("pinned_epoch_ahead");
      assert.equal(textOf(find(ahead, "error")).trim(), texts["account.error.pinned_epoch_ahead"]);

      // An ended session goes to the sign-in page.
      await open("session_ended");
      assert.deepEqual(moves, ["/login"]);
    });
  }
});

test("every_passkey_unlock_text_is_in_both_languages", () => {
  const en = read("en");
  const nb = read("nb");
  const keys = Object.keys(en).filter((key) => key.startsWith("vault.unlock.passkey"));
  assert.ok(keys.length >= 16);
  assert.deepEqual(Object.keys(nb).filter((key) => key.startsWith("vault.unlock.passkey")), keys);
  for (const code of PASSKEY_UNLOCK_ERRORS) {
    for (const texts of [en, nb]) assert.ok(texts[`vault.unlock.passkey_error.${code}`], code);
  }
  // The help list reuses the texts of the passkey methods page.
  for (const texts of [en, nb]) for (const key of ["methods.blocked.mac", "methods.blocked.windows", "methods.blocked.other_manager"]) assert.ok(texts[key], key);
});

// ------------------------------------------------------------------------------------------------------------- secrets

test("the_prf_output_is_never_in_storage_console_or_a_request_at_unlock", async () => {
  const forms = sentinelForms(PRF_RESULT);
  const found = (haystack) => forms.filter((form) => haystack.includes(form));
  const consoleLines = [];
  const kinds = ["log", "info", "warn", "error", "debug", "trace"];
  const saved = Object.fromEntries(kinds.map((kind) => [kind, console[kind]]));
  for (const kind of kinds) console[kind] = (...args) => consoleLines.push(args.map((a) => (typeof a === "string" ? a : JSON.stringify(a, (_, v) => (v instanceof Uint8Array ? [...v] : v)))).join(" "));
  const webStorage = () => {
    const data = new Map();
    return { data, getItem: (k) => data.get(k) ?? null, setItem: (k, v) => void data.set(String(k), String(v)), removeItem: (k) => void data.delete(k), clear: () => data.clear() };
  };
  const stubs = { localStorage: webStorage(), sessionStorage: webStorage() };
  const had = Object.fromEntries(Object.keys(stubs).map((name) => [name, Object.getOwnPropertyDescriptor(globalThis, name)]));
  for (const [name, stub] of Object.entries(stubs)) Object.defineProperty(globalThis, name, { value: stub, configurable: true, writable: true });
  const world = await closedWorld();
  let shown = "";
  try {
    await withDom(async () => {
      const credentials = phoneKey();
      const session = pageSession(world, credentials);
      const host = unlockScreen({ session, t, go: () => undefined, onUnlocked: () => undefined });
      await settle();
      await fire(find(host, "passkey-unlock"), "click");
      await settle(40);
      shown = textOf(host) + JSON.stringify([...walk(host)].map((n) => [...(n.attributes?.entries?.() ?? [])]));
    });
  } finally {
    for (const kind of kinds) console[kind] = saved[kind];
    for (const name of Object.keys(stubs)) {
      if (had[name]) Object.defineProperty(globalThis, name, had[name]);
      else delete globalThis[name];
    }
  }
  assert.equal(world.prfUnlocks.length, 1, "the vault was opened with the passkey");
  assert.equal(hex(world.prfUnlocks[0].output), hex(PRF_RESULT), "the core got the result");
  const given = world.client.called("unlock_prf")[0].args[2];
  assert.ok(given.every((byte) => byte === 0), "the array handed to the core is wiped");

  const replacer = (_, v) => (v instanceof Uint8Array ? [...v] : typeof v === "bigint" ? Number(v) : v);
  const coreCalls = JSON.stringify(world.client.calls.filter((c) => c.method !== "unlock_prf").map((c) => [c.method, c.snapshot]), replacer);
  const stored = await dumpDatabase(world.db.store);
  // A control: what the stubs hold is searched, so a value written there would be found.
  stubs.localStorage.setItem("control", forms[0]);
  assert.deepEqual(found(JSON.stringify([...stubs.localStorage.data])), [forms[0]]);
  stubs.localStorage.removeItem("control");
  const where = {
    webStorage: JSON.stringify([...stubs.localStorage.data, ...stubs.sessionStorage.data]),
    requests: JSON.stringify(world.requests, replacer),
    log: world.log.join("\n"),
    console: consoleLines.join("\n"),
    coreCalls,
    stored,
    shown,
  };
  for (const [name, text] of Object.entries(where)) assert.deepEqual(found(text), [], `the PRF result is not in ${name}`);
  assert.ok(shown.length > 0);
  assert.ok(ORIGIN.length > 0);
});

// ------------------------------------------------------------------------------------------------------- the shared file

test("the_shared_flow_never_reads_the_pages_own_browser_objects", () => {
  // The page hands the WebAuthn call in; the file is the extension's too, and must run where there is no page.
  const code = (name) => readFileSync(join(web, "src", "flows", name), "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  const browser = /navigator|location|document|window|localStorage|sessionStorage/;
  assert.doesNotMatch(code("prfUnlock.mjs"), browser);
  assert.doesNotMatch(code("passkeyAnswer.mjs"), browser);
  // A package with the passkey unlock off holds no call to the browser's credentials: the page hands the call in.
  for (const name of ["prfUnlock.mjs", "passkeyAnswer.mjs"]) assert.doesNotMatch(readFileSync(join(web, "src", "flows", name), "utf8"), /credentials\s*\.\s*(?:get|create)/, name);
});

test("without_a_passkey_method_the_unlock_screen_is_as_before", async () => {
  await withDom(async () => {
    const session = fakeSession();
    const host = unlockScreen({ session, t, go: () => undefined, onUnlocked: () => undefined });
    await settle();
    assert.equal(find(host, "passkey-section"), null, "no passkey method: nothing is offered");
    assert.equal(all(host, "passkey-unlock").length, 0);
    assert.ok(find(host, "password"));
  });
});

test("the_origin_of_the_answer_is_a_string_or_a_function_that_says_true", async () => {
  // The browser extension gives a function, because Firefox writes an origin of its own making for an extension's page.
  const credentials = fakeCredentials({ credential: CREDENTIAL });
  const ask = (origin) =>
    evaluateOneOf(
      { rpId: HOST, credentials: [{ id: CREDENTIAL, salt: SALT }], getAssertion: (publicKey) => credentials.get({ publicKey }) },
      { ...ceremonyDeps(credentials), origin },
    ).then((answer) => ({ ok: true, output: answer.output }), (error) => ({ ok: false, code: error.code }));
  assert.equal((await ask(ORIGIN)).ok, true, "the exact string");
  assert.equal((await ask((seen) => seen === ORIGIN)).ok, true, "a function that accepts it");
  assert.deepEqual(await ask("https://evil.example"), { ok: false, code: "passkey_bad_answer" });
  assert.deepEqual(await ask(() => false), { ok: false, code: "passkey_bad_answer" });
  assert.deepEqual(await ask(() => "yes"), { ok: false, code: "passkey_bad_answer" }, "anything but true is a refusal");
});
