// The passkeys that unlock the vault, from the web vault's side: the list, adding one (the password check first, the two
// WebAuthn calls, the core's own body signed and sent), removing one, the page, and that the PRF result goes nowhere but
// into the core. The fake core writes the bodies the way the real one does; the fake credentials answer well-formed data.
import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { createApi } from "../../src/api.mjs";
import { b64u } from "../../src/b64.mjs";
import { createI18n } from "../../src/i18n.mjs";
import { passkeysOffered, checkName, MAX_PASSKEYS } from "../../src/flows/unlockMethods.mjs";
import { signedCall } from "../../src/flows/signedCall.mjs";
import accountRoute from "../../src/routes/account.route.mjs";
import unlockMethodsRoute from "../../src/routes/unlock-methods.route.mjs";
import { autoLockFor } from "../../src/lock.mjs";
import { SHAPES, checkStep, readWire } from "../../src/wire.mjs";
import { offeredRoutes } from "../../src/views/account.mjs";
import { METHODS_ERRORS, formatAaguid, methodsErrorText, unlockMethodsView } from "../../src/views/unlockMethods.mjs";
import { formatMoment } from "../../src/views/common.mjs";
import { cache } from "../../src/store/cache.mjs";
import { byRole, dumpDatabase, filled, fire, settle, textOf, walk } from "./accountHelpers.mjs";
import { accountDocument } from "./accountHelpers.mjs";
import * as vaultHelpers from "./vaultHelpers.mjs";
import { AAGUID, CREDENTIAL, HOST, METHOD_ID, OLD, ORIGIN, PRF_RESULT, SALT, ceremonyDeps, fakeCredentials, passkeyWorld, reauthWith, sentinelForms } from "./methodsHelpers.mjs";
import { web } from "./helpers.mjs";

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const writes = (world) => world.requests.filter((r) => r.method !== "GET");
const MAC = Object.freeze({ id: "6b".repeat(16), credential: Uint8Array.from({ length: 20 }, (_, i) => i + 1), salt: SALT, aaguid: "fbfc3007154e4ecc8c0b6e020557d7bd", name: "Mac", synced: true, createdAt: 1_750_000_000 });
const UNNAMED = Object.freeze({ id: "7c".repeat(16), credential: Uint8Array.from({ length: 20 }, (_, i) => i + 40), salt: SALT, aaguid: "00".repeat(16), name: null, synced: false });

const read = (lang) => {
  const dir = join(web, "src", "locales", lang);
  const out = {};
  for (const name of readdirSync(dir)) Object.assign(out, JSON.parse(readFileSync(join(dir, name), "utf8")));
  return out;
};
const i18n = (lang = "en") => createI18n({ en: read("en"), nb: read("nb") }, lang);

/** Adds a passkey through the session, with the fake credentials; gives what the page would get. */
async function addPasskey(world, credentials, name = "Phone") {
  const deps = ceremonyDeps(credentials);
  const adding = await world.session.beginAddPasskey({ reauth: reauthWith(world), deps, rpId: HOST });
  await adding.create(name);
  return { adding, added: await adding.confirm() };
}

// ------------------------------------------------------------------------------------------------ adding

test("add_needs_reauth_and_sends_a_signed_body_with_aaguid", async () => {
  // A password check that is cancelled stops everything before the first request.
  const cancelled = await passkeyWorld();
  await assert.rejects(
    cancelled.session.beginAddPasskey({ reauth: reauthWith(cancelled, "cancelled"), deps: ceremonyDeps(fakeCredentials()), rpId: HOST }),
    { code: "cancelled" },
  );
  assert.deepEqual(cancelled.log, ["reauth"]);
  assert.equal(cancelled.requests.length, 0);

  const world = await passkeyWorld();
  const credentials = fakeCredentials({ be: true, bs: true });
  const deps = ceremonyDeps(credentials);
  const adding = await world.session.beginAddPasskey({ reauth: reauthWith(world), deps, rpId: HOST });
  assert.deepEqual(world.log, [
    "reauth", // the master password again, first
    "GET /api/auth/session",
    "GET /api/vault/unlock-methods",
    "vault.seed_pinned",
    "vault.check_server_methods", // the list is checked against the manifest as at an unlock
    "vault.prf_salt_new",
  ]);
  assert.equal(adding.count, 0);
  assert.equal(credentials.calls.create.length, 0, "no passkey is made before the click");
  assert.equal(writes(world).length, 0);

  const made = await adding.create("  Phone ");
  assert.deepEqual(made, { synced: true });
  assert.equal(credentials.calls.get.length, 0, "the second call waits for the second click");
  assert.equal(writes(world).length, 0, "nothing is sent while the passkey is only made");

  world.log.length = 0;
  const added = await adding.confirm();
  assert.deepEqual(world.log, [
    "vault.wrap_prf",
    "GET /api/vault/unlock-methods", // the manifest as the server has it now
    "vault.seed_pinned",
    "vault.check_server_methods",
    "vault.manifest_add_method",
    "POST /api/auth/challenge",
    "vault.auth_sign",
    "POST /api/vault/unlock-methods",
  ]);
  assert.deepEqual(added, { id: hex(METHOD_ID), name: "Phone", synced: true, aaguid: hex(AAGUID), addedAt: null });

  // The core was given what the registration told, and the manifest the server holds: the name and the flags go inside the sealed manifest.
  assert.equal(world.adds.length, 1);
  const [add] = world.adds;
  assert.equal(add.label, "  Phone ", "the core reads the name as typed");
  assert.deepEqual([add.be, add.bs, add.current.rev], [true, true, 1]);
  assert.equal(hex(add.aaguid), hex(AAGUID));

  // The bytes that were signed are the bytes the core wrote, and the request carries exactly those, with the nonce and the proof.
  assert.equal(world.signed.length, 1);
  assert.equal(world.signed[0].op, "unlock-method.add");
  assert.deepEqual(world.signed[0].bytes, add.body);
  assert.equal(world.posts.length, 1);
  assert.deepEqual(world.posts[0].body, JSON.parse(new TextDecoder().decode(add.body)), "the server received the body of the core");
  assert.equal(world.posts[0].body.aaguid, hex(AAGUID), "the AAGUID is in the body, as display data");
  assert.equal(world.posts[0].body.method_type, 3);
  assert.ok(world.posts[0].headers["Ferret-Nonce"] && world.posts[0].headers["Ferret-Proof"]);
  const sentText = JSON.stringify(world.posts[0].body);
  assert.ok(!sentText.includes("Phone"), "the name is only in the sealed manifest");
  assert.equal(world.methods.list.length, 1);

  // A password check that has run out while the passkey was used is asked for once more, and the same change goes again.
  const stale = await passkeyWorld({ postStatus: (n) => (n === 0 ? 403 : 200) });
  const again = await stale.session.beginAddPasskey({ reauth: reauthWith(stale), deps: ceremonyDeps(fakeCredentials()), rpId: HOST });
  await again.create("Phone");
  stale.log.length = 0;
  await again.confirm();
  assert.equal(stale.log.filter((line) => line === "reauth").length, 1, "the password is asked for again");
  assert.equal(stale.posts.length, 2);
  assert.deepEqual(stale.posts[0].body, stale.posts[1].body, "the same change is sent again");
  assert.equal(stale.adds.length, 1, "the manifest is made once");
});

test("add_needs_one_get_after_create_and_compares_when_create_gave_a_result", async () => {
  // The registration gave a result and the evaluation gives the same: one get, and the key is made from it.
  const world = await passkeyWorld();
  const credentials = fakeCredentials();
  const { added } = await addPasskey(world, credentials);
  assert.equal(credentials.calls.create.length, 1);
  assert.equal(credentials.calls.get.length, 1, "exactly one evaluation");
  assert.equal(world.wraps.length, 1);
  assert.equal(hex(world.wraps[0].output), hex(PRF_RESULT));
  assert.equal(hex(world.wraps[0].salt), hex(SALT), "the salt of the registration is the salt of the key");
  assert.equal(world.wraps[0].generation, 1);
  assert.equal(hex(world.wraps[0].methodId), hex(METHOD_ID), "the id comes from the random source");
  assert.equal(added.synced, false);

  // The same salt in both calls, the credential that was made in the second.
  const [create] = credentials.calls.create;
  const [get] = credentials.calls.get;
  assert.equal(hex(new Uint8Array(create.publicKey.extensions.prf.eval.first)), hex(SALT));
  assert.equal(hex(new Uint8Array(get.publicKey.extensions.prf.eval.first)), hex(SALT));
  assert.equal(get.publicKey.allowCredentials.length, 1);
  assert.equal(hex(new Uint8Array(get.publicKey.allowCredentials[0].id)), hex(CREDENTIAL));

  // The registration gave no result: the evaluation is the only one, and it is used.
  const none = await passkeyWorld();
  const noResult = fakeCredentials({ atCreate: false });
  await addPasskey(none, noResult);
  assert.equal(noResult.calls.get.length, 1);
  assert.equal(none.posts.length, 1);

  // The registration gave another result than the evaluation does: the passkey is no stable key, and nothing is made of it.
  const different = await passkeyWorld();
  const unstable = fakeCredentials({ atCreate: Uint8Array.from({ length: 32 }, (_, i) => i + 1) });
  const adding = await different.session.beginAddPasskey({ reauth: reauthWith(different), deps: ceremonyDeps(unstable), rpId: HOST });
  await adding.create("Phone");
  await assert.rejects(adding.confirm(), { code: "passkey_unstable" });
  assert.equal(different.wraps.length, 0, "no key was made");
  assert.equal(writes(different).length, 0, "nothing was sent");
  await assert.rejects(adding.confirm(), { code: "passkey_sequence" }, "the attempt is over");
});

test("a_result_that_is_not_32_bytes_or_lacks_uv_is_refused_and_nothing_is_sent", async () => {
  /** [what is wrong, credentials, the code, which call refuses] */
  const cases = [
    ["a result of 31 bytes", { atCreate: false, output: PRF_RESULT.slice(0, 31) }, "passkey_bad_output", "confirm"],
    ["a result of 33 bytes", { atCreate: false, output: new Uint8Array(33).fill(7) }, "passkey_bad_output", "confirm"],
    ["a result of 31 bytes at registration", { atCreate: PRF_RESULT.slice(0, 31) }, "passkey_bad_output", "create"],
    ["no UV at registration", { uv: false }, "passkey_not_verified", "create"],
    ["no UV at the evaluation", { getUv: false }, "passkey_not_verified", "confirm"],
    ["an authenticator without the PRF", { enabled: false }, "passkey_no_prf", "create"],
    ["no result at the evaluation", { atCreate: false, output: null }, "passkey_no_output", "confirm"],
    ["another credential at the evaluation", { otherId: true }, "passkey_other_credential", "confirm"],
    ["another BE flag at the evaluation", { be: false, getBe: true }, "passkey_bad_answer", "confirm"],
    ["another relying party", { host: "other.example.test" }, "passkey_bad_answer", "create"],
  ];
  for (const [what, options, code, where] of cases) {
    const world = await passkeyWorld();
    const credentials = fakeCredentials(options);
    const adding = await world.session.beginAddPasskey({ reauth: reauthWith(world), deps: ceremonyDeps(credentials), rpId: HOST });
    if (where === "create") {
      await assert.rejects(adding.create("Phone"), { code }, what);
    } else {
      await adding.create("Phone");
      await assert.rejects(adding.confirm(), { code }, what);
    }
    assert.equal(writes(world).length, 0, `${what}: nothing is sent`);
    assert.equal(world.wraps.length, 0, `${what}: no key is made`);
    assert.equal(world.adds.length, 0, `${what}: no manifest is made`);
  }
});

test("a_ferret_stored_passkey_cannot_become_an_unlock_method", async () => {
  // The vault holds a passkey item with this credential id: it would live in the vault it has to open.
  const world = await passkeyWorld({ items: [{ id: "c1".repeat(16), credential: CREDENTIAL }, { id: "c2".repeat(16), credential: filled(10, 5) }] });
  const credentials = fakeCredentials();
  const adding = await world.session.beginAddPasskey({ reauth: reauthWith(world), deps: ceremonyDeps(credentials), rpId: HOST });
  await adding.create("Phone");
  await assert.rejects(adding.confirm(), { code: "passkey_stored_here" });
  // The core was told every passkey of the vault, read from the rows this device holds.
  assert.equal(world.wraps.length, 1);
  assert.deepEqual(world.wraps[0].storedIds.map(hex).sort(), [hex(CREDENTIAL), hex(filled(10, 5))].sort());
  assert.equal(writes(world).length, 0, "nothing is sent");
  assert.equal(world.adds.length, 0);

  // Ferret's own authenticator (or a refusal of the core for any other reason of the same kind) is the same refusal.
  const own = await passkeyWorld({ refuseWrap: true });
  const ownAdding = await own.session.beginAddPasskey({ reauth: reauthWith(own), deps: ceremonyDeps(fakeCredentials()), rpId: HOST });
  await ownAdding.create("Phone");
  await assert.rejects(ownAdding.confirm(), { code: "passkey_stored_here" });
  assert.equal(writes(own).length, 0);

  // A vault with no passkey items says so with the marker, never with an empty list.
  const none = await passkeyWorld();
  await addPasskey(none, fakeCredentials());
  assert.equal(none.wraps[0].storedIds, "no_stored_passkeys");
});

test("the_registration_asks_for_the_exact_host_with_user_verification", async () => {
  const world = await passkeyWorld({ passkeys: [OLD] });
  const credentials = fakeCredentials();
  await addPasskey(world, credentials);
  const { publicKey } = credentials.calls.create[0];
  assert.equal(publicKey.rp.id, HOST, "the relying party is the exact host, never a parent domain");
  assert.equal(publicKey.authenticatorSelection.userVerification, "required");
  assert.equal(publicKey.authenticatorSelection.residentKey, "discouraged");
  assert.equal(publicKey.attestation, "none");
  assert.deepEqual(publicKey.pubKeyCredParams.map((p) => p.alg), [-7, -257]);
  assert.deepEqual(publicKey.excludeCredentials.map((c) => hex(c.id)), [hex(OLD.credential)], "a passkey that is a method already is not made again");
  assert.equal(credentials.calls.get[0].publicKey.rpId, HOST);
  assert.equal(credentials.calls.get[0].publicKey.userVerification, "required");
  // The user handle names nobody: it is not the account id or the e-mail address.
  assert.ok(!hex(new Uint8Array(publicKey.user.id)).includes("ab".repeat(16)));
});

test("a_registration_that_fails_at_once_says_another_provider_may_be_in_the_way", async () => {
  for (const [name, after, code] of [
    ["NotAllowedError", 100, "passkey_blocked"],
    ["NotAllowedError", 30_000, "passkey_cancelled"],
    ["InvalidStateError", 100, "passkey_exists"],
    ["NotSupportedError", 100, "passkey_unsupported"],
    ["SecurityError", 100, "passkey_security"],
    ["OperationError", 100, "passkey_failed"],
  ]) {
    const world = await passkeyWorld();
    const clock = { at: 0 };
    const credentials = fakeCredentials({ fail: { create: name }, clock, failAfter: after });
    const adding = await world.session.beginAddPasskey({ reauth: reauthWith(world), deps: ceremonyDeps(credentials, { clock }), rpId: HOST });
    await assert.rejects(adding.create("Phone"), { code }, `${name} after ${after} ms`);
    assert.equal(writes(world).length, 0);
  }
  // The page shows the three things to check, in both languages, only for the refusal at once.
  for (const lang of ["en", "nb"]) {
    const texts = read(lang);
    const page = await withPage(await passkeyWorld(), { credentials: fakeCredentials({ fail: { create: "NotAllowedError" }, clock: { at: 0 }, failAfter: 0 }), lang });
    await openForm(page);
    byRole(page.root, "methods-name-input").value = "Phone";
    await fire(byRole(page.root, "methods-name-form"), "submit");
    await settle();
    const help = byRole(page.root, "methods-blocked-help");
    assert.ok(help, lang);
    assert.ok(textOf(help).includes(texts["methods.blocked.mac"]));
    assert.ok(textOf(help).includes(texts["methods.blocked.windows"]));
    assert.ok(textOf(help).includes(texts["methods.blocked.other_manager"]));
    assert.ok(textOf(byRole(page.root, "methods-error")).includes(texts["methods.error.passkey_blocked"]));
    page.done();
  }
});

test("a_name_is_checked_before_the_passkey_is_made_and_the_most_is_ten_passkeys", async () => {
  const world = await passkeyWorld();
  const credentials = fakeCredentials();
  const adding = await world.session.beginAddPasskey({ reauth: reauthWith(world), deps: ceremonyDeps(credentials), rpId: HOST });
  const rlo = String.fromCharCode(0x202e);
  const zwsp = String.fromCharCode(0x200b);
  const bom = String.fromCharCode(0xfeff);
  for (const [name, code] of [
    ["", "method_name_empty"], ["   ", "method_name_empty"], ["a".repeat(65), "method_name_too_long"],
    [`a${rlo}b`, "method_name_bad_character"], [`a${zwsp}b`, "method_name_bad_character"], [`${bom}a`, "method_name_bad_character"],
    ["a\nb", "method_name_bad_character"], ["a\u0000b", "method_name_bad_character"],
  ]) {
    await assert.rejects(adding.create(name), { code }, JSON.stringify(name));
  }
  assert.equal(credentials.calls.create.length, 0, "a name the core would refuse leaves no passkey behind");
  assert.equal(checkName("a".repeat(64)), "a".repeat(64));
  assert.equal(checkName("é".repeat(64)), "é".repeat(64));
  // A name of 64 characters after NFC counts as 64: a letter and its combining accent are one.
  const decomposed = `e${String.fromCharCode(0x301)}`.repeat(64);
  assert.equal(checkName(decomposed), decomposed);
  await adding.create("Phone");

  const full = await passkeyWorld({
    passkeys: Array.from({ length: MAX_PASSKEYS }, (_, i) => ({ ...OLD, id: String(i + 10).repeat(16), credential: filled(8, i + 1), name: `Key ${i}` })),
  });
  const more = fakeCredentials();
  await assert.rejects(full.session.beginAddPasskey({ reauth: reauthWith(full), deps: ceremonyDeps(more), rpId: HOST }), { code: "too_many_passkeys" });
  assert.equal(more.calls.create.length, 0);
});

test("a_get_that_was_closed_can_be_tried_again_from_the_next_click", async () => {
  const world = await passkeyWorld();
  const credentials = fakeCredentials({ fail: { get: "NotAllowedError" }, failTimes: 1, clock: { at: 0 }, failAfter: 5_000 });
  const clock = { at: 0 };
  const deps = ceremonyDeps(credentials, { clock });
  const adding = await world.session.beginAddPasskey({ reauth: reauthWith(world), deps, rpId: HOST });
  await adding.create("Phone");
  await assert.rejects(adding.confirm(), (error) => ["passkey_cancelled", "passkey_blocked"].includes(error.code));
  assert.equal(world.posts.length, 0);
  const added = await adding.confirm();
  assert.equal(added.name, "Phone");
  assert.equal(world.posts.length, 1);
  assert.equal(credentials.calls.get.length, 2);
  assert.equal(credentials.calls.create.length, 1, "the passkey is made once");
});

test("the_passkeys_the_vault_stores_are_read_after_the_new_credential_exists", async () => {
  const world = await passkeyWorld();
  const credentials = fakeCredentials();
  const original = credentials.create.bind(credentials);
  credentials.create = async (options) => {
    const made = await original(options);
    // A provider of Ferret's own saves the new passkey into the vault while it is being made: the row arrives after the
    // click, so a list read before the click would not have it.
    const id = "d4".repeat(16);
    world.stored.set(id, CREDENTIAL);
    await cache.putRows(await world.store.open(), world.scope, [{ itemId: id, rev: 1, seq: 9, deleted: false, envelope: filled(40, 1), tag: filled(32, 2) }]);
    return made;
  };
  const adding = await world.session.beginAddPasskey({ reauth: reauthWith(world), deps: ceremonyDeps(credentials), rpId: HOST });
  await adding.create("Phone");
  await assert.rejects(adding.confirm(), { code: "passkey_stored_here" });
  assert.equal(world.wraps.length, 1);
  assert.deepEqual(world.wraps[0].storedIds.map(hex), [hex(CREDENTIAL)]);
  assert.equal(writes(world).length, 0);
});

test("a_cancel_while_a_passkey_prompt_is_open_writes_nothing_and_keeps_nothing", async () => {
  for (const call of ["create", "get"]) {
    const world = await passkeyWorld();
    const credentials = fakeCredentials();
    let release = () => {};
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const original = credentials[call].bind(credentials);
    credentials[call] = async (options) => {
      const answered = await original(options);
      await gate;
      return answered;
    };
    const adding = await world.session.beginAddPasskey({ reauth: reauthWith(world), deps: ceremonyDeps(credentials), rpId: HOST });
    if (call === "create") {
      // The page is locked or left while the browser's prompt is open.
      const pending = adding.create("Phone");
      adding.cancel();
      release();
      await assert.rejects(pending, { code: "cancelled" });
      await assert.rejects(adding.confirm(), { code: "passkey_sequence" });
      assert.equal(credentials.calls.get.length, 0, "no second call");
    } else {
      await adding.create("Phone");
      const pending = adding.confirm();
      adding.cancel();
      release();
      await assert.rejects(pending, { code: "cancelled" });
      assert.equal(world.wraps.length, 0, "no key is made");
    }
    assert.equal(writes(world).length, 0, call);
    assert.equal(world.adds.length, 0, call);
  }
});

// ------------------------------------------------------------------------------------------------ the list

test("the_list_shows_synced_or_this_device_only", async () => {
  const world = await passkeyWorld({ passkeys: [OLD, MAC, UNNAMED] });
  const rows = await world.session.listPasskeys();
  assert.deepEqual(rows, [
    { id: OLD.id, name: "Old laptop", synced: false, aaguid: null, addedAt: 1_700_000_000_000 },
    { id: MAC.id, name: "Mac", synced: true, aaguid: MAC.aaguid, addedAt: 1_750_000_000_000 },
    { id: UNNAMED.id, name: null, synced: false, aaguid: null, addedAt: null },
  ]);
  assert.deepEqual(world.log.slice(0, 4), ["GET /api/auth/session", "GET /api/vault/unlock-methods", "vault.seed_pinned", "vault.check_server_methods"]);

  for (const lang of ["en", "nb"]) {
    const texts = read(lang);
    const page = await withPage(world, { lang });
    await settle();
    const shown = [...walk(page.root)].filter((n) => n.getAttribute?.("data-role") === "methods-row");
    assert.equal(shown.length, 3, lang);
    assert.deepEqual(shown.map((row) => row.getAttribute("data-kind")), ["device", "synced", "device"]);
    const [old, mac, unnamed] = shown;
    assert.equal(textOf(byRole(old, "methods-kind")).trim(), texts["methods.kind.device"]);
    assert.equal(textOf(byRole(mac, "methods-kind")).trim(), texts["methods.kind.synced"]);
    assert.equal(textOf(byRole(mac, "methods-row-name")).trim(), "Mac");
    assert.ok(textOf(byRole(mac, "methods-aaguid")).includes("fbfc3007-154e-4ecc-8c0b-6e020557d7bd"));
    // A zero or missing AAGUID is "unknown", and a passkey without a name is shown as such.
    assert.equal(textOf(byRole(old, "methods-aaguid")).trim(), texts["methods.aaguid_unknown"]);
    assert.equal(textOf(byRole(unnamed, "methods-aaguid")).trim(), texts["methods.aaguid_unknown"]);
    assert.equal(textOf(byRole(unnamed, "methods-row-name")).trim(), texts["methods.list.unnamed"]);
    // When it was added, in the reader's date format; "unknown" when the server does not say.
    const when = (ms) => formatMoment(ms, lang);
    assert.equal(textOf(byRole(old, "methods-added")).trim(), texts["methods.added"].replace("{time}", when(1_700_000_000_000)));
    assert.equal(textOf(byRole(mac, "methods-added")).trim(), texts["methods.added"].replace("{time}", when(1_750_000_000_000)));
    assert.equal(textOf(byRole(unnamed, "methods-added")).trim(), texts["methods.added_unknown"]);
    page.done();
  }
  assert.equal(formatAaguid(MAC.aaguid), "fbfc3007-154e-4ecc-8c0b-6e020557d7bd");
});

test("the_page_says_what_a_passkey_does_and_does_not_do", async () => {
  for (const lang of ["en", "nb"]) {
    const texts = read(lang);
    const page = await withPage(await passkeyWorld(), { lang });
    await settle();
    const what = byRole(page.root, "methods-what");
    for (const key of ["still", "no_password", "synced", "remove", "suspect"]) assert.ok(textOf(what).includes(texts[`methods.what.${key}`]), `${lang} ${key}`);
    assert.ok(textOf(what).includes(texts["methods.what.host"].replace("{site}", HOST)), "the exact host is named");
    assert.ok(byRole(page.root, "methods-empty"), "an empty list says so");
    page.done();
  }
  // The key says the master password and the recovery key still work; the other says where the key is kept after a removal.
  assert.match(read("en")["methods.what.still"], /master password and your recovery key still work/);
  assert.match(read("en")["methods.what.remove"], /Windows, iCloud or your phone/);
  assert.match(read("nb")["methods.what.synced"], /Synkronisert|synkronisert/);
});

// ----------------------------------------------------------------------------------------------- removing

test("remove_needs_reauth_and_updates_the_manifest", async () => {
  const world = await passkeyWorld({ passkeys: [OLD, MAC] });
  await assert.rejects(world.session.removePasskey({ id: OLD.id, reauth: reauthWith(world, "cancelled") }), { code: "cancelled" });
  assert.deepEqual(world.log, ["reauth"]);
  assert.equal(world.requests.length, 0);
  world.log.length = 0;

  const done = await world.session.removePasskey({ id: OLD.id, reauth: reauthWith(world) });
  assert.deepEqual(done, { remaining: 1 });
  assert.deepEqual(world.log, [
    "reauth",
    "GET /api/auth/session",
    "GET /api/vault/unlock-methods",
    "vault.seed_pinned",
    "vault.check_server_methods",
    "vault.manifest_remove_method",
    "POST /api/auth/challenge",
    "vault.auth_sign",
    `DELETE /api/vault/unlock-methods/${OLD.id}`,
  ]);
  assert.deepEqual(world.removes.map((r) => [r.id, r.current.rev]), [[OLD.id, 1]]);
  assert.equal(world.signed[0].op, "unlock-method.remove");
  assert.equal(world.deletes.length, 1);
  assert.equal(world.deletes[0].body.method_id, OLD.id, "the body names the method, and the address does too");
  assert.equal(world.deletes[0].body.manifest.rev, 2, "the next revision of the manifest");
  assert.ok(world.deletes[0].headers["Ferret-Nonce"] && world.deletes[0].headers["Ferret-Proof"]);
  assert.deepEqual((await world.session.listPasskeys()).map((m) => m.id), [MAC.id], "the list is as the manifest has it now");

  // Only a passkey goes this way, and only one that is listed.
  const before = writes(world).length;
  await assert.rejects(world.session.removePasskey({ id: "11".repeat(16), reauth: reauthWith(world) }), { code: "not_a_passkey" });
  await assert.rejects(world.session.removePasskey({ id: "99".repeat(16), reauth: reauthWith(world) }), { code: "method_not_found" });
  await assert.rejects(world.session.removePasskey({ id: "../x", reauth: reauthWith(world) }), TypeError);
  assert.equal(writes(world).length, before, "nothing was sent for them");

  // A password check that has run out is asked for again, and the same change goes again.
  const stale = await passkeyWorld({ passkeys: [OLD], deleteStatus: (n) => (n === 0 ? 403 : 200) });
  await stale.session.removePasskey({ id: OLD.id, reauth: reauthWith(stale) });
  assert.equal(stale.deletes.length, 2);
  assert.deepEqual(stale.deletes[0].body, stale.deletes[1].body);
  assert.equal(stale.removes.length, 1);
});

test("a_change_the_server_does_not_confirm_is_said_to_be_unconfirmed", async () => {
  const world = await passkeyWorld({ passkeys: [OLD], deleteStatus: 502 });
  await assert.rejects(world.session.removePasskey({ id: OLD.id, reauth: reauthWith(world) }), { code: "method_unconfirmed" });
  // A refusal that says plainly it changed nothing is not "unconfirmed".
  const conflict = await passkeyWorld({ passkeys: [OLD], deleteStatus: 409 });
  await assert.rejects(conflict.session.removePasskey({ id: OLD.id, reauth: reauthWith(conflict) }), { code: "write_conflict" });
  const added = await passkeyWorld({ postStatus: 409 });
  const adding = await added.session.beginAddPasskey({ reauth: reauthWith(added), deps: ceremonyDeps(fakeCredentials()), rpId: HOST });
  await adding.create("Phone");
  await assert.rejects(adding.confirm(), { code: "write_conflict" });
});

// ------------------------------------------------------------------------------------------ the page itself

/**
 * The page over the world, with a fake document. `credentials` are the fake passkeys.
 */
async function withPage(world, { credentials = fakeCredentials(), lang = "en", win = {} } = {}) {
  const saved = globalThis.document;
  globalThis.document = accountDocument();
  const deps = ceremonyDeps(credentials);
  const reauth = reauthWith(world);
  const root = unlockMethodsView({
    t: i18n(lang).t,
    site: HOST,
    locale: lang,
    load: () => world.session.listPasskeys(),
    begin: () => world.session.beginAddPasskey({ reauth, deps, rpId: HOST }),
    remove: (id) => world.session.removePasskey({ id, reauth }),
    win,
  });
  return {
    root, credentials, deps,
    done: () => {
      if (saved === undefined) delete globalThis.document;
      else globalThis.document = saved;
    },
  };
}

/** Presses "Add a passkey" and waits for the name form. */
async function openForm(page) {
  await fire(byRole(page.root, "methods-add"), "click");
  await settle();
}

test("the_page_adds_a_passkey_with_one_webauthn_call_for_each_click", async () => {
  const world = await passkeyWorld();
  const calls = [];
  const credentials = fakeCredentials();
  // What the page had done when each call was made: nothing but the click, no request and no step in between.
  for (const method of ["create", "get"]) {
    const original = credentials[method].bind(credentials);
    credentials[method] = (options) => {
      calls.push({ method, requests: world.requests.length, log: world.log.length });
      return original(options);
    };
  }
  const page = await withPage(world, { credentials });
  try {
    await settle();
    const before = { requests: world.requests.length, log: world.log.length };
    assert.equal(byRole(page.root, "methods-name-form").hidden, true);
    await openForm(page);
    assert.equal(byRole(page.root, "methods-name-form").hidden, false, "the name form follows the password check");
    assert.equal(byRole(page.root, "methods-add").hidden, true);
    assert.ok(world.log.includes("reauth"));
    assert.equal(calls.length, 0, "no passkey call before the first click on the form");

    // An empty name is refused before the passkey is made.
    await fire(byRole(page.root, "methods-name-form"), "submit");
    await settle();
    assert.equal(calls.length, 0);
    assert.equal(byRole(page.root, "methods-error").hidden, false);
    assert.ok(textOf(byRole(page.root, "methods-error")).includes(read("en")["methods.error.method_name_empty"]));

    const atClick = { requests: world.requests.length, log: world.log.length };
    byRole(page.root, "methods-name-input").value = "Phone";
    await fire(byRole(page.root, "methods-name-form"), "submit");
    await settle();
    assert.deepEqual(calls.map((c) => c.method), ["create"], "one call for the click");
    assert.deepEqual([calls[0].requests, calls[0].log], [atClick.requests, atClick.log], "the call is the first thing the click does");
    assert.equal(byRole(page.root, "methods-confirm-step").hidden, false);
    assert.equal(byRole(page.root, "methods-name-form").hidden, true);
    assert.equal(world.posts.length, 0, "nothing is sent before the second click");

    const atSecond = { requests: world.requests.length, log: world.log.length };
    await fire(byRole(page.root, "methods-confirm"), "click");
    await settle(40);
    assert.deepEqual(calls.map((c) => c.method), ["create", "get"], "one more call for the second click");
    assert.deepEqual([calls[1].requests, calls[1].log], [atSecond.requests, atSecond.log]);
    assert.equal(world.posts.length, 1);
    assert.equal(byRole(page.root, "methods-add").hidden, false, "back to the start");
    assert.equal(byRole(page.root, "methods-done").hidden, false);
    assert.ok(textOf(byRole(page.root, "methods-done")).includes("“Phone” can now unlock your vault (This device only)."));
    assert.equal(byRole(page.root, "methods-name-input").value, "", "the name is not kept");
    const rows = [...walk(page.root)].filter((n) => n.getAttribute?.("data-role") === "methods-row");
    assert.equal(rows.length, 1, "the list shows the new method");
    assert.equal(before.requests < world.requests.length, true);
  } finally {
    page.done();
  }
});

test("a_cancelled_addition_leaves_nothing_and_says_where_the_passkey_is", async () => {
  const world = await passkeyWorld();
  const page = await withPage(world);
  try {
    await settle();
    await openForm(page);
    byRole(page.root, "methods-name-input").value = "Phone";
    await fire(byRole(page.root, "methods-name-form"), "submit");
    await settle();
    await fire(byRole(page.root, "methods-confirm-cancel"), "click");
    await settle();
    assert.equal(world.posts.length, 0);
    assert.equal(byRole(page.root, "methods-add").hidden, false);
    assert.ok(textOf(byRole(page.root, "methods-done")).includes(read("en")["methods.add.leftover"]));
    assert.equal(byRole(page.root, "methods-name-input").value, "");
  } finally {
    page.done();
  }
});

test("a_lock_or_leaving_the_page_drops_a_passkey_that_was_made_and_not_used", async () => {
  for (const how of ["lock", "leave"]) {
    const world = await passkeyWorld();
    const wipers = new Set();
    const listeners = new Map();
    const scope = { add: (fn) => { wipers.add(fn); return () => wipers.delete(fn); } };
    const win = { addEventListener: (type, fn) => listeners.set(type, fn), removeEventListener: (type) => listeners.delete(type) };
    const saved = globalThis.document;
    globalThis.document = accountDocument();
    try {
      const credentials = fakeCredentials();
      const deps = ceremonyDeps(credentials);
      const reauth = reauthWith(world);
      const root = unlockMethodsView({
        t: i18n("en").t, site: HOST, load: () => world.session.listPasskeys(), scope, win,
        begin: () => world.session.beginAddPasskey({ reauth, deps, rpId: HOST }),
        remove: (id) => world.session.removePasskey({ id, reauth }),
      });
      await settle();
      await fire(byRole(root, "methods-add"), "click");
      await settle();
      byRole(root, "methods-name-input").value = "Phone";
      await fire(byRole(root, "methods-name-form"), "submit");
      await settle();
      assert.equal(byRole(root, "methods-confirm-step").hidden, false, how);
      if (how === "lock") for (const fn of [...wipers]) fn();
      else listeners.get("hashchange")();
      assert.equal(byRole(root, "methods-confirm-step").hidden, true, how);
      assert.equal(byRole(root, "methods-add").hidden, false, how);
      // The click that was left cannot be made any more.
      await fire(byRole(root, "methods-confirm"), "click");
      await settle();
      assert.equal(credentials.calls.get.length, 0, how);
      assert.equal(world.posts.length, 0, how);
    } finally {
      if (saved === undefined) delete globalThis.document;
      else globalThis.document = saved;
    }
  }
});

test("the_page_removes_a_passkey_after_a_confirmation", async () => {
  const world = await passkeyWorld({ passkeys: [OLD, MAC] });
  const page = await withPage(world);
  try {
    await settle();
    const rows = () => [...walk(page.root)].filter((n) => n.getAttribute?.("data-role") === "methods-row");
    assert.equal(rows().length, 2);
    // "No" in the dialog sends nothing.
    let running = fire(byRole(rows()[0], "methods-remove"), "click");
    await settle();
    assert.ok(byRole(page.root, "dialog"), "the dialog asks first");
    assert.ok(textOf(byRole(page.root, "dialog")).includes("Old laptop"));
    await fire(byRole(page.root, "dialog-cancel"), "click");
    await running;
    assert.equal(world.deletes.length, 0);
    assert.equal(world.requests.filter((r) => r.method === "DELETE").length, 0);

    running = fire(byRole(rows()[0], "methods-remove"), "click");
    await settle();
    await fire(byRole(page.root, "dialog-confirm"), "click");
    await running;
    await settle(40);
    assert.equal(world.deletes.length, 1);
    assert.equal(rows().length, 1, "the list is read again");
    assert.ok(textOf(byRole(page.root, "methods-done")).includes("“Old laptop” was removed"));
    // The text says the key stays in the provider.
    assert.ok(textOf(byRole(page.root, "methods-done")).includes("Delete the passkey from your passkey provider as well."));
  } finally {
    page.done();
  }
});

// ----------------------------------------------------------------------------- hidden when the server has no passkeys

test("the_page_is_hidden_when_prf_is_off", async () => {
  // What the server says.
  const answers = { yes: { prf: { enabled: true } }, no: { prf: { enabled: false } }, odd: { prf: { enabled: "true" } }, none: {} };
  for (const [name, body] of Object.entries(answers)) {
    const api = { get: async () => body };
    assert.equal(await passkeysOffered(api), name === "yes", name);
  }
  assert.equal(await passkeysOffered({ get: async () => { throw Object.assign(new Error("x"), { code: "not_found" }); } }), false, "a server without the route");
  assert.equal(await passkeysOffered({ get: async () => null }), false);
  const off = await passkeyWorld({ offered: false });
  assert.equal(await off.session.passkeysOffered(), false);
  const on = await passkeyWorld({ offered: true });
  assert.equal(await on.session.passkeysOffered(), true);

  // The account menu leaves the page out, and a route that says nothing is always listed.
  const routes = [
    { path: "/password", title: "k.password", menu: "account" },
    { path: "/unlock-methods", title: "methods.title", menu: "account", requires: "prf" },
  ];
  assert.deepEqual(offeredRoutes(routes, { prf: false }).map((r) => r.path), ["/password"]);
  assert.deepEqual(offeredRoutes(routes, { prf: true }).map((r) => r.path), ["/password", "/unlock-methods"]);
  assert.equal(unlockMethodsRoute.requires, "prf");
  assert.equal(unlockMethodsRoute.menu, "account");

  // The routes themselves, over the vault frame.
  for (const [offered, listed] of [[false, false], [true, true]]) {
    await vaultHelpers.withDom(async () => {
      const r = rig({ offered });
      try {
        const account = await accountRoute.load(r.ctx("/account", { routes }));
        await vaultHelpers.settle();
        const links = vaultHelpers.all(account, "account-link").map((n) => n.getAttribute("data-path"));
        assert.equal(links.includes("/unlock-methods"), listed, `the account menu with offered ${offered}`);
        assert.ok(links.includes("/password"));

        const page = await unlockMethodsRoute.load(r.ctx("/unlock-methods"));
        await vaultHelpers.settle();
        assert.equal(vaultHelpers.find(page, "methods-page") !== null, offered, `the page with offered ${offered}`);
        assert.equal(vaultHelpers.find(page, "methods-unavailable") !== null, !offered);
        // Nothing to press when the server has no passkeys.
        assert.equal(vaultHelpers.find(page, "methods-add") !== null, offered);
        assert.equal(r.session.listed, offered ? 1 : 0, "the list is not read when the server has none");
      } finally {
        r.done();
      }
    });
  }
});

/** A page context over fakes for the two routes: an open vault whose session answers `passkeysOffered`. */
function rig({ offered }) {
  const engine = vaultHelpers.fakeEngine({ items: [], views: {} });
  const client = vaultHelpers.fakeClient(engine);
  const session = vaultHelpers.fakeSession({ client, open: true });
  session.reauthUntil = () => null;
  session.passkeysOffered = async () => offered;
  session.listed = 0;
  session.listPasskeys = async () => {
    session.listed += 1;
    return [];
  };
  const sync = { engine, started: [], current: () => engine, start: async () => engine, stop: () => engine.stop(), discard: engine.discard, discardMissing: engine.discardMissing };
  const ctx = (path, extra = {}) => ({
    params: {}, path, i18n: { t: vaultHelpers.t, lang: "en", missing: [] }, client, services: { crypto: session, sync }, go: () => {}, ...extra,
  });
  return { session, ctx, done: () => autoLockFor(session, sync).stop() };
}

// ---------------------------------------------------------------------- the PRF result goes nowhere but into the core

test("the_prf_output_is_never_in_storage_console_or_a_request", async () => {
  const forms = sentinelForms(PRF_RESULT);
  const found = (haystack) => forms.filter((form) => haystack.includes(form));
  // The search finds what it is looking for.
  for (const form of forms) assert.deepEqual(found(`before ${form} after`).includes(form), true, "the search has a positive control");

  const consoleLines = [];
  const kinds = ["log", "info", "warn", "error", "debug", "trace"];
  const saved = Object.fromEntries(kinds.map((kind) => [kind, console[kind]]));
  for (const kind of kinds) console[kind] = (...args) => consoleLines.push(args.map((a) => (typeof a === "string" ? a : JSON.stringify(a, (_, v) => (v instanceof Uint8Array ? [...v] : v)))).join(" "));
  // The web storage of the page is recorded too: the vault keeps small preferences there, and the PRF result must not be among them.
  const webStorage = () => {
    const data = new Map();
    return { data, getItem: (k) => data.get(k) ?? null, setItem: (k, v) => void data.set(String(k), String(v)), removeItem: (k) => void data.delete(k), clear: () => data.clear() };
  };
  const stubs = { localStorage: webStorage(), sessionStorage: webStorage() };
  const hadStorage = Object.fromEntries(Object.keys(stubs).map((name) => [name, Object.getOwnPropertyDescriptor(globalThis, name)]));
  for (const [name, stub] of Object.entries(stubs)) Object.defineProperty(globalThis, name, { value: stub, configurable: true, writable: true });
  const world = await passkeyWorld({ passkeys: [OLD] });
  let page = null;
  try {
    const credentials = fakeCredentials({ be: true });
    page = await withPage(world, { credentials });
    await settle();
    await openForm(page);
    byRole(page.root, "methods-name-input").value = "Phone";
    await fire(byRole(page.root, "methods-name-form"), "submit");
    await settle();
    await fire(byRole(page.root, "methods-confirm"), "click");
    await settle(40);
    assert.equal(world.posts.length, 1, "the passkey was added");
  } finally {
    for (const kind of kinds) console[kind] = saved[kind];
    for (const name of Object.keys(stubs)) {
      if (hadStorage[name]) Object.defineProperty(globalThis, name, hadStorage[name]);
      else delete globalThis[name];
    }
  }
  // The core got the result exactly once, and the array it was given was wiped by the call.
  assert.equal(world.wraps.length, 1);
  assert.equal(hex(world.wraps[0].output), hex(PRF_RESULT));
  const given = world.client.called("wrap_prf")[0].args[2];
  assert.ok(given.every((byte) => byte === 0), "the array handed to the core is wiped");

  const replacer = (_, v) => (v instanceof Uint8Array ? [...v] : typeof v === "bigint" ? Number(v) : v);
  const requests = JSON.stringify(world.requests, replacer);
  const log = world.log.join("\n");
  const coreCalls = JSON.stringify(world.client.calls.filter((c) => c.method !== "wrap_prf").map((c) => [c.method, c.snapshot]), replacer);
  const signed = world.signed.map((s) => Buffer.from(s.bytes).toString("latin1")).join("\n");
  const stored = await dumpDatabase(world.db.store);
  const shown = textOf(page.root) + JSON.stringify([...walk(page.root)].map((n) => [...(n.attributes?.entries?.() ?? [])]));
  // A control: what the stubs hold is searched, so a value written there would be found.
  stubs.localStorage.setItem("control", forms[0]);
  assert.deepEqual(found(JSON.stringify([...stubs.localStorage.data])), [forms[0]]);
  stubs.localStorage.removeItem("control");
  const webStorageText = JSON.stringify([...stubs.localStorage.data, ...stubs.sessionStorage.data]);
  const where = { webStorage: webStorageText, requests, log, console: consoleLines.join("\n"), coreCalls, signed, stored, shown };
  for (const [name, text] of Object.entries(where)) assert.deepEqual(found(text), [], `the PRF result is not in ${name}`);
  page.done();
});

// ---------------------------------------------------------------------------------------------- the wire and the texts

test("the_servers_list_gives_the_aaguid_as_hex_and_the_web_reads_it", () => {
  const row = (extra) => JSON.stringify({
    methods: [{ method_id: "20".repeat(16), method_type: 3, kek_generation: 1, wrap: b64u.encode(filled(72, 1)), credential_id: b64u.encode(filled(20, 2)), prf_salt: b64u.encode(filled(32, 3)), ...extra }],
    pk_a: b64u.encode(filled(32, 4)), vk_epoch: 1, manifest: { rev: 1, envelope: b64u.encode(filled(80, 5)), tag: b64u.encode(filled(32, 6)) },
  });
  const ok = readWire("methods_res", row({ aaguid: "fbfc3007154e4ecc8c0b6e020557d7bd" }));
  assert.equal(ok.methods[0].aaguid, "fbfc3007154e4ecc8c0b6e020557d7bd");
  assert.equal(readWire("methods_res", row({})).methods[0].aaguid, undefined, "a list without it is read as before");
  for (const bad of ["FBFC3007154E4ECC8C0B6E020557D7BD", "fbfc", "zz".repeat(16), 7]) {
    assert.throws(() => readWire("methods_res", row({ aaguid: bad })), /./, String(bad));
  }
  assert.ok("methods_res" in SHAPES);
  // The time a method was added is a whole number of seconds, optional; the recovery answer has neither it nor an AAGUID.
  assert.equal(readWire("methods_res", row({ created_at: 1_700_000_000 })).methods[0].created_at, 1_700_000_000);
  for (const bad of ["1700000000", -1, 1.5]) assert.throws(() => readWire("methods_res", row({ created_at: bad })), /./, String(bad));
  const answer = readWire("recovery_res", readFileSync(join(web, "..", "crates/ferret-server/tests/fixtures/wire/recovery_res.json"), "utf8"));
  for (const [field, value] of [["aaguid", "ab".repeat(16)], ["created_at", 5]]) {
    const passkey = { ...answer, wrap: { ...answer.wrap, [field]: value } };
    assert.throws(() => checkStep("recovery_res", passkey), /./, field);
  }
});

test("a_signed_call_with_bytes_signs_and_sends_those_bytes_and_a_delete_is_one", async () => {
  const bytes = new TextEncoder().encode('{ "z":1,   "a":2 }');
  const calls = [];
  const fake = {
    api: {
      post: async () => ({ nonce: b64u.encode(filled(32, 7)), expires_in: 300 }),
      sendSigned: async (method, path, sent, proof, options) => {
        calls.push({ method, path, sent, proof, options });
        return { seq: 3 };
      },
    },
    client: { vault: { auth_sign: async (op, nonce, signedBytes) => (calls.push({ op, signedBytes: signedBytes.slice() }), filled(64, 5)) } },
  };
  const answer = await signedCall(fake, { op: "unlock-method.remove", method: "DELETE", path: "/api/vault/unlock-methods/x", bytes, reply: null });
  assert.deepEqual(answer, { seq: 3 });
  assert.deepEqual(calls[0].signedBytes, bytes);
  assert.equal(calls[1].method, "DELETE");
  assert.equal(calls[1].sent, bytes, "the array that is sent is the array that was given");
  assert.deepEqual(calls[1].options, {}, "the answer is read as plain JSON");
  await assert.rejects(signedCall(fake, { op: "x", method: "POST", path: "/a", bytes, shape: "recovery_put_req", body: {} }), TypeError);
  await assert.rejects(signedCall(fake, { op: "x", method: "POST", path: "/a" }), TypeError);
});

test("every_text_of_the_page_is_in_both_languages_and_every_error_code_has_one", () => {
  const en = read("en");
  const nb = read("nb");
  for (const code of METHODS_ERRORS) {
    assert.ok(en[`methods.error.${code}`], `en ${code}`);
    assert.ok(nb[`methods.error.${code}`], `nb ${code}`);
  }
  const listed = Object.keys(en).filter((key) => key.startsWith("methods.error.")).map((key) => key.slice("methods.error.".length)).sort();
  assert.deepEqual(listed, [...METHODS_ERRORS].sort(), "every text of an error is a code the page knows");
  // An unknown code falls back to the general texts, and the message of an error is never shown.
  const unknown = methodsErrorText(i18n("en").t, Object.assign(new Error("secret message"), { code: "something_else" }));
  assert.ok(unknown.startsWith(en["vault.error.unknown"]) && !unknown.includes("secret message"), unknown);
  assert.equal(methodsErrorText(i18n("en").t, Object.assign(new Error("x"), { code: "write_conflict" })), en["methods.error.write_conflict"]);
  // The route and the page use no inline style and no script.
  for (const file of ["views/unlockMethods.mjs", "flows/unlockMethods.mjs", "flows/passkeyCeremony.mjs", "routes/unlock-methods.route.mjs"]) {
    const source = readFileSync(join(web, "src", file), "utf8");
    assert.ok(!/\.style\b|\bstyle\s*[:=]|innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(/.test(source), file);
  }
});
