// The binding end to end, in Node, against the build with `test-support`:
// accounts, sign-in, the account flows, items, passkeys, export and import.
// Run: node --test tests/node/
import assert from "node:assert/strict";
import { createHash, createPublicKey, verify } from "node:crypto";
import { test } from "node:test";
import {
  CTX, IDS, LOGIN_DRAFT, NOW, PASSWORD, PASSWORD_2, URL_, codeOf, enc, fill, firstUse,
  newAccount, pinned, row, signIn, wasm,
} from "./helpers.mjs";

const ITEM = fill(16, 0x41);

function code(fn) {
  const e = codeOf(fn);
  assert.equal(e.name, "FerretError");
  assert.equal(e.message, e.code, "the message is the code and nothing else");
  return e.code;
}

function open(vault, itemId, sealed) {
  return vault.open_item(itemId, sealed.rev, sealed.envelope, sealed.tag);
}

// ---------------------------------------------------------------- errors

test("errors_are_codes_only", () => {
  const { vault } = newAccount("errors");
  const sealed = vault.encrypt_item(ITEM, 1, LOGIN_DRAFT, undefined, NOW);
  const sabotaged = sealed.envelope.slice();
  sabotaged[sabotaged.length - 5] ^= 1;
  const err = codeOf(() => vault.open_item(ITEM, 1, sabotaged, sealed.tag));
  assert.ok(err instanceof Error);
  assert.equal(err.code, "decrypt");
  assert.equal(err.message, "decrypt");
  // Nothing from the input is in the error: not the bytes, not the id.
  for (const text of [err.message, err.code, err.name]) {
    assert.ok(!text.includes("hunter2"));
    assert.ok(!/[0-9a-f]{8}/i.test(text.replace(/decrypt|FerretError/g, "")), "no hex in the error");
  }
  assert.deepEqual(Object.keys(err).sort(), ["code", "name"], "own properties: the code and the name");
  // A wrong tag, a wrong revision and a wrong id are the same code.
  assert.equal(code(() => vault.open_item(ITEM, 1, sealed.envelope, fill(32, 0))), "decrypt");
  assert.equal(code(() => vault.open_item(ITEM, 2, sealed.envelope, sealed.tag)), "decrypt");
  assert.equal(code(() => vault.open_item(fill(16, 0x42), 1, sealed.envelope, sealed.tag)), "decrypt");
  // A mistake in the call is a code of its own, still without data.
  assert.equal(code(() => vault.open_item(fill(15, 1), 1, sealed.envelope, sealed.tag)), "invalid_input");
  assert.equal(code(() => vault.encrypt_item(ITEM, 1.5, LOGIN_DRAFT, undefined, NOW)), "invalid_input");
  assert.equal(code(() => vault.item_view(999)), "invalid_handle");
  assert.equal(code(() => vault.encrypt_item(ITEM, 1, { ...LOGIN_DRAFT, priv: "x" }, undefined, NOW)), "invalid_input");
  vault.lock();
  assert.equal(code(() => vault.context()), "vault_locked");
  assert.equal(vault.is_locked(), true);
});

// ----------------------------------------------------------------- items

test("item_view_hides_secrets", () => {
  const { vault } = newAccount("view");
  const sealed = vault.encrypt_item(ITEM, 1, LOGIN_DRAFT, undefined, NOW);
  const h = open(vault, ITEM, sealed);
  const view = vault.item_view(h);
  const text = JSON.stringify(view);
  for (const secret of ["hunter2-secret", "JBSWY3DPEHPK3PXP", "private note text", "otpauth"]) {
    assert.ok(!text.includes(secret), secret);
  }
  assert.equal(view.fields[0].value, "alice");
  assert.equal(view.fields[1].value, null, "a password field has no value in the view");
  assert.equal(view.has_totp, true);
  assert.equal(view.has_notes, true);
  assert.equal(view.urls[0].url, "https://example.com");
  // One secret at a time, on request.
  assert.equal(vault.reveal_item_field(h, 1), "hunter2-secret");
  assert.equal(vault.reveal_item_notes(h), "private note text");
  assert.ok(vault.reveal_totp_secret(h).includes("JBSWY3DPEHPK3PXP"));
  assert.equal(code(() => vault.reveal_item_field(h, 9)), "invalid_input");
  vault.close_item(h);
  assert.equal(code(() => vault.item_view(h)), "invalid_handle");
});

test("an_edit_keeps_what_the_draft_does_not_mention", () => {
  const { vault } = newAccount("edit");
  const first = vault.encrypt_item(ITEM, 1, LOGIN_DRAFT, undefined, NOW);
  const h = open(vault, ITEM, first);
  // Only the name, and the value of one field: the hidden password, the TOTP
  // address, the notes and the addresses stay.
  const second = vault.encrypt_item(
    ITEM, 2,
    { name: "Renamed", fields: [{ id: "user", value: "bob" }, { id: "pass" }] },
    h, NOW + 1000,
  );
  const h2 = open(vault, ITEM, second);
  const view = vault.item_view(h2);
  assert.equal(view.name, "Renamed");
  assert.equal(view.fields[0].value, "bob");
  assert.equal(view.fields[0].label, "User", "label kept");
  assert.equal(view.fields[1].kind, "password", "kind kept");
  assert.equal(vault.reveal_item_field(h2, 1), "hunter2-secret");
  assert.ok(vault.reveal_totp_secret(h2).includes("JBSWY3DPEHPK3PXP"));
  assert.equal(vault.reveal_item_notes(h2), "private note text");
  assert.equal(view.urls[0].url, "https://example.com");
  assert.equal(view.created, NOW);
  assert.equal(view.modified, NOW + 1000);
  // The item key is kept on an edit: the 72-byte ik_wrap is the same.
  assert.deepEqual(first.envelope.slice(3, 75), second.envelope.slice(3, 75));
  // Removals are explicit.
  const third = vault.encrypt_item(ITEM, 3, { remove_totp: true, remove_notes: true }, h2, NOW + 2000);
  const view3 = vault.item_view(open(vault, ITEM, third));
  assert.equal(view3.has_totp, false);
  assert.equal(view3.has_notes, false);
  // A draft for another item id than the handle is refused.
  assert.equal(code(() => vault.encrypt_item(fill(16, 9), 4, { name: "x" }, h2, NOW)), "invalid_input");
  // A new item needs its type and name.
  assert.equal(code(() => vault.encrypt_item(fill(16, 9), 1, { name: "x" }, undefined, NOW)), "invalid_input");
});

test("totp_time_and_address_are_validated_in_the_glue", () => {
  const { vault } = newAccount("totp");
  const h = open(vault, ITEM, vault.encrypt_item(ITEM, 1, LOGIN_DRAFT, undefined, NOW));
  // RFC 6238, SHA-1, 6 digits: 59 s.
  assert.equal(vault.totp_code(h, 59).code.length, 6);
  assert.equal(vault.totp_code(h, 59.9).code, vault.totp_code(h, 59).code, "the fraction is dropped");
  assert.equal(vault.totp_code(h, 0).seconds_left, 30);
  vault.totp_code(h, 2 ** 53);
  for (const bad of [NaN, Infinity, -Infinity, -1, 2 ** 53 + 2, 1e300]) {
    assert.equal(code(() => vault.totp_code(h, bad)), "invalid_input", String(bad));
  }
  assert.equal(code(() => vault.totp_code(h, undefined)), "invalid_input", "undefined is NaN");
  // The address is trimmed, the algorithm may be lower case, the issuer is
  // trimmed.
  const loose =
    "  otpauth://totp/Acme:bob?secret=JBSWY3DPEHPK3PXP&algorithm=sha1&issuer=%20Acme%20  ";
  const info = wasm.totp_parse(loose);
  assert.deepEqual(
    [info.algorithm, info.issuer, info.digits, info.period],
    ["SHA1", "Acme", 6, 30],
  );
  assert.ok(!JSON.stringify(info).includes("JBSWY3DP"), "no secret in the parsed view");
  const sealed = vault.encrypt_item(fill(16, 5), 1, { item_type: "login", name: "A", totp: { uri: loose } }, undefined, NOW);
  const h2 = open(vault, fill(16, 5), sealed);
  assert.ok(vault.reveal_totp_secret(h2).startsWith("otpauth://totp/Acme:bob?"));
  assert.ok(vault.reveal_totp_secret(h2).includes("algorithm=SHA1"));
  // What the strict parser refuses stays refused.
  assert.equal(code(() => wasm.totp_parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&foo=1")), "malformed_otpauth");
  assert.equal(
    code(() => vault.encrypt_item(fill(16, 6), 1, { item_type: "login", name: "A", totp: { uri: "https://x" } }, undefined, NOW)),
    "malformed_otpauth",
  );
});

// -------------------------------------------------------------- passkeys

const CALLER = { origin: "https://example.com", top_origin_is_same: true };
const UV = { user_present: true, user_verified: true };
const CREATE = {
  challenge: fill(32, 9),
  rp_id: "example.com",
  rp_name: "Example",
  user_id: fill(8, 1),
  user_name: "alice",
  user_display_name: "Alice",
  algorithms: [-7],
  exclude: [],
  user_verification: "preferred",
  prf: {},
};
const GET = { challenge: fill(32, 3), rp_id: "example.com", allow: [], user_verification: "required" };

function assertSignature(created, got) {
  const key = createPublicKey({ key: Buffer.from(created.response.public_key_spki), format: "der", type: "spki" });
  const signed = Buffer.concat([
    Buffer.from(got.authenticator_data),
    createHash("sha256").update(Buffer.from(got.client_data_json)).digest(),
  ]);
  assert.ok(verify("sha256", signed, { key, dsaEncoding: "der" }, Buffer.from(got.signature)));
}

test("item_view_of_a_passkey_hides_the_key_and_the_seeds", () => {
  const { vault } = newAccount("pk-view");
  const id = fill(16, 0x51);
  const created = vault.passkey_create(id, 1, "Example", CREATE, CALLER, UV, [], NOW, undefined);
  // The address of the site is set on a new item.
  const h = open(vault, id, created.item);
  const view = vault.item_view(h);
  assert.deepEqual(view.urls.map((u) => u.url), ["https://example.com"]);
  assert.equal(view.passkey.rp_id, "example.com");
  assert.equal(view.passkey.has_prf, true);
  const text = JSON.stringify(view);
  for (const key of ["priv", "prf_seed", "private_key", "secret", "user_handle"]) {
    assert.ok(!text.includes(key), key);
  }
  assert.equal(created.response.alg, -7);
  assert.equal(created.response.prf.enabled, true);
  // The password-less item has nothing to reveal.
  assert.equal(code(() => vault.reveal_totp_secret(h)), "invalid_input");
});

test("edit_keeps_unchanged_secrets_inside_wasm", () => {
  const { vault } = newAccount("pk-edit");
  const id = fill(16, 0x52);
  const created = vault.passkey_create(id, 1, "Example", CREATE, CALLER, UV, [], NOW, undefined);
  let h = open(vault, id, created.item);
  const before = vault.passkey_get(h, GET, CALLER, UV);
  assertSignature(created, before);
  // Rename the item, and the user name of the passkey: the key is still the
  // one that signs.
  const edited = vault.encrypt_item(id, 2, { name: "Renamed", passkey: { user_name: "alice@work" } }, h, NOW + 5);
  h = open(vault, id, edited);
  const view = vault.item_view(h);
  assert.equal(view.name, "Renamed");
  assert.equal(view.passkey.user_name, "alice@work");
  assert.deepEqual(view.urls.map((u) => u.url), ["https://example.com"]);
  const after = vault.passkey_get(h, GET, CALLER, UV);
  assertSignature(created, after);
  // A draft cannot carry the key or the seeds, and cannot add a passkey.
  assert.equal(code(() => vault.encrypt_item(id, 3, { passkey: { user_name: "x", priv: "00" } }, h, NOW)), "invalid_input");
  const plain = vault.encrypt_item(fill(16, 0x53), 1, { item_type: "login", name: "L" }, undefined, NOW);
  const ph = open(vault, fill(16, 0x53), plain);
  assert.equal(code(() => vault.encrypt_item(fill(16, 0x53), 2, { passkey: { user_name: "x" } }, ph, NOW)), "invalid_input");
  // A passkey attached to a login that exists changes nothing else in it.
  const attached = vault.passkey_create(
    fill(16, 0x41), 2, "ignored",
    { ...CREATE, user_name: "carol" }, CALLER, UV, [], NOW + 9,
    (() => {
      const first = vault.encrypt_item(fill(16, 0x41), 1, LOGIN_DRAFT, undefined, NOW);
      return open(vault, fill(16, 0x41), first);
    })(),
  );
  const ah = open(vault, fill(16, 0x41), attached.item);
  const aview = vault.item_view(ah);
  assert.equal(aview.name, "Example");
  assert.equal(aview.fields.length, 2);
  assert.equal(vault.reveal_item_field(ah, 1), "hunter2-secret");
  assert.ok(vault.reveal_totp_secret(ah).includes("JBSWY3DPEHPK3PXP"));
  assert.equal(aview.passkey.user_name, "carol");
  assertSignature(attached, vault.passkey_get(ah, GET, CALLER, UV));
  // A second passkey is not put over the first one: invalid_state.
  assert.equal(
    code(() => vault.passkey_create(fill(16, 0x41), 3, "ignored", { ...CREATE, user_name: "dave" }, CALLER, UV, [], NOW + 20, ah)),
    "invalid_state",
  );
  assertSignature(attached, vault.passkey_get(ah, GET, CALLER, UV));
});

test("passkey_rules_hold_in_the_binding", () => {
  const { vault } = newAccount("pk-rules");
  const id = fill(16, 0x54);
  const created = vault.passkey_create(id, 1, "E", CREATE, CALLER, UV, [], NOW, undefined);
  const h = open(vault, id, created.item);
  // Cross-origin and a wrong RP ID are the one value, not_allowed.
  assert.equal(code(() => vault.passkey_get(h, GET, { ...CALLER, top_origin_is_same: false }, UV)), "not_allowed");
  assert.equal(code(() => vault.passkey_get(h, { ...GET, rp_id: "other.com" }, { origin: "https://other.com", top_origin_is_same: true }, UV)), "not_allowed");
  assert.equal(code(() => vault.passkey_get(h, GET, CALLER, { user_present: true, user_verified: false })), "not_allowed");
  // An existing credential in excludeCredentials is invalid_state; the
  // item is not made.
  const credId = created.response.id;
  assert.equal(
    code(() => vault.passkey_create(fill(16, 0x55), 1, "E", { ...CREATE, exclude: [credId] }, CALLER, UV, [{ rp_id: "example.com", id: credId }], NOW, undefined)),
    "invalid_state",
  );
  assert.equal(code(() => vault.passkey_create(fill(16, 0x55), 1, "E", { ...CREATE, extra: 1 }, CALLER, UV, [], NOW, undefined)), "invalid_input");
});

// ----------------------------------------------------- sign-in and flows

test("the_pin_state_is_always_required", () => {
  const { server, created, record } = newAccount("pin-required");
  const job = new wasm.UnlockJob();
  const ke1 = job.login_start(enc.encode(PASSWORD), created.vault.reveal_secret_key_code());
  const ke2 = server.login_start(record, IDS.account_id, ke1);
  for (const bad of [undefined, null, {}, { kind: "none" }, { kind: "pinned" }, { kind: "first_use", record: created.pinned }, "pinned"]) {
    assert.equal(code(() => job.login_finish(ke2, 1, bad)), "invalid_input", JSON.stringify(bad));
  }
  // A login that failed on the pin state left no state to continue with.
  assert.equal(code(() => job.unlock_password(URL_, CTX, created.wraps[0], pinned(created.pinned))), "invalid_input");
  // The other unlocks take it too.
  const job2 = new wasm.UnlockJob();
  assert.equal(code(() => job2.pin_unlock(enc.encode("123456"), undefined, created.wraps[0], null)), "invalid_input");
  assert.equal(code(() => job2.unlock_recovery(URL_, CTX, "FFR1-", created.wraps[1], undefined)), "invalid_input");
  assert.equal(code(() => job2.recover(URL_, CTX, "x", created.wraps[1], created.manifest, fill(16, 0x73), undefined, null)), "invalid_input");
});

test("sign_in_checks_the_pins_and_returns_the_record", () => {
  const { server, created, record } = newAccount("sign-in");
  const sk = created.vault.reveal_secret_key_code();
  // A device with the record.
  const out = signIn(server, record, PASSWORD, sk, pinned(created.pinned), created.wraps[0]);
  assert.equal(out.vault.context().vk_epoch, 1);
  assert.deepEqual(out.vault.auth_public_key(), created.pk_a);
  assert.deepEqual(out.pinned.server_public_key, created.pinned.server_public_key);
  // A new device: trust on first use; the key is pinned from the login.
  const fresh = signIn(server, record, PASSWORD, sk, firstUse(true), created.wraps[0]);
  assert.deepEqual(fresh.pinned.server_public_key, server.public_key());
  assert.equal(fresh.pinned.sk_bit, true);
  assert.deepEqual(fresh.pinned.kek_generation_max.map((f) => [f.type, f.generation]), [["password", 1]]);
  // The recovery floor is added from the manifest.
  const seeded = fresh.vault.seed_pinned(fresh.pinned, created.manifest);
  assert.deepEqual(seeded.kek_generation_max.map((f) => f.type).sort(), ["password", "recovery"]);
  // The SK bit is the user's input: a pinned account with a secret key
  // refuses a sign-in without one, before Argon2 runs.
  const job = new wasm.UnlockJob();
  const ke1 = job.login_start(enc.encode(PASSWORD), null);
  const ke2 = server.login_start(record, IDS.account_id, ke1);
  assert.equal(code(() => job.login_finish(ke2, 1, pinned(created.pinned))), "pinned_sk_bit");
  // A wrong password is decrypt, a wrong secret key too.
  const bad = new wasm.UnlockJob();
  const ke1b = bad.login_start(enc.encode("another password!!"), sk);
  const ke2b = server.login_start(record, IDS.account_id, ke1b);
  assert.equal(code(() => bad.login_finish(ke2b, 1, pinned(created.pinned))), "decrypt");
  // An unknown KSF profile is refused before anything else.
  const job3 = new wasm.UnlockJob();
  const ke1c = job3.login_start(enc.encode(PASSWORD), sk);
  const ke2c = server.login_start(record, IDS.account_id, ke1c);
  assert.equal(code(() => job3.login_finish(ke2c, 2, pinned(created.pinned))), "kdf_profile_unknown");
  // A record for another server key is a hard error.
  const other = structuredClone(created.pinned);
  other.server_public_key = fill(32, 7);
  const job4 = new wasm.UnlockJob();
  const ke1d = job4.login_start(enc.encode(PASSWORD), sk);
  const ke2d = server.login_start(record, IDS.account_id, ke1d);
  assert.ok(["pinned_server_key", "decrypt"].includes(code(() => job4.login_finish(ke2d, 1, pinned(other)))));
});

test("recovery_key_and_secret_key_confirmation_at_setup", () => {
  const { created, vault } = newAccount("confirm");
  const rk = vault.reveal_recovery_code();
  const sk = vault.reveal_secret_key_code();
  assert.match(rk, /^FFR1-/);
  assert.match(sk, /^FFS1-/);
  // The sheet carries the QR payload; the host is for the user to confirm.
  const sheet = vault.reveal_emergency_sheet(URL_, "alice@example.com");
  assert.equal(sheet.access.secret_key_code, sk);
  assert.equal(sheet.recovery_key_code, rk);
  const qr = wasm.setup_qr_parse(sheet.access.qr_payload);
  assert.equal(qr.host, "ferret.example");
  assert.equal(qr.scheme, "https");
  assert.equal(qr.port, null);
  assert.equal(qr.sk_bit, true);
  assert.deepEqual(qr.server_public_key, created.server_public_key);
  // A typo is checksum; another valid key is decrypt; neither confirms.
  const typo = rk.slice(0, -1) + (rk.endsWith("0") ? "1" : "0");
  assert.equal(code(() => vault.verify_recovery_setup(typo, created.wraps[1])), "checksum");
  assert.equal(code(() => vault.verify_secret_key_entry(sk.slice(0, -1) + (sk.endsWith("0") ? "1" : "0"))), "checksum");
  const other = newAccount("confirm-2").vault;
  assert.equal(code(() => vault.verify_recovery_setup(other.reveal_recovery_code(), created.wraps[1])), "decrypt");
  assert.equal(vault.reveal_recovery_code(), rk, "still there after the failures");
  // The recovery key typed back is not the end: the secret key is still held.
  vault.verify_recovery_setup(rk, created.wraps[1]);
  assert.equal(vault.reveal_secret_key_code(), sk);
  // When every key the setup holds has been typed back, they are gone.
  vault.verify_secret_key_entry(sk);
  assert.equal(code(() => vault.reveal_recovery_code()), "invalid_input");
  assert.equal(code(() => vault.reveal_secret_key_code()), "invalid_input");
  assert.equal(code(() => vault.reveal_emergency_sheet(URL_, "a@example.com")), "invalid_input");
  // clear_setup_secrets stays for a client that does not ask for the typing.
  const again = newAccount("confirm-3").vault;
  again.clear_setup_secrets();
  assert.equal(code(() => again.reveal_recovery_code()), "invalid_input");
});

test("the_host_shown_is_the_host_a_browser_connects_to", () => {
  const key = fill(32, 1);
  const parse = (url) => wasm.setup_qr_parse(wasm.setup_qr_build(url, IDS.account_id, 1, false, key));
  const BS = String.fromCharCode(92);
  // A backslash, user information and a percent escape cannot be written, so
  // they cannot be confirmed as the wrong host.
  for (const bad of [
    `https://evil.example${BS}@good.example/`,
    "https://good.example@evil.example/",
    "https://a.example%2F@b.example",
    "http://vault.example",
  ]) {
    assert.equal(code(() => wasm.setup_qr_build(bad, IDS.account_id, 1, false, key)), "malformed_setup_qr", bad);
  }
  // And a payload that was made by something else is refused on reading.
  const good = wasm.setup_qr_build("https://vault.example", IDS.account_id, 1, false, key);
  for (const host of ["good.example%40evil.example", `evil.example%5C%40good.example`]) {
    assert.equal(code(() => wasm.setup_qr_parse(good.replace("vault.example", host))), "malformed_setup_qr", host);
  }
  const mixed = parse("https://Vault.EXAMPLE:8443/Path");
  assert.deepEqual([mixed.scheme, mixed.host, mixed.port], ["https", "vault.example", 8443]);
  assert.equal(mixed.server_url, "https://Vault.EXAMPLE:8443/Path", "the address is kept as written");
  const lan = parse("http://10.0.3.26:3001");
  assert.deepEqual([lan.scheme, lan.host, lan.port], ["http", "10.0.3.26", 3001]);
  assert.equal(parse("https://[2001:DB8::1]:8443/x").host, "[2001:db8::1]");
});

test("change_password_returns_the_new_pinned_record", () => {
  const acct = newAccount("change");
  const { server, created, vault } = acct;
  const sk = vault.reveal_secret_key_code();
  const job = new wasm.UnlockJob();
  const request = job.register_start(enc.encode(PASSWORD_2), { kind: "code", code: sk });
  const registration = job.register_finish(server.register_response(IDS.account_id, request), 1);
  const changed = job.change_password(vault, created.pinned, created.wraps[0], created.manifest);
  assert.equal(changed.wrap.kek_generation, 2);
  assert.equal(changed.manifest.rev, 2);
  assert.equal(changed.pinned.kek_generation_max.find((f) => f.type === "password").generation, 2);
  assert.equal(changed.pinned.kek_generation_max.find((f) => f.type === "recovery").generation, 1);
  assert.deepEqual(changed.server_public_key, registration.server_public_key);
  // The proof of the request is made by the vault.
  assert.equal(vault.auth_sign("unlock-method.password.put", fill(32, 1), enc.encode("body")).length, 64);
  assert.equal(code(() => vault.auth_sign("recover", fill(32, 1), new Uint8Array())), "unsupported");
  assert.equal(code(() => vault.auth_sign("nonsense", fill(32, 1), new Uint8Array())), "invalid_input");
  // The new password signs in with the new wrap under the new record; the old
  // wrap is refused as a rollback.
  const next = signIn(server, changed.registration_record, PASSWORD_2, sk, pinned(changed.pinned), changed.wrap);
  assert.deepEqual(next.vault.auth_public_key(), created.pk_a);
  assert.equal(
    code(() => signIn(server, changed.registration_record, PASSWORD_2, sk, pinned(changed.pinned), created.wraps[0])),
    "pinned_kek_generation",
  );
  // A registration that a server with another key made is refused.
  const imposter = new wasm.TestServer(enc.encode("imposter"));
  const job2 = new wasm.UnlockJob();
  const request2 = job2.register_start(enc.encode(PASSWORD_2), { kind: "code", code: sk });
  job2.register_finish(imposter.register_response(IDS.account_id, request2), 1);
  assert.equal(
    code(() => job2.change_password(vault, created.pinned, created.wraps[0], created.manifest)),
    "pinned_server_key",
  );
  // Dropping the secret key is refused.
  const job3 = new wasm.UnlockJob();
  const request3 = job3.register_start(enc.encode(PASSWORD_2), { kind: "none" });
  job3.register_finish(server.register_response(IDS.account_id, request3), 1);
  assert.equal(
    code(() => job3.change_password(vault, created.pinned, created.wraps[0], created.manifest)),
    "pinned_sk_bit",
  );
});

test("recovery_compares_the_qr_server_key_inside_wasm", () => {
  const { server, created, vault } = newAccount("recover");
  const rk = vault.reveal_recovery_code();
  const sk = vault.reveal_secret_key_code();
  const newRecoveryId = fill(16, 0x73);
  // The text of a scanned QR code for this account.
  const qrOf = (key, url = URL_, account = IDS.account_id) => wasm.setup_qr_build(url, account, 1, true, key);
  const recoverWith = (pin, qr, text = rk) => {
    const job = new wasm.UnlockJob();
    const request = job.register_start(enc.encode(PASSWORD_2), { kind: "code", code: sk });
    job.register_finish(server.register_response(IDS.account_id, request), 1);
    return { job, call: () => job.recover(URL_, CTX, text, created.wraps[1], created.manifest, newRecoveryId, pin, qr) };
  };

  // A new device needs the value of the scanned QR code.
  assert.equal(code(() => recoverWith(firstUse(true), null).call()), "invalid_input");
  assert.equal(code(() => recoverWith(firstUse(true), undefined).call()), "invalid_input");
  // A different key is a hard error and nothing is returned.
  const wrong = created.server_public_key.slice();
  wrong[0] ^= 1;
  assert.equal(code(() => recoverWith(firstUse(true), qrOf(wrong)).call()), "pinned_server_key");
  // So is a QR code for another address (the record would pin that one) or
  // another account.
  assert.equal(code(() => recoverWith(firstUse(true), qrOf(created.server_public_key, "https://other.example")).call()), "pinned_server_url");
  assert.equal(code(() => recoverWith(firstUse(true), qrOf(created.server_public_key, URL_, fill(16, 0x99))).call()), "pinned_account_id");
  assert.equal(code(() => recoverWith(firstUse(true), "not a qr code").call()), "malformed_setup_qr");
  // The sheet's secret key bit must be the one of the new password input and
  // the answer given.
  const noSk = wasm.setup_qr_build(URL_, IDS.account_id, 1, false, created.server_public_key);
  assert.equal(code(() => recoverWith(firstUse(false), noSk).call()), "pinned_sk_bit");
  assert.equal(code(() => recoverWith(firstUse(false), qrOf(created.server_public_key)).call()), "pinned_sk_bit");
  // A typo in the code is checksum, a wrong key decrypt.
  assert.equal(code(() => recoverWith(firstUse(true), qrOf(created.server_public_key), rk.slice(0, -1) + (rk.endsWith("0") ? "1" : "0")).call()), "checksum");
  // The right one works, and returns the record to store.
  const { job, call } = recoverWith(firstUse(true), qrOf(created.server_public_key));
  const out = call();
  assert.equal(out.sk_bit, true);
  assert.equal(out.password_wrap.kek_generation, 2);
  assert.equal(out.recovery_wrap.kek_generation, 2);
  assert.deepEqual(out.pinned.server_public_key, created.server_public_key);
  assert.equal(out.pinned.server_url, URL_);
  assert.deepEqual(out.pinned.kek_generation_max.map((f) => f.generation), [2, 2]);
  // The vault is the same, and the new recovery key is the one to show.
  assert.deepEqual(out.vault.auth_public_key(), created.pk_a);
  const newRk = out.vault.reveal_recovery_code();
  assert.notEqual(newRk, rk);
  out.vault.verify_recovery_setup(newRk, out.recovery_wrap);
  assert.equal(code(() => out.vault.reveal_recovery_code()), "invalid_input", "typed back, so gone");
  // The proof is made with the old recovery key, then it is wiped.
  assert.equal(job.recover_sign(fill(32, 2), enc.encode("request")).length, 64);
  job.recover_done();
  assert.equal(code(() => job.recover_sign(fill(32, 2), new Uint8Array())), "invalid_input");
  // The new record unlocks with the new password wrap.
  const next = signIn(server, out.registration_record, PASSWORD_2, sk, pinned(out.pinned), out.password_wrap);
  assert.deepEqual(next.vault.auth_public_key(), created.pk_a);

  // A device with the record compares with it, and gets the raised floors.
  const known = recoverWith(pinned(created.pinned), null).call();
  assert.deepEqual(known.pinned.kek_generation_max.map((f) => f.generation), [2, 2]);
  const other = structuredClone(created.pinned);
  other.server_public_key = fill(32, 5);
  assert.equal(code(() => recoverWith(pinned(other), null).call()), "pinned_server_key");
  // A QR value that differs is refused on a pinned device too.
  assert.equal(code(() => recoverWith(pinned(created.pinned), qrOf(wrong)).call()), "pinned_server_key");
});

test("a_rekey_is_signed_by_the_old_vault_and_put_into_force_after", () => {
  const { server, created, vault } = newAccount("rekey");
  const sk = vault.reveal_secret_key_code();
  const idA = fill(16, 0x61);
  const item = vault.encrypt_item(idA, 1, LOGIN_DRAFT, undefined, NOW);
  // A checkpoint of the state: the manifest row and the item.
  const sha = (b) => new Uint8Array(createHash("sha256").update(Buffer.from(b)).digest());
  const tomb = vault.make_tombstone(fill(16, 0x62), 4);
  assert.equal(tomb.tomb.length, 40);
  const checkpoint = vault.make_checkpoint(7, [
    { item_id: new Uint8Array(16), rev: created.manifest.rev, hash: sha(created.manifest.envelope) },
    { item_id: idA, rev: 1, hash: sha(item.envelope) },
    { item_id: fill(16, 0x62), rev: 4, hash: null },
  ]);
  vault.verify_checkpoint(
    checkpoint,
    [
      { item_id: new Uint8Array(16), rev: created.manifest.rev, state: "live", envelope: created.manifest.envelope, tag: created.manifest.tag },
      { item_id: idA, rev: 1, state: "live", envelope: item.envelope, tag: item.tag },
      { item_id: fill(16, 0x62), rev: 4, state: "deleted", tomb: tomb.tomb },
    ],
    7,
  );

  // A sign-in for KEK_pw.
  const job = new wasm.UnlockJob();
  const ke1 = job.login_start(enc.encode(PASSWORD), sk);
  const ke2 = server.login_start(created.registration_record, IDS.account_id, ke1);
  job.login_finish(ke2, 1, pinned(created.pinned));
  const plan = job.rekey(
    vault,
    {
      base_seq: 7,
      old_checkpoint: checkpoint,
      old_manifest: created.manifest,
      items: [row(idA, item)],
      tombstones: [{ item_id: fill(16, 0x62), rev: 4, tomb: tomb.tomb }],
      password_method_id: IDS.password_method_id,
      recovery_method_id: fill(16, 0x74),
    },
    created.pinned,
  );
  assert.equal(plan.vk_epoch, 2);
  assert.equal(plan.items[0].rev, 2);
  assert.equal(plan.pinned.vk_epoch_max, 2);
  assert.deepEqual(plan.pinned.pk_a, plan.pk_a);
  assert.notDeepEqual(plan.pk_a, created.pk_a);
  // The old vault still is the vault and signs the request.
  assert.equal(vault.context().vk_epoch, 1);
  assert.equal(vault.auth_sign("rekey", fill(32, 4), enc.encode("rekey body")).length, 64);
  const oldRecovery = vault.reveal_recovery_code();
  vault.rekey_commit();
  assert.equal(vault.context().vk_epoch, 2);
  assert.deepEqual(vault.auth_public_key(), plan.pk_a);
  assert.notEqual(vault.reveal_recovery_code(), oldRecovery);
  // The item under the new keys opens; the old envelope does not.
  const h = vault.open_item(idA, plan.items[0].rev, plan.items[0].envelope, plan.items[0].tag);
  assert.equal(vault.reveal_item_field(h, 1), "hunter2-secret");
  assert.equal(code(() => vault.open_item(idA, 1, item.envelope, item.tag)), "decrypt");
  assert.equal(code(() => vault.rekey_commit()), "invalid_input", "nothing pending");
});

test("pin_and_passkey_unlock_go_through_the_same_checks", () => {
  const { vault, created } = newAccount("pin-prf");
  // PIN: Argon2id runs in this worker, the record is required.
  const pinWrap = vault.wrap_pin(enc.encode("123456"), fill(16, 0x75), null);
  assert.equal(pinWrap.method.type, "pin");
  assert.equal(pinWrap.wrap.length, 104);
  const job = new wasm.UnlockJob();
  const out = job.pin_unlock(enc.encode("123456"), created.pinned, pinWrap, null);
  assert.deepEqual(out.vault.auth_public_key(), created.pk_a);
  assert.equal(code(() => new wasm.UnlockJob().pin_unlock(enc.encode("654321"), created.pinned, pinWrap, null)), "decrypt");
  assert.equal(code(() => new wasm.UnlockJob().pin_unlock(enc.encode("12ab56"), created.pinned, pinWrap, null)), "input_forbidden_character");
  assert.equal(code(() => new wasm.UnlockJob().pin_unlock(enc.encode("123456"), created.pinned, pinWrap, fill(32, 1))), "decrypt", "the mobile variant is another key");
  // Passkey (PRF): the 32 bytes the authenticator gave.
  const prf = fill(32, 0x33);
  const prfWrap = vault.wrap_prf(fill(24, 0x44), fill(32, 0x55), prf, fill(16, 0x76), 1);
  assert.equal(prfWrap.wrap.length, 72);
  const withKey = pinned(created.pinned, { server_public_key: created.pinned.server_public_key });
  const viaPrf = new wasm.UnlockJob().unlock_prf(URL_, CTX, prf.slice(), prfWrap, withKey);
  assert.deepEqual(viaPrf.vault.auth_public_key(), created.pk_a);
  assert.ok(viaPrf.pinned.kek_generation_max.some((f) => f.type === "prf"));
  assert.equal(code(() => new wasm.UnlockJob().unlock_prf(URL_, CTX, prf.slice(), prfWrap, pinned(created.pinned))), "pinned_server_key");
  assert.equal(code(() => new wasm.UnlockJob().unlock_prf(URL_, CTX, fill(31, 0), prfWrap, withKey)), "input_too_short");
  assert.equal(code(() => new wasm.UnlockJob().unlock_prf(URL_, CTX, fill(32, 0x34), prfWrap, withKey)), "decrypt");
  // Recovery key unlock, first use: the SK bit is the user's answer.
  const rk = vault.reveal_recovery_code();
  // On a new device the scanned sheet is required and binds the address, the
  // account, the secret key bit and the server key.
  const sheetQr = (key = created.server_public_key, url = URL_, sk = true, account = IDS.account_id) =>
    wasm.setup_qr_build(url, account, 1, sk, key);
  const unlockRecovery = (pin, qr) => new wasm.UnlockJob().unlock_recovery(URL_, CTX, rk, created.wraps[1], pin, qr);
  const rec = unlockRecovery(firstUse(true), sheetQr());
  assert.equal(rec.pinned.sk_bit, true);
  assert.deepEqual(rec.pinned.server_public_key, created.server_public_key, "the record pins the sheet's key");
  assert.equal(rec.pinned.server_url, URL_);
  assert.equal(code(() => unlockRecovery(firstUse(true), null)), "invalid_input");
  assert.equal(unlockRecovery({ kind: "first_use" }, sheetQr()).pinned.sk_bit, true, "the bit comes from the sheet");
  assert.equal(code(() => unlockRecovery(firstUse(true), sheetQr(created.server_public_key, "https://other.example"))), "pinned_server_url");
  assert.equal(code(() => unlockRecovery(firstUse(true), sheetQr(created.server_public_key, URL_, true, fill(16, 9)))), "pinned_account_id");
  assert.equal(code(() => unlockRecovery(firstUse(false), sheetQr())), "pinned_sk_bit");
  assert.equal(code(() => unlockRecovery(firstUse(true, { server_public_key: fill(32, 1) }), sheetQr())), "pinned_server_key");
  // The same for the passkey unlock.
  const viaPrf2 = new wasm.UnlockJob().unlock_prf(URL_, CTX, prf.slice(), prfWrap, firstUse(true), sheetQr());
  assert.deepEqual(viaPrf2.pinned.server_public_key, created.server_public_key);
  assert.equal(code(() => new wasm.UnlockJob().unlock_prf(URL_, CTX, prf.slice(), prfWrap, firstUse(true), null)), "invalid_input");
  assert.equal(code(() => new wasm.UnlockJob().unlock_prf(URL_, CTX, prf.slice(), prfWrap, firstUse(true), sheetQr(created.server_public_key, "https://other.example"))), "pinned_server_url");
  // A pinned device may bring the sheet; a key that is not the record's is refused.
  unlockRecovery(pinned(created.pinned, { server_public_key: created.pinned.server_public_key }), sheetQr());
  assert.equal(code(() => unlockRecovery(pinned(created.pinned, { server_public_key: created.pinned.server_public_key }), sheetQr(fill(32, 2)))), "pinned_server_key");
});

// ----------------------------------------------------- export and import

test("export_and_import_split_the_slow_step_into_the_job_worker", () => {
  const { vault } = newAccount("export");
  const ids = [fill(16, 0x41), fill(16, 0x42)];
  const rows = [
    row(ids[0], vault.encrypt_item(ids[0], 1, LOGIN_DRAFT, undefined, NOW)),
    row(ids[1], vault.encrypt_item(ids[1], 1, { item_type: "note", name: "Second", notes: "n" }, undefined, NOW)),
  ];
  const kdf = { m_kib: 65536, t: 3, p: 1 };
  const started = vault.export_begin(rows, NOW, kdf);
  assert.equal(started.salt.length, 16);
  assert.deepEqual(started.kdf, kdf);
  const exportPassword = "export password for tests";
  // The master password is required when a file is written, and the export
  // password may not equal it.
  assert.equal(code(() => wasm.argon2_export_key(enc.encode(exportPassword), started.salt, started.kdf, "write", null)), "invalid_input");
  assert.equal(code(() => wasm.argon2_export_key(enc.encode(PASSWORD), started.salt, started.kdf, "write", enc.encode(PASSWORD))), "input_same_as_master_password");
  assert.equal(code(() => wasm.argon2_export_key(enc.encode("short"), started.salt, started.kdf, "write", enc.encode(PASSWORD))), "input_too_short");
  assert.equal(code(() => wasm.argon2_export_key(enc.encode(exportPassword), started.salt, { m_kib: 1024, t: 3, p: 1 }, "write", enc.encode(PASSWORD))), "kdf_out_of_range");
  assert.equal(code(() => wasm.argon2_export_key(enc.encode(exportPassword), started.salt, started.kdf, "other", null)), "invalid_input");
  const wrapKey = wasm.argon2_export_key(enc.encode(exportPassword), started.salt, started.kdf, "write", enc.encode(PASSWORD));
  assert.equal(wrapKey.length, 32);
  const file = vault.export_finish(wrapKey.slice());
  assert.equal(code(() => vault.export_finish(wrapKey.slice())), "invalid_input", "one finish per begin");

  // Import: the header first, then the slow step, then the items stay in WASM.
  const header = wasm.import_header(file);
  assert.deepEqual(header.salt, started.salt);
  assert.deepEqual(header.kdf, kdf);
  assert.equal(header.created_at, NOW);
  const key = wasm.argon2_export_key(enc.encode(exportPassword), header.salt, header.kdf, "open", null);
  assert.deepEqual(key, wrapKey);
  const opened = vault.import_open(file, key.slice());
  assert.equal(opened.count, 2);
  const names = [0, 1].map((i) => vault.import_view(i).view.name).sort();
  assert.deepEqual(names, ["Example", "Second"]);
  const view = vault.import_view(0);
  assert.ok(!JSON.stringify(view).includes("hunter2-secret"));
  const index = vault.import_view(0).view.name === "Example" ? 0 : 1;
  const sealed = vault.import_seal(index, fill(16, 0x91), 1);
  const h = open(vault, fill(16, 0x91), sealed);
  assert.equal(vault.reveal_item_field(h, 1), "hunter2-secret");
  vault.import_close();
  assert.equal(code(() => vault.import_view(0)), "invalid_input");
  // A wrong password and a changed byte are decrypt.
  const wrong = wasm.argon2_export_key(enc.encode("another export password"), header.salt, header.kdf, "open", null);
  assert.equal(code(() => vault.import_open(file, wrong)), "decrypt");
  const damaged = file.slice();
  damaged[damaged.length - 1] ^= 1;
  assert.equal(code(() => vault.import_open(damaged, key.slice())), "decrypt");
  assert.equal(code(() => wasm.import_header(new Uint8Array(10))), "malformed_export_header");
  // The plaintext exports are explicit.
  const json = vault.reveal_plain_export(rows, "json", false);
  assert.ok(json.includes("hunter2-secret"));
  const csv = vault.reveal_plain_export(rows, "csv", false);
  assert.ok(csv.startsWith("id,type,name"));
  assert.equal(code(() => vault.reveal_plain_export(rows, "xml", false)), "invalid_input");
});

// ------------------------------------------------------------ the memory

test("lock_zeroizes_vault_memory", () => {
  const { vault } = newAccount("lock");
  const [ptr, len] = vault.test_vk_region();
  assert.equal(len, 32);
  const before = wasm.test_read_memory(ptr, len);
  assert.ok(before.some((b) => b !== 0), "the key is in memory while the vault is open");
  vault.lock();
  const after = wasm.test_read_memory(ptr, len);
  assert.ok(after.every((b) => b === 0), "the key region is wiped");
  assert.throws(() => vault.test_vk_region());
});

test("argon2_oom_maps_to_code", () => {
  // 3 GiB of Argon2id memory cannot be had by a 1 GiB linear memory.
  assert.equal(wasm.test_argon2_unchecked(3 * 1024 * 1024), "kdf_out_of_memory");
  // The instance is still usable afterwards (the client ends its worker
  // anyway).
  assert.equal(wasm.test_argon2_unchecked(64), "ok");
});
