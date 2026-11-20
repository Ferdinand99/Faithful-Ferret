// The recovery flow (spec Fase 1 § 6.3): the one-time code, the recovery key, a new master
// password and a new recovery key that is typed back before anything is sent; the request is
// signed with the old recovery key. Nothing here asks for the old master password.
import assert from "node:assert/strict";
import { test } from "node:test";
import { b64u } from "../../src/b64.mjs";
import { canonicalQrText, recoverAccount } from "../../src/flows/recover.mjs";
import { readSetupQr } from "../../src/flows/setupQr.mjs";
import { dumpDatabase } from "./accountHelpers.mjs";
import {
  ACCOUNT, CODE, EMAIL, NEW_PASSWORD, NEW_RK, PASSWORD, PROOF, RK_CODE, RK_TYPO, SERVER, SK_CODE,
  coded, passwordOf, pinHere, qrText, recoverIn, recoverWorld, typeBack,
} from "./recoverHelpers.mjs";

const requestLine = (r) => `${r.method} ${r.url}`;

test("the_flow_never_asks_for_the_old_password", async () => {
  const world = await recoverWorld();
  assert.equal(await recoverIn(world, {}), "recovered");
  // The interface has no field for it, and no sign-in runs before the server has the new password.
  const lines = world.requests.map(requestLine);
  const recoverAt = lines.indexOf("POST /api/vault/recover");
  assert.ok(recoverAt > 0, "the recovery was sent");
  const loginAt = lines.indexOf("POST /api/auth/opaque/login/start");
  assert.ok(loginAt > recoverAt, "the only sign-in is the one after the recovery");
  // Every password the core was given is the new one.
  for (const method of ["register_start", "login_start", "check_master_password"]) {
    const calls = world.client.called(method);
    assert.ok(calls.length > 0, method);
    for (const call of calls) assert.equal(passwordOf(call), NEW_PASSWORD, `${method} got the new password`);
  }
  // The old password appears nowhere: not in a request, not in a call of the core.
  for (const r of world.requests) assert.ok(!JSON.stringify(r.body ?? null).includes(PASSWORD), `${requestLine(r)}`);
  for (const call of world.client.calls) {
    for (const arg of call.snapshot) {
      const text = arg instanceof Uint8Array ? new TextDecoder().decode(arg) : JSON.stringify(arg ?? null);
      assert.ok(!String(text).includes(PASSWORD), `vault.${String(call.method)}`);
    }
  }
});

test("a_typo_in_the_recovery_key_is_caught_before_any_key_is_derived", async () => {
  const world = await recoverWorld();
  const error = await recoverIn(world, { rkCode: RK_TYPO }).catch((e) => e);
  assert.equal(error.code, "checksum");
  assert.deepEqual(world.requests, [], "nothing was sent: the code is not spent");
  assert.deepEqual(world.client.calls.map((c) => c.method), ["check_code"], "only the code was read");
  // A typo in the secret key is caught the same way, before anything is sent.
  const other = await recoverWorld();
  const skError = await recoverIn(other, { skCode: "FFS1-TYPO" }).catch((e) => e);
  assert.equal(skError.code, "checksum");
  assert.deepEqual(other.requests, []);
  for (const method of ["register_start", "register_finish", "recover", "check_master_password"]) {
    assert.equal(other.client.called(method).length, 0, method);
  }
  // An empty key is asked for before anything else.
  const empty = await recoverWorld();
  assert.equal((await recoverIn(empty, { rkCode: "  " }).catch((e) => e)).code, "rk_required");
  assert.deepEqual(empty.client.calls, []);
});

test("the_new_recovery_key_must_be_typed_back_before_recover_is_sent", async () => {
  // A wrong key typed back: refused by the core, and nothing goes out; then the user stops.
  const world = await recoverWorld();
  const asked = [];
  const error = await recoverIn(world, {
    confirmNewRk: async ({ sheet, check }) => {
      asked.push(sheet);
      await assert.rejects(check(RK_CODE), (e) => e.code === "decrypt", "the old key does not confirm the new one");
      assert.ok(!world.requests.some((r) => requestLine(r) === "POST /api/vault/recover"), "nothing was sent while the sheet shows");
      throw Object.assign(new Error("cancelled"), { code: "cancelled" });
    },
  }).catch((e) => e);
  assert.equal(error.code, "cancelled");
  assert.deepEqual(asked, [{ access: null, recoveryKeyCode: NEW_RK }], "page 2 only, with the new key");
  assert.equal(world.recovers.length, 0, "the request was never sent");
  assert.equal(world.client.called("recover_sign").length, 0);
  assert.ok(world.client.called("recover_done").length >= 1, "the old key is wiped");
  assert.ok(world.client.called("clear").length >= 1, "the core dropped the registration");
  assert.ok(world.client.locked >= 1, "the worker that held the recovered vault was ended");
  assert.equal(await world.store.pinHintForEmail(await world.store.open(), SERVER, EMAIL), null, "nothing was pinned");

  // A confirmation that never checks is not one.
  const lazy = await recoverWorld();
  const unchecked = await recoverIn(lazy, { confirmNewRk: async () => undefined }).catch((e) => e);
  assert.equal(unchecked.code, "not_confirmed");
  assert.equal(lazy.recovers.length, 0);

  // Typed back: the check comes first, then the request.
  const ok = await recoverWorld();
  await recoverIn(ok, { confirmNewRk: typeBack() });
  const verifyAt = ok.log.indexOf("vault.verify_recovery_setup");
  const sendAt = ok.log.indexOf("POST /api/vault/recover");
  assert.ok(verifyAt >= 0 && verifyAt < sendAt, "the key was typed back before the request");
  // It was checked against the NEW recovery wrap the core made.
  const [verify] = ok.client.called("verify_recovery_setup");
  assert.equal(verify.args[0], NEW_RK);
  assert.equal(verify.args[1].kek_generation, 2);
});

test("recover_is_signed_with_the_old_key_and_the_old_key_is_wiped_after", async () => {
  const world = await recoverWorld();
  await recoverIn(world, {});
  assert.equal(world.client.called("auth_sign").length, 0, "the account key signs nothing here");
  const [sign] = world.client.called("recover_sign");
  assert.ok(sign, "the old recovery key signed the request");
  const [sent] = world.recovers;
  // The bytes that were signed are the bytes that were sent, with the proof the old key gave.
  assert.deepEqual(JSON.parse(new TextDecoder().decode(sign.snapshot[1])), sent.body);
  assert.equal(sent.headers["Ferret-Proof"] ?? sent.headers["ferret-proof"], b64u.encode(PROOF));
  assert.deepEqual(Object.keys(sent.body).sort(), [
    "ksf_profile", "manifest", "pk_r_new", "pw_kek_generation", "pw_wrap", "registration_record", "rk_kek_generation", "rk_wrap",
  ]);
  assert.equal(sent.body.pw_kek_generation, 2);
  assert.equal(sent.body.rk_kek_generation, 2);
  const lines = world.log;
  const sendAt = lines.indexOf("POST /api/vault/recover");
  const doneAt = lines.indexOf("vault.recover_done");
  assert.ok(lines.indexOf("vault.recover_sign") < sendAt && sendAt < doneAt, "wiped after the request");

  // A refusal wipes it too, and says nothing was changed.
  const refused = await recoverWorld({ recoverStatus: 401 });
  const error = await recoverIn(refused, {}).catch((e) => e);
  assert.equal(error.code, "denied");
  assert.ok(refused.client.called("recover_done").length >= 1);
  assert.equal(await refused.store.pinHintForEmail(await refused.store.open(), SERVER, EMAIL), null, "nothing was pinned");
  // No answer after the request was sent: the outcome is unknown, and the page says so.
  const silent = await recoverWorld({ recoverStatus: 502, recoverBody: { error: "internal" } });
  assert.equal((await recoverIn(silent, {}).catch((e) => e)).code, "recover_unconfirmed");
  assert.ok(silent.client.called("recover_done").length >= 1);
});

test("after_recover_the_device_signs_in_with_the_new_password", async () => {
  const world = await recoverWorld();
  await recoverIn(world, {});
  const opened = world.session.current();
  assert.ok(opened, "the vault is open in the session");
  assert.equal(opened.accountId, ACCOUNT);
  const [login] = world.client.called("login_start");
  assert.equal(passwordOf(login), NEW_PASSWORD);
  assert.equal(login.args[1], SK_CODE, "the account's own secret key");
  // The record of the recovery is the pin now, and its floors are the raised ones.
  const record = await world.store.pinHintForEmail(await world.store.open(), SERVER, EMAIL);
  assert.deepEqual(record.kek_generation_max.map((f) => [f.type, f.generation]), [["password", 2], ["recovery", 2]]);
  // The reset session was used once: the redeem came first, and the recovery ended it.
  const lines = world.requests.map(requestLine);
  assert.ok(lines.indexOf("POST /api/auth/redeem") < lines.indexOf("GET /api/vault/recovery"));
  assert.equal(lines.filter((l) => l === "POST /api/auth/redeem").length, 1);
  // A sign-in that fails afterwards says that the recovery itself went through.
  const failing = await recoverWorld({ overrides: { "POST /api/auth/opaque/login/start": () => new Response(JSON.stringify({ error: "denied" }), { status: 401, headers: { "content-type": "application/json" } }) } });
  const error = await recoverIn(failing, {}).catch((e) => e);
  assert.equal(error.code, "recovered_not_signed_in");
  assert.equal(failing.recovers.length, 1);
});

test("a_pinned_device_may_skip_the_qr", async () => {
  const world = await recoverWorld();
  await pinHere(world, { keepSk: true });
  assert.equal(await recoverIn(world, { qrText: null, skCode: "" }), "recovered");
  const [call] = world.client.called("recover");
  assert.equal(call.args[5].kind, "pinned", "the record is the pin");
  assert.deepEqual(call.args[5].record.kek_generation_max.map((f) => f.generation), [1, 1]);
  assert.equal(call.args[6], undefined, "no sheet text");
  // The secret key came from this device.
  const [register] = world.client.called("register_start");
  assert.deepEqual(register.args[1], { kind: "code", code: SK_CODE });

  // A device without a record needs the sheet, and nothing is sent without it.
  const fresh = await recoverWorld();
  const error = await recoverIn(fresh, { qrText: "" }).catch((e) => e);
  assert.equal(error.code, "qr_required");
  assert.deepEqual(fresh.requests.filter((r) => r.method !== "GET"), []);
  // A device without a record and a sheet with a secret key needs the key from page 1.
  const noSk = await recoverWorld();
  assert.equal((await recoverIn(noSk, { skCode: "" }).catch((e) => e)).code, "sk_required");
  assert.deepEqual(noSk.requests.filter((r) => r.method !== "GET"), []);
  // A pinned device that does not hold the secret key needs it typed, before the code is spent.
  const pinnedNoSk = await recoverWorld();
  await pinHere(pinnedNoSk, { keepSk: false });
  assert.equal((await recoverIn(pinnedNoSk, { qrText: null, skCode: "" }).catch((e) => e)).code, "sk_required");
  assert.deepEqual(pinnedNoSk.requests.filter((r) => r.method !== "GET"), []);
});

test("a_new_device_binds_the_recovery_to_the_sheet_and_this_origin", async () => {
  // A sheet that wrote the same origin in another spelling: the core gets the text with this page's origin.
  const world = await recoverWorld();
  await recoverIn(world, { qrText: qrText({ url: "https://VAULT.example" }) });
  const [call] = world.client.called("recover");
  assert.equal(call.args[0], SERVER);
  assert.deepEqual(call.args[5], { kind: "first_use", sk_bit: true });
  assert.equal(call.args[6], qrText({ url: SERVER }));
  const read = (text) => readSetupQr(world.client, text);
  assert.equal(await canonicalQrText(world.env, qrText(), await read(qrText())), qrText(), "a canonical text is passed as it is");
  // It never turns a sheet for another server into this server's text.
  await assert.rejects(canonicalQrText(world.env, qrText({ url: "https://other.example" }), await read(qrText({ url: "https://other.example" }))), (e) => e.code === "qr_server_url");
  // A sheet for another server: nothing is sent.
  const other = await recoverWorld();
  assert.equal((await recoverIn(other, { qrText: qrText({ url: "https://other.example" }) }).catch((e) => e)).code, "qr_server_url");
  assert.deepEqual(other.requests.filter((r) => r.method !== "GET"), [], "only the session was asked");
  // The account is pinned under another address of this browser: refused before the code is spent.
  const elsewhere = await recoverWorld();
  const db = await elsewhere.store.open();
  const { pinnedRecord } = await import("./accountHelpers.mjs");
  await elsewhere.store.savePinned(db, "https://old.example", ACCOUNT, EMAIL, pinnedRecord({ server: "https://old.example" }));
  const refused = await recoverIn(elsewhere, {}).catch((e) => e);
  assert.equal(refused.code, "pinned_elsewhere");
  assert.deepEqual(elsewhere.requests.filter((r) => r.url === "/api/auth/redeem"), []);
});

test("a_full_session_or_a_reset_session_for_the_same_email_needs_no_new_code", async () => {
  const full = await recoverWorld({ session: "full" });
  await pinHere(full, { keepSk: true });
  assert.equal(await recoverIn(full, { email: "", code: "", qrText: null, skCode: "" }), "recovered");
  assert.ok(!full.requests.some((r) => r.url === "/api/auth/redeem"), "no code with a full session");
  // A typed e-mail of another account than the full session's: refused before anything is sent.
  const other = await recoverWorld({ session: "full" });
  await pinHere(other, { keepSk: true });
  assert.equal((await recoverIn(other, { email: "someone-else@example.test", code: "", qrText: null, skCode: "" }).catch((e) => e)).code, "pinned_account_mismatch");
  assert.deepEqual(other.requests.filter((r) => r.method !== "GET"), []);
  const reset = await recoverWorld({ session: "account_reset" });
  assert.equal(await recoverIn(reset, { code: "" }), "recovered");
  assert.ok(!reset.requests.some((r) => r.url === "/api/auth/redeem"), "the open reset session is used again");
  const none = await recoverWorld();
  assert.equal((await recoverIn(none, { code: "" }).catch((e) => e)).code, "code_required");
  assert.deepEqual(none.requests.filter((r) => r.method !== "GET"), []);
});

test("secrets_never_reach_url_storage_or_console", async () => {
  const sheet = qrText();
  const marks = [RK_CODE, NEW_RK, NEW_PASSWORD, SK_CODE, sheet, encodeURIComponent(sheet), RK_TYPO];
  const saved = { log: console.log, info: console.info, warn: console.warn, error: console.error, debug: console.debug, trace: console.trace };
  const heard = [];
  for (const name of Object.keys(saved)) console[name] = (...args) => void heard.push(args.map((a) => (a instanceof Error ? `${a.message}\n${a.stack}` : String(a))).join(" "));
  const storage = () => {
    const items = new Map();
    return { items, getItem: (k) => items.get(k) ?? null, setItem: (k, v) => void items.set(k, String(v)), removeItem: (k) => void items.delete(k), clear: () => items.clear() };
  };
  const savedStorage = [globalThis.localStorage, globalThis.sessionStorage];
  const local = storage();
  const session = storage();
  Object.defineProperty(globalThis, "localStorage", { value: local, configurable: true });
  Object.defineProperty(globalThis, "sessionStorage", { value: session, configurable: true });
  const worlds = [];
  const errors = [];
  try {
    const ok = await recoverWorld();
    await recoverIn(ok, {});
    worlds.push(ok);
    for (const [options, args] of [
      [{ redeemStatus: 401 }, {}],
      [{}, { rkCode: RK_TYPO }],
      [{ handlers: { recover: () => { throw coded("decrypt"); } } }, {}],
      [{ recoverStatus: 409, recoverBody: { error: "write_conflict" } }, {}],
      [{}, { confirmNewRk: async ({ check }) => check(RK_CODE) }],
    ]) {
      const w = await recoverWorld(options);
      errors.push(await recoverIn(w, args).catch((e) => e));
      worlds.push(w);
    }
    for (const w of worlds) {
      for (const r of w.requests) {
        for (const mark of marks) {
          assert.ok(!String(r.url).includes(mark), `url: ${r.url}`);
          assert.ok(!JSON.stringify(r.body ?? null).includes(mark), `body of ${r.url}`);
          assert.ok(!JSON.stringify(r.headers ?? null).includes(mark), `headers of ${r.url}`);
        }
        // The one-time code goes to the server in the body of the redeem request, and nowhere else.
        if (r.url !== "/api/auth/redeem") assert.ok(!JSON.stringify(r).includes(CODE), `the code in ${r.url}`);
        assert.ok(!String(r.url).includes(CODE));
      }
      const stored = await dumpDatabase(w.db.store);
      for (const mark of [...marks, CODE]) assert.ok(!stored.includes(mark), `stored: ${mark}`);
    }
    for (const error of errors) {
      assert.ok(error && typeof error.code === "string", "every failure has a code");
      const dump = `${error.message}\n${error.stack}\n${JSON.stringify(error, Object.getOwnPropertyNames(error))}`;
      for (const mark of [...marks, CODE]) assert.ok(!dump.includes(mark), `error ${error.code}: ${mark}`);
    }
    assert.deepEqual(errors.map((e) => e.code), ["code_refused", "checksum", "decrypt", "write_conflict", "decrypt"]);
  } finally {
    Object.assign(console, saved);
    for (const [name, value] of [["localStorage", savedStorage[0]], ["sessionStorage", savedStorage[1]]]) {
      if (value === undefined) delete globalThis[name];
      else Object.defineProperty(globalThis, name, { value, configurable: true });
    }
  }
  assert.equal(local.items.size + session.items.size, 0, "nothing was written to web storage");
  for (const line of heard) for (const mark of [...marks, CODE]) assert.ok(!line.includes(mark), `console: ${mark}`);
});

test("the_flow_needs_a_confirmation_step", async () => {
  const world = await recoverWorld();
  await assert.rejects(
    recoverAccount(world.env, { email: EMAIL, code: CODE, qrText: qrText(), skCode: SK_CODE, rkCode: RK_CODE, newPassword: NEW_PASSWORD, newPasswordAgain: NEW_PASSWORD }),
    TypeError,
  );
  const mismatch = await recoverWorld();
  assert.equal((await recoverIn(mismatch, { newPasswordAgain: `${NEW_PASSWORD}x` }).catch((e) => e)).code, "password_mismatch");
  assert.deepEqual(mismatch.requests, []);
});
