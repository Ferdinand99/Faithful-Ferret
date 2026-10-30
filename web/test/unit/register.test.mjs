// Registration of the first administrator: the order of the calls, and that
// nothing is uploaded before the recovery key and the secret key are typed back.
import assert from "node:assert/strict";
import { test } from "node:test";
import { b64u } from "../../src/b64.mjs";
import { loadPinned } from "../../src/store/pinned.mjs";
import { deviceSecrets } from "../../src/store/settings.mjs";
import { ACCOUNT, EMAIL, PASSWORD, RK_CODE, SERVER, SK_CODE, VAULT, coded, dumpDatabase, scenario, wiped } from "./accountHelpers.mjs";

const start = (world, extra = {}) =>
  world.session.register({ email: EMAIL, password: PASSWORD, setupToken: "setup-token-1", ...extra });

const uploaded = (world) => world.requests.filter((r) => r.url.endsWith("/register/finish"));

test("register_runs_the_calls_in_the_documented_order", async () => {
  const stored = [];
  const world = await scenario({
    handlers: {
      // At this point the device must already hold both the record and the secret key.
      clear_setup_secrets: async () => {
        stored.push(`pinned=${(await loadPinned(world.db.store, SERVER, EMAIL)) !== null}`);
        stored.push(`secret=${(await deviceSecrets.get(world.db.store, SERVER, ACCOUNT)) !== null}`);
      },
    },
  });
  const flow = await start(world);
  await flow.confirm(RK_CODE, SK_CODE);
  const account = await flow.finish();
  assert.deepEqual({ accountId: account.accountId, vaultId: account.vaultId }, { accountId: ACCOUNT, vaultId: VAULT });

  assert.deepEqual(world.log, [
    "vault.check_master_password",
    "vault.register_start",
    "POST /api/auth/opaque/register/start",
    "vault.register_finish",
    "vault.create_account",
    "vault.reveal_emergency_sheet",
    "vault.verify_recovery_setup",
    "vault.verify_secret_key_entry",
    "POST /api/auth/opaque/register/finish",
    "vault.clear_setup_secrets",
  ]);
  // The record and the sealed secret key are saved before the core drops the setup secrets.
  assert.deepEqual(stored, ["pinned=true", "secret=true"]);
  assert.equal((await loadPinned(world.db.store, SERVER, EMAIL)).sk_bit, true);
  assert.ok(await deviceSecrets.get(world.db.store, SERVER, ACCOUNT));
  assert.deepEqual(world.session.current().accountId, ACCOUNT);
});

test("register_sends_what_the_documented_calls_need", async () => {
  const world = await scenario();
  const flow = await start(world);
  const [first] = world.requests;
  // The token is in the body, never in the URL; the request is the core's 32 bytes.
  assert.equal(first.url, "/api/auth/opaque/register/start");
  assert.equal(first.body.setup_token, "setup-token-1");
  assert.equal(first.body.email, EMAIL);
  assert.equal(b64u.decode(first.body.request).length, 32);
  assert.ok(!first.url.includes("setup-token-1"));
  assert.equal(first.headers["Ferret-Protocol"], "1");

  const check = world.client.called("check_master_password")[0];
  assert.equal(check.snapshot[1], "with_secret_key");
  assert.deepEqual(world.client.called("register_start")[0].snapshot[1], { kind: "generate" });
  const create = world.client.called("create_account")[0];
  assert.equal(create.snapshot[0], SERVER);
  // Both method ids are new random ids, not zero, and not the same.
  const { password_method_id: p, recovery_method_id: r } = create.snapshot[1];
  assert.ok(!wiped(p) && !wiped(r) && !p.every((n, i) => n === r[i]));
  assert.equal(world.client.called("reveal_emergency_sheet")[0].snapshot[1], EMAIL);
  assert.equal(flow.sheet.recoveryKeyCode, RK_CODE);
  assert.equal(flow.sheet.access.secret_key_code, SK_CODE);

  await flow.confirm(RK_CODE, SK_CODE);
  await flow.finish();
  const body = uploaded(world)[0].body;
  assert.equal(body.sk_bit, true);
  assert.equal(body.wraps.length, 2);
  assert.deepEqual(body.wraps.map((w) => w.method_type), [1, 2]);
  assert.equal(body.ksf_profile, 1);
  assert.match(body.device_id, /^[0-9a-f]{32}$/);
  // The recovery wrap is the one the core is asked to open with the typed key.
  assert.equal(world.client.called("verify_recovery_setup")[0].snapshot[0], RK_CODE);
  assert.equal(world.client.called("verify_recovery_setup")[0].snapshot[1].method.type, "recovery");
  assert.equal(world.client.called("verify_secret_key_entry")[0].snapshot[0], SK_CODE);
});

test("register_without_a_secret_key_asks_for_the_longer_password_and_confirms_only_the_recovery_key", async () => {
  const world = await scenario({ skBit: false });
  const flow = await start(world, { useSecretKey: false });
  assert.equal(world.client.called("check_master_password")[0].snapshot[1], "without_secret_key");
  assert.deepEqual(world.client.called("register_start")[0].snapshot[1], { kind: "none" });
  assert.equal(flow.sheet.access.secret_key_code, null);
  await flow.confirm(RK_CODE, "");
  assert.equal(world.client.called("verify_secret_key_entry").length, 0);
  await flow.finish();
  assert.equal(uploaded(world)[0].body.sk_bit, false);
  assert.equal(await deviceSecrets.get(world.db.store, SERVER, ACCOUNT), null);
});

test("register_uploads_nothing_before_both_confirmations", async () => {
  let secretKeyOk = false;
  const world = await scenario({
    handlers: {
      verify_secret_key_entry: () => {
        if (!secretKeyOk) throw coded("checksum");
      },
    },
  });
  const flow = await start(world);
  // After the sheet is shown only the first request has been made.
  assert.deepEqual(world.requests.map((r) => r.url), ["/api/auth/opaque/register/start"]);
  await assert.rejects(flow.finish(), { code: "not_confirmed" });
  // The recovery key was right, the secret key not: still nothing is uploaded.
  await assert.rejects(flow.confirm(RK_CODE, "wrong"), { code: "checksum" });
  await assert.rejects(flow.finish(), { code: "not_confirmed" });
  assert.equal(uploaded(world).length, 0);
  assert.equal(await loadPinned(world.db.store, SERVER, EMAIL), null);
  // Typed back again, both right: now it goes.
  secretKeyOk = true;
  await flow.confirm(RK_CODE, SK_CODE);
  await flow.finish();
  assert.equal(uploaded(world).length, 1);
});

test("confirmation_mismatch_aborts_and_uploads_nothing", async () => {
  const world = await scenario({
    handlers: {
      verify_recovery_setup: () => {
        throw coded("decrypt");
      },
    },
  });
  const flow = await start(world);
  await assert.rejects(flow.confirm("FFR1-WRONG", SK_CODE), { code: "decrypt" });
  await assert.rejects(flow.finish(), { code: "not_confirmed" });
  assert.equal(uploaded(world).length, 0);
  assert.equal(await loadPinned(world.db.store, SERVER, EMAIL), null);
  assert.equal(await deviceSecrets.get(world.db.store, SERVER, ACCOUNT), null);
  assert.equal(world.session.current(), null);

  // Giving up drops the keys the core holds and ends the worker; nothing can be finished afterwards.
  const lockedBefore = world.client.locked;
  await flow.abort();
  assert.equal(world.client.called("clear_setup_secrets").length, 1);
  assert.equal(world.client.locked, lockedBefore + 1);
  await assert.rejects(flow.confirm(RK_CODE, SK_CODE), { code: "not_confirmed" });
  await assert.rejects(flow.finish(), { code: "not_confirmed" });
  assert.equal(uploaded(world).length, 0);
});

test("a_weak_password_or_a_failed_start_uploads_nothing_and_ends_the_worker", async () => {
  const weak = await scenario({
    handlers: {
      check_master_password: () => {
        throw coded("input_too_short");
      },
    },
  });
  await assert.rejects(start(weak), { code: "input_too_short" });
  assert.equal(weak.requests.length, 0);
  assert.equal(weak.client.called("register_start").length, 0);
  assert.equal(weak.client.locked, 1);

  const closed = await scenario({
    overrides: { "POST /api/auth/opaque/register/start": () => new Response(JSON.stringify({ error: "registration_closed" }), { status: 409, headers: { "content-type": "application/json" } }) },
  });
  await assert.rejects(start(closed), { code: "registration_closed" });
  assert.equal(closed.client.called("register_finish").length, 0);
  assert.equal(closed.client.locked, 1);
});

test("a_failed_upload_can_be_tried_again_and_a_lost_pin_record_is_a_hard_error", async () => {
  let failures = 1;
  const world = await scenario({
    overrides: {
      "POST /api/auth/opaque/register/finish": () => {
        if (failures-- > 0) return new Response(JSON.stringify({ error: "internal" }), { status: 500, headers: { "content-type": "application/json" } });
        return undefined;
      },
    },
  });
  const flow = await start(world);
  await flow.confirm(RK_CODE, SK_CODE);
  await assert.rejects(flow.finish(), { code: "internal" });
  assert.equal(await loadPinned(world.db.store, SERVER, EMAIL), null);
  await flow.finish();
  assert.ok(await loadPinned(world.db.store, SERVER, EMAIL));

  // A record the store refuses is not swallowed: the vault is locked and the error says the account exists.
  const refusing = await scenario({
    handlers: { create_account: (_s, ids) => ({ ...badAccount(ids) }) },
  });
  const second = await start(refusing);
  await second.confirm(RK_CODE, SK_CODE);
  await assert.rejects(second.finish(), { code: "pin_save_failed" });
  assert.equal(refusing.session.current(), null);
});

/** An account whose record the store refuses (it names another server than the one it is saved under). */
function badAccount(ids) {
  const good = {
    wraps: [
      { method_id: ids.password_method_id, kek_generation: 1, method: { type: "password", ksf_profile: 1 }, wrap: new Uint8Array(104).fill(5) },
      { method_id: ids.recovery_method_id, kek_generation: 1, method: { type: "recovery" }, wrap: new Uint8Array(72).fill(6) },
    ],
    manifest: { rev: 1, envelope: new Uint8Array(80).fill(4), tag: new Uint8Array(32).fill(5) },
    checkpoint: { seq: 1, digest: new Uint8Array(32).fill(6), mac: new Uint8Array(32).fill(7), entries: new Uint8Array(40).fill(8) },
    pk_a: new Uint8Array(32).fill(3),
    pk_r: new Uint8Array(32).fill(10),
    registration_record: new Uint8Array(192).fill(2),
    ksf_profile: 1,
    server_public_key: new Uint8Array(32).fill(9),
  };
  return { ...good, pinned: { server_url: "https://elsewhere.example", broken: true } };
}

test("the_password_is_encoded_for_the_worker_and_the_arrays_are_wiped", async () => {
  const world = await scenario();
  const flow = await start(world);
  for (const method of ["check_master_password", "register_start"]) {
    const call = world.client.called(method)[0];
    assert.equal(new TextDecoder().decode(call.snapshot[0]), PASSWORD);
    assert.ok(wiped(call.args[0]), `${method}: the array was not wiped`);
  }
  await flow.abort();
  // The sheet and the keys are not in storage.
  const dump = await dumpDatabase(world.db.store);
  for (const secret of [PASSWORD, RK_CODE, SK_CODE]) assert.ok(!dump.includes(secret));
});
