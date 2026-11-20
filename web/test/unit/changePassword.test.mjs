// Changing the master password: the order of the calls, what is pinned and when, what a refusal
// leaves behind, the floor of the new password and that nothing typed leaks.
import assert from "node:assert/strict";
import { test } from "node:test";
import { b64u } from "../../src/b64.mjs";
import { loadPinned } from "../../src/store/pinned.mjs";
import { ACCOUNT, SERVER, coded, dumpDatabase, wiped } from "./accountHelpers.mjs";
import { EMAIL, NEW_PASSWORD, NONCE, PASSWORD, PROOF, SK_CODE, answer, changed, filled, signedInWorld } from "./securityHelpers.mjs";

const change = (world, extra = {}) =>
  world.session.changePassword({ current: PASSWORD, next: NEW_PASSWORD, nextAgain: NEW_PASSWORD, ...extra });

/** The generation the password floor of the stored record holds. */
async function storedGeneration(world) {
  const record = await loadPinned(world.db.store, SERVER, EMAIL);
  return record.kek_generation_max.find((f) => f.type === "password").generation;
}

test("change_password_runs_the_steps_in_order_and_pins_only_after_200", async () => {
  const world = await signedInWorld({ reauthUntil: Math.floor(Date.now() / 1000) + 300 });
  assert.equal(await storedGeneration(world), 1);
  // A spy on the store: the record is written once, and only after the server's answer.
  const saves = [];
  const save = world.store.savePinned;
  world.store.savePinned = async (...args) => {
    world.log.push("savePinned");
    saves.push(args);
    return save(...args);
  };

  const done = await change(world);
  assert.equal(done.kekGeneration, 2);
  assert.deepEqual(world.log, [
    "GET /api/auth/session", // who the session is
    "vault.check_master_password", // the floor, before anything is sent
    "vault.login_start", // the fresh re-authentication
    "POST /api/auth/opaque/login/start",
    "vault.login_finish",
    "POST /api/auth/opaque/login/finish",
    "GET /api/auth/session",
    "vault.clear",
    "GET /api/vault/unlock-methods", // what the server holds
    "vault.seed_pinned",
    "vault.check_server_methods",
    "vault.register_start", // the new registration
    "POST /api/auth/opaque/reregister/start",
    "vault.register_finish",
    "vault.change_password", // the new wrap and manifest
    "POST /api/auth/challenge", // the signed write
    "vault.auth_sign",
    "PUT /api/vault/unlock-methods/password",
    "savePinned", // only now
  ]);
  assert.equal(saves.length, 1);
  assert.equal(await storedGeneration(world), 2);
  assert.ok(world.session.current(), "the vault stays open");
  assert.equal(world.client.locked, 0);

  // What went to the server: the record, the new wrap, the generation the core made, and a proof over exactly those bytes.
  const [put] = world.puts;
  assert.deepEqual(Object.keys(put.body).sort(), ["kek_generation", "ksf_profile", "manifest", "registration_record", "wrap"]);
  assert.equal(put.body.kek_generation, 2);
  assert.equal(put.body.wrap, b64u.encode(filled(104, 8)));
  assert.equal(put.body.registration_record, b64u.encode(filled(192, 11)));
  assert.deepEqual(put.body.manifest, { rev: 2, envelope: b64u.encode(filled(80, 9)), tag: b64u.encode(filled(32, 10)) });
  const [op, nonce, body] = world.client.called("auth_sign")[0].snapshot;
  assert.equal(op, "unlock-method.password.put");
  assert.deepEqual(nonce, NONCE);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(body)), put.body);
  assert.equal(put.headers["Ferret-Proof"], b64u.encode(PROOF));

  // The core was given the account's record, the server's current wrap and the manifest the server holds.
  const [pinned, current, manifest] = world.client.called("change_password")[0].snapshot;
  assert.equal(pinned.account_id.length, 16);
  assert.equal(current.method.type, "password");
  assert.equal(manifest.rev, 1);
  // The new registration is made for the account's own secret key, which does not change.
  assert.deepEqual(world.client.called("register_start")[0].snapshot[1], { kind: "code", code: SK_CODE });
  assert.equal(world.client.called("register_finish")[0].snapshot[1], 1);
  // The new record is exactly what the core handed back, for this server and account.
  assert.deepEqual(saves[0].slice(1, 4), [SERVER, ACCOUNT, EMAIL]);
  assert.deepEqual(saves[0][4], changed().pinned);
  // Every byte array that held a password was wiped after its call.
  for (const call of [...world.client.called("check_master_password"), ...world.client.called("register_start"), ...world.client.called("login_start")]) {
    assert.ok(wiped(call.args[0]), call.method);
  }
});

test("a_refused_change_keeps_the_old_pin_and_says_why", async () => {
  const cases = [
    [403, { error: "reauth_required" }, "reauth_required"],
    [403, { error: "second_factor_required" }, "second_factor_required"],
    [409, { error: "write_conflict" }, "write_conflict"],
    [401, { error: "denied" }, "denied"],
    [422, { error: "bad_request" }, "bad_request"],
  ];
  for (const [status, body, code] of cases) {
    const world = await signedInWorld({ putStatus: status, putBody: body });
    const saves = [];
    const save = world.store.savePinned;
    world.store.savePinned = async (...args) => {
      saves.push(args);
      return save(...args);
    };
    const before = await loadPinned(world.db.store, SERVER, EMAIL);
    await assert.rejects(change(world), (error) => error.code === code && error.status === status, code);
    // Nothing was pinned, the stored record is the old one, and the vault and the session go on.
    assert.deepEqual(saves, []);
    assert.deepEqual(await loadPinned(world.db.store, SERVER, EMAIL), before);
    assert.equal(await storedGeneration(world), 1);
    assert.ok(world.session.current());
    assert.equal(world.client.locked, 0);
    // The core drops what it held of the new registration.
    assert.equal(world.log.at(-1), "vault.clear");
  }
});

test("a_change_the_server_accepts_but_this_device_cannot_pin_says_so", async () => {
  const world = await signedInWorld();
  world.store.savePinned = async () => {
    throw coded("storage");
  };
  await assert.rejects(change(world), (error) => error.code === "pin_save_failed");
  assert.equal(world.client.called("change_password").length, 1);
  // A different generation in the server's answer than the one signed is not trusted: nothing is pinned, and the outcome is unknown.
  const other = await signedInWorld({ putBody: { kek_generation: 7, seq: 12 } });
  await assert.rejects(change(other), { code: "change_unconfirmed" });
  assert.equal(await storedGeneration(other), 1);
});

test("a_failure_after_the_write_was_sent_that_is_no_refusal_is_an_unknown_outcome_not_try_again", async () => {
  const unknown = {
    "no answer": () => {
      throw new Error("offline");
    },
    "a server error": () => answer(500, { error: "internal" }),
    "a gateway error": () => answer(502, { error: "bad_gateway" }),
    "a page that is not JSON": () => new Response("<html>proxy</html>", { status: 200, headers: { "content-type": "text/html" } }),
    "an answer of the wrong shape": () => answer(200, { kek_generation: "2" }),
    "an answer for another generation": () => answer(200, { kek_generation: 7, seq: 12 }),
  };
  for (const [name, put] of Object.entries(unknown)) {
    const world = await signedInWorld({ overrides: { "PUT /api/vault/unlock-methods/password": put } });
    const saves = [];
    const save = world.store.savePinned;
    world.store.savePinned = async (...args) => {
      saves.push(args);
      return save(...args);
    };
    await assert.rejects(change(world), { code: "change_unconfirmed" }, name);
    // Nothing is pinned: the server's state is not known, and the old record is still a floor the new password passes.
    assert.deepEqual(saves, [], name);
    assert.equal(await storedGeneration(world), 1, name);
    assert.ok(world.session.current(), "the vault stays open");
  }

  // Explicit refusals are not unknown: the server said nothing was changed.
  for (const [status, code] of [[403, "reauth_required"], [409, "write_conflict"], [401, "denied"], [422, "bad_request"], [429, "throttled"]]) {
    const world = await signedInWorld({ putStatus: status, putBody: { error: code } });
    await assert.rejects(change(world), (error) => error.code === code, code);
  }

  // A failure before the write (the challenge) is certain: nothing was sent, so it stays what it is.
  const world = await signedInWorld({
    overrides: {
      "POST /api/auth/challenge": () => {
        throw new Error("offline");
      },
    },
  });
  await assert.rejects(change(world), { code: "network" });
  assert.equal(world.requests.some((r) => r.method === "PUT"), false);
  assert.equal(await storedGeneration(world), 1);
});

test("the_new_password_must_meet_the_floor_for_the_sk_bit_and_match_twice", async () => {
  // The two typed passwords must match, and differ from the current one: nothing is sent or asked of the core.
  const world = await signedInWorld();
  await assert.rejects(change(world, { nextAgain: `${NEW_PASSWORD}x` }), { code: "password_mismatch" });
  await assert.rejects(change(world, { next: PASSWORD, nextAgain: PASSWORD }), { code: "password_unchanged" });
  await assert.rejects(change(world, { current: "" }), { code: "password_required" });
  await assert.rejects(change(world, { next: "", nextAgain: "" }), { code: "password_required" });
  assert.deepEqual(world.log, []);
  assert.deepEqual(world.requests, []);

  // The floor is the core's: 12 characters with a secret key, 15 without, chosen by the bit this device pinned.
  const floors = (skBit) => (mp, mode) => {
    const length = new TextDecoder().decode(mp).length;
    if (mode !== (skBit ? "with_secret_key" : "without_secret_key")) throw coded("wrong_mode");
    if (length < (skBit ? 12 : 15)) throw coded("input_too_short");
  };
  for (const skBit of [true, false]) {
    const w = await signedInWorld({ skBit, handlers: { check_master_password: floors(skBit) } });
    // Short: refused by the core before any sign-in call.
    await assert.rejects(change(w, { next: "short-pw-12", nextAgain: "short-pw-12" }), { code: "input_too_short" });
    assert.deepEqual(w.log.filter((entry) => entry.startsWith("POST ")), [], `no sign-in call is made (${skBit})`);
    assert.equal(w.client.called("check_master_password")[0].snapshot[1], skBit ? "with_secret_key" : "without_secret_key");
    // The floor between the two: 12 characters pass with a secret key and fail without one.
    const twelve = "abcdefgh1234";
    if (skBit) {
      await change(w, { next: twelve, nextAgain: twelve });
    } else {
      await assert.rejects(change(w, { next: twelve, nextAgain: twelve }), { code: "input_too_short" });
    }
  }
});

test("an_account_without_a_secret_key_is_registered_without_one_and_with_one_never_without", async () => {
  const none = await signedInWorld({ skBit: false });
  await change(none, { skCode: SK_CODE });
  assert.deepEqual(none.client.called("register_start")[0].snapshot[1], { kind: "none" });

  // The device does not hold the code and none was typed: nothing is sent, because the registration would lock the account out.
  const lost = await signedInWorld({ forgetKey: true });
  await assert.rejects(change(lost), { code: "sk_required" });
  assert.equal(lost.requests.filter((r) => r.method !== "GET").length, 0);
  assert.equal(lost.client.called("register_start").length, 0);
  // Typed, it is used for the sign-in and for the registration.
  await change(lost, { skCode: SK_CODE });
  assert.equal(lost.client.called("login_start")[0].snapshot[1], SK_CODE);
  assert.deepEqual(lost.client.called("register_start")[0].snapshot[1], { kind: "code", code: SK_CODE });
});

test("a_wrong_current_password_changes_nothing_and_registers_nothing", async () => {
  const world = await signedInWorld({
    handlers: {
      login_finish: () => {
        throw coded("decrypt");
      },
    },
  });
  await assert.rejects(change(world), { code: "decrypt" });
  assert.equal(world.client.called("register_start").length, 0);
  assert.equal(world.client.called("change_password").length, 0);
  assert.equal(world.requests.filter((r) => r.method === "PUT").length, 0);
  assert.equal(await storedGeneration(world), 1);
  assert.equal(world.client.locked, 0);
});

test("a_server_that_disagrees_with_the_pin_closes_the_vault_before_anything_is_registered", async () => {
  for (const code of ["method_list_changed", "pinned_kek_generation"]) {
    const world = await signedInWorld({
      handlers: {
        check_server_methods: () => {
          throw coded(code);
        },
      },
    });
    await assert.rejects(change(world), { code });
    assert.equal(world.client.locked, 1, "the vault was closed");
    assert.equal(world.session.current(), null);
    assert.equal(world.client.called("register_start").length, 0);
  }
  // A public key that is not the pinned one is the same.
  const world = await signedInWorld({
    overrides: {
      "GET /api/vault/unlock-methods": () =>
        answer(200, {
          methods: [
            { method_id: "11".repeat(16), method_type: 1, kek_generation: 1, wrap: b64u.encode(filled(104, 5)) },
            { method_id: "22".repeat(16), method_type: 2, kek_generation: 1, wrap: b64u.encode(filled(72, 6)) },
          ],
          pk_a: b64u.encode(filled(32, 99)),
          vk_epoch: 1,
          manifest: { rev: 1, envelope: b64u.encode(filled(80, 4)), tag: b64u.encode(filled(32, 5)) },
        }),
    },
  });
  await assert.rejects(change(world), { code: "pinned_auth_key" });
  assert.equal(world.client.locked, 1);
});

test("the_session_will_not_change_a_password_without_an_open_vault", async () => {
  const world = await signedInWorld();
  await world.session.lock();
  world.requests.length = 0;
  await assert.rejects(change(world), { code: "session_ended" });
  assert.equal(world.requests.length, 0);
});

test("no_secret_reaches_url_storage_or_console", async () => {
  const world = await signedInWorld();
  const logged = [];
  const saved = {};
  for (const name of ["log", "info", "warn", "error", "debug", "trace"]) {
    saved[name] = console[name];
    console[name] = (...args) => logged.push(args.map(String).join(" "));
  }
  try {
    // A success, and failures at three different steps.
    await change(world);
    const refused = await signedInWorld({ putStatus: 409, putBody: { error: "write_conflict" } });
    await assert.rejects(change(refused));
    const wrong = await signedInWorld({ handlers: { login_finish: () => { throw coded("decrypt"); } } });
    await assert.rejects(change(wrong));
    const short = await signedInWorld({ handlers: { check_master_password: () => { throw coded("input_too_short"); } } });
    await assert.rejects(change(short));
    for (const w of [world, refused, wrong, short]) {
      for (const request of w.requests) {
        for (const secret of [PASSWORD, NEW_PASSWORD, SK_CODE]) {
          assert.ok(!request.url.includes(secret) && !request.url.includes("?") && !request.url.includes("#"), request.url);
          assert.ok(!JSON.stringify(request.body ?? "").includes(secret), `${request.url} carries a secret`);
        }
      }
      // Browser storage is IndexedDB here: no password and no secret key code (the sealed copy is not the code).
      const dump = await dumpDatabase(w.db.store);
      assert.ok(!dump.includes(PASSWORD) && !dump.includes(NEW_PASSWORD), "no password in the database");
    }
  } finally {
    Object.assign(console, saved);
  }
  assert.deepEqual(logged, [], "nothing is logged");
});
