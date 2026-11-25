// The PIN in the background: set, used and wiped (design document, sections 7.2 and 7.6). The real session of the
// background (the shared one in device mode, over a fake server), the real PIN store (over a small IndexedDB), the real
// PIN host, router, lock and handlers; the core is a fake that answers like the real one for what these tests ask.
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { build } from "../../scripts/build.mjs";
import { CONTENT_TYPES, UI_TYPES, encode } from "../../src/shared/protocol.mjs";
import { makeRoot } from "./buildHelpers.mjs";
import { contentScriptSender, extensionPageSender } from "./fakeBrowser.mjs";
import { createFakeIdb, createSession as createUnlockSession } from "./localUnlockHelpers.mjs";
import {
  ACCOUNT, EMAIL, SERVER, SK_CODE, answer, coreClient, deviceServer, filled, memoryDb, memoryStore, methodsRes, pkg, portPair, sessionWorld,
} from "./sessionHelpers.mjs";

const MP = "Correct-horse-UNIQUE-4711";
const PIN = "Sentinel-PIN-4711x";
const WRONG = "Wrong-PIN-0000y";
const DAY = 24 * 3600 * 1000;
const START = 1_700_000_000_000;

const settle = () => new Promise((resolve) => setTimeout(resolve, 25));
const token = (/** @type {number} */ fill) => Buffer.alloc(32, fill).toString("base64url");
/** @param {string} code */
const coded = (code) => Object.assign(new Error(code), { code });

/**
 * A device that is signed in, with a PIN store, the PIN host and the fake core and server the tests change as they go.
 * @param {{ policy?: any, policyStatus?: number, unlockTimeoutMs?: number }} [options]
 */
async function pinWorld({ policy, policyStatus = 200, unlockTimeoutMs } = {}) {
  const { load } = await pkg();
  const { createLocalUnlock } = await load("background/localUnlock.mjs");
  /** The world's clock, set below: the PIN store reads the same time as everything else. @type {any} */
  let w = null;
  const idb = createFakeIdb();
  const unlockSession = createUnlockSession();
  const pinStore = createLocalUnlock({ idb: idb.factory, session: unlockSession, now: () => w.clock.now() });

  /** What the fake server and the fake core do now. */
  const state = {
    online: true,
    policyStatus,
    policy: policy ?? { pin: { allowed: true, after_restart: true, min_length: 6 }, prf: { enabled: false } },
    /** The next answers of the policy route that are 401 `token_expired` (the access token ran out). */
    expireAccess: 0,
    refresh: "ok",
    refreshes: 0,
    policyReads: 0,
    correctPin: PIN,
    correctPassword: MP,
    /** What the core was given, as text, before its copy was wiped. */
    pinsSeen: /** @type {string[]} */ ([]),
    passwordsSeen: /** @type {string[]} */ ([]),
    unlockCalls: 0,
    wraps: 0,
    unlockBehaviour: /** @type {null | ((n: number) => Promise<unknown> | unknown)} */ (null),
    methodsCheck: /** @type {null | (() => unknown)} */ (null),
    confirmCheck: /** @type {null | (() => unknown)} */ (null),
    confirmCalls: /** @type {any[]} */ ([]),
    vkEpoch: 1,
    /** The status of the list of unlock methods: 200, or an answer of the server that is no revocation. */
    methodsStatus: 200,
    /** The server never answers. */
    hang: false,
  };

  const server = deviceServer({
    "/api/vault/policy": () => {
      state.policyReads += 1;
      if (state.expireAccess > 0) {
        state.expireAccess -= 1;
        return answer(401, { error: "token_expired" });
      }
      if (state.policyStatus === 404) return answer(404, { error: "not_found" });
      return answer(200, state.policy);
    },
    "/api/auth/token/refresh": () => {
      state.refreshes += 1;
      if (state.refresh !== "ok") return answer(401, { error: state.refresh });
      return answer(200, { access_token: token(100 + state.refreshes), refresh_token: token(150 + state.refreshes), token_type: "DPoP", expires_in: 900 });
    },
    "/api/vault/unlock-methods": () => (state.methodsStatus === 200 ? answer(200, { ...methodsRes(), vk_epoch: state.vkEpoch }) : answer(state.methodsStatus, { error: "throttled" })),
  });
  /** @type {typeof fetch} */
  const fetchImpl = async (input, init) => {
    if (state.hang) return new Promise(() => {});
    if (!state.online) throw new TypeError("fetch failed");
    return server.fetchImpl(input, init);
  };

  const client = coreClient({
    login_start: (/** @type {Uint8Array} */ mp) => {
      state.passwordsSeen.push(Buffer.from(mp).toString("utf8"));
      return filled(96, 1);
    },
    login_finish: () => {
      if (state.passwordsSeen.at(-1) !== state.correctPassword) throw coded("decrypt");
      return { ke3: filled(64, 2), server_public_key: filled(32, 9) };
    },
    pin_unlock: async (/** @type {Uint8Array} */ pin, /** @type {any} */ record, /** @type {any} */ wrap, /** @type {any} */ rule) => {
      state.unlockCalls += 1;
      state.pinsSeen.push(Buffer.from(pin).toString("utf8"));
      pin.fill(0); // the real client wipes what it was given
      if (state.unlockBehaviour) await state.unlockBehaviour(state.unlockCalls);
      if (wrap.vk_epoch < record.vk_epoch_max) throw coded("pin_stale");
      // Before any key stretching, as the core does.
      if (!rule.allowed) throw coded("pin_not_allowed");
      if ([...state.pinsSeen.at(-1)].length < rule.min_length) throw coded("input_too_short");
      if (state.pinsSeen.at(-1) !== state.correctPin) throw coded("decrypt");
      return { pinned: record };
    },
    check_server_methods: () => state.methodsCheck?.(),
    confirm_password: (/** @type {string} */ _url, /** @type {any} */ ctx, /** @type {any} */ _wrap, /** @type {any} */ pin) => {
      state.confirmCalls.push({ ctx, kind: pin?.kind });
      return state.confirmCheck?.();
    },
  });
  /** @type {any} */ (client).pinWrap = async (/** @type {Uint8Array} */ pin, /** @type {Uint8Array} */ methodId, /** @type {any} */ rule) => {
    const text = Buffer.from(pin).toString("utf8");
    state.pinsSeen.push(text);
    if (!rule.allowed) throw coded("pin_not_allowed");
    if ([...text].length < rule.min_length) throw coded("input_too_short");
    state.wraps += 1;
    state.correctPin = text;
    return { method_id: methodId, wrap: filled(104, 9), device_salt: filled(16, 8), profile: 1, vk_epoch: state.vkEpoch, ms: 5 };
  };

  const db = memoryDb();
  const store = memoryStore(db);
  w = await sessionWorld({
    client,
    store,
    fetchImpl,
    pin: { store: pinStore, options: { ...(unlockTimeoutMs ? { unlockTimeoutMs } : {}), policyTimeoutMs: 2000 } },
  });
  w.clock.set(START);
  const page = w.page("pages/settings.html");
  const signIn = async () => page.request("sign_in", { server: SERVER, email: EMAIL, mp: MP, sk: SK_CODE, remember_sk: true });
  const setPin = (/** @type {Record<string, unknown>} */ extra = {}) =>
    page.request("pin_set", { mp: MP, pin: PIN, location: "disk", acknowledged: true, ...extra });
  const unlockWithPin = (/** @type {string} */ pin = PIN) => page.request("pin_unlock", { pin });
  const status = () => pinStore.status(SERVER, ACCOUNT);
  const lockNow = async () => {
    await w.coreHost.lock("manual");
    await settle();
  };
  return { ...w, page, state, server, client, db, store, pinStore, idb, unlockSession, signIn, setPin, unlockWithPin, status, lockNow, advance: (/** @type {number} */ ms) => w.clock.advance(ms), fetchImpl };
}

/** A world with a signed-in device and a PIN set (on disk by default). */
async function withPin(options = {}) {
  const w = await pinWorld(options);
  const signedIn = await w.signIn();
  assert.equal(signedIn.ok, true);
  const set = await w.setPin();
  assert.deepEqual(set, { ok: true });
  assert.equal((await w.status()).set, true);
  return w;
}

// ------------------------------------------------------------------------------------------------ setting a PIN

test("pin_set_needs_an_open_vault_the_network_and_the_master_password_again", async () => {
  const w = await pinWorld();
  await w.signIn();
  await w.lockNow();
  // A locked vault: the router refuses it, and nothing is stored.
  await assert.rejects(w.setPin(), { message: "vault_locked" });
  assert.equal((await w.status()).set, false);

  // Open again (the master password, as always).
  await w.page.request("unlock", { mp: MP });
  assert.equal(w.coreHost.state(), "unlocked");

  // No network: no PIN (and the core never ran the PIN's Argon2id).
  w.state.online = false;
  assert.deepEqual(await w.setPin(), { ok: false, reason: "network" });
  assert.equal(w.state.wraps, 0);
  w.state.online = true;

  // A wrong master password: the same refusal as at an unlock, nothing is stored, no Argon2id for the PIN.
  assert.deepEqual(await w.setPin({ mp: "not-the-password-0" }), { ok: false, reason: "wrong_credentials" });
  assert.equal(w.state.wraps, 0);
  assert.equal((await w.status()).set, false);

  // The right one: the PIN is set, the vault is still open, and the master password reached the core as bytes, wiped.
  assert.deepEqual(await w.setPin(), { ok: true });
  assert.equal(w.coreHost.state(), "unlocked");
  const now = await w.status();
  assert.equal(now.set, true);
  assert.equal(now.location, "disk");
  assert.equal(w.state.wraps, 1);
  const starts = w.client.calls.filter((c) => c.method === "login_start");
  assert.ok(starts.length >= 2);
  assert.ok(/** @type {Uint8Array} */ (starts.at(-1)?.args[0]).every((b) => b === 0), "the password bytes were wiped");
  // The PIN went to the core's job-worker half (`pinWrap`), never to `wrap_pin` of the vault worker.
  assert.equal(w.client.calls.some((c) => c.method === "wrap_pin" || c.method === "wrap_pin_key"), false);
});

test("pin_set_refuses_a_pin_the_rule_does_not_allow", async () => {
  const w = await pinWorld();
  await w.signIn();
  // Too short for the rule of the server (6): the core says so before the Argon2id; nothing is stored.
  assert.deepEqual(await w.setPin({ pin: "12345" }), { ok: false, reason: "pin_rule" });
  assert.equal((await w.status()).set, false);
  assert.equal(w.state.wraps, 0);
  // The administrator has switched PINs off: no PIN, and no password was asked of the core for it either.
  w.state.policy = { pin: { allowed: false, after_restart: true, min_length: 6 }, prf: { enabled: false } };
  const before = w.client.calls.filter((c) => c.method === "login_start").length;
  assert.deepEqual(await w.setPin(), { ok: false, reason: "pin_not_allowed" });
  assert.equal(w.client.calls.filter((c) => c.method === "login_start").length, before);
  // Not ticked: a PIN on disk needs the acknowledgement, and nothing is sent anywhere for it.
  w.state.policy = { pin: { allowed: true, after_restart: true, min_length: 6 }, prf: { enabled: false } };
  const reads = w.state.policyReads;
  assert.deepEqual(await w.setPin({ acknowledged: false }), { ok: false, reason: "not_acknowledged" });
  assert.equal(w.state.policyReads, reads);
  // Out of memory and too slow are the core's words for a machine that cannot do it.
  /** @type {any} */ (w.client).pinWrap = async () => {
    throw coded("kdf_out_of_memory");
  };
  assert.deepEqual(await w.setPin(), { ok: false, reason: "out_of_memory" });
  /** @type {any} */ (w.client).pinWrap = async () => {
    throw coded("pin_too_slow");
  };
  assert.deepEqual(await w.setPin(), { ok: false, reason: "too_slow" });
  assert.equal(w.coreHost.state(), "unlocked", "a failure of the job worker does not lock the vault");
  assert.equal((await w.status()).set, false);
});

test("pin_set_refuses_disk_when_admin_forbids_after_restart", async () => {
  const w = await pinWorld({ policy: { pin: { allowed: true, after_restart: false, min_length: 6 }, prf: { enabled: false } } });
  await w.signIn();
  assert.deepEqual(await w.setPin({ location: "disk" }), { ok: false, reason: "after_restart_not_allowed" });
  assert.equal((await w.status()).set, false);
  // In memory only it is allowed.
  assert.deepEqual(await w.setPin({ location: "session", acknowledged: false }), { ok: true });
  const set = await w.status();
  assert.equal(set.set, true);
  assert.equal(set.location, "session");
});

// ------------------------------------------------------------------------------------------------ using a PIN

test("pin_unlock_opens_the_vault_without_the_network_within_the_window", async () => {
  const w = await withPin();
  await w.lockNow();
  w.state.online = false;
  w.advance(6 * DAY);
  const seeded = w.client.calls.filter((c) => c.method === "seed_pinned").length;
  const reply = await w.unlockWithPin();
  assert.deepEqual(reply, { ok: true, account_email: EMAIL, server: SERVER });
  assert.equal(w.coreHost.state(), "unlocked");
  // The PIN reached the core once, as bytes (and was wiped there), and nothing was checked against the server.
  assert.equal(w.state.pinsSeen.filter((p) => p === PIN).length >= 1, true);
  assert.equal(w.client.calls.filter((c) => c.method === "seed_pinned").length, seeded);
  assert.equal((await w.status()).failuresLeft, 5);
  // The sync starts for the vault that is open (the session says so), as after any unlock.
  assert.equal(w.sessionHost.session()?.current()?.email, EMAIL);
});

test("pin_unlock_runs_the_post_unlock_checks_when_online_and_marks_online", async () => {
  const w = await withPin();
  await w.lockNow();
  w.advance(DAY);
  const before = w.client.calls.filter((c) => c.method === "seed_pinned").length;
  const reply = await w.unlockWithPin();
  assert.equal(reply.ok, true);
  // The server's list of methods against the manifest, and the account key against the pinned one.
  assert.equal(w.client.calls.filter((c) => c.method === "seed_pinned").length, before + 1);
  assert.ok(w.client.calls.some((c) => c.method === "check_server_methods"));
  assert.equal(w.server.to("/api/vault/unlock-methods").length >= 1, true);
  // Online: the record says when (display only). A PIN opened offline does not move it.
  const online = (await w.status()).lastOnlineAt;
  assert.equal(online, START + DAY);
  await w.lockNow();
  w.state.online = false;
  w.advance(DAY);
  assert.equal((await w.unlockWithPin()).ok, true);
  assert.equal((await w.status()).lastOnlineAt, online);
});

test("a_pinned_refusal_after_pin_unlock_locks_and_wipes", async () => {
  const w = await withPin();
  await w.lockNow();
  const locks = w.client.locks;
  w.state.methodsCheck = () => {
    throw coded("method_list_changed");
  };
  const reply = await w.unlockWithPin();
  // The page gets what it gets after a master password: the attack warning.
  assert.deepEqual(reply, { ok: false, reason: "attack_warning" });
  assert.equal(w.coreHost.state(), "locked");
  assert.ok(w.client.locks > locks, "the worker that held the vault was ended");
  assert.equal((await w.status()).set, false, "the PIN is wiped");
  assert.equal(w.sessionHost.session()?.current() ?? null, null);
  // The control: without a refusal the same device opens.
  const control = await withPin();
  await control.lockNow();
  assert.equal((await control.unlockWithPin()).ok, true);
  // The account key the server lists is not the pinned one: the same refusal, the same wipe.
  const other = await withPin();
  await other.lockNow();
  const [entry] = [...other.store.pinned.values()];
  entry.record = { ...entry.record, pk_a: filled(32, 77) };
  const refused = await other.unlockWithPin();
  assert.equal(refused.ok, false);
  assert.equal((await other.status()).set, false);
});

test("a_wrong_pin_counts_and_five_wipe", async () => {
  const w = await withPin();
  await w.lockNow();
  let reply = await w.unlockWithPin(WRONG);
  assert.deepEqual(reply, { ok: false, reason: "wrong_pin", left: 4, wait_ms: 0 });
  reply = await w.unlockWithPin(WRONG);
  assert.deepEqual(reply, { ok: false, reason: "wrong_pin", left: 3, wait_ms: 5000 });
  // The wait is the store's: until it is over, nothing runs.
  const runs = w.state.unlockCalls;
  assert.deepEqual(await w.unlockWithPin(), { ok: false, reason: "pin_wait", left: 3, wait_ms: 5000 });
  assert.equal(w.state.unlockCalls, runs);
  for (const left of [2, 1]) {
    w.advance(40_000);
    reply = await w.unlockWithPin(WRONG);
    assert.equal(reply.left, left);
  }
  w.advance(40_000);
  assert.deepEqual(await w.unlockWithPin(WRONG), { ok: false, reason: "pin_wiped" });
  assert.equal((await w.status()).set, false);
  assert.deepEqual(await w.unlockWithPin(), { ok: false, reason: "pin_unavailable" });
});

test("a_master_password_unlock_gives_the_pin_its_attempts_back", async () => {
  const w = await withPin();
  await w.lockNow();
  await w.unlockWithPin(WRONG);
  assert.equal((await w.status()).failuresLeft, 4);
  await w.page.request("unlock", { mp: MP });
  await settle();
  assert.equal((await w.status()).failuresLeft, 5);
  assert.equal((await w.status()).set, true);
});

test("a_killed_worker_during_pin_unlock_counts_one_attempt", async () => {
  const w = await withPin();
  await w.lockNow();
  // The worker dies in the middle of the Argon2id: the call rejects with the client's code.
  w.state.unlockBehaviour = async () => {
    throw coded("worker_failed");
  };
  const reply = await w.unlockWithPin();
  assert.deepEqual(reply, { ok: false, reason: "wrong_pin", left: 4, wait_ms: 0 });
  assert.equal(w.coreHost.state(), "locked");
  // One attempt, no more and no fewer, and the next try is a normal one.
  w.state.unlockBehaviour = null;
  assert.equal((await w.status()).failuresLeft, 4);
  assert.equal((await w.unlockWithPin()).ok, true);
  assert.equal((await w.status()).failuresLeft, 5);
});

test("a_pin_unlock_that_never_answers_counts_and_ends_the_worker", async () => {
  const w = await withPin({ unlockTimeoutMs: 30 });
  await w.lockNow();
  w.state.unlockBehaviour = () => new Promise(() => {});
  const locks = w.client.locks;
  const reply = await w.unlockWithPin();
  assert.deepEqual(reply, { ok: false, reason: "wrong_pin", left: 4, wait_ms: 0 });
  assert.ok(w.client.locks > locks);
  assert.equal(w.coreHost.state(), "locked");
});

test("a_pin_wiped_while_its_unlock_runs_is_not_trusted", async () => {
  const w = await withPin();
  await w.lockNow();
  // The device is signed out (the PIN is wiped) while the core is still opening the vault with it.
  w.state.unlockBehaviour = async () => {
    await w.pinStore.wipe(SERVER, ACCOUNT, "signed_out");
  };
  const locks = w.client.locks;
  const reply = await w.unlockWithPin();
  assert.equal(reply.ok, false);
  assert.equal(w.coreHost.state(), "locked");
  assert.ok(w.client.locks > locks, "the worker that holds the vault is ended");
  assert.equal((await w.status()).set, false);
});

test("a_higher_vk_epoch_wipes_without_counting", async () => {
  const w = await withPin();
  await w.lockNow();
  // The pinned record has moved to epoch 2 (a master password unlock after a rekey): the PIN's wrap is old.
  const [entry] = [...w.store.pinned.values()];
  entry.record = { ...entry.record, vk_epoch_max: 2 };
  const runs = w.state.unlockCalls;
  const reply = await w.unlockWithPin();
  assert.deepEqual(reply, { ok: false, reason: "pin_stale" });
  assert.equal((await w.status()).set, false);
  assert.ok(w.state.unlockCalls > runs, "the core was asked and said stale before any key stretching");
  // The other way round: a wrap for a later epoch than this record has seen is no wrap it can open. It is stale too, and
  // the core is not asked (it would answer `decrypt` and the attempt would count).
  const v = await withPin();
  await v.lockNow();
  const [pinned] = [...v.store.pinned.values()];
  pinned.record = { ...pinned.record, vk_epoch_max: 0 };
  const asked = v.state.unlockCalls;
  assert.deepEqual(await v.unlockWithPin(), { ok: false, reason: "pin_stale" });
  assert.equal(v.state.unlockCalls, asked);
  assert.equal((await v.status()).set, false);
});

test("an_epoch_of_the_server_above_the_pins_is_an_attack_warning_that_wipes_and_locks", async () => {
  // No rekey proof is checked in this release: a server that shows a newer vault key than the device knows is refused as the
  // core refuses it at a master password unlock. It is not "the PIN is out of date" (pin_stale is for the PIN's own record).
  const w = await withPin();
  await w.lockNow();
  w.state.vkEpoch = 2;
  const reply = await w.unlockWithPin();
  assert.deepEqual(reply, { ok: false, reason: "attack_warning" });
  assert.equal(w.coreHost.state(), "locked");
  assert.equal((await w.status()).set, false);
});

// ------------------------------------------------------------------------------------------------ wiping

test("sign_out_while_offline_still_wipes_the_pin", async () => {
  const w = await withPin();
  w.state.online = false;
  // Forgetting the server and a device whose tokens have ended lock the vault for `sign_out`: the wipe is local.
  await w.coreHost.lock("sign_out");
  await settle();
  assert.equal((await w.status()).set, false);
  assert.deepEqual(await w.unlockWithPin(), { ok: false, reason: "pin_unavailable" });
});

test("forget_and_every_terminal_token_error_wipe_the_pin", async () => {
  for (const code of ["device_revoked", "token_reused", "token_expired"]) {
    const w = await withPin();
    await w.lockNow();
    w.state.refresh = code;
    // The tokens are renewed on a schedule: the access token ran out, and the renewal is refused.
    w.state.expireAccess = 1;
    await w.events.fireAlarm("ferret-contact");
    await settle();
    assert.equal((await w.status()).set, false, code);
  }
  // A device that finds out at a state poll: its tokens ended and nothing else noticed.
  const w = await withPin();
  await w.lockNow();
  w.state.refresh = "device_revoked";
  // The tokens end in a renewal that the state poll did not make: the poll then sees the device is gone.
  await w.sessionHost.sessionFor(SERVER).then((session) => session.renewTokens().catch(() => {}));
  await settle();
  assert.deepEqual(await w.page.request("state", {}).then((r) => r.state), "signed_out");
  assert.equal((await w.status()).set, false);
  // And forgetting the server (the vault locks for `sign_out`).
  const f = await withPin();
  await f.coreHost.lock("sign_out");
  await settle();
  assert.equal((await f.status()).set, false);
});

test("a_new_sign_in_wipes_an_older_pin", async () => {
  const w = await withPin();
  await w.lockNow();
  const again = await w.signIn();
  assert.equal(again.ok, true);
  await settle();
  assert.equal((await w.status()).set, false);
});

test("a_stricter_rule_or_a_switch_off_wipes_at_the_next_contact", async () => {
  // A stricter minimum than the PIN was made under.
  let w = await withPin();
  w.state.policy = { pin: { allowed: true, after_restart: true, min_length: 8 }, prf: { enabled: false } };
  await w.events.fireAlarm("ferret-contact");
  assert.equal((await w.status()).set, false, "stricter");
  // The switch for PINs turned off.
  w = await withPin();
  w.state.policy = { pin: { allowed: false, after_restart: true, min_length: 6 }, prf: { enabled: false } };
  await w.events.fireAlarm("ferret-contact");
  assert.equal((await w.status()).set, false, "off");
  // After a restart turned off: the PIN on disk goes, a PIN in memory stays.
  w = await withPin();
  w.state.policy = { pin: { allowed: true, after_restart: false, min_length: 6 }, prf: { enabled: false } };
  await w.events.fireAlarm("ferret-contact");
  assert.equal((await w.status()).set, false, "disk");
  assert.deepEqual(await w.setPin({ location: "session", acknowledged: false }), { ok: true });
  await w.events.fireAlarm("ferret-contact");
  assert.equal((await w.status()).location, "session");
  // The same at an unlock: a looser rule leaves it.
  const loose = await withPin();
  loose.state.policy = { pin: { allowed: true, after_restart: true, min_length: 4 }, prf: { enabled: false } };
  await loose.events.fireAlarm("ferret-contact");
  assert.equal((await loose.status()).set, true);
});

test("a_revoked_device_wipes_at_its_first_contact", async () => {
  const w = await withPin();
  await w.lockNow();
  // Eight days without contact: the PIN asks the server first, and the server says the device is gone.
  w.advance(8 * DAY);
  w.state.refresh = "device_revoked";
  const reply = await w.unlockWithPin();
  assert.deepEqual(reply, { ok: false, reason: "pin_wiped" });
  assert.equal((await w.status()).set, false);
  assert.equal(w.coreHost.state(), "locked");
});

test("a_token_renewal_while_locked_counts_as_contact", async () => {
  const w = await withPin();
  await w.lockNow();
  w.advance(6 * DAY);
  // The renewal on the schedule: the access token has run out, the renewal works, the window moves.
  w.state.expireAccess = 1;
  await w.events.fireAlarm("ferret-contact");
  await settle();
  assert.equal(w.state.refreshes >= 1, true);
  w.advance(6 * DAY);
  w.state.online = false;
  // Twelve days after the PIN was set, six after the contact.
  assert.equal((await w.unlockWithPin()).ok, true);
});

test("without_a_renewal_the_window_ends_and_a_renewal_before_the_pin_brings_it_back", async () => {
  const w = await withPin();
  await w.lockNow();
  w.advance(8 * DAY);
  w.state.online = false;
  assert.deepEqual(await w.unlockWithPin(), { ok: false, reason: "pin_offline_expired" });
  assert.equal((await w.status()).set, true, "the PIN is kept");
  assert.equal(w.state.unlockCalls, 0, "and the core was not asked");
  assert.equal((await w.status()).failuresLeft, 5, "and nothing was counted");
  // With the server back, the device shows it is not revoked and the PIN opens.
  w.state.online = true;
  assert.equal((await w.unlockWithPin()).ok, true);
});

test("the_renewal_runs_with_or_without_a_pin", async () => {
  const w = await pinWorld();
  await w.signIn();
  assert.equal((await w.status()).set, false);
  w.state.expireAccess = 1;
  const reads = w.state.policyReads;
  await w.events.fireAlarm("ferret-contact");
  await settle();
  assert.ok(w.state.policyReads > reads, "the device asked the server");
  assert.ok(w.state.refreshes >= 1, "and renewed its tokens");
  // The alarm is made at the start of the host, the same for every device.
  w.pinHost.start();
  assert.ok(w.events.alarmList.has("ferret-contact"));
});

test("a_server_without_the_policy_route_means_no_pin", async () => {
  const w = await withPin();
  w.state.policyStatus = 404;
  await w.events.fireAlarm("ferret-contact");
  assert.equal((await w.status()).set, false, "the blob is deleted at that contact");
  const reply = await w.page.request("unlock_policy", {});
  assert.equal(reply.pin_state.allowed, false);
  assert.equal(reply.pin_state.set, false);
  assert.deepEqual(await w.setPin(), { ok: false, reason: "pin_not_allowed" });
});

test("pin_off_deletes_the_pin_and_needs_no_password", async () => {
  const w = await withPin();
  const starts = w.client.calls.filter((c) => c.method === "login_start").length;
  assert.deepEqual(await w.page.request("pin_off", {}), { ok: true });
  assert.equal((await w.status()).set, false);
  assert.equal(w.client.calls.filter((c) => c.method === "login_start").length, starts);
});

test("unlock_policy_answers_while_locked_and_tells_what_the_device_has", async () => {
  const w = await withPin();
  await w.lockNow();
  const reply = await w.page.request("unlock_policy", {});
  assert.deepEqual(reply, {
    pin_state: { allowed: true, after_restart: true, min_length: 6, set: true, location: "disk", failures_left: 5, wait_ms: 0, offline_ok: true },
    prf: { enabled: false },
  });
  await w.unlockWithPin(WRONG);
  const after = await w.page.request("unlock_policy", {});
  assert.equal(after.pin_state.failures_left, 4);
  // Offline it answers from the rule it has kept.
  w.state.online = false;
  assert.equal((await w.page.request("unlock_policy", {})).pin_state.min_length, 6);
});

// ------------------------------------------------------------------------------------------------ who may send

test("a_content_script_or_framed_page_cannot_send_pin_messages", async () => {
  const w = await withPin();
  await w.lockNow();
  const before = w.state.unlockCalls;
  // A content script's message is decoded with the content table only: the PIN types are not in it.
  for (const type of ["pin_unlock", "pin_set", "pin_off", "unlock_policy"]) {
    assert.equal(Object.hasOwn(CONTENT_TYPES, type), false, type);
    const raw = JSON.stringify({ v: 1, id: "x1", type, body: type === "pin_unlock" ? { pin: PIN } : {} });
    assert.equal(await w.router.onMessage(raw, w.contentSender()), undefined);
  }
  // A port a web page opened to this extension's page frames (frameId above 0) is refused.
  const framed = portPair("ferret-ui", extensionPageSender(w.fake, "pages/popup.html", { frameId: 4 }));
  w.router.onConnect(framed.background);
  assert.equal(framed.background.disconnected, true);
  // And a port with a content script as the sender.
  const content = portPair("ferret-ui", contentScriptSender(w.fake, "https://evil.example/"));
  w.router.onConnect(content.background);
  assert.equal(content.background.disconnected, true);
  // The handler asks again: a context of another kind is refused before anything is called.
  const { load } = await pkg();
  const handler = (await load("background/handlers/unlock.handler.mjs")).default;
  for (const sender of [contentScriptSender(w.fake), extensionPageSender(w.fake, "pages/popup.html", { frameId: 2 })]) {
    await assert.rejects(
      handler.handle({ pin: PIN }, { channel: "ui", type: "pin_unlock", sender, runtime: w.fake.runtime, state: () => "locked", call: async () => ({ ok: true }) }),
      { code: "not_available" },
    );
  }
  assert.equal(w.state.unlockCalls, before, "the core was never asked");
  assert.equal((await w.status()).failuresLeft, 5);
});

test("pin_messages_are_refused_with_unlock_off", async () => {
  const env = makeRoot();
  try {
    const result = await build({ root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath, manifest: "mv2", variant: "release" });
    const { pathToFileURL } = await import("node:url");
    const handler = (await import(pathToFileURL(join(result.dir, "background", "handlers", "unlock.handler.mjs")).href)).default;
    const sender = { id: "ferret@hedgerow.tools", url: "moz-extension://x/pages/popup.html", frameId: 0 };
    let called = 0;
    for (const type of handler.types) {
      await assert.rejects(
        handler.handle({ pin: PIN }, { channel: "ui", type, sender, runtime: { id: "ferret@hedgerow.tools", getURL: (/** @type {string} */ p) => `moz-extension://x/${p}` }, state: () => "locked", call: async () => { called += 1; }, lock: async () => {} }),
        { code: "not_available" },
        type,
      );
    }
    assert.equal(called, 0);
    // And no PIN store: a release has the generated module with nothing in it, and so no operation.
    const gen = readFileSync(join(result.dir, "background", "unlockStore.gen.mjs"), "utf8");
    assert.match(gen, /createLocalUnlock = null/);
  } finally {
    env.cleanup();
  }
});

// ------------------------------------------------------------------------------------------------ secrets

/** Everything a value could hide in, as text: strings, and bytes as hex and base64. @param {unknown} value */
function dump(value) {
  const seen = new Set();
  /** @param {unknown} v @returns {string} */
  const walk = (v) => {
    if (v === null || v === undefined) return "";
    if (typeof v === "string") return v;
    if (typeof v !== "object") return String(v);
    if (seen.has(v)) return "";
    seen.add(v);
    if (v instanceof Uint8Array) return `${Buffer.from(v).toString("hex")} ${Buffer.from(v).toString("base64")} ${Buffer.from(v).toString("latin1")}`;
    if (v instanceof Map) return [...v.entries()].map(walk).join(" ");
    if (v instanceof Set || Array.isArray(v)) return [...v].map(walk).join(" ");
    return Object.entries(v).map(([k, x]) => `${k} ${walk(x)}`).join(" ");
  };
  return walk(value);
}

/** The forms a text secret could be found in. @param {string} text */
const formsOf = (text) => {
  const bytes = Buffer.from(text, "utf8");
  return [text, bytes.toString("hex"), bytes.toString("base64"), bytes.toString("base64url"), encodeURIComponent(text)];
};

test("the_pin_is_never_stored_logged_or_echoed", async () => {
  const w = await pinWorld();
  /** @type {unknown[]} */
  const logged = [];
  const saved = { ...console };
  for (const name of ["log", "info", "warn", "error", "debug", "trace"]) {
    /** @type {any} */ (console)[name] = (/** @type {unknown[]} */ ...args) => logged.push(args);
  }
  /** @type {unknown[]} */
  const replies = [];
  try {
    await w.signIn();
    replies.push(await w.setPin());
    await w.lockNow();
    replies.push(await w.unlockWithPin(WRONG));
    replies.push(await w.page.request("unlock_policy", {}));
    w.advance(40_000);
    replies.push(await w.unlockWithPin());
    replies.push(await w.setPin({ pin: "12" }).catch((error) => String(error?.message)));
    // Refusals carry no text either.
    replies.push(await w.setPin({ mp: "another-MP-9999zz" }));
  } finally {
    Object.assign(console, saved);
  }
  const places = {
    "the replies to the page": [...w.ports.flatMap((p) => p.fromBackground), ...replies],
    "the log": logged,
    "the PIN store's database": w.idb.databases,
    "storage.session of the PIN store": w.unlockSession.data,
    "storage.session": w.sessionStorage.data,
    "storage.local": w.local.data,
    "the extension's IndexedDB": w.db.data,
    "the pinned records": w.store.pinned,
    "the server": w.server.calls,
  };
  // The positive control: the search finds a PIN that is planted in the place it searches.
  for (const form of formsOf(PIN)) assert.equal(dump({ planted: form }).includes(form), true);
  for (const [where, value] of Object.entries(places)) {
    const text = dump(value);
    for (const secret of [PIN, WRONG, "another-MP-9999zz"]) {
      for (const form of formsOf(secret)) assert.equal(text.includes(form), false, `${where} holds ${secret} as ${form === secret ? "text" : "an encoding"}`);
    }
    for (const form of formsOf(MP)) assert.equal(text.includes(form), false, `${where} holds the master password`);
  }
  // The PIN reached the core as bytes (wiped there), and the store holds a record with no field that could be it.
  assert.ok(w.state.pinsSeen.includes(PIN));
  const record = w.idb.dump("ferret-unlock", "pin")[0]?.value;
  assert.ok(record, "the record is on disk");
  assert.deepEqual(Object.keys(/** @type {object} */ (record)).sort(), [
    "createdAt", "deviceSalt", "failures", "highestSeenAt", "lastContactAt", "lastFailureAt", "lastOnlineAt", "methodId", "pinProfile", "rule", "vkEpoch", "wrap",
  ]);
});

// ------------------------------------------------------------------------------------------------ the review's rounds

test("pin_set_confirms_the_account_key_of_the_password_wrap_without_making_a_vault", async () => {
  const w = await pinWorld();
  await w.signIn();
  const unlocks = w.client.calls.filter((c) => c.method === "unlock_password").length;
  // The server planted a record for a password of its own: the wrap it lists opens to another vault key.
  w.state.confirmCheck = () => {
    throw coded("pinned_auth_key");
  };
  // That is the signal of a server that lies, not a typo: the attack warning.
  assert.deepEqual(await w.setPin(), { ok: false, reason: "attack_warning" });
  assert.equal(w.state.wraps, 0, "no Argon2id and no wrap");
  assert.equal((await w.status()).set, false);
  assert.equal(w.coreHost.state(), "unlocked", "the vault that is open stays open");
  // The check is the core's own, against the pinned record and the wrap the server lists, with the epoch of the list.
  w.state.confirmCheck = null;
  assert.deepEqual(await w.setPin(), { ok: true });
  const call = w.state.confirmCalls.at(-1);
  assert.equal(call.kind, "pinned");
  assert.deepEqual(Object.keys(call.ctx).sort(), ["account_id", "vault_id", "vk_epoch"]);
  assert.equal(call.ctx.vk_epoch, 1);
  assert.equal(w.client.calls.filter((c) => c.method === "unlock_password").length, unlocks, "no second vault was made");
  assert.deepEqual(await w.page.request("pin_off", {}), { ok: true });

  // The server says the vault is at another epoch than the one that is open: the core takes a vault key of a higher
  // epoch as new, so the password is not confirmed against it, and the core is not asked.
  w.state.vkEpoch = 2;
  const asked = w.state.confirmCalls.length;
  assert.deepEqual(await w.setPin(), { ok: false, reason: "attack_warning" });
  assert.equal(w.state.confirmCalls.length, asked);
  assert.equal(w.state.wraps, 1, "only the first PIN was wrapped");
  assert.equal((await w.status()).set, false);
});

test("every_refusal_after_a_pin_unlock_that_is_not_an_answer_of_the_server_locks_and_wipes", async () => {
  // A code that no list knows.
  let w = await withPin();
  await w.lockNow();
  w.state.methodsCheck = () => {
    throw coded("some_new_refusal");
  };
  assert.equal((await w.unlockWithPin()).ok, false);
  assert.equal(w.coreHost.state(), "locked");
  assert.equal((await w.status()).set, false);
  // The server's epoch below the pinned one: a downgrade, the attack warning.
  w = await withPin();
  await w.lockNow();
  w.state.vkEpoch = 0;
  assert.deepEqual(await w.unlockWithPin(), { ok: false, reason: "attack_warning" });
  assert.equal((await w.status()).set, false);
  // An answer of the server that is no revocation (too many requests) locks and keeps the PIN.
  w = await withPin();
  await w.lockNow();
  w.state.methodsStatus = 429;
  const throttled = await w.unlockWithPin();
  assert.deepEqual(throttled, { ok: false, reason: "throttled" });
  assert.equal(w.coreHost.state(), "locked");
  assert.equal((await w.status()).set, true);
});

test("a_pin_set_that_is_overtaken_by_a_sign_out_leaves_no_pin_and_a_dead_device_opens_nothing", async () => {
  const w = await pinWorld();
  await w.signIn();
  // The vault locks for a sign-out in the middle of `pin_set`: the wipe of that came before the save.
  /** @type {any} */ (w.client).pinWrap = async (/** @type {Uint8Array} */ pin, /** @type {Uint8Array} */ methodId) => {
    await w.coreHost.lock("sign_out");
    await settle();
    return { method_id: methodId, wrap: filled(104, 9), device_salt: filled(16, 8), profile: 1, vk_epoch: 1, ms: 5 };
  };
  const reply = await w.setPin();
  assert.deepEqual(reply, { ok: false, reason: "vault_locked" });
  assert.equal((await w.status()).set, false, "no record is left behind");

  // A device whose tokens have ended opens nothing, even if an earlier wipe never went through.
  const v = await withPin();
  await v.lockNow();
  v.state.refresh = "device_revoked";
  await v.sessionHost.sessionFor(SERVER).then((session) => session.renewTokens().catch(() => {}));
  assert.equal((await v.status()).set, true, "the wipe did not run");
  assert.deepEqual(await v.unlockWithPin(), { ok: false, reason: "pin_wiped" });
  assert.equal(v.state.unlockCalls, 0, "the core was not asked");
  assert.equal((await v.status()).set, false);
});

test("a_failed_attempt_ends_the_worker_that_ran_the_argon2id", async () => {
  const w = await withPin();
  await w.lockNow();
  let locks = w.client.locks;
  assert.equal((await w.unlockWithPin(WRONG)).reason, "wrong_pin");
  assert.ok(w.client.locks > locks, "a wrong PIN: the worker that grew is ended");
  w.advance(40_000);
  locks = w.client.locks;
  w.state.unlockBehaviour = async () => {
    throw coded("kdf_out_of_memory");
  };
  assert.equal((await w.unlockWithPin()).reason, "out_of_memory");
  assert.ok(w.client.locks > locks, "out of memory: the same");
});

test("unlock_policy_answers_at_once_from_the_cached_rule_when_the_server_is_slow", async () => {
  const w = await withPin();
  await w.lockNow();
  // The server never answers: the popup still gets the rule and the state of the PIN, and does not wait.
  w.state.hang = true;
  const started = Date.now();
  const reply = await w.page.request("unlock_policy", {});
  assert.ok(Date.now() - started < 1500, "no wait for the server");
  assert.equal(reply.pin_state.set, true);
  assert.equal(reply.pin_state.min_length, 6);
  assert.equal(reply.pin_state.offline_ok, true);
});

test("a_lost_rule_is_no_permission_a_forget_wipes_awaited_a_short_pin_costs_nothing_and_pin_off_works_locked", async () => {
  // The cached rule is gone (and the server cannot be reached): the PIN does not open, it goes.
  let w = await withPin();
  await w.lockNow();
  w.idb.databases.get("ferret-unlock")?.stores.get("policy")?.clear();
  w.state.online = false;
  assert.deepEqual(await w.unlockWithPin(), { ok: false, reason: "pin_wiped" });
  assert.equal((await w.status()).set, false);

  // Forgetting the server wipes the PIN in the call itself, whether or not the vault lock did.
  w = await withPin();
  await w.sessionHost.forget();
  assert.equal((await w.status()).set, false);

  // A PIN shorter than the rule, or longer than a PIN can be, is a typo: it has a reason of its own, and costs nothing.
  w = await withPin();
  await w.lockNow();
  const runs = w.state.unlockCalls;
  assert.deepEqual(await w.unlockWithPin("12345"), { ok: false, reason: "pin_rule", left: 5, wait_ms: 0 });
  assert.deepEqual(await w.unlockWithPin("x".repeat(65)), { ok: false, reason: "pin_rule", left: 5, wait_ms: 0 });
  // The length is counted the way the core counts it (NFC of the NFKD form): four Hangul syllables are four, whether they are
  // written as syllables or as twelve jamo, and so are four accented letters in either spelling; none of them reaches the core.
  const jamo = "한글한글";
  for (const short of ["한글한글", jamo, "éééé", "éééé"]) {
    assert.deepEqual(await w.unlockWithPin(short), { ok: false, reason: "pin_rule", left: 5, wait_ms: 0 }, short);
  }
  assert.equal(w.state.unlockCalls, runs);
  assert.equal((await w.status()).failuresLeft, 5);

  // Turning the PIN off needs no key: it works from the locked popup.
  assert.equal(w.coreHost.state(), "locked");
  assert.deepEqual(await w.page.request("pin_off", {}), { ok: true });
  assert.equal((await w.status()).set, false);
});

test("the_real_protocol_accepts_the_exact_bodies_the_settings_view_sends", async () => {
  // The settings view's own steps (pages/unlockFlow.mjs) over the real UI port, the real schemas and the real handler.
  const { load } = await pkg();
  const { createUnlockFlow, readUnlockState } = await load("pages/unlockFlow.mjs");
  const w = await withPin();
  await w.page.request("pin_off", {});
  /** @type {Array<{ type: string, body: any }>} */
  const sent = [];
  const request = (/** @type {string} */ type, /** @type {any} */ body) => {
    sent.push({ type, body });
    return w.page.request(type, body);
  };
  const flow = createUnlockFlow(request);

  const loaded = await flow.load();
  assert.equal(loaded.ok, true, JSON.stringify(loaded));
  assert.deepEqual(
    { allowed: loaded.state.pin.allowed, afterRestart: loaded.state.pin.afterRestart, minLength: loaded.state.pin.minLength, set: loaded.state.pin.set },
    { allowed: true, afterRestart: true, minLength: 6, set: false },
  );
  assert.notEqual(readUnlockState(await w.page.request("unlock_policy", {})), null);

  // With and without the secret key: the exact bodies the view sends.
  assert.deepEqual(await flow.setPin({ password: "not-the-password-0", pin: PIN, location: "disk", acknowledged: true }), { ok: false, reason: "wrong_credentials" });
  assert.deepEqual(await flow.setPin({ password: MP, secretKey: SK_CODE, pin: PIN, location: "disk", acknowledged: true }), { ok: true });
  assert.deepEqual(await flow.setPin({ password: MP, pin: PIN, location: "session", acknowledged: false }), { ok: true });
  const bodies = sent.filter((m) => m.type === "pin_set").map((m) => m.body);
  assert.deepEqual(Object.keys(bodies[0]).sort(), ["acknowledged", "location", "mp", "pin"]);
  assert.deepEqual(Object.keys(bodies[1]).sort(), ["acknowledged", "location", "mp", "pin", "sk"]);
  assert.equal(bodies[2].location, "session");

  const after = await flow.load();
  assert.equal(after.ok && after.state.pin.set, true);
  assert.equal(after.ok && after.state.pin.location, "session");
  assert.deepEqual(await flow.turnOff(), { ok: true });
  const off = await flow.load();
  assert.equal(off.ok && off.state.pin.set, false);
});

test("the_protocol_types_of_the_pin_are_the_ones_the_pages_use", async () => {
  // The request and the reply shapes of the messages the popup and the settings use.
  const encodes = [
    ["unlock_policy", {}],
    ["pin_set", { mp: "m", sk: "s", pin: "123456", location: "disk", acknowledged: true }],
    ["pin_set", { mp: "m", pin: "123456", location: "session", acknowledged: false }],
    ["pin_unlock", { pin: "123456" }],
    ["pin_off", {}],
  ];
  for (const [type, body] of /** @type {Array<[string, any]>} */ (encodes)) {
    assert.ok(Object.hasOwn(UI_TYPES, type), type);
    assert.equal(typeof encode(type, body, { id: "a1" }), "string");
  }
  // `password` and `secret_key` are not the names: `mp` and `sk` are, as in `unlock`.
  assert.throws(() => encode("pin_set", { password: "m", pin: "123456", location: "disk", acknowledged: true }, { id: "a1" }));
});

// ------------------------------------------------------------------------------------------------ the source

/** The files under `dir` that end in `.mjs`, without the test-only folders. @param {string} dir @returns {string[]} */
function sources(dir) {
  /** @type {string[]} */
  const out = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      if (name !== "test-only") out.push(...sources(path));
    } else if (name.endsWith(".mjs")) out.push(path);
  }
  return out;
}

test("product_code_never_calls_the_single_worker_wrap_pin_nor_hands_a_key_to_wrap_pin_key", () => {
  const src = join(fileURLToPath(new URL("../../src", import.meta.url)));
  const offenders = [];
  for (const file of sources(src)) {
    const text = readFileSync(file, "utf8")
      // The comments are no calls.
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/(^|[^:])\/\/[^\n]*/g, "$1");
    // `wrap_pin(` and `"wrap_pin"` (one worker, a 256 MiB Argon2id in the vault worker); `wrap_pin_key` is only the second
    // half of `client.pinWrap`, which makes the key itself, so a caller never hands it one.
    if (/\bwrap_pin\b(?!_)/.test(text) || /\bwrap_pin_key\b/.test(text) || /\bargon2_pin_key\b/.test(text)) offenders.push(file.slice(src.length + 1));
  }
  assert.deepEqual(offenders, []);
  // The one way to set a PIN is the client's `pinWrap`, and only the PIN host calls it.
  const callers = sources(src).filter((f) => /\bpinWrap\s*\(/.test(readFileSync(f, "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/[^\n]*/g, "$1")));
  assert.deepEqual(callers.map((f) => f.slice(src.length + 1).replaceAll("\\", "/")), ["background/coreHost.mjs", "background/pinHost.mjs"]);
});

test("the_unlock_ops_are_not_reachable_as_runtime_messages_and_nothing_hands_on_a_wipe_reason", async () => {
  const src = join(fileURLToPath(new URL("../../src", import.meta.url)));
  // `markContact`, `markOnline`, `resetFailures`, `tick`, `save` and `wipe` of the store are called from the PIN host only.
  const callers = sources(src)
    .filter((f) => /\.(?:markContact|markOnline|resetFailures|save|wipe|wipeServer|wipeAll|attempt)\(/.test(readFileSync(f, "utf8").replace(/\/\*[\s\S]*?\*\//g, "")))
    .map((f) => f.slice(src.length + 1).replaceAll("\\", "/"))
    .filter((f) => !f.startsWith("pages/") && f !== "background/localUnlock.mjs" && !f.startsWith("shared/"));
  assert.ok(callers.includes("background/pinHost.mjs"));
  // No handler calls them (a handler gets `ctx.call` and nothing of the store).
  assert.equal(callers.some((f) => f.includes("handlers/") || f.includes("router")), false, callers.join(", "));
  const handler = readFileSync(join(src, "background", "handlers", "unlock.handler.mjs"), "utf8");
  assert.equal(/\bstore\b/.test(handler.replace(/\/\/[^\n]*/g, "")), false);
});
