// The local PIN store (src/background/localUnlock.mjs): where a record lives,
// how it is wiped, the cached rule, and that nobody else touches the database.
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import { PIN_STORE, POLICY_STORE, SESSION_KEY_PREFIX, UNLOCK_DB_NAME, WIPE_REASONS } from "../../src/background/localUnlock.mjs";
import { ACCOUNT, ACCOUNT_2, OTHER_SERVER, SERVER, createWorld, fakeUnlock, makeBlob } from "./localUnlockHelpers.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = join(HERE, "..", "..", "src");
const WEB_SRC = join(HERE, "..", "..", "..", "web", "src");

/** @param {ReturnType<typeof createWorld>} world */
const diskRecords = (world) => world.idb.dump(UNLOCK_DB_NAME, PIN_STORE);
/** @param {ReturnType<typeof createWorld>} world */
const sessionKeys = (world) => [...world.session.data.keys()];

const policy = (/** @type {object} */ pin = {}, prf = true) => ({ pin: { allowed: true, after_restart: true, min_length: 6, ...pin }, prf: { enabled: prf } });

test("the_disk_location_needs_the_acknowledgement", async () => {
  const world = createWorld();
  for (const acknowledged of [undefined, false, "yes", 1]) {
    await assert.rejects(
      world.store.save(SERVER, ACCOUNT, makeBlob(), { location: "disk", acknowledged: /** @type {any} */ (acknowledged) }),
      { code: "acknowledgement_required" },
    );
  }
  assert.equal(diskRecords(world).length, 0);
  assert.equal(sessionKeys(world).length, 0);
  // The session location is the safer one and needs no acknowledgement.
  await world.store.save(SERVER, ACCOUNT, makeBlob(), { location: "session" });
  await world.store.save(SERVER, ACCOUNT, makeBlob({ fill: 9 }), { location: "disk", acknowledged: true });
  assert.equal((await world.store.status(SERVER, ACCOUNT)).location, "disk");
  await assert.rejects(world.store.save(SERVER, ACCOUNT, makeBlob(), { location: /** @type {any} */ ("local"), acknowledged: true }), { code: "bad_location" });
});

test("session_location_lives_only_in_storage_session", async () => {
  const world = createWorld();
  await world.store.save(SERVER, ACCOUNT, makeBlob(), { location: "session" });
  assert.deepEqual(diskRecords(world), []);
  assert.equal(sessionKeys(world).length, 1);
  assert.ok(sessionKeys(world)[0].startsWith(SESSION_KEY_PREFIX));
  const status = await world.store.status(SERVER, ACCOUNT);
  assert.equal(status.location, "session");
  assert.equal(status.set, true);
  // It works from there, and after a restart of the browser (the session data is gone) it is gone.
  const answer = await world.store.attempt(SERVER, ACCOUNT, { online: true }, fakeUnlock(["ok"]).run);
  assert.equal(answer.result, "ok");
  world.session.data.clear();
  assert.equal((await world.store.status(SERVER, ACCOUNT)).set, false);
});

test("disk_location_lives_only_in_ferret_unlock", async () => {
  const world = createWorld();
  await world.store.save(SERVER, ACCOUNT, makeBlob(), { location: "disk", acknowledged: true });
  assert.equal(sessionKeys(world).length, 0);
  assert.equal(world.session.writes.length, 0);
  assert.deepEqual(world.idb.opens.names, [UNLOCK_DB_NAME]);
  assert.equal(diskRecords(world).length, 1);
  assert.deepEqual(diskRecords(world)[0].key, [SERVER, ACCOUNT]);
  // The disk record survives a restart of the background and of the browser (new store, session data gone).
  world.session.data.clear();
  const restarted = world.another();
  const status = await restarted.status(SERVER, ACCOUNT);
  assert.equal(status.set, true);
  assert.equal(status.location, "disk");
});

test("moving_a_blob_removes_it_from_the_old_place", async () => {
  const world = createWorld();
  await world.store.save(SERVER, ACCOUNT, makeBlob(), { location: "session" });
  await world.store.save(SERVER, ACCOUNT, makeBlob({ fill: 20 }), { location: "disk", acknowledged: true });
  assert.equal(sessionKeys(world).length, 0, "session -> disk leaves nothing in the session storage");
  assert.equal(diskRecords(world).length, 1);
  await world.store.save(SERVER, ACCOUNT, makeBlob({ fill: 30 }), { location: "session" });
  assert.equal(diskRecords(world).length, 0, "disk -> session leaves nothing in the database");
  assert.equal(sessionKeys(world).length, 1);
  assert.equal((await world.store.status(SERVER, ACCOUNT)).location, "session");
});

test("a_record_found_in_both_places_keeps_the_newer_one", async () => {
  // A crash between the write of a move and the delete of the old place.
  const world = createWorld();
  await world.store.save(SERVER, ACCOUNT, makeBlob(), { location: "disk", acknowledged: true });
  world.clock.advance(1_000);
  const second = world.another();
  await second.save(SERVER, ACCOUNT, makeBlob({ fill: 40 }), { location: "session" });
  // Put the old one back, as a crash would have left it.
  const keep = diskRecords(world)[0];
  assert.equal(diskRecords(world).length, 0);
  world.idb.plant(UNLOCK_DB_NAME, PIN_STORE, keep?.key ?? [SERVER, ACCOUNT], {
    ...makeBlob(),
    failures: 0,
    lastFailureAt: null,
    lastContactAt: 1,
    lastOnlineAt: 1,
    highestSeenAt: 1,
    createdAt: 1,
  });
  const status = await world.store.status(SERVER, ACCOUNT);
  assert.equal(status.location, "session");
  assert.equal(diskRecords(world).length, 0);
});

test("the_stored_pin_record_has_no_kind_and_no_length", async () => {
  const world = createWorld();
  await world.store.save(SERVER, ACCOUNT, makeBlob(), { location: "disk", acknowledged: true });
  const stored = /** @type {any} */ (diskRecords(world)[0].value);
  assert.deepEqual(Object.keys(stored).sort(), [
    "createdAt", "deviceSalt", "failures", "highestSeenAt", "lastContactAt", "lastFailureAt", "lastOnlineAt", "methodId", "pinProfile", "rule", "vkEpoch", "wrap",
  ]);
  assert.deepEqual(Object.keys(stored.rule), ["minLength"], "the rule is the floor of the server, the same for every user");
  assert.equal(stored.wrap.length, 104);
  // Nowhere in the record, at any depth, is there a field that could carry a PIN, its length or its kind.
  /** @param {unknown} value @returns {string[]} */
  const names = (value) => (value && typeof value === "object" && !(value instanceof Uint8Array) ? Object.entries(value).flatMap(([k, v]) => [k, ...names(v)]) : []);
  for (const name of names(stored)) assert.doesNotMatch(name.toLowerCase(), /^(pin|kind|length|digits|numeric|type|charset|secret|password)$/);
  // The session form is the same fields.
  await world.store.save(SERVER, ACCOUNT, makeBlob(), { location: "session" });
  const raw = /** @type {any} */ ([...world.session.data.values()][0]);
  assert.deepEqual(Object.keys(raw).sort(), Object.keys(stored).sort());
  // A blob that carries one of those fields is refused, whatever it is called.
  for (const extra of ["pin", "kind", "length", "pinLength", "digitsOnly", "pin_kind"]) {
    await assert.rejects(world.store.save(SERVER, ACCOUNT_2, { ...makeBlob(), [extra]: 6 }, { location: "session" }), { code: "bad_blob" }, extra);
  }
  await assert.rejects(world.store.save(SERVER, ACCOUNT_2, { ...makeBlob(), rule: { minLength: 6, length: 8 } }, { location: "session" }), { code: "bad_blob" });
  assert.equal((await world.store.status(SERVER, ACCOUNT_2)).set, false);
});

test("the_save_refuses_a_blob_of_the_wrong_shape", async () => {
  const world = createWorld();
  /** @type {Array<Record<string, unknown>>} */
  const bad = [
    { wrap: new Uint8Array(103) },
    { deviceSalt: new Uint8Array(15) },
    { methodId: new Uint8Array(0) },
    { methodId: "abcd" },
    { pinProfile: 0 },
    { vkEpoch: -1 },
    { rule: { minLength: 3 } },
    { rule: { minLength: 65 } },
    { rule: {} },
  ];
  for (const change of bad) {
    await assert.rejects(world.store.save(SERVER, ACCOUNT, { ...makeBlob(), ...change }, { location: "session" }), { code: "bad_blob" }, JSON.stringify(Object.keys(change)));
  }
  await assert.rejects(world.store.save("not a url", ACCOUNT, makeBlob(), { location: "session" }), { code: "bad_server" });
  await assert.rejects(world.store.save(SERVER, "xyz", makeBlob(), { location: "session" }), { code: "bad_account" });
  assert.equal(sessionKeys(world).length, 0);
});

test("nothing_is_written_to_storage_local", async () => {
  /** @type {string[]} */
  const touched = [];
  const trap = new Proxy({}, { get: (_t, name) => (...args) => (touched.push(String(name)), Promise.resolve(args)) });
  const g = /** @type {any} */ (globalThis);
  const saved = { browser: g.browser, chrome: g.chrome };
  g.browser = { storage: { local: trap, sync: trap, session: trap } };
  g.chrome = g.browser;
  try {
    const world = createWorld();
    await world.store.save(SERVER, ACCOUNT, makeBlob(), { location: "disk", acknowledged: true });
    await world.store.save(SERVER, ACCOUNT_2, makeBlob(), { location: "session" });
    await world.store.attempt(SERVER, ACCOUNT, { online: true }, fakeUnlock(["wrong"]).run);
    await world.store.markContact(SERVER, ACCOUNT);
    await world.store.tick();
    await world.store.cachePolicy(SERVER, policy());
    await world.store.wipeAll("pin_off");
    assert.deepEqual(touched, []);
  } finally {
    g.browser = saved.browser;
    g.chrome = saved.chrome;
  }
  // And the source names neither area.
  const text = readFileSync(join(SRC, "background", "localUnlock.mjs"), "utf8");
  assert.doesNotMatch(text, /storage\s*\.\s*(local|sync)/);
  assert.doesNotMatch(text, /\b(browser|chrome)\s*\./);
});

test("wipe_never_counts_and_never_runs_the_unlock", async () => {
  for (const location of /** @type {const} */ (["disk", "session"])) {
    const world = createWorld();
    await world.store.save(SERVER, ACCOUNT, makeBlob(), { location, acknowledged: true });
    await world.store.attempt(SERVER, ACCOUNT, { online: true }, fakeUnlock(["wrong"]).run);
    const unlock = fakeUnlock(["ok"]);
    await world.store.wipe(SERVER, ACCOUNT, "signed_out");
    assert.equal(unlock.calls.count, 0);
    assert.equal((await world.store.status(SERVER, ACCOUNT)).set, false);
    assert.equal(diskRecords(world).length, 0);
    assert.equal(sessionKeys(world).length, 0);
    // Wiping nothing is fine and writes nothing back.
    await world.store.wipe(SERVER, ACCOUNT, "signed_out");
    assert.equal(diskRecords(world).length, 0);
    // A wipe has a reason from the list; one that is not on it still wipes (the safe direction) and is then refused.
    await world.store.save(SERVER, ACCOUNT, makeBlob(), { location, acknowledged: true });
    await assert.rejects(world.store.wipe(SERVER, ACCOUNT, /** @type {any} */ ("whatever")), { code: "bad_reason" });
    assert.equal((await world.store.status(SERVER, ACCOUNT)).set, false);
    await world.store.save(SERVER, ACCOUNT, makeBlob(), { location, acknowledged: true });
    await assert.rejects(world.store.wipeServer(SERVER, /** @type {any} */ ("whatever")), { code: "bad_reason" });
    assert.equal((await world.store.status(SERVER, ACCOUNT)).set, false);
    await world.store.save(SERVER, ACCOUNT, makeBlob(), { location, acknowledged: true });
    await assert.rejects(world.store.wipeAll(/** @type {any} */ ("whatever")), { code: "bad_reason" });
    assert.equal((await world.store.status(SERVER, ACCOUNT)).set, false);
  }
  assert.ok(WIPE_REASONS.includes("device_revoked") && WIPE_REASONS.includes("failures") && WIPE_REASONS.includes("forgot_server"));
});

test("a_wipe_overwrites_and_then_deletes_and_a_crash_in_between_still_ends_in_a_wipe", async () => {
  const world = createWorld();
  await world.store.save(SERVER, ACCOUNT, makeBlob(), { location: "disk", acknowledged: true });
  const mark = world.idb.log.length;
  await world.store.wipe(SERVER, ACCOUNT, "pin_off");
  const wipes = world.idb.log.slice(mark).filter((entry) => entry.mode === "readwrite");
  assert.deepEqual(wipes.map((entry) => entry.ops.filter((op) => op !== `get:${PIN_STORE}`)), [[`put:${PIN_STORE}`], [`delete:${PIN_STORE}`]]);
  // Said honestly: the overwrite is a courtesy, not a secure delete (the database has no secure_delete).
  // What a crash between the two steps leaves is a record that is spent: zeroed and at the limit.
  const left = createWorld();
  await left.store.save(SERVER, ACCOUNT, makeBlob(), { location: "disk", acknowledged: true });
  left.idb.state.failOp = (tx, label) => (label === `delete:${PIN_STORE}` ? new Error("crash") : null);
  await assert.rejects(left.store.wipe(SERVER, ACCOUNT, "pin_off"));
  left.idb.state.failOp = null;
  const spent = /** @type {any} */ (diskRecords(left)[0].value);
  assert.equal(spent.failures, 5);
  assert.ok(spent.wrap.every((/** @type {number} */ b) => b === 0));
  const unlock = fakeUnlock(["ok"]);
  assert.equal((await left.store.attempt(SERVER, ACCOUNT, { online: true }, unlock.run)).result, "wiped");
  assert.equal(unlock.calls.count, 0);
  assert.equal(diskRecords(left).length, 0);
});

test("wipe_server_covers_every_account_of_that_server", async () => {
  const world = createWorld();
  await world.store.save(SERVER, ACCOUNT, makeBlob(), { location: "disk", acknowledged: true });
  await world.store.save(SERVER, ACCOUNT_2, makeBlob({ fill: 11 }), { location: "session" });
  await world.store.save(OTHER_SERVER, ACCOUNT, makeBlob({ fill: 12 }), { location: "disk", acknowledged: true });
  await world.store.save(OTHER_SERVER, ACCOUNT_2, makeBlob({ fill: 13 }), { location: "session" });
  await world.store.wipeServer(`${SERVER}/some/path`, "forgot_server");
  assert.equal((await world.store.status(SERVER, ACCOUNT)).set, false);
  assert.equal((await world.store.status(SERVER, ACCOUNT_2)).set, false);
  assert.equal((await world.store.status(OTHER_SERVER, ACCOUNT)).set, true);
  assert.equal((await world.store.status(OTHER_SERVER, ACCOUNT_2)).set, true);
  // wipeAll takes the rest.
  await world.store.wipeAll("pin_off");
  assert.equal((await world.store.status(OTHER_SERVER, ACCOUNT)).set, false);
  assert.equal((await world.store.status(OTHER_SERVER, ACCOUNT_2)).set, false);
  assert.equal(diskRecords(world).length, 0);
  assert.equal(sessionKeys(world).length, 0);
});

test("a_stricter_rule_or_a_forbidden_pin_deletes_the_blob", async () => {
  const world = createWorld();
  await world.store.save(SERVER, ACCOUNT, makeBlob({ minLength: 6 }), { location: "disk", acknowledged: true });
  await world.store.save(SERVER, ACCOUNT_2, makeBlob({ minLength: 6 }), { location: "session" });
  // The same rule or a weaker one keeps both.
  await world.store.cachePolicy(SERVER, policy({ min_length: 6 }));
  await world.store.cachePolicy(SERVER, policy({ min_length: 4 }));
  assert.equal((await world.store.status(SERVER, ACCOUNT)).set, true);
  assert.equal((await world.store.status(SERVER, ACCOUNT_2)).set, true);
  // A stricter minimum deletes the blobs made under the weaker one, in both places.
  await world.store.cachePolicy(SERVER, policy({ min_length: 8 }));
  assert.equal((await world.store.status(SERVER, ACCOUNT)).set, false);
  assert.equal((await world.store.status(SERVER, ACCOUNT_2)).set, false);
  // A rule that forbids PINs deletes them as well.
  await world.store.save(SERVER, ACCOUNT, makeBlob({ minLength: 8 }), { location: "disk", acknowledged: true });
  await world.store.save(SERVER, ACCOUNT_2, makeBlob({ minLength: 8 }), { location: "session" });
  await world.store.cachePolicy(SERVER, policy({ min_length: 8, allowed: false }));
  assert.equal((await world.store.status(SERVER, ACCOUNT)).set, false);
  assert.equal((await world.store.status(SERVER, ACCOUNT_2)).set, false);
  // The rule is refused for a save, and a record that slipped in is still not unlocked: the attempt wipes it.
  await assert.rejects(world.store.save(SERVER, ACCOUNT, makeBlob({ minLength: 8 }), { location: "session" }), { code: "rule_forbids" });
  await world.store.cachePolicy(SERVER, policy({ min_length: 4 }));
  await world.store.save(SERVER, ACCOUNT, makeBlob({ minLength: 4 }), { location: "session" });
  await world.store.cachePolicy(OTHER_SERVER, policy({ allowed: false }));
  assert.equal((await world.store.status(SERVER, ACCOUNT)).set, true, "another server's rule touches nothing here");
  world.idb.plant(UNLOCK_DB_NAME, POLICY_STORE, SERVER, policy({ min_length: 10 }));
  const unlock = fakeUnlock(["ok"]);
  assert.equal((await world.store.attempt(SERVER, ACCOUNT, { online: true }, unlock.run)).result, "wiped");
  assert.equal(unlock.calls.count, 0);
});

test("after_restart_off_deletes_a_disk_blob", async () => {
  const world = createWorld();
  await world.store.save(SERVER, ACCOUNT, makeBlob(), { location: "disk", acknowledged: true });
  await world.store.save(SERVER, ACCOUNT_2, makeBlob({ fill: 15 }), { location: "session" });
  await world.store.cachePolicy(SERVER, policy({ after_restart: false }));
  assert.equal((await world.store.status(SERVER, ACCOUNT)).set, false, "the disk blob is gone");
  assert.equal(diskRecords(world).length, 0);
  assert.equal((await world.store.status(SERVER, ACCOUNT_2)).set, true, "the memory blob stays");
  await assert.rejects(world.store.save(SERVER, ACCOUNT, makeBlob(), { location: "disk", acknowledged: true }), { code: "rule_forbids" });
  await world.store.save(SERVER, ACCOUNT, makeBlob(), { location: "session" });
});

test("the_cached_policy_is_kept_and_checked", async () => {
  const world = createWorld();
  assert.equal(await world.store.cachedPolicy(SERVER), null);
  await world.store.cachePolicy(SERVER, policy({ min_length: 9 }, false));
  assert.deepEqual(await world.another().cachedPolicy(SERVER), policy({ min_length: 9 }, false));
  assert.equal(await world.store.cachedPolicy(OTHER_SERVER), null);
  for (const bad of [null, {}, { pin: {}, prf: {} }, policy({ min_length: 3 }), policy({ min_length: 65 }), policy({ allowed: "yes" }), { pin: policy().pin }]) {
    await assert.rejects(world.store.cachePolicy(SERVER, /** @type {any} */ (bad)), { code: "bad_policy" });
  }
  // A refused rule changes nothing.
  assert.deepEqual(await world.store.cachedPolicy(SERVER), policy({ min_length: 9 }, false));
  // A rule is not a secret and not a record: wipeAll leaves it.
  await world.store.wipeAll("pin_off");
  assert.deepEqual(await world.store.cachedPolicy(SERVER), policy({ min_length: 9 }, false));
  assert.equal(world.session.writes.length, 0);
});

test("only_local_unlock_opens_the_ferret_unlock_database", () => {
  /** @param {string} dir @returns {string[]} */
  const walk = (dir) =>
    readdirSync(dir).flatMap((name) => {
      const path = join(dir, name);
      return statSync(path).isDirectory() ? walk(path) : /\.(?:mjs|js|html)$/.test(name) ? [path] : [];
    });
  const home = join(SRC, "background", "localUnlock.mjs");
  /** @type {string[]} */
  const offenders = [];
  for (const file of [...walk(SRC), ...walk(WEB_SRC)]) {
    if (file === home) continue;
    const text = readFileSync(file, "utf8")
      // The one thing a build without the feature may do: delete the database at start.
      .replace(/indexedDB\s*\.\s*deleteDatabase\(\s*["']ferret-unlock["']\s*\)/g, "");
    if (/ferret-unlock/.test(text) || text.includes(SESSION_KEY_PREFIX) || /["'`]ferretPin\b/.test(text)) offenders.push(relative(join(HERE, "..", "..", ".."), file));
  }
  assert.deepEqual(offenders, [], "only background/localUnlock.mjs names the database or the session key of the PIN");
  // The module opens it by its name, once.
  const text = readFileSync(home, "utf8");
  assert.equal(UNLOCK_DB_NAME, "ferret-unlock");
  assert.equal((text.match(/factory\.open\(/g) ?? []).length, 1);
});

test("the_store_has_no_imports_and_no_logging", () => {
  const text = readFileSync(join(SRC, "background", "localUnlock.mjs"), "utf8");
  assert.doesNotMatch(text, /^\s*import\s/m);
  assert.doesNotMatch(text, /console\s*\./);
});

test("bytes_from_another_realm_are_accepted_like_bytes_of_this_one", async () => {
  // A value that comes back from IndexedDB or from a message may be a Uint8Array of another global.
  const world = createWorld();
  const foreign = (/** @type {number} */ length, /** @type {number} */ fill) => runInNewContext(`new Uint8Array(${length}).fill(${fill})`);
  assert.ok(!(foreign(1, 0) instanceof Uint8Array));
  const blob = { ...makeBlob(), methodId: foreign(16, 1), wrap: foreign(104, 2), deviceSalt: foreign(16, 3) };
  await world.store.save(SERVER, ACCOUNT, blob, { location: "session" });
  assert.equal((await world.store.status(SERVER, ACCOUNT)).set, true);
});
