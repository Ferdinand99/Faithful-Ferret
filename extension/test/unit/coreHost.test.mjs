import assert from "node:assert/strict";
import { test } from "node:test";
import { CORE_OPS, CoreError, LOCK_REASONS, createCoreHost } from "../../src/background/coreHost.mjs";
import { ops as testOps } from "../../src/background/test-only/testHooks.mjs";
import { AAGUID, createClock, createFakeClient } from "./backgroundHelpers.mjs";

/** Operations that only the tests have: one that needs the vault and one that opens it. */
const probes = Object.freeze({
  vault_probe: { vault: true, worker: /** @type {"vault"} */ ("vault"), run: async (/** @type {any} */ client) => client.vault.item_list() },
  unlock_probe: {
    vault: false,
    worker: /** @type {"none"} */ ("none"),
    run: async (/** @type {any} */ _client, /** @type {any} */ _args, /** @type {any} */ ctx) => {
      ctx.setUnlocked();
      return { ok: true };
    },
  },
});
const names = [...CORE_OPS, "vault_probe", "unlock_probe"];

/** @param {Record<string, (...args: any[]) => any>} [methods] */
function setup(methods = {}) {
  const client = createFakeClient({
    vault: { ferret_aaguid: () => Uint8Array.from(AAGUID), item_list: () => ["a"], ...methods },
    job: { argon2_export_key: () => new Uint8Array(32).fill(7) },
  });
  let made = 0;
  const clock = createClock();
  const host = createCoreHost({
    createClient: () => {
      made += 1;
      return client;
    },
    now: clock.now,
    ops: probes,
    names,
  });
  return { client, host, clock, made: () => made };
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

test("lock_ends_the_worker_and_a_later_call_reports_vault_locked", async () => {
  const { client, host } = setup();
  assert.equal(host.state(), "locked");
  await host.call("unlock_probe");
  assert.equal(host.state(), "unlocked");
  assert.deepEqual(await host.call("vault_probe"), ["a"]);

  await host.lock("manual");
  assert.equal(client.locks, 1, "client.lock() ends the worker");
  assert.equal(host.state(), "locked");
  const before = client.calls.length;
  await assert.rejects(host.call("vault_probe"), { code: "vault_locked" });
  assert.equal(client.calls.length, before, "a locked host does not touch the client");
  // An op that needs no key still works, and does not unlock.
  assert.equal(/** @type {any} */ (await host.call("ping")).ok, true);
  assert.equal(host.state(), "locked");
});

test("a_call_that_is_waiting_when_the_vault_locks_is_refused_as_vault_locked", async () => {
  const { host } = setup({ item_list: () => new Promise(() => {}) });
  await host.call("unlock_probe");
  const waiting = host.call("vault_probe");
  await tick();
  await host.lock("idle");
  await assert.rejects(waiting, { code: "vault_locked" });
});

test("a_result_that_arrives_after_a_lock_is_not_handed_out", async () => {
  /** @type {() => void} */
  let release = () => {};
  const { host, client } = setup();
  // A client that does not reject the waiting call (the real one does): the host still refuses.
  client.lock = async () => {
    client.locks += 1;
  };
  client.vault = /** @type {any} */ ({
    item_list: () => new Promise((resolve) => {
      release = () => resolve(["late"]);
    }),
  });
  await host.call("unlock_probe");
  const waiting = host.call("vault_probe");
  await tick();
  await host.lock("timeout");
  release();
  await assert.rejects(waiting, { code: "vault_locked" });
});

test("unknown_core_op_is_refused", async () => {
  const { host, made } = setup();
  for (const op of ["", "nope", "__proto__", "constructor", "toString", "hasOwnProperty", "lock", "vault.lock", "PING", "ping ", 7, null, undefined, {}, ["ping"]]) {
    await assert.rejects(host.call(/** @type {any} */ (op)), { code: "unknown_core_op" }, String(op));
  }
  assert.equal(made(), 0, "a refused name never starts the client");
  // A name that is not in the list cannot be given an implementation, at start or later.
  assert.throws(() => createCoreHost({ createClient: () => createFakeClient(), ops: probes }), { code: "unknown_core_op" });
  const plain = createCoreHost({ createClient: () => createFakeClient() });
  await assert.rejects(plain.call("vault_probe"), { code: "unknown_core_op" });
  assert.throws(() => plain.addOps(probes), { code: "unknown_core_op" });
});

test("core_ops_is_a_frozen_list_and_the_release_has_no_argon2_bench", async () => {
  assert.equal(Object.isFrozen(CORE_OPS), true);
  assert.deepEqual([...CORE_OPS], ["ping", "argon2_bench"]);
  // Without the test build's implementation the name is in the list but refused.
  const release = createCoreHost({ createClient: () => createFakeClient() });
  await assert.rejects(release.call("argon2_bench", { m_kib: 8, t: 1, p: 1 }), { code: "unknown_core_op" });
});

test("ping_answers_from_the_wasm_client_and_starts_it_once", async () => {
  const { host, made } = setup();
  assert.deepEqual(await host.call("ping"), { ok: true, aaguid: "dc704a44b994410ca689ed8d71a84ac3" });
  await host.call("ping");
  assert.equal(made(), 1);
});

test("a_client_that_fails_to_start_is_tried_again_and_lock_still_works", async () => {
  let attempts = 0;
  const host = createCoreHost({
    createClient: () => {
      attempts += 1;
      if (attempts === 1) throw new Error("secret-looking text that must not leave");
      return createFakeClient({ vault: { ferret_aaguid: () => Uint8Array.from(AAGUID) } });
    },
  });
  await assert.rejects(host.call("ping"), (/** @type {any} */ error) => error instanceof CoreError && error.code === "internal" && !/secret/.test(error.message));
  await host.lock("manual");
  assert.equal(/** @type {any} */ (await host.call("ping")).ok, true);
});

test("an_error_of_the_client_leaves_as_its_code_only", async () => {
  const { host } = setup({
    ferret_aaguid: () => {
      throw Object.assign(new Error("password=hunter2"), { code: "kdf_out_of_memory" });
    },
  });
  await assert.rejects(host.call("ping"), (/** @type {any} */ error) => error.code === "kdf_out_of_memory" && !/hunter2/.test(error.message));
  const odd = setup({
    ferret_aaguid: () => {
      throw Object.assign(new Error("x"), { code: "Not A Code!" });
    },
  });
  await assert.rejects(odd.host.call("ping"), { code: "internal" });
  const wrongShape = setup({ ferret_aaguid: () => new Uint8Array(3) });
  await assert.rejects(wrongShape.host.call("ping"), { code: "internal" });
});

test("a_reply_is_plain_data_and_never_a_key", async () => {
  const { host } = setup();
  const value = await host.call("ping");
  assert.deepEqual(JSON.parse(JSON.stringify(value)), value);
});

test("lock_refuses_a_reason_it_does_not_know_and_tells_its_listeners", async () => {
  const { host, client } = setup();
  assert.deepEqual([...LOCK_REASONS], ["timeout", "idle", "manual", "sign_out", "restart", "worker_failed"]);
  await assert.rejects(host.lock(/** @type {any} */ ("because")), { code: "bad_reason" });
  assert.equal(client.locks, 0);
  /** @type {string[]} */
  const heard = [];
  const stop = host.onLocked((reason) => heard.push(reason));
  host.onLocked(() => {
    throw new Error("a listener that fails");
  });
  await host.lock("sign_out");
  await host.call("ping");
  await host.lock("restart");
  stop();
  await host.lock("manual");
  assert.deepEqual(heard, ["sign_out", "restart"]);
  assert.equal(host.state(), "locked");
});

test("a_lock_before_any_call_needs_no_client", async () => {
  const { host, made } = setup();
  await host.lock("restart");
  assert.equal(made(), 0);
});

test("argon2_bench_runs_in_the_job_worker_wipes_the_key_and_returns_only_the_time", async () => {
  const key = new Uint8Array(32).fill(7);
  const client = createFakeClient({ job: { argon2_export_key: () => key } });
  const clock = createClock(0);
  const host = createCoreHost({
    createClient: () => client,
    now: () => {
      clock.advance(25);
      return clock.now();
    },
  });
  host.addOps(testOps);
  assert.deepEqual(await host.call("argon2_bench", { m_kib: 65_536, t: 3, p: 1 }), { ok: true, ms: 25, key_length: 32 });
  assert.ok(key.every((b) => b === 0), "the key is wiped");
  const call = client.calls.find((c) => c.method === "argon2_export_key");
  assert.equal(call?.target, "job");
  assert.deepEqual(call?.args.slice(2), [{ m_kib: 65_536, t: 3, p: 1 }, "open", null]);
  assert.equal(client.calls.filter((c) => c.target === "vault").length, 0, "the vault worker is not used");
  for (const bad of [undefined, {}, { m_kib: 0, t: 1, p: 1 }, { m_kib: 1e9, t: 1, p: 1 }, { m_kib: 8, t: 1.5, p: 1 }, { m_kib: 8, t: 1, p: 9 }, { m_kib: "8", t: 1, p: 1 }]) {
    await assert.rejects(host.call("argon2_bench", bad), { code: "invalid_input" });
  }
});

test("a_worker_that_fails_locks_the_host_and_tells_its_listeners", async () => {
  for (const code of ["worker_failed", "internal", "kdf_out_of_memory"]) {
    const { host, client } = setup({
      item_list: () => {
        throw Object.assign(new Error("worker died"), { code });
      },
    });
    /** @type {string[]} */
    const heard = [];
    host.onLocked((reason) => heard.push(reason));
    await host.call("unlock_probe");
    await assert.rejects(host.call("vault_probe"), { code });
    assert.equal(host.state(), "locked", code);
    assert.deepEqual(heard, ["worker_failed"], code);
    // The next vault op is refused without touching the client.
    const before = client.calls.length;
    await assert.rejects(host.call("vault_probe"), { code: "vault_locked" });
    assert.equal(client.calls.length, before);
  }
});

test("a_failure_of_the_job_worker_or_of_the_host_itself_does_not_lock", async () => {
  // The job worker is ended by the client on its own; the vault is not affected.
  const client = createFakeClient({
    vault: { ferret_aaguid: () => Uint8Array.from(AAGUID) },
    job: { argon2_export_key: () => { throw Object.assign(new Error("oom"), { code: "kdf_out_of_memory" }); } },
  });
  const host = createCoreHost({ createClient: () => client, ops: probes, names });
  host.addOps(testOps);
  await host.call("unlock_probe");
  await assert.rejects(host.call("argon2_bench", { m_kib: 8, t: 1, p: 1 }), { code: "kdf_out_of_memory" });
  assert.equal(host.state(), "unlocked");
  // A bad answer that the op itself found (not the client) is not a dead worker either.
  const odd = createCoreHost({ createClient: () => createFakeClient({ vault: { ferret_aaguid: () => new Uint8Array(3) } }), ops: probes, names });
  await odd.call("unlock_probe");
  await assert.rejects(odd.call("ping"), { code: "internal" });
  assert.equal(odd.state(), "unlocked");
});

test("a_lock_during_an_unlock_wins", async () => {
  /** @type {() => void} */
  let open = () => {};
  const gate = new Promise((resolve) => {
    open = () => resolve(undefined);
  });
  const slow = {
    slow_unlock: {
      vault: false,
      worker: /** @type {"vault"} */ ("vault"),
      run: async (/** @type {any} */ _client, /** @type {any} */ _args, /** @type {any} */ ctx) => {
        await gate;
        ctx.setUnlocked();
        return { ok: true };
      },
    },
  };
  const client = createFakeClient();
  const host = createCoreHost({ createClient: () => client, ops: slow, names: [...CORE_OPS, "slow_unlock"] });
  let opened = 0;
  host.onUnlocked(() => {
    opened += 1;
  });
  const pending = host.call("slow_unlock");
  await tick();
  await host.lock("idle");
  open();
  await assert.rejects(pending, { code: "vault_locked" });
  assert.equal(host.state(), "locked");
  assert.equal(opened, 0, "nothing heard of an unlock that did not happen");
  // A later unlock works.
  const again = createCoreHost({ createClient: () => client, ops: probes, names });
  again.onUnlocked(() => {
    opened += 1;
  });
  await again.call("unlock_probe");
  assert.equal(again.state(), "unlocked");
  assert.equal(opened, 1);
});

test("add_ops_refuses_to_replace_an_op", async () => {
  const host = createCoreHost({ createClient: () => createFakeClient(), names });
  host.addOps(probes);
  assert.throws(() => host.addOps({ ping: { vault: false, worker: "none", run: async () => ({ ok: true, aaguid: "fake" }) } }), { code: "op_exists" });
  assert.throws(() => host.addOps({ vault_probe: probes.vault_probe }), { code: "op_exists" });
  // Nor can the constructor replace the base op.
  assert.throws(() => createCoreHost({ ops: { ping: probes.vault_probe }, names }), { code: "op_exists" });
  // The base op still answers as before.
  const fresh = setup();
  assert.equal(/** @type {any} */ (await fresh.host.call("ping")).ok, true);
});

test("an_op_that_uses_the_vault_locks_the_host_when_the_worker_fails_whatever_it_says", async () => {
  const failing = (/** @type {"job" | "none" | "vault"} */ worker) => ({
    // Says `worker`, and an export-like op: the job worker first, then the vault.
    mixed: {
      vault: false,
      worker,
      run: async (/** @type {any} */ client) => {
        await client.job.argon2_export_key("x", new Uint8Array(16).fill(1), {}, "open", null);
        return client.vault.export_finish();
      },
    },
  });
  for (const worker of /** @type {const} */ (["job", "none", "vault"])) {
    const client = createFakeClient({
      vault: { export_finish: () => { throw Object.assign(new Error("trap"), { code: "internal" }); } },
      job: { argon2_export_key: () => new Uint8Array(32).fill(3) },
    });
    const host = createCoreHost({ createClient: () => client, ops: { ...probes, ...failing(worker) }, names: [...names, "mixed"] });
    /** @type {string[]} */
    const heard = [];
    host.onLocked((reason) => heard.push(reason));
    await host.call("unlock_probe");
    await assert.rejects(host.call("mixed"), { code: "internal" });
    assert.equal(host.state(), "locked", worker);
    assert.deepEqual(heard, ["worker_failed"], worker);
  }
});

test("a_job_op_that_never_touches_the_vault_does_not_lock_but_any_other_failure_does", async () => {
  const client = createFakeClient({ job: { argon2_export_key: () => { throw Object.assign(new Error("oom"), { code: "internal" }); } } });
  const host = createCoreHost({ createClient: () => client, ops: probes, names });
  host.addOps(testOps);
  await host.call("unlock_probe");
  await assert.rejects(host.call("argon2_bench", { m_kib: 8, t: 1, p: 1 }), { code: "internal" });
  assert.equal(host.state(), "unlocked", "a job worker is ended by the client on its own");
  // The same failure from an op declared `none` locks: only a job op is exempt.
  const none = createCoreHost({
    createClient: () => createFakeClient(),
    ops: { ...probes, undeclared: { vault: false, worker: /** @type {"none"} */ ("none"), run: async () => { throw Object.assign(new Error("x"), { code: "worker_failed" }); } } },
    names: [...names, "undeclared"],
  });
  await none.call("unlock_probe");
  await assert.rejects(none.call("undeclared"), { code: "worker_failed" });
  assert.equal(none.state(), "locked");
});

test("an_op_needs_a_known_worker_and_a_vault_op_runs_on_the_vault_worker", () => {
  const run = async () => ({});
  const make = (/** @type {any} */ def) => () => createCoreHost({ ops: { probe: def }, names: [...CORE_OPS, "probe"] });
  assert.throws(make({ vault: false, run }), { code: "bad_op" }, "no worker");
  assert.throws(make({ vault: false, worker: undefined, run }), { code: "bad_op" });
  for (const worker of ["Vault", "vault ", "worker", "", null, 1, "__proto__"]) {
    assert.throws(make({ vault: false, worker, run }), { code: "bad_op" }, String(worker));
  }
  assert.throws(make({ vault: true, worker: "job", run }), { code: "bad_op" });
  assert.throws(make({ vault: true, worker: "none", run }), { code: "bad_op" });
  assert.throws(make({ vault: "yes", worker: "vault", run }), { code: "bad_op" });
  assert.throws(make({ vault: false, worker: "job" }), { code: "bad_op" }, "no run");
  assert.throws(make(null), { code: "bad_op" });
  for (const worker of ["vault", "job", "none"]) assert.doesNotThrow(make({ vault: false, worker, run }));
  assert.doesNotThrow(make({ vault: true, worker: "vault", run }));
  // addOps checks the same.
  const host = createCoreHost({ names: [...CORE_OPS, "probe"] });
  assert.throws(() => host.addOps({ probe: { vault: false, run } }), { code: "bad_op" });
});
