// The message protocol and the page's client, run against the real dispatcher
// and the WASM build, with fake workers (no `Worker` in Node).
// Run: node --test tests/node/
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { createClient } from "../../bindings/wasm/js/client.mjs";
import { createDispatcher, createJobDispatcher } from "../../bindings/wasm/js/protocol.mjs";
import { IDS, PASSWORD, URL_, enc, fill, wasm } from "./helpers.mjs";

/** A worker in this thread: structured clone both ways, one tick of delay. */
class FakeWorker {
  constructor(dispatch) {
    this.dispatch = dispatch;
    this.terminated = false;
    this.received = [];
  }

  postMessage(message, transfer = []) {
    const copy = structuredClone(message, { transfer });
    this.received.push(copy);
    queueMicrotask(() => {
      if (this.terminated) return;
      const { reply, transfer: out } = this.dispatch(copy);
      const cloned = structuredClone(reply, { transfer: out });
      this.onmessage?.({ data: cloned });
    });
  }

  terminate() {
    this.terminated = true;
  }
}

function setup() {
  const made = { vault: [], job: [] };
  const client = createClient({
    createVaultWorker: () => {
      const w = new FakeWorker(createDispatcher(wasm));
      made.vault.push(w);
      return w;
    },
    createJobWorker: () => {
      const w = new FakeWorker(createJobDispatcher(wasm));
      made.job.push(w);
      return w;
    },
  });
  return { client, made };
}

async function rejection(promise) {
  try {
    await promise;
  } catch (e) {
    return e;
  }
  throw new Error("expected a rejection");
}

test("lone_surrogate_rejected_at_js_boundary", async () => {
  const { client, made } = setup();
  // The text of a password with a lone surrogate would become U+FFFD in a
  // TextEncoder: it is invalid_input, and nothing is sent.
  for (const method of ["login_start", "register_start", "check_master_password"]) {
    const args = method === "login_start" ? ["abc\uD800", null] : ["abc\uD800", "with_secret_key"];
    const e = await rejection(client.vault[method](...args));
    assert.equal(e.code, "invalid_input", method);
  }
  assert.equal(made.vault.length, 0, "no worker was even started");
  // The same in a text that is not a password: no silent replacement.
  const e = await rejection(client.vault.check_code("recovery_key", "FFR1-\uDC00"));
  assert.equal(e.code, "invalid_input");
  // A well-formed pair (an emoji) goes through, and is judged by the core.
  const ok = await rejection(client.vault.check_master_password("abc😀", "with_secret_key"));
  assert.equal(ok.code, "input_too_short");
  // Not a lone surrogate inside an object either.
  const nested = await rejection(client.vault.encrypt_item(fill(16, 1), 1, { name: "x\uD800" }, undefined, 1));
  assert.equal(nested.code, "invalid_input");
});

test("secret_arguments_are_wiped_after_they_are_sent", async () => {
  const { client, made } = setup();
  const password = enc.encode("long enough password text");
  await client.vault.check_master_password(password, "without_secret_key");
  assert.ok(password.every((b) => b === 0), "the caller's buffer is wiped");
  // The worker got a copy, and wipes it after the call as well.
  assert.ok(made.vault[0].received[0].args[0].every((b) => b === 0));
  // A public argument is not wiped.
  const account = fill(16, 7);
  const payload = await client.vault.setup_qr_build(URL_, account, 1, true, fill(32, 1));
  assert.match(payload, /^ferret-setup:v1\?/);
  assert.ok(account.every((b) => b === 7));
});

test("one_vault_worker_lives_until_lock_and_a_new_one_starts_after", async () => {
  const { client, made } = setup();
  await client.vault.clear();
  assert.equal(made.vault.length, 1);
  assert.equal(made.vault[0].terminated, false);
  await client.vault.clear();
  assert.equal(made.vault.length, 1, "the same worker answers the next call");
  await client.lock();
  assert.equal(made.vault[0].terminated, true, "lock ends the worker, which frees its heap");
  // The next call starts a new worker with nothing in it.
  const e = await rejection(client.vault.context());
  assert.equal(e.code, "vault_locked");
  assert.equal(made.vault.length, 2);
});

test("the_vault_lives_in_the_worker_and_never_in_a_reply", async () => {
  const { client, made } = setup();
  const server = new wasm.TestServer(enc.encode("client-flow"));
  const request = await client.vault.register_start(enc.encode(PASSWORD), { kind: "generate" });
  await client.vault.register_finish(server.register_response(IDS.account_id, request), 1);
  const created = await client.vault.create_account(URL_, IDS);
  assert.equal(created.vault, undefined, "the Vault object stays in the worker");
  assert.equal(created.pinned.sk_bit, true);
  assert.equal(created.wraps.length, 2);
  // The vault methods work on the vault the worker holds.
  const code = await client.vault.reveal_recovery_code();
  assert.match(code, /^FFR1-/);
  assert.equal((await client.vault.context()).vk_epoch, 1);
  const sealed = await client.vault.encrypt_item(fill(16, 1), 1, { item_type: "note", name: "n" }, undefined, 5);
  assert.equal(sealed.rev, 1);
  // Nothing sent to the worker or received from it holds a key: the vault
  // key is 32 bytes inside WASM, the messages hold the values the server
  // gets, and the recovery key only through reveal_recovery_code.
  const sent = JSON.stringify(made.vault[0].received);
  assert.ok(!sent.includes("FFR1-"));
  await client.lock();
  assert.equal((await rejection(client.vault.reveal_recovery_code())).code, "vault_locked");
  assert.equal(made.vault[0].terminated, true);
});

test("the_job_worker_runs_one_function_and_is_ended_after_each_call", async () => {
  const { client, made } = setup();
  const salt = fill(16, 5);
  const kdf = { m_kib: 65536, t: 3, p: 1 };
  const key = await client.job.argon2_export_key(enc.encode("export password for tests"), salt, kdf, "open", null);
  assert.equal(key.length, 32);
  assert.equal(made.job.length, 1);
  assert.equal(made.job[0].terminated, true);
  // Another call is another worker.
  const again = await client.job.argon2_export_key(enc.encode("export password for tests"), salt, kdf, "open", null);
  assert.deepEqual(again, key);
  assert.equal(made.job.length, 2);
  // The job worker answers nothing else, not even the vault's methods.
  for (const method of ["login_start", "open_item", "lock", "reveal_recovery_code"]) {
    const e = await rejection(client.job[method](new Uint8Array(1)));
    assert.equal(e.code, "invalid_input", method);
  }
  assert.ok(made.job.every((w) => w.terminated));
  // And the vault worker does not answer on behalf of the job target.
  const dispatch = createDispatcher(wasm);
  const { reply } = dispatch({ id: 1, target: "job", method: "argon2_export_key", args: [] });
  assert.equal(reply.ok, false);
  assert.equal(reply.code, "invalid_input");
  // A failed call has a code and nothing else.
  const e = await rejection(client.job.argon2_export_key(enc.encode("x"), salt, kdf, "open", null).then(() => client.job.argon2_export_key(enc.encode("y"), salt, { m_kib: 1, t: 1, p: 1 }, "open", null)));
  assert.equal(e.code, "kdf_out_of_range");
  assert.deepEqual(Object.keys(e).sort(), ["code", "name"]);
});

test("kdf_out_of_memory_ends_the_worker_that_reported_it", async () => {
  const made = [];
  const client = createClient({
    createVaultWorker: () => {
      const w = new FakeWorker((request) => ({
        reply: { id: request.id, ok: false, code: "kdf_out_of_memory" },
        transfer: [],
      }));
      made.push(w);
      return w;
    },
  });
  const e = await rejection(client.vault.login_finish(new Uint8Array(1), 1, { kind: "first_use" }));
  assert.equal(e.code, "kdf_out_of_memory");
  assert.equal(made[0].terminated, true, "a heap that failed to grow is not reused");
  await rejection(client.vault.login_finish(new Uint8Array(1), 1, { kind: "first_use" }));
  assert.equal(made.length, 2, "the next call starts a new worker");
});

test("a_crashing_worker_rejects_what_waits_for_it", async () => {
  const worker = new FakeWorker(() => {
    throw new Error("boom");
  });
  worker.postMessage = function () {
    queueMicrotask(() => this.onerror?.({}));
  };
  const client = createClient({ createVaultWorker: () => worker });
  const e = await rejection(client.vault.context());
  assert.equal(e.code, "worker_failed");
  assert.equal(worker.terminated, true);
});

test("lock_through_the_proxy_ends_the_worker_like_client_lock", async () => {
  const { client, made } = setup();
  await client.vault.clear();
  assert.equal(made.vault.length, 1);
  await client.vault.lock();
  assert.equal(made.vault[0].terminated, true, "the worker is ended, not only emptied");
  const e = await rejection(client.vault.context());
  assert.equal(e.code, "vault_locked");
  assert.equal(made.vault.length, 2, "a new worker answered");
  // The dispatcher's method set holds no internal names of wasm-bindgen.
  for (const name of ["__destroy_into_raw", "free", "constructor"]) {
    const bad = await rejection(client.vault[name]());
    assert.equal(bad.code, "invalid_input", name);
  }
});

test("an_internal_error_ends_the_vault_worker", async () => {
  const made = [];
  const client = createClient({
    createVaultWorker: () => {
      const w = new FakeWorker((request) => ({
        reply: { id: request.id, ok: false, code: "internal" },
        transfer: [],
      }));
      made.push(w);
      return w;
    },
  });
  const e = await rejection(client.vault.context());
  assert.equal(e.code, "internal");
  assert.equal(made[0].terminated, true, "an instance that aborted is not reused");
  await rejection(client.vault.context());
  assert.equal(made.length, 2);
});

test("u32_arguments_are_checked_before_wasm_bindgen_coerces_them", async () => {
  const { client } = setup();
  const bad = [4294967297, 1.9, -1, "3", NaN, Infinity, null, undefined, {}];
  for (const v of bad) {
    for (const call of [
      () => client.vault.item_view(v),
      () => client.vault.close_item(v),
      () => client.vault.reveal_item_field(1, v),
      () => client.vault.import_view(v),
      () => client.vault.login_finish(new Uint8Array(1), v, { kind: "first_use" }),
    ]) {
      const e = await rejection(call());
      assert.equal(e.code, "invalid_input", String(v));
    }
  }
  // 2^32 - 1 is in range (and is simply not an open item).
  assert.equal((await rejection(client.vault.item_view(4294967295))).code, "vault_locked");
  // An optional handle may be left out.
  const e = await rejection(client.vault.encrypt_item(fill(16, 1), 1, { name: "x" }, undefined, 1));
  assert.equal(e.code, "vault_locked");
  assert.equal((await rejection(client.vault.encrypt_item(fill(16, 1), 1, { name: "x" }, 1.5, 1))).code, "invalid_input");
});

// ------------------------------------------------------------ lock under load

test("lock_ends_the_worker_at_once_even_while_a_call_is_running", async () => {
  // A worker that never answers: a long Argon2id, an import, or a module that
  // is still loading. `lock()` does not wait for it.
  const made = [];
  const client = createClient({
    createVaultWorker: () => {
      const w = new FakeWorker(() => ({ reply: { ok: true }, transfer: [] }));
      w.postMessage = function (message, transfer = []) {
        this.received.push(structuredClone(message, { transfer }));
      };
      made.push(w);
      return w;
    },
  });
  const running = client.vault.login_finish(new Uint8Array(1), 1, { kind: "first_use" });
  const running2 = client.vault.context();
  const outcome = await Promise.race([
    client.lock().then(() => "locked"),
    new Promise((resolve) => setTimeout(() => resolve("waited"), 1000)),
  ]);
  assert.equal(outcome, "locked", "lock() did not queue behind the running call");
  assert.equal(made[0].terminated, true);
  assert.equal((await rejection(running)).code, "locked");
  assert.equal((await rejection(running2)).code, "locked");
  // No lock message was sent to the worker: it was ended first.
  assert.ok(made[0].received.every((m) => m.method !== "lock"));
  // Locking when there is no worker, and twice, is fine.
  await client.lock();
  await client.vault.lock();
  assert.equal(made.length, 1, "no worker was started to be locked");
});

// ------------------------------------------------------- secret argument types

/** A client whose worker answers every call with `null`, to see what is sent. */
function echoClient() {
  const made = [];
  const client = createClient({
    createVaultWorker: () => {
      const w = new FakeWorker((request) => ({ reply: { id: request.id, ok: true, value: null }, transfer: [] }));
      made.push(w);
      return w;
    },
  });
  return { client, made };
}

test("a_secret_array_is_wiped_and_a_second_call_with_it_fails_loudly", async () => {
  const { client, made } = echoClient();
  const key = fill(32, 0x42);
  await client.vault.export_finish(key);
  assert.ok(key.every((b) => b === 0), "the caller's array was wiped");
  assert.equal(made[0].received.length, 1);
  // The retry with the same variable: input_all_zero (the code of the core for
  // the same input), and nothing is sent.
  const e = await rejection(client.vault.export_finish(key));
  assert.equal(e.code, "input_all_zero");
  assert.equal(made[0].received.length, 1, "the zero key never reached the worker");
  // The same for every position that takes a key.
  const zero = () => new Uint8Array(32);
  const salt = fill(32, 5);
  for (const [name, args] of [
    ["wrap_prf", [fill(24, 1), salt, zero(), fill(16, 2), 1, fill(16, 3), "no_stored_passkeys"]],
    ["wrap_pin", [enc.encode("123456"), fill(16, 2), zero()]],
    ["unlock_prf", ["https://x", {}, zero(), {}, {}]],
    ["pin_unlock", [enc.encode("123456"), {}, {}, zero()]],
    ["import_open", [fill(100, 1), zero()]],
    ["reveal_plain_export", [[], "json", false, zero(), 1_700_000_000_000]],
  ]) {
    assert.equal((await rejection(client.vault[name](...args))).code, "input_all_zero", name);
  }
  assert.equal(made[0].received.length, 1);
  // An optional key may be left out.
  await client.vault.wrap_pin(enc.encode("123456"), fill(16, 2), null);
  await client.vault.wrap_pin(enc.encode("123456"), fill(16, 2));
  assert.equal(made[0].received.length, 3);
});

test("key_arguments_must_be_uint8arrays", async () => {
  const { client, made } = echoClient();
  const wrong = [
    "a".repeat(32),
    Array.from(fill(32, 9)),
    new Uint16Array(16).fill(9),
    fill(32, 9).buffer,
    new Uint8ClampedArray(32).fill(9),
    { length: 32 },
    undefined,
    null,
    7,
  ];
  for (const v of wrong) {
    for (const call of [
      () => client.vault.export_finish(v),
      () => client.vault.import_open(fill(40, 1), v),
      () => client.vault.wrap_prf(fill(24, 1), fill(32, 5), v, fill(16, 2), 1, fill(16, 3), "no_stored_passkeys"),
    ]) {
      assert.equal((await rejection(call())).code, "invalid_input", String(v));
    }
  }
  assert.equal(made.length, 0, "nothing was sent, no worker started");
  // A Node Buffer is a Uint8Array: it is copied (not shared with the pool) and wiped.
  const buffer = Buffer.alloc(32, 9);
  await client.vault.export_finish(buffer);
  assert.ok(buffer.every((b) => b === 0));
  // Passwords: text or bytes, nothing else.
  for (const v of [undefined, 5, ["a"], { a: 1 }]) {
    assert.equal((await rejection(client.vault.login_start(v, null))).code, "invalid_input");
    assert.equal((await rejection(client.vault.check_master_password(v, "with_secret_key"))).code, "invalid_input");
  }
});

test("the_dispatcher_checks_the_arguments_as_well", () => {
  // A page that does not use the client still meets the same checks.
  const dispatch = createDispatcher(wasm);
  const send = (method, args) => dispatch({ id: 1, target: "vault", method, args }).reply;
  assert.equal(send("export_finish", [new Uint8Array(32)]).code, "input_all_zero");
  assert.equal(send("export_finish", ["x".repeat(32)]).code, "invalid_input");
  assert.equal(send("totp_code", [1, null]).code, "invalid_input");
  assert.equal(send("wrap_prf", [fill(24, 1), fill(32, 5), new Uint8Array(32), fill(16, 2), 1, fill(16, 3), "no_stored_passkeys"]).code, "input_all_zero");
  // A valid shape gets to the vault check.
  assert.equal(send("export_finish", [fill(32, 3)]).code, "vault_locked");
  const job = createJobDispatcher(wasm);
  const jobReply = job({ id: 1, target: "job", method: "argon2_export_key", args: ["pw", fill(16, 1), {}, "open", null] }).reply;
  assert.equal(jobReply.code, "invalid_input", "a password that is not bytes");
});

// ---------------------------------------------------------- number arguments

test("f64_arguments_are_checked_for_type_and_unit", async () => {
  const { client } = setup();
  const id = fill(16, 1);
  const env = fill(40, 1);
  const tag = fill(32, 1);
  const bad = [null, undefined, "5", "", false, true, NaN, Infinity, -1, {}, [], 1.5];
  for (const v of bad) {
    for (const call of [
      () => client.vault.open_item(id, v, env, tag),
      () => client.vault.make_tombstone(id, v),
      () => client.vault.make_checkpoint(v, []),
      () => client.vault.verify_checkpoint({}, [], v),
      () => client.vault.import_seal(0, id, v),
    ]) {
      assert.equal((await rejection(call())).code, "invalid_input", String(v));
    }
  }
  // Revisions are whole numbers up to 2^53.
  assert.equal((await rejection(client.vault.make_tombstone(id, 2 ** 53 + 2))).code, "invalid_input");
  assert.equal((await rejection(client.vault.make_tombstone(id, 2 ** 53))).code, "vault_locked");
  // Times: milliseconds below 4e13, seconds below 4e10; a fraction is fine.
  for (const v of [null, "1700000000000", NaN, -1, 4e13 + 1, undefined]) {
    assert.equal((await rejection(client.vault.encrypt_item(id, 1, { name: "x" }, undefined, v))).code, "invalid_input", String(v));
    assert.equal((await rejection(client.vault.export_begin([], v))).code, "invalid_input", String(v));
  }
  assert.equal((await rejection(client.vault.encrypt_item(id, 1, { name: "x" }, undefined, 1_700_000_000_000.5))).code, "vault_locked");
  for (const v of [null, "59", NaN, -1, Date.now(), 4e10 + 1]) {
    assert.equal((await rejection(client.vault.totp_code(1, v))).code, "invalid_input", String(v));
  }
  assert.equal((await rejection(client.vault.totp_code(1, Date.now() / 1000))).code, "vault_locked");
  assert.equal((await rejection(client.vault.totp_code(1, 59))).code, "vault_locked");
  assert.equal((await rejection(client.vault.passkey_create(id, 1, "n", {}, {}, {}, "no_existing", 1.7e12, undefined))).code, "vault_locked");
  assert.equal((await rejection(client.vault.passkey_create(id, 1, "n", {}, {}, {}, "no_existing", "now", undefined))).code, "invalid_input");
  assert.equal((await rejection(client.vault.wrap_prf(id, fill(32, 5), fill(32, 9), id, "1", fill(16, 3), "no_stored_passkeys"))).code, "invalid_input");
});

// ------------------------------------------------------------- error mapping

test("a_type_error_is_invalid_input_and_does_not_end_the_session", async () => {
  const { client, made } = setup();
  await client.vault.clear();
  // wasm-bindgen refuses an `undefined` where a string is needed with a
  // TypeError; that is a mistake in the call, not a broken instance.
  const e = await rejection(client.vault.check_code(undefined, "x"));
  assert.equal(e.code, "invalid_input");
  assert.equal(made.vault.length, 1);
  assert.equal(made.vault[0].terminated, false, "the worker, and the vault in it, live on");
  assert.equal((await rejection(client.vault.context())).code, "vault_locked");
  assert.equal(made.vault.length, 1);
});

test("only_a_type_error_is_not_fatal", () => {
  const fake = (thrown) => ({
    UnlockJob: class {},
    Vault: class {},
    check_code() {
      throw thrown;
    },
  });
  const code = (thrown) =>
    createDispatcher(fake(thrown))({ id: 1, target: "vault", method: "check_code", args: ["a", "b"] }).reply.code;
  assert.equal(code(new TypeError("x")), "invalid_input");
  assert.equal(code(new RangeError("memory")), "internal", "a heap that failed to grow ends the worker");
  assert.equal(code(new WebAssembly.RuntimeError("unreachable")), "internal");
  assert.equal(code(new Error("plain")), "internal");
  assert.equal(code("a string"), "internal");
  assert.equal(code(null), "internal");
  assert.equal(code(Object.assign(new Error("x"), { code: "decrypt" })), "decrypt");
  assert.equal(code(Object.assign(new TypeError("x"), { code: "Bad Code" })), "invalid_input");
});

// ---------------------------------------------------------------- constants

test("the_aaguid_constant_is_the_one_of_the_build", async () => {
  const { FERRET_AAGUID, NO_EXISTING } = await import("../../bindings/wasm/js/client.mjs");
  assert.deepEqual(Array.from(wasm.ferret_aaguid()), Array.from(FERRET_AAGUID));
  assert.equal(FERRET_AAGUID.length, 16);
  assert.ok(Object.isFrozen(FERRET_AAGUID));
  assert.equal(NO_EXISTING, "no_existing");
  const { client } = setup();
  assert.deepEqual(Array.from(await client.vault.ferret_aaguid()), Array.from(FERRET_AAGUID));
});

// ------------------------------------------------------ plaintext export gate

test("a_plaintext_export_through_the_client_needs_a_fresh_sign_in", async () => {
  const { client } = setup();
  const server = new wasm.TestServer(enc.encode("client-plain"));
  const request = await client.vault.register_start(enc.encode(PASSWORD), { kind: "generate" });
  const registration = await client.vault.register_finish(server.register_response(IDS.account_id, request), 1);
  const created = await client.vault.create_account(URL_, IDS);
  const sk = await client.vault.reveal_secret_key_code();
  const id = fill(16, 3);
  const sealed = await client.vault.encrypt_item(id, 1, { item_type: "note", name: "n", notes: "plain note text" }, undefined, 1_700_000_000_000);
  const rows = [{ item_id: id, rev: sealed.rev, envelope: sealed.envelope, tag: sealed.tag }];

  // Without a token, and with one that was made up: reauth_required.
  assert.equal((await rejection(client.vault.reveal_plain_export(rows, "json", false, fill(32, 7), 1_700_000_000_000))).code, "reauth_required");

  // A fresh sign-in with the master password makes the token.
  const ke1 = await client.vault.login_start(enc.encode(PASSWORD), sk);
  const ke2 = server.login_start(registration.record, IDS.account_id, ke1);
  await client.vault.login_finish(ke2, 1, { kind: "pinned", record: created.pinned });
  const token = await client.vault.reauth_grant(created.wraps[0], 1_700_000_000_000);
  assert.equal(token.length, 32);
  const copy = token.slice();
  const json = await client.vault.reveal_plain_export(rows, "json", false, token, 1_700_000_100_000);
  assert.ok(json.includes("plain note text"));
  assert.ok(token.every((b) => b === 0), "the token is wiped on the page once it is sent");
  // One use: the same token again (a retry with the wiped array, or a copy).
  assert.equal((await rejection(client.vault.reveal_plain_export(rows, "json", false, token, 1_700_000_100_000))).code, "input_all_zero");
  assert.equal((await rejection(client.vault.reveal_plain_export(rows, "json", false, copy, 1_700_000_100_000))).code, "reauth_required");
  await client.lock();
});

test("the_rollback_memory_is_a_required_argument", async () => {
  const { client, made } = echoClient();
  const checkpoint = { seq: 1, digest: fill(32, 1), mac: fill(32, 2), entries: new Uint8Array(0) };
  for (const memory of [undefined, null, "bytes", [1, 2, 3], new ArrayBuffer(21)]) {
    assert.equal((await rejection(client.vault.verify_checkpoint(checkpoint, [], 1, memory))).code, "invalid_input", String(memory));
    assert.equal((await rejection(client.vault.rekey({}, {}, memory))).code, "invalid_input", String(memory));
  }
  assert.equal((await rejection(client.vault.verify_checkpoint(checkpoint, [], 1))).code, "invalid_input", "no default memory");
  assert.equal((await rejection(client.vault.sync_memory_prune(undefined, []))).code, "invalid_input");
  assert.equal((await rejection(client.vault.accept_older_state(checkpoint, [], null))).code, "invalid_input", "top seq is checked");
  for (const memory of [undefined, null, "bytes", [1, 2, 3], new ArrayBuffer(21)]) {
    assert.equal((await rejection(client.vault.accept_rows([], 1, memory))).code, "invalid_input", String(memory));
  }
  for (const seq of [undefined, null, "1", -1, 1.5, NaN]) {
    assert.equal((await rejection(client.vault.accept_rows([], seq, new Uint8Array(21)))).code, "invalid_input", String(seq));
  }
  assert.equal(made.length, 0, "nothing was sent");
  // The memory is public: it is sent as it is and not wiped.
  const memory = (await import("./helpers.mjs")).wasm.sync_memory_new();
  const copy = memory.slice();
  await client.vault.verify_checkpoint(checkpoint, [], 1, memory);
  assert.deepEqual(memory, copy);
});

// ------------------------------------------- re-authentication token and marker

test("a_missing_token_is_reauth_required_and_an_old_one_expires", async () => {
  const { client } = setup();
  const server = new wasm.TestServer(enc.encode("client-ttl"));
  const request = await client.vault.register_start(enc.encode(PASSWORD), { kind: "generate" });
  const registration = await client.vault.register_finish(server.register_response(IDS.account_id, request), 1);
  const created = await client.vault.create_account(URL_, IDS);
  const sk = await client.vault.reveal_secret_key_code();
  const id = fill(16, 3);
  const sealed = await client.vault.encrypt_item(id, 1, { item_type: "note", name: "n", notes: "plain note text" }, undefined, 1_700_000_000_000);
  const rows = [{ item_id: id, rev: sealed.rev, envelope: sealed.envelope, tag: sealed.tag }];
  const NOW = 1_700_000_000_000;
  const grant = async () => {
    const ke1 = await client.vault.login_start(enc.encode(PASSWORD), sk);
    await client.vault.login_finish(server.login_start(registration.record, IDS.account_id, ke1), 1, { kind: "pinned", record: created.pinned });
    return client.vault.reauth_grant(created.wraps[0], NOW);
  };
  // No token: reauth_required, as the header says; the time is still required.
  assert.equal((await rejection(client.vault.reveal_plain_export(rows, "json", false, undefined, NOW))).code, "reauth_required");
  assert.equal((await rejection(client.vault.reveal_plain_export(rows, "json", false, undefined))).code, "invalid_input");
  // Five minutes and no more.
  assert.ok((await client.vault.reveal_plain_export(rows, "json", false, await grant(), NOW + 300_000)).includes("plain note text"));
  assert.equal((await rejection(client.vault.reveal_plain_export(rows, "json", false, await grant(), NOW + 300_001))).code, "reauth_required");
  assert.equal((await rejection(client.vault.reveal_plain_export(rows, "json", false, await grant(), NOW - 1))).code, "reauth_required");
  assert.equal((await rejection(client.vault.reauth_grant(created.wraps[0], "now"))).code, "invalid_input");
});

test("the_rollback_memory_comes_back_as_newSyncMemory", async () => {
  const { client } = setup();
  const server = new wasm.TestServer(enc.encode("client-memory"));
  const request = await client.vault.register_start(enc.encode(PASSWORD), { kind: "generate" });
  await client.vault.register_finish(server.register_response(IDS.account_id, request), 1);
  const created = await client.vault.create_account(URL_, IDS);
  const empty = await client.vault.sync_memory_new();
  const sha = (b) => new Uint8Array(createHash("sha256").update(Buffer.from(b)).digest());
  const entry = { item_id: new Uint8Array(16), rev: created.manifest.rev, hash: sha(created.manifest.envelope) };
  const checkpoint = await client.vault.make_checkpoint(5, [entry]);
  const rows = [{ item_id: new Uint8Array(16), rev: created.manifest.rev, state: "live", envelope: created.manifest.envelope, tag: created.manifest.tag }];
  const verified = await client.vault.verify_checkpoint(checkpoint, rows, 5, empty);
  assert.deepEqual(Object.keys(verified), ["newSyncMemory"]);
  assert.ok(verified.newSyncMemory instanceof Uint8Array && verified.newSyncMemory.length > empty.length);
  // The state the memory now holds cannot be shown again at a lower seq.
  const lower = await client.vault.make_checkpoint(4, [entry]);
  assert.equal((await rejection(client.vault.verify_checkpoint(lower, rows, 5, verified.newSyncMemory))).code, "checkpoint_seq_below_remembered");
  const older = await client.vault.accept_older_state(lower, rows, 5);
  assert.deepEqual(Object.keys(older), ["newSyncMemory"]);
  // The rows of an incremental /changes answer give the memory back the same way.
  const accepted = await client.vault.accept_rows(rows, 6, verified.newSyncMemory);
  assert.deepEqual(Object.keys(accepted), ["newSyncMemory"]);
  assert.ok(accepted.newSyncMemory instanceof Uint8Array);
  assert.equal((await rejection(client.vault.accept_rows(rows, 5, accepted.newSyncMemory))).code, "checkpoint_top_seq_below_remembered");
  const pruned = await client.vault.sync_memory_prune(verified.newSyncMemory, [new Uint8Array(16)]);
  assert.deepEqual(Object.keys(pruned).sort(), ["dropped", "newSyncMemory"]);
  assert.equal(pruned.dropped, 1);
  // sync_memory_new is the starting point and stays plain bytes.
  assert.ok(empty instanceof Uint8Array);
});

test("client_validates_verify_tombstone_argument_types", async () => {
  const { client, made } = echoClient();
  const id = fill(16, 1);
  const tomb = fill(40, 2);
  // The item id and the tombstone must be Uint8Arrays.
  const notBytes = ["a".repeat(16), Array.from(fill(16, 1)), new Uint16Array(8), fill(16, 1).buffer, { length: 16 }, undefined, null, 7];
  for (const v of notBytes) {
    assert.equal((await rejection(client.vault.verify_tombstone(v, 1, tomb))).code, "invalid_input", `id ${String(v)}`);
    assert.equal((await rejection(client.vault.verify_tombstone(id, 1, v))).code, "invalid_input", `tomb ${String(v)}`);
  }
  // The revision is a whole number from 0 to 2^53.
  for (const v of [null, undefined, "5", "", false, true, NaN, Infinity, -1, {}, [], 1.5, 2 ** 53 + 2]) {
    assert.equal((await rejection(client.vault.verify_tombstone(id, v, tomb))).code, "invalid_input", String(v));
  }
  assert.equal(made.length, 0, "nothing was sent, no worker started");
  // Nothing about the arguments is a secret: they are sent as they are, not wiped.
  const idCopy = id.slice();
  const tombCopy = tomb.slice();
  assert.equal(await client.vault.verify_tombstone(id, 2 ** 53, tomb), null);
  assert.deepEqual(id, idCopy);
  assert.deepEqual(tomb, tombCopy);
  assert.equal(made[0].received.length, 1);

  // A real client: valid types reach the vault check, and the dispatcher says the same.
  const real = setup().client;
  assert.equal((await rejection(real.vault.verify_tombstone(id, 2 ** 53, tomb))).code, "vault_locked");
  const dispatch = createDispatcher(wasm);
  const send = (args) => dispatch({ id: 1, target: "vault", method: "verify_tombstone", args }).reply;
  assert.equal(send(["x".repeat(16), 1, tomb]).code, "invalid_input");
  assert.equal(send([id, "1", tomb]).code, "invalid_input");
  assert.equal(send([id, 1, tomb]).code, "vault_locked");
});

test("lock_also_ends_the_job_workers", async () => {
  const jobs = [];
  const client = createClient({
    createVaultWorker: () => new FakeWorker(() => ({ reply: { ok: true }, transfer: [] })),
    createJobWorker: () => {
      const w = new FakeWorker(() => ({ reply: { ok: true }, transfer: [] }));
      w.postMessage = function (message, transfer = []) {
        this.received.push(structuredClone(message, { transfer }));
      };
      jobs.push(w);
      return w;
    },
  });
  const kdf = { m_kib: 65536, t: 3, p: 1 };
  const running = [
    client.job.argon2_export_key(enc.encode("export password for tests"), fill(16, 5), kdf, "open", null),
    client.job.argon2_export_key(enc.encode("another export password!"), fill(16, 6), kdf, "open", null),
  ];
  await client.lock();
  assert.equal(jobs.length, 2);
  assert.ok(jobs.every((w) => w.terminated), "both job workers were ended");
  for (const call of running) assert.equal((await rejection(call)).code, "locked");
});

test("a_key_of_another_length_keeps_the_code_of_the_core", async () => {
  const { client, made } = echoClient();
  // The length is checked first by the core; zeros only count in a key-sized array.
  for (const length of [0, 1, 16, 31, 33, 64]) {
    await client.vault.export_finish(new Uint8Array(length));
  }
  assert.equal(made[0].received.length, 6, "the core judges these, with its own codes");
  assert.equal((await rejection(client.vault.export_finish(new Uint8Array(32)))).code, "input_all_zero");
  // The dispatcher lets the same arrays through to the vault (here locked).
  const dispatch = createDispatcher(wasm);
  const send = (key) => dispatch({ id: 1, target: "vault", method: "export_finish", args: [key] }).reply;
  assert.equal(send(new Uint8Array(0)).code, "vault_locked");
});

test("wrap_prf_needs_the_marker_for_no_stored_passkeys", async () => {
  const { client, made } = echoClient();
  const { NO_STORED_PASSKEYS } = await import("../../bindings/wasm/js/client.mjs");
  assert.equal(NO_STORED_PASSKEYS, "no_stored_passkeys");
  await client.vault.wrap_prf(fill(24, 1), fill(32, 5), fill(32, 9), fill(16, 2), 1, fill(16, 3), NO_STORED_PASSKEYS);
  assert.equal(made[0].received.length, 1);
});
