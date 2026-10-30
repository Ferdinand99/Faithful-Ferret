// The message protocol and the page's client, run against the real dispatcher
// and the WASM build, with fake workers (no `Worker` in Node).
// Run: node --test tests/node/
import assert from "node:assert/strict";
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
  // The retry with the same variable: invalid_input, and nothing is sent.
  const e = await rejection(client.vault.export_finish(key));
  assert.equal(e.code, "invalid_input");
  assert.equal(made[0].received.length, 1, "the zero key never reached the worker");
  // The same for every position that takes a key.
  const zero = () => new Uint8Array(32);
  const salt = fill(32, 5);
  for (const [name, args] of [
    ["wrap_prf", [fill(24, 1), salt, zero(), fill(16, 2), 1, fill(16, 3), []]],
    ["wrap_pin", [enc.encode("123456"), fill(16, 2), zero()]],
    ["unlock_prf", ["https://x", {}, zero(), {}, {}]],
    ["pin_unlock", [enc.encode("123456"), {}, {}, zero()]],
    ["import_open", [fill(100, 1), zero()]],
    ["reveal_plain_export", [[], "json", false, zero()]],
  ]) {
    assert.equal((await rejection(client.vault[name](...args))).code, "invalid_input", name);
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
      () => client.vault.wrap_prf(fill(24, 1), fill(32, 5), v, fill(16, 2), 1, fill(16, 3), []),
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
  assert.equal(send("export_finish", [new Uint8Array(32)]).code, "invalid_input");
  assert.equal(send("export_finish", ["x".repeat(32)]).code, "invalid_input");
  assert.equal(send("totp_code", [1, null]).code, "invalid_input");
  assert.equal(send("wrap_prf", [fill(24, 1), fill(32, 5), new Uint8Array(32), fill(16, 2), 1, fill(16, 3), []]).code, "invalid_input");
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
  assert.equal((await rejection(client.vault.wrap_prf(id, fill(32, 5), fill(32, 9), id, "1", fill(16, 3), []))).code, "invalid_input");
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
  assert.equal((await rejection(client.vault.reveal_plain_export(rows, "json", false, fill(32, 7)))).code, "reauth_required");

  // A fresh sign-in with the master password makes the token.
  const ke1 = await client.vault.login_start(enc.encode(PASSWORD), sk);
  const ke2 = server.login_start(registration.record, IDS.account_id, ke1);
  await client.vault.login_finish(ke2, 1, { kind: "pinned", record: created.pinned });
  const token = await client.vault.reauth_grant(created.wraps[0]);
  assert.equal(token.length, 32);
  const copy = token.slice();
  const json = await client.vault.reveal_plain_export(rows, "json", false, token);
  assert.ok(json.includes("plain note text"));
  assert.ok(token.every((b) => b === 0), "the token is wiped on the page once it is sent");
  // One use: the same token again (a retry with the wiped array, or a copy).
  assert.equal((await rejection(client.vault.reveal_plain_export(rows, "json", false, token))).code, "invalid_input");
  assert.equal((await rejection(client.vault.reveal_plain_export(rows, "json", false, copy))).code, "reauth_required");
  await client.lock();
});
