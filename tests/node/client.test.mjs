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
