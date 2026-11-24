// The PIN functions of the binding: setting a PIN (the rule, the new salt, the
// time and memory limits), opening it (the checks that come before Argon2id,
// the epoch, the pinned key), and the passkey unlock that needs a record.
// Run: node --test tests/node/pin.test.mjs
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createDispatcher } from "../../bindings/wasm/js/protocol.mjs";
import {
  CTX, IDS, PIN_RULE, PASSWORD, URL_, codeOf, enc, fill, firstUse, newAccount, pinWrapOf, pinned, root, wasm,
} from "./helpers.mjs";

const MIB = 1024 * 1024;
const GIB = 1024 * MIB;

function code(fn) {
  const e = codeOf(fn);
  assert.equal(e.name, "FerretError");
  assert.equal(e.message, e.code, "the message is the code and nothing else");
  return e.code;
}

const runs = () => wasm.test_argon2_runs();
const rule = (extra) => ({ ...PIN_RULE, ...extra });

/** Runs `fn` and says how many Argon2id runs it started. */
function argonRunsOf(fn) {
  const before = runs();
  const result = fn();
  return { result, runs: runs() - before };
}

test("wrap_pin_checks_the_rule_before_argon2", () => {
  const { vault } = newAccount("pin-rule");
  const id = fill(16, 0x75);
  const refuse = (pin, r, want) => {
    const before = runs();
    assert.equal(code(() => vault.wrap_pin(enc.encode(pin), id, r)), want, pin);
    assert.equal(runs(), before, `${pin}: nothing was computed`);
  };
  refuse("123456", rule({ allowed: false }), "pin_not_allowed");
  refuse("12345", PIN_RULE, "input_too_short");
  refuse("123", rule({ min_length: 1 }), "input_too_short");
  refuse("", PIN_RULE, "input_too_short");
  refuse("12\u0009456", PIN_RULE, "input_forbidden_character");
  refuse("x".repeat(65), PIN_RULE, "input_too_long");
  // A rule with a key the binding does not know, or a missing one, is a bad call.
  refuse("123456", { allowed: true, after_restart: true, min_length: 6, kind: "digits" }, "invalid_input");
  refuse("123456", { allowed: true, after_restart: true }, "invalid_input");
  refuse("123456", undefined, "invalid_input");
  // The job-worker half refuses in the same way.
  const before = runs();
  assert.equal(code(() => wasm.argon2_pin_key(enc.encode("123456"), rule({ allowed: false }))), "pin_not_allowed");
  assert.equal(code(() => wasm.argon2_pin_key(enc.encode("12345"), PIN_RULE)), "input_too_short");
  assert.equal(runs(), before);
  // A rule that is met runs Argon2id exactly once.
  const ok = argonRunsOf(() => vault.wrap_pin(enc.encode("123456"), id, PIN_RULE));
  assert.equal(ok.runs, 1);
  // A text PIN is as good as digits; a rule of four lets four through.
  assert.equal(vault.wrap_pin(enc.encode("abcd"), id, rule({ min_length: 4 })).wrap.length, 104);
});

test("pin_unlock_refuses_before_argon2", () => {
  const { vault, created } = newAccount("pin-unlock-refusals");
  const made = vault.wrap_pin(enc.encode("123456"), fill(16, 0x75), PIN_RULE);
  const wrap = pinWrapOf(made);
  const refuse = (pin, record, w, r, want) => {
    const before = runs();
    assert.equal(code(() => new wasm.UnlockJob().pin_unlock(enc.encode(pin), record, w, r)), want);
    assert.equal(runs(), before, `${want}: nothing was computed`);
  };
  refuse("123456", created.pinned, wrap, rule({ allowed: false }), "pin_not_allowed");
  refuse("12345", created.pinned, wrap, PIN_RULE, "input_too_short");
  refuse("123", created.pinned, wrap, rule({ min_length: 1 }), "input_too_short");
  refuse("123456", created.pinned, { ...wrap, profile: 0 }, PIN_RULE, "kdf_profile_unknown");
  refuse("123456", created.pinned, { ...wrap, profile: 2 }, PIN_RULE, "kdf_profile_unknown");
  refuse("123456", created.pinned, { ...wrap, wrap: wrap.wrap.slice(0, 72) }, PIN_RULE, "invalid_input");
  // The right PIN under the right rule opens it, with one Argon2id run.
  const opened = argonRunsOf(() => new wasm.UnlockJob().pin_unlock(enc.encode("123456"), created.pinned, wrap, PIN_RULE));
  assert.equal(opened.runs, 1);
  assert.deepEqual(opened.result.vault.auth_public_key(), created.pk_a);
  assert.deepEqual(opened.result.pinned, created.pinned, "a local unlock changes nothing");
});

test("a_stale_pin_wrap_is_refused_as_pin_stale_without_argon2", () => {
  const { vault, created } = newAccount("pin-stale");
  const wrap = pinWrapOf(vault.wrap_pin(enc.encode("123456"), fill(16, 0x75), PIN_RULE));
  assert.equal(wrap.vk_epoch, 1);
  // The record is at epoch 2 now (a rekey happened): the epoch-1 wrap is old.
  const later = { ...created.pinned, vk_epoch_max: 2 };
  const before = runs();
  assert.equal(code(() => new wasm.UnlockJob().pin_unlock(enc.encode("123456"), later, wrap, PIN_RULE)), "pin_stale");
  // It is stale whatever the PIN is, and the answer is the same for a wrong PIN.
  assert.equal(code(() => new wasm.UnlockJob().pin_unlock(enc.encode("654321"), later, wrap, PIN_RULE)), "pin_stale");
  assert.equal(runs(), before, "no Argon2id ran");
  // A wrap of a newer epoch than the record is not one this record can open.
  const newer = { ...wrap, vk_epoch: 3 };
  assert.equal(code(() => new wasm.UnlockJob().pin_unlock(enc.encode("123456"), created.pinned, newer, PIN_RULE)), "decrypt");
  assert.equal(runs(), before, "and no Argon2id either");
  // The epoch is bound into the AAD: relabelling a wrap does not open it.
  const relabelled = { ...wrap, vk_epoch: 2 };
  assert.equal(code(() => new wasm.UnlockJob().pin_unlock(enc.encode("123456"), later, relabelled, PIN_RULE)), "decrypt");
});

test("pin_unlock_refuses_a_blob_whose_vault_key_does_not_give_the_pinned_pk_a", () => {
  // Another vault with the same ids but its own keys: its wrap opens under the
  // pinned account and epoch, and its public key is not the pinned one.
  const mine = newAccount("pin-mine");
  const other = newAccount("pin-other");
  assert.notDeepEqual(other.created.pk_a, mine.created.pk_a);
  const wrap = pinWrapOf(other.vault.wrap_pin(enc.encode("123456"), fill(16, 0x75), PIN_RULE));
  // Offline too: the only inputs are the record and the blob.
  const e = code(() => new wasm.UnlockJob().pin_unlock(enc.encode("123456"), mine.created.pinned, wrap, PIN_RULE));
  assert.equal(e, "pinned_auth_key");
  // The same blob opens under the record of the vault it was made from.
  const ok = new wasm.UnlockJob().pin_unlock(enc.encode("123456"), other.created.pinned, wrap, PIN_RULE);
  assert.deepEqual(ok.vault.auth_public_key(), other.created.pk_a);
});

test("wrap_pin_returns_no_kind_and_no_length", () => {
  const { vault } = newAccount("pin-shape");
  const id = fill(16, 0x75);
  const long = "correct horse battery staple, 64 characters at the most!";
  for (const pin of ["1234", "123456", long, "\u{1F511}\u{1F511}\u{1F511}\u{1F511}"]) {
    const made = vault.wrap_pin(enc.encode(pin), id, rule({ min_length: 4 }));
    assert.deepEqual(Object.keys(made).sort(), ["device_salt", "method_id", "ms", "profile", "vk_epoch", "wrap"]);
    assert.equal(made.wrap.length, 104, "the same size for every PIN");
    assert.equal(made.device_salt.length, 16);
    assert.equal(made.method_id.length, 16);
    assert.equal(made.profile, 1);
    assert.equal(made.vk_epoch, 1);
    assert.ok(Number.isInteger(made.ms) && made.ms >= 0 && made.ms < 10_000);
  }
  // The key-taking half returns the same shape (with a time of zero).
  const job = wasm.argon2_pin_key(enc.encode("123456"), PIN_RULE);
  assert.deepEqual(Object.keys(job).sort(), ["device_salt", "key", "ms", "profile"]);
  assert.equal(job.key.length, 32);
  const second = vault.wrap_pin_key(job.key.slice(), job.device_salt, id);
  assert.deepEqual(Object.keys(second).sort(), ["device_salt", "method_id", "ms", "profile", "vk_epoch", "wrap"]);
  assert.equal(second.wrap.length, 104);
  assert.equal(second.ms, 0);
  assert.deepEqual(second.device_salt, job.device_salt);
});

test("the_key_half_makes_the_same_wrap_the_one_call_does", () => {
  const { vault, created } = newAccount("pin-split");
  const job = wasm.argon2_pin_key(enc.encode("424242"), PIN_RULE);
  const split = vault.wrap_pin_key(job.key.slice(), job.device_salt, fill(16, 0x78));
  const opened = new wasm.UnlockJob().pin_unlock(enc.encode("424242"), created.pinned, pinWrapOf(split), PIN_RULE);
  assert.deepEqual(opened.vault.auth_public_key(), created.pk_a);
  assert.equal(code(() => new wasm.UnlockJob().pin_unlock(enc.encode("424243"), created.pinned, pinWrapOf(split), PIN_RULE)), "decrypt");
  // An all-zero key (a wiped array) and a key, salt or id of the wrong length are refused.
  assert.equal(code(() => vault.wrap_pin_key(new Uint8Array(32), job.device_salt, fill(16, 0x78))), "input_all_zero");
  assert.equal(code(() => vault.wrap_pin_key(fill(31, 7), job.device_salt, fill(16, 0x78))), "invalid_input");
  assert.equal(code(() => vault.wrap_pin_key(fill(32, 7), fill(15, 1), fill(16, 0x78))), "invalid_input");
  assert.equal(code(() => vault.wrap_pin_key(fill(32, 7), job.device_salt, fill(15, 1))), "invalid_input");
});

test("changing_the_pin_makes_a_new_salt_and_id", () => {
  const { vault, created } = newAccount("pin-change");
  const first = vault.wrap_pin(enc.encode("123456"), fill(16, 0x75), PIN_RULE);
  const second = vault.wrap_pin(enc.encode("123456"), fill(16, 0x76), PIN_RULE);
  const third = vault.wrap_pin(enc.encode("654321"), fill(16, 0x77), PIN_RULE);
  // Even the same PIN under a new id gets a new salt, hence a new key and wrap.
  assert.notDeepEqual(first.device_salt, second.device_salt);
  assert.notDeepEqual(first.wrap, second.wrap);
  assert.notDeepEqual(first.method_id, second.method_id);
  assert.notDeepEqual(second.device_salt, third.device_salt);
  // The old wrap still opens with the old PIN until the store deletes it, and
  // a new one never opens with the old PIN.
  new wasm.UnlockJob().pin_unlock(enc.encode("123456"), created.pinned, pinWrapOf(first), PIN_RULE);
  assert.equal(code(() => new wasm.UnlockJob().pin_unlock(enc.encode("123456"), created.pinned, pinWrapOf(third), PIN_RULE)), "decrypt");
  // The salt is drawn on every call, also when the id is the same.
  const again = vault.wrap_pin(enc.encode("123456"), fill(16, 0x75), PIN_RULE);
  assert.notDeepEqual(again.device_salt, first.device_salt);
  const a = wasm.argon2_pin_key(enc.encode("123456"), PIN_RULE);
  const b = wasm.argon2_pin_key(enc.encode("123456"), PIN_RULE);
  assert.notDeepEqual(a.device_salt, b.device_salt);
  assert.notDeepEqual(a.key, b.key);
});

test("unlock_prf_refuses_first_use", () => {
  const { vault, created } = newAccount("pin-prf-first-use");
  const prf = fill(32, 0x33);
  const prfWrap = vault.wrap_prf(fill(24, 0x44), fill(32, 0x55), prf.slice(), fill(16, 0x76), 1, fill(16, 0xaa), "no_stored_passkeys");
  const withKey = pinned(created.pinned, { server_public_key: created.pinned.server_public_key });
  // A record opens it ...
  const out = new wasm.UnlockJob().unlock_prf(URL_, CTX, prf.slice(), prfWrap, withKey);
  assert.deepEqual(out.vault.auth_public_key(), created.pk_a);
  // ... and a first use does not, whatever else it carries.
  for (const state of [
    firstUse(true),
    firstUse(true, { server_public_key: created.pinned.server_public_key }),
    firstUse(false),
    { kind: "first_use" },
    undefined,
    null,
  ]) {
    assert.equal(code(() => new wasm.UnlockJob().unlock_prf(URL_, CTX, prf.slice(), prfWrap, state)), "invalid_input", JSON.stringify(state));
  }
  // The signature has no sheet argument any more: there is no first use to bind it to.
  assert.equal(wasm.UnlockJob.prototype.unlock_prf.length, 5);
});

test("pin_unlock_zeroizes_its_copy_of_the_pin", () => {
  const { vault, created } = newAccount("pin-wipe");
  const wrap = pinWrapOf(vault.wrap_pin(enc.encode("123456"), fill(16, 0x75), PIN_RULE));
  const dispatch = createDispatcher(wasm);
  const call = (pin, ...rest) => {
    const copy = new Uint8Array(pin);
    const answer = dispatch({ id: 1, target: "vault", method: "pin_unlock", args: [copy, ...rest] });
    assert.ok(copy.every((b) => b === 0), "the worker wiped its copy of the PIN");
    return answer.reply;
  };
  assert.equal(call(enc.encode("123456"), created.pinned, wrap, PIN_RULE).ok, true);
  assert.equal(call(enc.encode("654321"), created.pinned, wrap, PIN_RULE).code, "decrypt");
  // Also when the call is refused before anything else happens.
  assert.equal(call(enc.encode("123456"), created.pinned, wrap, rule({ allowed: false })).code, "pin_not_allowed");
  assert.equal(call(enc.encode("12"), created.pinned, wrap, PIN_RULE).code, "input_too_short");
  assert.equal(call(enc.encode("123456"), created.pinned, { ...wrap, profile: 9 }, PIN_RULE).code, "kdf_profile_unknown");
  assert.equal(call(enc.encode("123456"), undefined, wrap, PIN_RULE).code, "invalid_input");
  // The same for the setting of a PIN.
  const set = (method, pin, ...rest) => {
    const copy = new Uint8Array(pin);
    const answer = dispatch({ id: 2, target: "vault", method, args: [copy, ...rest] });
    assert.ok(copy.every((b) => b === 0), `${method}: wiped`);
    return answer.reply;
  };
  assert.equal(set("wrap_pin", enc.encode("123456"), fill(16, 1), PIN_RULE).ok, true);
  assert.equal(set("wrap_pin", enc.encode("12"), fill(16, 1), PIN_RULE).code, "input_too_short");
});

test("binding_pin_agrees_with_the_core_vectors", async () => {
  // Every case of pin.json runs through this very build, none is native-only,
  // and the answers are the core's (the Rust runner and the JavaScript
  // reference read the same file).
  const { parseOps, runVectorFile } = await import("../../bindings/wasm/js/vector-runner.mjs");
  const ops = parseOps(readFileSync(join(root, "vectors", "OPS.md"), "utf8"));
  const file = JSON.parse(readFileSync(join(root, "vectors", "internal", "pin.json"), "utf8"));
  assert.ok(file.cases.length >= 40);
  for (const c of file.cases) assert.ok(!c.tags.includes("native-only"), c.id);
  for (const op of ["pin.normalize", "pin.rule", "pin.profile", "pin.aad", "pin.kek"]) {
    assert.ok(ops.has(op), `${op} has a WASM method`);
    assert.ok(file.cases.some((c) => c.op === op), op);
  }
  const report = runVectorFile(wasm, file, ops);
  assert.deepEqual(report.failures, []);
  assert.equal(report.skipped, 0);
  assert.equal(report.passed, file.cases.length);
});

test("wrap_pin_refuses_out_of_memory_and_too_slow", () => {
  const { vault, created } = newAccount("pin-limits");
  const id = fill(16, 0x75);
  const wrap = pinWrapOf(vault.wrap_pin(enc.encode("123456"), id, PIN_RULE));
  try {
    // Too slow: with a budget no device can meet, nothing is returned.
    wasm.test_pin_limit_ms(-1);
    assert.equal(code(() => vault.wrap_pin(enc.encode("123456"), id, PIN_RULE)), "pin_too_slow");
    assert.equal(code(() => wasm.argon2_pin_key(enc.encode("123456"), PIN_RULE)), "pin_too_slow");
    wasm.test_pin_limit_ms(10_000);
    assert.equal(vault.wrap_pin(enc.encode("123456"), id, PIN_RULE).wrap.length, 104, "the budget is back");
    // Out of memory: take the heap to its end, give a little back, and the
    // 256 MiB of the PIN do not fit (what the earlier calls freed is reused
    // first, so the loop runs until even that is gone).
    let held = 0;
    while (wasm.test_hold_memory(8)) held += 1;
    assert.ok(held > 8, `${held} blocks held`);
    wasm.test_release_memory(12);
    assert.ok(wasm.test_memory_bytes() <= GIB);
    assert.equal(code(() => vault.wrap_pin(enc.encode("123456"), id, PIN_RULE)), "kdf_out_of_memory");
    assert.equal(code(() => wasm.argon2_pin_key(enc.encode("123456"), PIN_RULE)), "kdf_out_of_memory");
    assert.equal(code(() => new wasm.UnlockJob().pin_unlock(enc.encode("123456"), created.pinned, wrap, PIN_RULE)), "kdf_out_of_memory");
    // Nothing is left half done: with the memory back, the same calls work.
    wasm.test_release_memory(0);
    assert.equal(vault.wrap_pin(enc.encode("123456"), id, PIN_RULE).wrap.length, 104);
    const opened = new wasm.UnlockJob().pin_unlock(enc.encode("123456"), created.pinned, wrap, PIN_RULE);
    assert.deepEqual(opened.vault.auth_public_key(), created.pk_a);
  } finally {
    wasm.test_pin_limit_ms(10_000);
    wasm.test_release_memory(0);
  }
});

test("confirm_password_proves_the_password_and_the_account_key_without_making_a_vault", () => {
  const { server, created, record } = newAccount("confirm-password");
  const sk = created.vault.reveal_secret_key_code();
  const login = (password = PASSWORD) => {
    const job = new wasm.UnlockJob();
    const ke1 = job.login_start(enc.encode(password), sk);
    const ke2 = server.login_start(record, IDS.account_id, ke1);
    job.login_finish(ke2, 1, pinned(created.pinned));
    return job;
  };
  // The right password, against the wrap and the pinned record: nothing comes back, and the job holds nothing after.
  const job = login();
  assert.equal(job.confirm_password(URL_, CTX, created.wraps[0], pinned(created.pinned)), undefined);
  assert.equal(code(() => job.confirm_password(URL_, CTX, created.wraps[0], pinned(created.pinned))), "invalid_input", "the sign-in state is used up");
  // The wrap opens to a vault key whose account key is not the pinned one: refused (a server that planted a record).
  const other = newAccount("confirm-password-other");
  const forged = { ...created.pinned, pk_a: other.created.pinned.pk_a };
  assert.equal(code(() => login().confirm_password(URL_, CTX, created.wraps[0], pinned(forged))), "pinned_auth_key");
  // A device confirms against what it has pinned: there is no first use, and a recovery wrap is not a password wrap.
  assert.equal(code(() => login().confirm_password(URL_, CTX, created.wraps[0], firstUse(true))), "invalid_input");
  assert.equal(code(() => login().confirm_password(URL_, CTX, created.wraps[1], pinned(created.pinned))), "invalid_input");
  // A wrap for another epoch than the pinned one is refused too.
  assert.equal(typeof code(() => login().confirm_password(URL_, { ...CTX, vk_epoch: 2 }, created.wraps[0], pinned(created.pinned))), "string");
});

test("confirm_password_refuses_a_wrap_of_another_vault_key_made_for_the_next_epoch", () => {
  // A server that knows the export key (an account without a secret key, an OPAQUE record of its own) serves the password
  // wrap of ANOTHER vault key, made for the next epoch under that export key. A higher epoch has no `pk_a` to compare,
  // and no rekey proof is checked yet, so neither `unlock_password` nor `confirm_password` takes it.
  const { server, created, record } = newAccount("confirm-epoch", { secretKey: false });
  const other = newAccount("confirm-epoch-other");
  const [ptr, len] = other.vault.test_vk_region();
  const otherVk = Buffer.from(wasm.test_read_memory(ptr, len)).toString("hex");
  const hex = (bytes) => Buffer.from(bytes).toString("hex");
  const login = () => {
    const job = new wasm.UnlockJob();
    const ke1 = job.login_start(enc.encode(PASSWORD), null);
    const ke2 = server.login_start(record, IDS.account_id, ke1);
    job.login_finish(ke2, 1, pinned(created.pinned));
    return job;
  };
  const exportKey = login().test_export_key();
  const sealed = JSON.parse(
    wasm.test_run_case(
      "wrap_password",
      JSON.stringify({
        op: "wrap.seal.password",
        input: {
          account_id: hex(IDS.account_id), vault_id: hex(IDS.vault_id), method_id: hex(created.wraps[0].method_id),
          vk_epoch: "2", kek_generation: "1", ksf_profile: 1, export_key: hex(exportKey), vk: otherVk,
        },
        rng: [hex(fill(24, 7))],
      }),
    ),
  );
  assert.equal(sealed.ok, true, JSON.stringify(sealed));
  const forged = { ...created.wraps[0], wrap: Uint8Array.from(Buffer.from(sealed.output.wrap, "hex")) };
  const next = { ...CTX, vk_epoch: 2 };
  // `unlock_password` refuses a higher epoch than the pinned one, although the wrap opens under the export key.
  assert.equal(code(() => login().unlock_password(URL_, next, forged, pinned(created.pinned))), "pinned_epoch_ahead");
  // Without a pinned record (a first unlock) the epoch is not judged.
  assert.doesNotThrow(() => login().unlock_password(URL_, next, forged, firstUse(false)));
  // Confirming a password refuses it, whichever epoch the caller names for it.
  assert.equal(code(() => login().confirm_password(URL_, next, forged, pinned(created.pinned))), "pinned_vk_epoch");
  assert.equal(code(() => login().confirm_password(URL_, CTX, forged, pinned(created.pinned))), "decrypt");
  // And the honest wrap at the pinned epoch still confirms.
  assert.equal(login().confirm_password(URL_, CTX, created.wraps[0], pinned(created.pinned)), undefined);
});
