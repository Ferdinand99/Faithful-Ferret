// No reply of the binding holds key material.
//
// The `.d.ts` test only sees what is typed `Uint8Array`; nearly every reply is
// `any`. This test runs the main flows against the build with `test-support`,
// which can show the secrets (the vault key out of memory, the OPAQUE export
// key, the key encryption keys, the item keys), and walks every reply
// recursively. A byte value (a Uint8Array, any other TypedArray, an
// ArrayBuffer, a DataView, an array of byte numbers) may not contain any run
// of 16 bytes of a secret, and a text may not contain such a run as hex (any
// case), base64 or base64url (at any alignment). The secrets are the keys
// (vault key, derived keys and signing seed, key encryption keys, OPAQUE
// export keys, item keys, PRF output, recovery and secret keys, the private
// key and PRF seeds of a passkey) and the plain values a user enters (a
// password, a TOTP secret, a hidden field, notes, the codes of the recovery
// and secret keys), which only `reveal_*` may return. A Map or a Set is walked
// (keys and values). It also keeps the set of byte-array paths that replies
// have as an explicit list: a new one must be added here, with the reason that
// it is not a key.
// Run: node --test tests/node/secrets.test.mjs
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  CTX, IDS, LOGIN_DRAFT, NOW, PASSWORD, PASSWORD_2, URL_, enc, fill, firstUse, pinned, row, wasm,
} from "./helpers.mjs";

const hex = (b) => Buffer.from(b).toString("hex");
const fromHex = (h) => Uint8Array.from(Buffer.from(h, "hex"));
const op = (method, name, input) =>
  JSON.parse(wasm.test_run_case(method, JSON.stringify({ op: name, input, rng: [] }))).output;

const secrets = new Map();
const addSecret = (name, bytes) => {
  const b = Uint8Array.from(bytes);
  assert.ok(b.length >= 16 && b.some((x) => x !== 0), `${name} looks like a key`);
  secrets.set(name, b);
};
/** Plain values that only a `reveal_*` method may return. */
const textSecrets = new Map();
const addText = (name, text) => textSecrets.set(name, text);
let sampleVault = null;

const replies = [];
/** Runs a call of the binding and keeps its reply for the check. */
function call(name, fn) {
  const value = fn();
  replies.push({ name, value });
  return value;
}

/** The bytes of a byte-like value, or null. */
function bytesOf(v) {
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  return null;
}

function* leaves(value, path, depth = 0) {
  assert.ok(depth < 16, `${path}: too deep`);
  // The Vault and the job stay in the worker: only a pointer is here.
  if (value instanceof wasm.Vault || value instanceof wasm.UnlockJob) return;
  const bytes = bytesOf(value);
  if (bytes) {
    const kind = value instanceof Uint8Array ? "" : `<${value.constructor.name}>`;
    yield { path: `${path}${kind}`, bytes };
  } else if (Array.isArray(value)) {
    if (value.length >= 8 && value.every((n) => Number.isInteger(n) && n >= 0 && n < 256)) {
      yield { path: `${path}(numbers)`, bytes: Uint8Array.from(value) };
    } else {
      for (const v of value) yield* leaves(v, `${path}[]`, depth + 1);
    }
  } else if (typeof value === "string") {
    yield { path, text: value };
  } else if (value instanceof Map) {
    for (const [k, v] of value) {
      yield* leaves(k, `${path}{key}`, depth + 1);
      yield* leaves(v, `${path}{}`, depth + 1);
    }
  } else if (value instanceof Set) {
    for (const v of value) yield* leaves(v, `${path}{}`, depth + 1);
  } else if (value !== null && typeof value === "object") {
    for (const key of Object.keys(value)) {
      yield* leaves(value[key], path ? `${path}.${key}` : key, depth + 1);
    }
  }
}

const WINDOW = 16;

/** Every run of 16 bytes of a secret (the secret itself when it is shorter). */
function windows(secret) {
  if (secret.length <= WINDOW) return [secret];
  const out = [];
  for (let i = 0; i + WINDOW <= secret.length; i++) out.push(secret.subarray(i, i + WINDOW));
  return out;
}

/**
 * The texts in which a run of bytes shows: hex (compared in lower case) and
 * base64 / base64url as it looks at each of the three alignments. The
 * characters at the ends that depend on bytes next to the run are cut.
 */
function needles(window) {
  const b64 = [];
  for (let shift = 0; shift < 3; shift++) {
    const text = Buffer.concat([Buffer.alloc(shift), Buffer.from(window)]).toString("base64").replace(/=+$/, "");
    const cut = text.slice(Math.ceil((8 * shift) / 6), text.length - 2);
    b64.push(cut, cut.replace(/\+/g, "-").replace(/\//g, "_"));
  }
  return { hex: Buffer.from(window).toString("hex"), b64 };
}

const needleCache = new Map();
function needlesOf(name, secret) {
  if (!needleCache.has(name)) needleCache.set(name, windows(secret).map(needles));
  return needleCache.get(name);
}

function bytesHold(haystack, secret) {
  const hay = Buffer.from(haystack);
  return windows(secret).some((w) => hay.includes(Buffer.from(w)));
}

function textHolds(text, name, secret) {
  const lower = text.toLowerCase();
  return needlesOf(name, secret).some((n) => lower.includes(n.hex) || n.b64.some((x) => x.length >= 12 && text.includes(x)));
}

/** The byte-array paths seen, as `reply:path`. */
function checkAll() {
  const seen = new Set();
  for (const { name, value } of replies) {
    for (const leaf of leaves(value, "")) {
      const where = `${name}:${leaf.path}`;
      if (leaf.bytes) {
        seen.add(where);
        for (const [secretName, secret] of secrets) {
          assert.ok(!bytesHold(leaf.bytes, secret), `${where} holds ${secretName}`);
        }
        for (const [textName, text] of textSecrets) {
          assert.ok(!Buffer.from(leaf.bytes).includes(Buffer.from(text)), `${where} holds ${textName}`);
        }
      } else {
        for (const [secretName, secret] of secrets) {
          assert.ok(!textHolds(leaf.text, secretName, secret), `${where} holds ${secretName} as text`);
        }
        for (const [textName, text] of textSecrets) {
          assert.ok(!leaf.text.includes(text), `${where} holds ${textName}`);
        }
      }
    }
  }
  return seen;
}

/** The vault key, read out of WASM memory (test-support only). */
function vaultKey(vault) {
  const [ptr, len] = vault.test_vk_region();
  return wasm.test_read_memory(ptr, len);
}

// Every byte-array path a reply has, and why none of them is a key:
// public keys and ids (`pk_a`, `pk_r`, `account_id`, `vault_id`,
// `server_public_key`, `method_id`, `item_id`, `salt`, `device_salt`,
// `prf_salt`, `credential_id`), ciphertext and tags (`wrap`, `envelope`,
// `tag`, `tomb`, `manifest.*`, `entries`, `digest`, `mac`), protocol messages
// (`ke3`, `login_start`, `register_start`, `record`, `registration_record`),
// signatures (`auth_sign`, `recover_sign`, `signature`) and the WebAuthn
// response fields the page is given by design (`attestation_object`,
// `authenticator_data`, `client_data_json`, `public_key_spki`, `id`,
// `user_handle`; the passkey item view shows `cred_id` and `user_handle`, which
// the relying party has too). `export_finish` is the encrypted file.
// `reauth_grant` is the one-time token of a plaintext export: a permission
// that a fresh sign-in makes, not a key. `prf_salt_new` is the public salt of a
// passkey registration; `sync_memory_*`, `accept_rows` and `rekey:sync_memory` are the rollback
// memory (item ids and revision numbers); `manifest_*:body`, `pk_a` and
// `sealed.*` are the signed request body, the public key and the new manifest
// row (ciphertext and tag).
const EXPECTED_BYTE_PATHS = [
  "accept_rows:",
  "auth_public_key:",
  "auth_sign:",
  "change_password:manifest.envelope",
  "change_password:manifest.tag",
  "change_password:pinned.account_id",
  "change_password:pinned.pk_a",
  "change_password:pinned.server_public_key",
  "change_password:pinned.vault_id",
  "change_password:registration_record",
  "change_password:server_public_key",
  "change_password:wrap.method_id",
  "change_password:wrap.wrap",
  "context:account_id",
  "context:vault_id",
  "create_account:checkpoint.digest",
  "create_account:checkpoint.entries",
  "create_account:checkpoint.mac",
  "create_account:manifest.envelope",
  "create_account:manifest.tag",
  "create_account:pinned.account_id",
  "create_account:pinned.pk_a",
  "create_account:pinned.server_public_key",
  "create_account:pinned.vault_id",
  "create_account:pk_a",
  "create_account:pk_r",
  "create_account:registration_record",
  "create_account:server_public_key",
  "create_account:wraps[].method_id",
  "create_account:wraps[].wrap",
  "encrypt_item (edit):envelope",
  "encrypt_item (edit):tag",
  "encrypt_item:envelope",
  "encrypt_item:tag",
  "export_begin:salt",
  "export_finish:",
  "import_header:salt",
  "import_seal:envelope",
  "import_seal:tag",
  "import_view:item_id",
  "item_view (passkey):passkey.cred_id",
  "item_view (passkey):passkey.user_handle",
  "login_finish:ke3",
  "login_finish:server_public_key",
  "login_start:",
  "make_checkpoint:digest",
  "make_checkpoint:entries",
  "make_checkpoint:mac",
  "make_tombstone:tomb",
  "manifest_add_method:body",
  "manifest_add_method:pk_a",
  "manifest_add_method:sealed.envelope",
  "manifest_add_method:sealed.tag",
  "manifest_remove_method:body",
  "manifest_remove_method:pk_a",
  "manifest_remove_method:sealed.envelope",
  "manifest_remove_method:sealed.tag",
  "passkey_create:item.envelope",
  "passkey_create:item.tag",
  "passkey_create:item_id",
  "passkey_create_confirm:response.attestation_object",
  "passkey_create_confirm:response.authenticator_data",
  "passkey_create_confirm:response.client_data_json",
  "passkey_create_confirm:response.id",
  "passkey_create_confirm:response.public_key_spki",
  "passkey_get:authenticator_data",
  "passkey_get:client_data_json",
  "passkey_get:id",
  "passkey_get:signature",
  "passkey_get:user_handle",
  "pin_unlock:pinned.account_id",
  "pin_unlock:pinned.pk_a",
  "pin_unlock:pinned.server_public_key",
  "pin_unlock:pinned.vault_id",
  "prf_salt_new:",
  "reauth_grant:",
  "recover:manifest.envelope",
  "recover:manifest.tag",
  "recover:password_wrap.method_id",
  "recover:password_wrap.wrap",
  "recover:pinned.account_id",
  "recover:pinned.pk_a",
  "recover:pinned.server_public_key",
  "recover:pinned.vault_id",
  "recover:pk_r",
  "recover:recovery_wrap.method_id",
  "recover:recovery_wrap.wrap",
  "recover:registration_record",
  "recover:server_public_key",
  "recover_sign:",
  "register_finish (change):record",
  "register_finish (change):server_public_key",
  "register_finish:record",
  "register_finish:server_public_key",
  "register_start:",
  "rekey:checkpoint.digest",
  "rekey:checkpoint.entries",
  "rekey:checkpoint.mac",
  "rekey:items[].envelope",
  "rekey:items[].item_id",
  "rekey:items[].tag",
  "rekey:manifest.envelope",
  "rekey:manifest.tag",
  "rekey:pinned.account_id",
  "rekey:pinned.pk_a",
  "rekey:pinned.server_public_key",
  "rekey:pinned.vault_id",
  "rekey:pk_a",
  "rekey:pk_r",
  "rekey:sync_memory",
  "rekey:wraps[].method_id",
  "rekey:wraps[].wrap",
  "seed_pinned:account_id",
  "seed_pinned:pk_a",
  "seed_pinned:server_public_key",
  "seed_pinned:vault_id",
  "setup_qr_parse:account_id",
  "setup_qr_parse:server_public_key",
  "sync_memory_new:",
  "sync_memory_prune:sync_memory",
  "unlock_password:pinned.account_id",
  "unlock_password:pinned.pk_a",
  "unlock_password:pinned.server_public_key",
  "unlock_password:pinned.vault_id",
  "unlock_prf:pinned.account_id",
  "unlock_prf:pinned.kek_generation_max[].credential_id",
  "unlock_prf:pinned.pk_a",
  "unlock_prf:pinned.server_public_key",
  "unlock_prf:pinned.vault_id",
  "unlock_recovery:pinned.account_id",
  "unlock_recovery:pinned.pk_a",
  "unlock_recovery:pinned.server_public_key",
  "unlock_recovery:pinned.vault_id",
  "wrap_pin:method.device_salt",
  "wrap_pin:method_id",
  "wrap_pin:wrap",
  "wrap_prf:method.credential_id",
  "wrap_prf:method.prf_salt",
  "wrap_prf:method_id",
  "wrap_prf:wrap",
];

test("no_reply_holds_key_material", () => {
  const server = new wasm.TestServer(enc.encode("secrets"));
  const accountHex = hex(IDS.account_id);
  const kekPw = (exportKey) => fromHex(op("kek_from_export_key", "kdf.kek.password", { account_id: accountHex, export_key: hex(exportKey) }).kek);

  // ---- create the account
  const job = new wasm.UnlockJob();
  const request = call("register_start", () => job.register_start(enc.encode(PASSWORD), { kind: "generate" }));
  const registration = call("register_finish", () => job.register_finish(server.register_response(IDS.account_id, request), 1));
  const exportKey = job.test_export_key();
  assert.equal(exportKey.length, 64);
  addSecret("export key (create)", exportKey);
  addSecret("KEK_pw (create)", kekPw(exportKey));
  const created = call("create_account", () => job.create_account(URL_, IDS));
  const vault = created.vault;
  addSecret("VK", vaultKey(vault));
  sampleVault = vault;
  const rkCode = vault.reveal_recovery_code();
  const skCode = vault.reveal_secret_key_code();
  addText("master password", PASSWORD);
  addText("second master password", PASSWORD_2);
  addText("recovery key code", rkCode);
  addText("secret key code", skCode);
  addText("login password field", "hunter2-secret");
  addText("TOTP secret", "JBSWY3DPEHPK3PXP");
  addText("notes", "private note text");
  const derive = (vk, epoch) => {
    const k = op("vault_derive_keys", "kdf.vk_derive", {
      account_id: accountHex, vault_id: hex(IDS.vault_id), vk_epoch: String(epoch), vk: hex(vk),
    });
    for (const name of ["k_head", "k_del", "k_meta", "seed_a"]) addSecret(`${name} (epoch ${epoch})`, fromHex(k[name]));
  };
  derive(secrets.get("VK"), 1);
  const rk = fromHex(op("recovery_key_decode", "code.rk.decode", { code: rkCode }).key);
  addSecret("RK", rk);
  addSecret("KEK_rk", fromHex(op("kek_from_recovery_key", "kdf.kek.recovery", { account_id: accountHex, rk: hex(rk) }).kek));
  addSecret("SK", fromHex(op("secret_key_decode", "code.sk.decode", { code: skCode }).key));
  call("context", () => vault.context());
  call("auth_public_key", () => vault.auth_public_key());

  // ---- items
  const id = fill(16, 0x41);
  const sealed = call("encrypt_item", () => vault.encrypt_item(id, 1, LOGIN_DRAFT, undefined, NOW));
  addSecret("IK", vault.test_item_key(id, 1, sealed.envelope, sealed.tag));
  const h = vault.open_item(id, 1, sealed.envelope, sealed.tag);
  call("item_view", () => vault.item_view(h));
  call("totp_code", () => vault.totp_code(h, 59));
  const edited = call("encrypt_item (edit)", () => vault.encrypt_item(id, 2, { name: "Renamed" }, h, NOW + 1));
  const tombstone = call("make_tombstone", () => vault.make_tombstone(fill(16, 0x42), 3));
  call("verify_tombstone", () => vault.verify_tombstone(fill(16, 0x42), 3, tombstone.tomb));
  call("auth_sign", () => vault.auth_sign("unlock-method.add", fill(32, 1), enc.encode("body")));
  const cp = call("make_checkpoint", () => vault.make_checkpoint(1, [{ item_id: id, rev: 2, hash: fill(32, 7) }]));
  assert.equal(cp.seq, 1);
  call("seed_pinned", () => vault.seed_pinned(created.pinned, created.manifest));

  // ---- sign in with the password, with the PIN, with a passkey
  const login = new wasm.UnlockJob();
  const ke1 = call("login_start", () => login.login_start(enc.encode(PASSWORD), skCode));
  const ke2 = server.login_start(registration.record, IDS.account_id, ke1);
  call("login_finish", () => login.login_finish(ke2, 1, pinned(created.pinned)));
  addSecret("export key (login)", login.test_export_key());
  const unlocked = call("unlock_password", () => login.unlock_password(URL_, CTX, created.wraps[0], pinned(created.pinned)));
  assert.deepEqual(vaultKey(unlocked.vault), secrets.get("VK"));

  const pinWrap = call("wrap_pin", () => vault.wrap_pin(enc.encode("123456"), fill(16, 0x75), null));
  addSecret("KEK_pin", fromHex(op("kek_from_pin_extension", "kdf.kek.pin_extension", { pin: "123456", device_salt: hex(pinWrap.method.device_salt) }).kek));
  call("pin_unlock", () => new wasm.UnlockJob().pin_unlock(enc.encode("123456"), created.pinned, pinWrap, null));

  const prfOutput = fill(32, 0x33);
  addSecret("PRF output", prfOutput);
  const prfWrap = call("wrap_prf", () => vault.wrap_prf(fill(24, 0x44), fill(32, 0x55), prfOutput.slice(), fill(16, 0x76), 1, fill(16, 0xaa), "no_stored_passkeys"));
  addSecret("KEK_prf", fromHex(op("kek_from_prf", "kdf.kek.prf", { credential_id: hex(fill(24, 0x44)), prf_output: hex(prfOutput) }).kek));
  call("unlock_prf", () => new wasm.UnlockJob().unlock_prf(URL_, CTX, prfOutput.slice(), prfWrap, pinned(created.pinned, { server_public_key: created.pinned.server_public_key })));
  // ---- the methods and the rollback memory (all public values)
  call("prf_salt_new", () => wasm.prf_salt_new());
  call("sync_memory_new", () => wasm.sync_memory_new());
  call("sync_memory_prune", () => wasm.sync_memory_prune(wasm.sync_memory_new(), [fill(16, 1)]));
  call("accept_rows", () => vault.accept_rows([{ item_id: id, rev: edited.rev, state: "live", envelope: edited.envelope, tag: edited.tag }], 3, wasm.sync_memory_new()));
  const addChange = call("manifest_add_method", () => vault.manifest_add_method(created.manifest, prfWrap));
  call("manifest_remove_method", () => vault.manifest_remove_method(addChange.sealed, prfWrap.method_id));
  call("unlock_recovery", () => new wasm.UnlockJob().unlock_recovery(URL_, CTX, rkCode, created.wraps[1], firstUse(true), wasm.setup_qr_build(URL_, IDS.account_id, 1, true, created.server_public_key)));

  // ---- change the password
  const change = new wasm.UnlockJob();
  const changeRequest = change.register_start(enc.encode(PASSWORD_2), { kind: "code", code: skCode });
  call("register_finish (change)", () => change.register_finish(server.register_response(IDS.account_id, changeRequest), 1));
  addSecret("export key (change)", change.test_export_key());
  call("change_password", () => change.change_password(vault, created.pinned, created.wraps[0], created.manifest));

  // ---- recover
  const recovery = new wasm.UnlockJob();
  const recoverRequest = recovery.register_start(enc.encode(PASSWORD_2), { kind: "code", code: skCode });
  recovery.register_finish(server.register_response(IDS.account_id, recoverRequest), 1);
  addSecret("export key (recover)", recovery.test_export_key());
  const qr = wasm.setup_qr_build(URL_, IDS.account_id, 1, true, created.server_public_key);
  const recovered = call("recover", () => recovery.recover(URL_, CTX, rkCode, created.wraps[1], created.manifest, fill(16, 0x73), firstUse(true), qr));
  addSecret("RK (new)", fromHex(op("recovery_key_decode", "code.rk.decode", { code: recovered.vault.reveal_recovery_code() }).key));
  call("recover_sign", () => recovery.recover_sign(fill(32, 2), enc.encode("request")));

  // ---- rekey, then everything the new vault does
  const rekeyJob = new wasm.UnlockJob();
  const rk1 = rekeyJob.login_start(enc.encode(PASSWORD), skCode);
  rekeyJob.login_finish(server.login_start(registration.record, IDS.account_id, rk1), 1, pinned(created.pinned));
  const hash = (b) => new Uint8Array(createHash("sha256").update(Buffer.from(b)).digest());
  const base = vault.make_checkpoint(7, [
    { item_id: new Uint8Array(16), rev: created.manifest.rev, hash: hash(created.manifest.envelope) },
    { item_id: id, rev: 2, hash: hash(edited.envelope) },
  ]);
  const plan = call("rekey", () =>
    rekeyJob.rekey(
      vault,
      {
        base_seq: 7,
        old_checkpoint: base,
        old_manifest: created.manifest,
        items: [row(id, edited)],
        tombstones: [],
        password_method_id: IDS.password_method_id,
        recovery_method_id: fill(16, 0x74),
      },
      created.pinned,
      wasm.sync_memory_new(),
    ),
  );
  vault.rekey_commit();
  addSecret("VK (new epoch)", vaultKey(vault));
  derive(secrets.get("VK (new epoch)"), 2);
  addSecret("RK (rekey)", fromHex(op("recovery_key_decode", "code.rk.decode", { code: vault.reveal_recovery_code() }).key));
  const newItem = plan.items[0];
  addSecret("IK (new epoch)", vault.test_item_key(id, newItem.rev, newItem.envelope, newItem.tag));

  // ---- passkeys
  const caller = { origin: "https://example.com", top_origin_is_same: true };
  const uv = { user_present: true, user_verified: true };
  const create = {
    challenge: fill(32, 9), rp_id: "example.com", rp_name: "Example", user_id: fill(8, 1),
    user_name: "alice", user_display_name: "Alice", algorithms: [-7], exclude: [],
    user_verification: "preferred", prf: {},
  };
  const pkId = fill(16, 0x51);
  const made = call("passkey_create", () => vault.passkey_create(pkId, 1, "Example", create, caller, uv, "no_existing", NOW, undefined));
  call("passkey_create_confirm", () => vault.passkey_create_confirm(made.pending));
  addSecret("IK (passkey item)", vault.test_item_key(pkId, 1, made.item.envelope, made.item.tag));
  const ph = vault.open_item(pkId, 1, made.item.envelope, made.item.tag);
  // (Not the PKCS#8 file: it holds the public key too, which replies have.
  // The scalar is in it, so a leak of the file is a leak of the scalar.)
  for (const which of ["scalar", "seed_uv", "seed_nouv"]) {
    addSecret(`passkey ${which}`, vault.test_passkey_secret(ph, which));
  }
  call("passkey_get", () => vault.passkey_get(ph, { challenge: fill(32, 3), rp_id: "example.com", allow: [], user_verification: "required" }, caller, uv));
  call("item_view (passkey)", () => vault.item_view(ph));

  // ---- export and import
  const rows = [row(id, newItem), row(pkId, made.item)];
  const kdf = { m_kib: 65536, t: 3, p: 1 };
  const started = call("export_begin", () => vault.test_export_begin(rows, NOW, kdf));
  const wrapKey = wasm.argon2_export_key(enc.encode("export password for tests"), started.salt, started.kdf, "write", enc.encode(PASSWORD));
  const file = call("export_finish", () => vault.export_finish(wrapKey.slice()));
  const header = call("import_header", () => wasm.import_header(file));
  const key = wasm.argon2_export_key(enc.encode("export password for tests"), header.salt, header.kdf, "open", null);
  call("import_open", () => vault.import_open(file, key));
  call("import_view", () => vault.import_view(0));
  call("import_seal", () => vault.import_seal(0, fill(16, 0x91), 1));
  call("totp_parse", () => wasm.totp_parse(LOGIN_DRAFT.totp.uri));
  call("setup_qr_parse", () => wasm.setup_qr_parse(qr));

  // ---- the plaintext export: the widest reveal, behind a fresh sign-in
  // It returns every secret as text by design, so it is not one of the
  // replies that are walked. What is checked is the gate.
  const refuse = (token) => {
    try {
      vault.reveal_plain_export(rows, "json", true, token, NOW);
    } catch (e) {
      return e.code;
    }
    return "returned";
  };
  assert.equal(refuse(fill(32, 1)), "reauth_required", "no sign-in, no export");
  const grantJob = new wasm.UnlockJob();
  const g1 = grantJob.login_start(enc.encode(PASSWORD), skCode);
  grantJob.login_finish(server.login_start(registration.record, IDS.account_id, g1), 1, pinned(plan.pinned));
  const token = call("reauth_grant", () => grantJob.reauth_grant(vault, plan.wraps.find((w) => w.method.type === "password"), NOW));
  assert.equal(token.length, 32);
  assert.equal(refuse(fill(32, 1)), "reauth_required", "a wrong token");
  assert.equal(refuse(token.slice()), "reauth_required", "and the failed attempt used the grant up");
  const g2 = grantJob.login_start(enc.encode(PASSWORD), skCode);
  grantJob.login_finish(server.login_start(registration.record, IDS.account_id, g2), 1, pinned(plan.pinned));
  const token2 = grantJob.reauth_grant(vault, plan.wraps.find((w) => w.method.type === "password"), NOW);
  const plain = vault.reveal_plain_export(rows, "json", true, token2.slice(), NOW);
  assert.ok(plain.includes("hunter2-secret") && plain.includes("example.com"));
  assert.equal(refuse(token2), "reauth_required", "one use");

  // ---- the walk, over every reply and every secret known at the end
  assert.ok(secrets.size >= 25, `${secrets.size} secrets`);
  const seen = [...checkAll()].sort();
  assert.deepEqual(seen, EXPECTED_BYTE_PATHS, "the byte-array paths of the replies are the listed ones");
});

test("the_walk_finds_a_key_when_one_is_there", () => {
  // The check above must be able to fail: put secrets into a reply in each
  // form it looks for.
  const vk = secrets.get("VK");
  assert.ok(vk && sampleVault, "the first test ran");
  const scalar = secrets.get("passkey scalar");
  const copy = () => Uint8Array.from(vk);
  const forms = {
    "whole key": { vk },
    "inside a longer buffer": { nested: [{ deep: { bytes: Uint8Array.from([1, 2, 3, ...vk, 9]) } }] },
    "numbers": { numbers: Array.from(vk) },
    "the first 16 bytes": { half: vk.slice(0, 16) },
    "16 bytes from the middle": { half: vk.slice(9, 25) },
    "a key named vault": { vault: vk },
    "a Map value": { map: new Map([["k", vk]]) },
    "a Map key": { map: new Map([[vk, 1]]) },
    "a Set": { set: new Set([vk]) },
    "a Uint16Array": { view: new Uint16Array(copy().buffer) },
    "a Uint32Array": { view: new Uint32Array(copy().buffer) },
    "a Float64Array": { view: new Float64Array(copy().buffer) },
    "an Int8Array": { view: new Int8Array(copy().buffer) },
    "an ArrayBuffer": { buffer: copy().buffer },
    "a DataView": { view: new DataView(copy().buffer) },
    "hex": { text: `prefix ${hex(vk)} suffix` },
    "upper-case hex": { text: hex(vk).toUpperCase() },
    "half of it as hex": { text: hex(vk.slice(4, 20)) },
    "base64": { text: Buffer.from(vk).toString("base64") },
    "base64url": { text: Buffer.from(vk).toString("base64url") },
    "base64 at offset 1": { text: Buffer.from([7, ...vk]).toString("base64") },
    "base64 at offset 2": { text: Buffer.from([7, 7, ...vk]).toString("base64") },
    "base64url at offset 2": { text: Buffer.from([7, 7, ...vk]).toString("base64url") },
    "half of it as base64 at offset 1": { text: Buffer.from([7, ...vk.slice(3, 19), 8]).toString("base64") },
    "the passkey scalar": { scalar },
    "a password as text": { note: "my password is hunter2-secret ok" },
    "a TOTP secret as bytes": { b: Buffer.from("xx JBSWY3DPEHPK3PXP yy") },
    "a recovery key code": { text: [...textSecrets.values()].find((t) => t.startsWith("FFR1-")) },
  };
  const before = replies.length;
  for (const [what, value] of Object.entries(forms)) {
    replies.push({ name: "planted", value });
    assert.throws(() => checkAll(), /holds /, what);
    replies.pop();
  }
  assert.equal(replies.length, before);
  // And what is fine stays fine: the Vault object (a pointer), a key that is
  // not one of ours, a short run, text that only looks like one.
  for (const value of [
    { vault: sampleVault },
    { other: fill(32, 0xee), text: hex(fill(32, 0xee)), view: new Uint16Array(16) },
    { short: vk.slice(0, 15) },
    { text: hex(vk).slice(0, 30) },
    { map: new Map([["k", new Set([1, 2])]]) },
  ]) {
    replies.push({ name: "planted", value });
    checkAll();
    replies.pop();
  }
  checkAll();
});
