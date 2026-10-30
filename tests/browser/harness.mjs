// The page side of the browser tests: Playwright calls `window.ferret.<name>`.
//
// Two builds of the binding are served (see serve.mjs):
//   /test/     the web package with `test-support` (the vector operations, a
//              test OPAQUE server and probes for the keys)
//   /release/  the release web package, as shipped
// The page itself always loads the test build, to play the server and to
// derive the expected secrets. Which build the workers run is chosen per test.
import { Recorder, SpyWorker } from "/spy.mjs";

const enc = new TextEncoder();
const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (h) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
const fill = (n, b) => new Uint8Array(n).fill(b);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const URL_ = "https://ferret.example";
const PASSWORD = "correct horse battery staple";
const PASSWORD_2 = "tr0ub4dor and three more words";
const EXPORT_PASSWORD = "export password for tests";
const NOW = 1_700_000_000_000;
const IDS = {
  account_id: fill(16, 0x11),
  vault_id: fill(16, 0x22),
  password_method_id: fill(16, 0x70),
  recovery_method_id: fill(16, 0x71),
};
const CTX = { account_id: IDS.account_id, vault_id: IDS.vault_id, vk_epoch: 1 };
const pinned = (record, extra = {}) => ({ kind: "pinned", record, ...extra });
const firstUse = (skBit, extra = {}) => ({ kind: "first_use", sk_bit: skBit, ...extra });
const row = (itemId, sealed) => ({ item_id: itemId, rev: sealed.rev, envelope: sealed.envelope, tag: sealed.tag });
const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

const LOGIN_DRAFT = {
  item_type: "login",
  name: "Example",
  fields: [
    { id: "user", label: "User", kind: "text", value: "alice" },
    { id: "pass", label: "Password", kind: "password", value: "hunter2-secret" },
  ],
  urls: [{ url: "https://example.com" }],
  totp: { uri: "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example" },
  notes: "private note text",
};

let testWasmPromise = null;
/** The page's own instance of the test build (a test server, key derivations). */
function testWasm() {
  testWasmPromise ??= import("/test/pkg-web/ferret_core_wasm.js").then(async (m) => {
    await m.default();
    return m;
  });
  return testWasmPromise;
}

/**
 * The client of bindings/wasm/js on real module workers, wrapped by spies.
 * `probe: true` runs the probe worker in place of the vault worker (the
 * `test` mount only).
 */
async function makeClient({ mount, probe = false }) {
  const { createClient } = await import(`/${mount}/js/client.mjs`);
  const recorder = new Recorder();
  const vaultUrl = probe ? "/probe.worker.mjs" : `/${mount}/js/vault.worker.mjs`;
  const jobUrl = `/${mount}/js/job.worker.mjs`;
  const client = createClient({
    createVaultWorker: () => new SpyWorker("vault", vaultUrl, recorder),
    createJobWorker: () => new SpyWorker("job", jobUrl, recorder),
  });
  const liveVault = () => recorder.workers.find((w) => w.label === "vault" && !w.terminated);
  return { client, recorder, liveVault };
}

/** Registers and creates an account through the client; the server is the page. */
async function createAccount(client, wasm, seed, password = PASSWORD) {
  const server = new wasm.TestServer(enc.encode(seed));
  const request = await client.vault.register_start(enc.encode(password), { kind: "generate" });
  const registration = await client.vault.register_finish(server.register_response(IDS.account_id, request), 1);
  const created = await client.vault.create_account(URL_, IDS);
  return { server, registration, created };
}

const op = (wasm, method, name, input) =>
  JSON.parse(wasm.test_run_case(method, JSON.stringify({ op: name, input, rng: [] }))).output;

// ------------------------------------------------------------------ vectors

function runInWorker(request) {
  return new Promise((resolve, reject) => {
    const worker = new Worker("/vectors.worker.mjs", { type: "module" });
    worker.onmessage = (event) => {
      worker.terminate();
      if (event.data.error) reject(new Error(event.data.error));
      else resolve(event.data.files);
    };
    worker.onerror = (e) => {
      worker.terminate();
      reject(new Error(`vectors worker failed: ${e.message}`));
    };
    worker.postMessage(request);
  });
}

// ------------------------------------------------------------------- export

async function exportRun() {
  const wasm = await testWasm();
  const { client, recorder } = await makeClient({ mount: "release" });
  await createAccount(client, wasm, "browser-export");
  const id = fill(16, 0x41);
  const sealed = await client.vault.encrypt_item(id, 1, { item_type: "note", name: "n", notes: "x".repeat(1000) }, undefined, NOW);
  const rows = [row(id, sealed)];
  // The default parameters: 256 MiB, 3 passes, 1 lane.
  const started = await client.vault.export_begin(rows, NOW);
  const t0 = performance.now();
  const key = await client.job.argon2_export_key(EXPORT_PASSWORD, started.salt, started.kdf, "write", PASSWORD);
  const writeMs = performance.now() - t0;
  const keyLength = key.length;
  const file = await client.vault.export_finish(key);
  const keyWiped = key.every((b) => b === 0);
  const header = await client.vault.import_header(file);
  const t1 = performance.now();
  const again = await client.job.argon2_export_key(EXPORT_PASSWORD, header.salt, header.kdf, "open", null);
  const openMs = performance.now() - t1;
  const opened = await client.vault.import_open(file, again);
  await client.lock();
  return {
    kdf: started.kdf,
    keyLength,
    keyWiped,
    fileBytes: file.length,
    count: opened.count,
    writeMs: Math.round(writeMs),
    openMs: Math.round(openMs),
    jobWorkers: recorder.workers.filter((w) => w.label === "job").map((w) => w.terminated),
  };
}

// ---------------------------------------------------- job worker is ended

async function jobTerminatedRun() {
  const { client, recorder } = await makeClient({ mount: "release" });
  const kdf = { m_kib: 65536, t: 3, p: 1 };
  const memory = () => (performance.memory ? performance.memory.usedJSHeapSize : null);
  const before = memory();
  const lengths = [];
  for (let i = 0; i < 3; i++) {
    const key = await client.job.argon2_export_key(EXPORT_PASSWORD, fill(16, 9), kdf, "open", null);
    lengths.push(key.length);
  }
  const jobs = recorder.workers.filter((w) => w.label === "job");
  // An ended worker answers nothing; a live one answers a bad request with a code.
  const ping = { id: 1, target: "job", method: "argon2_export_key", args: [] };
  const answers = (raw, ms) =>
    new Promise((resolve) => {
      const timer = setTimeout(() => resolve(false), ms);
      raw.addEventListener(
        "message",
        () => {
          clearTimeout(timer);
          resolve(true);
        },
        { once: true },
      );
      raw.postMessage(ping);
    });
  const endedAnswers = [];
  for (const w of jobs) endedAnswers.push(await answers(w.raw, 700));
  const live = new SpyWorker("job", "/release/js/job.worker.mjs", new Recorder());
  const liveAnswers = await answers(live.raw, 20_000);
  live.terminate();
  return {
    keyLengths: lengths,
    jobs: jobs.length,
    terminated: jobs.map((w) => w.terminated),
    endedAnswers,
    liveAnswers,
    heapBefore: before,
    heapAfter: memory(),
  };
}

// ------------------------------------------------------------ lock and wipe

async function lockRun() {
  const wasm = await testWasm();
  const { client, recorder, liveVault } = await makeClient({ mount: "test", probe: true });
  const password = enc.encode(PASSWORD);
  const server = new wasm.TestServer(enc.encode("browser-lock"));
  const request = await client.vault.register_start(password, { kind: "generate" });
  const passwordWiped = password.every((b) => b === 0);
  await client.vault.register_finish(server.register_response(IDS.account_id, request), 1);
  await client.vault.create_account(URL_, IDS);
  const first = liveVault();
  const wipe = await first.probe({ op: "lock_wipe" });
  if (!wipe.ok) throw new Error(wipe.error);
  // The vault is gone from the worker; `client.lock()` now ends the worker too.
  await client.lock();
  const afterLock = await client.vault.context().then(
    () => "answered",
    (e) => e.code,
  );
  return {
    passwordWiped,
    before: wipe.before,
    after: wipe.after,
    firstTerminated: first.terminated,
    workers: recorder.workers.filter((w) => w.label === "vault").map((w) => w.terminated),
    afterLock,
  };
}

// ------------------------------------------------- passkey and WebCrypto

function derToP1363(der) {
  let i = 0;
  const expect = (b) => {
    if (der[i++] !== b) throw new Error("not a DER ECDSA signature");
  };
  const length = () => {
    let n = der[i++];
    if (n & 0x80) {
      const bytes = n & 0x7f;
      n = 0;
      for (let k = 0; k < bytes; k++) n = (n << 8) | der[i++];
    }
    return n;
  };
  expect(0x30);
  length();
  const int = () => {
    expect(0x02);
    const n = length();
    let v = der.slice(i, i + n);
    i += n;
    while (v.length > 32 && v[0] === 0) v = v.slice(1);
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return out;
  };
  const r = int();
  const s = int();
  return Uint8Array.from([...r, ...s]);
}

async function passkeyRun() {
  const wasm = await testWasm();
  const { client } = await makeClient({ mount: "release" });
  await createAccount(client, wasm, "browser-passkey");
  const caller = { origin: "https://example.com", top_origin_is_same: true };
  const uv = { user_present: true, user_verified: true };
  const create = {
    challenge: fill(32, 9), rp_id: "example.com", rp_name: "Example", user_id: fill(8, 1),
    user_name: "alice", user_display_name: "Alice", algorithms: [-7], exclude: [],
    user_verification: "preferred", prf: {},
  };
  const pkId = fill(16, 0x51);
  const made = await client.vault.passkey_create(pkId, 1, "Example", create, caller, uv, [], NOW, undefined);
  const handle = await client.vault.open_item(pkId, 1, made.item.envelope, made.item.tag);
  const challenge = fill(32, 3);
  const got = await client.vault.passkey_get(handle, { challenge, rp_id: "example.com", allow: [], user_verification: "required" }, caller, uv);

  const key = await crypto.subtle.importKey("spki", made.response.public_key_spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const clientHash = await sha256(got.client_data_json);
  const signed = Uint8Array.from([...got.authenticator_data, ...clientHash]);
  const verify = (signature, message) =>
    crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, message);
  const p1363 = derToP1363(got.signature);
  const good = await verify(p1363, signed);
  const flipped = signed.slice();
  flipped[flipped.length - 1] ^= 1;
  const badMessage = await verify(p1363, flipped);
  const badSignature = p1363.slice();
  badSignature[5] ^= 1;
  const tampered = await verify(badSignature, signed);
  const clientData = JSON.parse(new TextDecoder().decode(got.client_data_json));
  const b64url = (u8) => btoa(String.fromCharCode(...u8)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  await client.lock();
  return {
    signatureDerLength: got.signature.length,
    good,
    badMessage,
    tampered,
    clientDataType: clientData.type,
    challengeMatches: clientData.challenge === b64url(challenge),
  };
}

// ----------------------------------------------------------- the leak walk

/** Every flow of the binding, on the real client, with the keys read out by the probe. */
async function leakRun() {
  const wasm = await testWasm();
  const { client, recorder, liveVault } = await makeClient({ mount: "test", probe: true });
  const probe = async (message) => {
    const r = await liveVault().probe(message);
    if (!r.ok) throw new Error(r.error);
    return r;
  };
  const secrets = {};
  const add = (name, bytesHex) => {
    if (typeof bytesHex !== "string" || bytesHex.length < 32) throw new Error(`${name}: not a key`);
    secrets[name] = bytesHex;
  };
  const zeroChecks = {};
  const accountHex = hex(IDS.account_id);
  const server = new wasm.TestServer(enc.encode("browser-leak"));

  const derive = (vkHex, epoch) => {
    const k = op(wasm, "vault_derive_keys", "kdf.vk_derive", {
      account_id: accountHex, vault_id: hex(IDS.vault_id), vk_epoch: String(epoch), vk: vkHex,
    });
    for (const name of ["k_head", "k_del", "k_meta", "seed_a"]) add(`${name} (epoch ${epoch})`, k[name]);
  };
  const kekPassword = (exportKeyHex) =>
    op(wasm, "kek_from_export_key", "kdf.kek.password", { account_id: accountHex, export_key: exportKeyHex }).kek;
  /** The OPAQUE export key of a registration, found by signing in on the page. */
  const exportKeyOf = (password, skCode, record, pin) => {
    const job = new wasm.UnlockJob();
    const ke1 = job.login_start(enc.encode(password), skCode);
    job.login_finish(server.login_start(record, IDS.account_id, ke1), 1, pin);
    const key = job.test_export_key();
    job.free();
    return hex(key);
  };

  // ---- create the account
  const request = await client.vault.register_start(enc.encode(PASSWORD), { kind: "generate" });
  const registration = await client.vault.register_finish(server.register_response(IDS.account_id, request), 1);
  const created = await client.vault.create_account(URL_, IDS);
  const vk1 = (await probe({ op: "vk" })).vk;
  add("VK", vk1);
  derive(vk1, 1);
  const rkCode = await client.vault.reveal_recovery_code();
  const skCode = await client.vault.reveal_secret_key_code();
  const rk = op(wasm, "recovery_key_decode", "code.rk.decode", { code: rkCode }).key;
  add("RK", rk);
  add("KEK_rk", op(wasm, "kek_from_recovery_key", "kdf.kek.recovery", { account_id: accountHex, rk }).kek);
  add("SK", op(wasm, "secret_key_decode", "code.sk.decode", { code: skCode }).key);
  const pin1 = pinned(created.pinned);
  add("KEK_pw", kekPassword(exportKeyOf(PASSWORD, skCode, registration.record, pin1)));
  await client.vault.context();
  await client.vault.auth_public_key();

  // ---- items
  const id = fill(16, 0x41);
  const sealed = await client.vault.encrypt_item(id, 1, LOGIN_DRAFT, undefined, NOW);
  add("IK", (await probe({ op: "call", method: "test_item_key", args: [id, 1, sealed.envelope, sealed.tag] })).value);
  const h = await client.vault.open_item(id, 1, sealed.envelope, sealed.tag);
  await client.vault.item_view(h);
  await client.vault.totp_code(h, 59);
  const edited = await client.vault.encrypt_item(id, 2, { name: "Renamed" }, h, NOW + 1);
  await client.vault.make_tombstone(fill(16, 0x42), 3);
  await client.vault.auth_sign("unlock-method.add", fill(32, 1), enc.encode("body"));
  await client.vault.make_checkpoint(1, [{ item_id: id, rev: 2, hash: fill(32, 7) }]);
  await client.vault.seed_pinned(created.pinned, created.manifest);

  // ---- a passkey inside the vault
  const caller = { origin: "https://example.com", top_origin_is_same: true };
  const uv = { user_present: true, user_verified: true };
  const create = {
    challenge: fill(32, 9), rp_id: "example.com", rp_name: "Example", user_id: fill(8, 1),
    user_name: "alice", user_display_name: "Alice", algorithms: [-7], exclude: [],
    user_verification: "preferred", prf: {},
  };
  const pkId = fill(16, 0x51);
  const made = await client.vault.passkey_create(pkId, 1, "Example", create, caller, uv, [], NOW, undefined);
  add("IK (passkey item)", (await probe({ op: "call", method: "test_item_key", args: [pkId, 1, made.item.envelope, made.item.tag] })).value);
  const ph = await client.vault.open_item(pkId, 1, made.item.envelope, made.item.tag);
  for (const which of ["scalar", "seed_uv", "seed_nouv"]) {
    add(`passkey ${which}`, (await probe({ op: "call", method: "test_passkey_secret", args: [ph, which] })).value);
  }
  await client.vault.passkey_get(ph, { challenge: fill(32, 3), rp_id: "example.com", allow: [], user_verification: "required" }, caller, uv);
  await client.vault.item_view(ph);

  // ---- the wraps of a PIN and of a passkey method
  const pinWrap = await client.vault.wrap_pin(enc.encode("123456"), fill(16, 0x75), null);
  add("KEK_pin", op(wasm, "kek_from_pin_extension", "kdf.kek.pin_extension", { pin: "123456", device_salt: hex(pinWrap.method.device_salt) }).kek);
  const prfOutput = crypto.getRandomValues(new Uint8Array(32));
  add("PRF output", hex(prfOutput));
  const prfWrap = await client.vault.wrap_prf(fill(24, 0x44), fill(32, 0x55), prfOutput.slice(), fill(16, 0x76), 1);
  add("KEK_prf", op(wasm, "kek_from_prf", "kdf.kek.prf", { credential_id: hex(fill(24, 0x44)), prf_output: hex(prfOutput) }).kek);

  // ---- every way to unlock (each replaces the vault in the worker)
  const ke1 = await client.vault.login_start(enc.encode(PASSWORD), skCode);
  const ke2 = server.login_start(registration.record, IDS.account_id, ke1);
  await client.vault.login_finish(ke2, 1, pin1);
  await client.vault.unlock_password(URL_, CTX, created.wraps[0], pin1);
  if ((await probe({ op: "vk" })).vk !== vk1) throw new Error("password unlock gave another key");
  await client.vault.pin_unlock(enc.encode("123456"), created.pinned, pinWrap, null);
  await client.vault.unlock_prf(URL_, CTX, prfOutput.slice(), prfWrap, pinned(created.pinned, { server_public_key: created.pinned.server_public_key }));
  const qr = wasm.setup_qr_build(URL_, IDS.account_id, 1, true, created.server_public_key);
  await client.vault.unlock_recovery(URL_, CTX, rkCode, created.wraps[1], firstUse(true), qr);

  // ---- change the password
  const changeRequest = await client.vault.register_start(enc.encode(PASSWORD_2), { kind: "code", code: skCode });
  const changeReg = await client.vault.register_finish(server.register_response(IDS.account_id, changeRequest), 1);
  add("KEK_pw (changed)", kekPassword(exportKeyOf(PASSWORD_2, skCode, changeReg.record, pin1)));
  await client.vault.change_password(created.pinned, created.wraps[0], created.manifest);

  // ---- recover
  const recoverRequest = await client.vault.register_start(enc.encode(PASSWORD_2), { kind: "code", code: skCode });
  const recoverReg = await client.vault.register_finish(server.register_response(IDS.account_id, recoverRequest), 1);
  add("KEK_pw (recovered)", kekPassword(exportKeyOf(PASSWORD_2, skCode, recoverReg.record, pin1)));
  await client.vault.recover(URL_, CTX, rkCode, created.wraps[1], created.manifest, fill(16, 0x73), firstUse(true), qr);
  const rkNew = op(wasm, "recovery_key_decode", "code.rk.decode", { code: await client.vault.reveal_recovery_code() }).key;
  add("RK (recovered)", rkNew);
  add("KEK_rk (recovered)", op(wasm, "kek_from_recovery_key", "kdf.kek.recovery", { account_id: accountHex, rk: rkNew }).kek);
  await client.vault.recover_sign(fill(32, 2), enc.encode("request"));
  await client.vault.recover_done();

  // ---- rekey
  const rekeyKe1 = await client.vault.login_start(enc.encode(PASSWORD), skCode);
  await client.vault.login_finish(server.login_start(registration.record, IDS.account_id, rekeyKe1), 1, pin1);
  const base = await client.vault.make_checkpoint(7, [
    { item_id: new Uint8Array(16), rev: created.manifest.rev, hash: await sha256(created.manifest.envelope) },
    { item_id: id, rev: 2, hash: await sha256(edited.envelope) },
  ]);
  const plan = await client.vault.rekey(
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
  );
  await client.vault.rekey_commit();
  const vk2 = (await probe({ op: "vk" })).vk;
  add("VK (new epoch)", vk2);
  derive(vk2, 2);
  const rkRekey = op(wasm, "recovery_key_decode", "code.rk.decode", { code: await client.vault.reveal_recovery_code() }).key;
  add("RK (rekey)", rkRekey);
  add("KEK_rk (rekey)", op(wasm, "kek_from_recovery_key", "kdf.kek.recovery", { account_id: accountHex, rk: rkRekey }).kek);
  const newItem = plan.items[0];
  add("IK (new epoch)", (await probe({ op: "call", method: "test_item_key", args: [id, newItem.rev, newItem.envelope, newItem.tag] })).value);

  // ---- export and import (64 MiB here; the 256 MiB step has its own test)
  const second = fill(16, 0x44);
  const sealed2 = await client.vault.encrypt_item(second, 1, { item_type: "note", name: "Second", notes: "second note" }, undefined, NOW);
  const rows = [row(id, newItem), row(second, sealed2)];
  const kdf = { m_kib: 65536, t: 3, p: 1 };
  const started = await client.vault.export_begin(rows, NOW, kdf);
  const wrapKey = await client.job.argon2_export_key(EXPORT_PASSWORD, started.salt, started.kdf, "write", PASSWORD);
  const file = await client.vault.export_finish(wrapKey);
  zeroChecks.exportKeyAfterFinish = wrapKey.every((b) => b === 0);
  const header = await client.vault.import_header(file);
  const openKey = await client.job.argon2_export_key(EXPORT_PASSWORD, header.salt, header.kdf, "open", null);
  const opened = await client.vault.import_open(file, openKey);
  zeroChecks.exportKeyAfterOpen = openKey.every((b) => b === 0);
  await client.vault.import_view(0);
  await client.vault.import_seal(0, fill(16, 0x91), 1);
  await client.vault.totp_parse(LOGIN_DRAFT.totp.uri);
  await client.vault.setup_qr_parse(qr);

  return {
    secrets,
    messages: recorder.dump(),
    imported: opened.count,
    zeroChecks,
    jobWorkers: recorder.workers.filter((w) => w.label === "job").map((w) => w.terminated),
  };
}

/** The forms in which a secret can sit in a message. */
function plantedForms(secretHex) {
  const vk = fromHex(secretHex);
  const copy = () => Uint8Array.from(vk);
  const b64 = (bytes) => btoa(String.fromCharCode(...bytes));
  const b64url = (bytes) => b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return {
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
    "a DataView with an offset": { view: new DataView(Uint8Array.from([5, 6, ...vk, 7]).buffer, 2, 32) },
    "hex": { text: `prefix ${secretHex} suffix` },
    "upper-case hex": { text: secretHex.toUpperCase() },
    "half of it as hex": { text: secretHex.slice(8, 40) },
    "base64": { text: b64(vk) },
    "base64url": { text: b64url(vk) },
    "base64 at offset 1": { text: b64([7, ...vk]) },
    "base64 at offset 2": { text: b64([7, 7, ...vk]) },
    "base64url at offset 2": { text: b64url([7, 7, ...vk]) },
    "half of it as base64 at offset 1": { text: b64([7, ...vk.slice(3, 19), 8]) },
  };
}

/** Innocent messages: the walk must not flag these. */
function innocentForms(secretHex) {
  const vk = fromHex(secretHex);
  return {
    "another key": { other: fill(32, 0xee), text: hex(fill(32, 0xee)), view: new Uint16Array(16) },
    "a short run": { short: vk.slice(0, 15) },
    "text that only looks like it": { text: secretHex.slice(0, 30) },
    "a Map with a Set": { map: new Map([["k", new Set([1, 2])]]) },
  };
}

/**
 * Posts each planted form to a worker (the page to the worker) and has the
 * worker post it back (the worker to the page), through the real spy, and
 * returns what the spy saw. The test process checks that the walk finds them.
 */
async function plantedRun(secretHex) {
  const recorder = new Recorder();
  const spy = new SpyWorker("vault", "/probe.worker.mjs", recorder);
  const out = [];
  let id = 1000;
  for (const [group, forms] of [["planted", plantedForms(secretHex)], ["innocent", innocentForms(secretHex)]]) {
    for (const [form, value] of Object.entries(forms)) {
      const start = recorder.messages.length;
      spy.postMessage({ id: id++, target: "vault", method: "no_such_method", args: [value] });
      // A probe reply comes after the worker has answered the message above.
      await spy.probe({ op: "call", method: "context", args: [] }).catch(() => {});
      const afterOut = recorder.messages.length;
      await spy.probe({ op: "emit", id: id++, value });
      await sleep(50);
      out.push({
        group,
        form,
        out: recorder.messages.slice(start, afterOut).filter((m) => m.dir === "out"),
        in: recorder.messages.slice(afterOut).filter((m) => m.dir === "in"),
      });
    }
  }
  spy.terminate();
  return out;
}

window.ferret = {
  userAgent: navigator.userAgent,
  runVectors: runInWorker,
  exportRun,
  jobTerminatedRun,
  lockRun,
  passkeyRun,
  leakRun,
  plantedRun,
};
window.__ferretReady = true;
