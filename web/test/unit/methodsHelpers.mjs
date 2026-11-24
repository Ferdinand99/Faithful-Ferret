// Helpers for the tests of the passkey unlock methods: a signed-in account whose fake core makes the wraps and the
// manifest the way the real one does (names and flags inside the manifest, the body written by the core), a fake
// server that lists, adds and removes passkey methods, and a fake `navigator.credentials` that answers the two
// WebAuthn calls with well-formed data. Every value here is a test value; the PRF result is a pattern that no other test
// value looks like, so a test can search for it everywhere.
import { createHash } from "node:crypto";
import { cache } from "../../src/store/cache.mjs";
import { b64u, hex16 } from "../../src/b64.mjs";
import { ACCOUNT, VAULT, coded, filled } from "./accountHelpers.mjs";
import { answer, signedInWorld } from "./securityHelpers.mjs";

export { ACCOUNT, coded, filled };

/** The host of the vault in the tests. */
export const HOST = "vault.example.test";
/** Its origin: the page's. */
export const ORIGIN = `https://${HOST}`;
/** The new salt of a registration. */
export const SALT = filled(32, 0x51);
/** The PRF result of the test passkey: 32 bytes that nothing else in the tests looks like. */
export const PRF_RESULT = Uint8Array.from({ length: 32 }, (_, i) => 0xc0 + ((i * 7) % 61));
/** The AAGUID of the test authenticator. */
export const AAGUID = Uint8Array.from({ length: 16 }, (_, i) => 0x70 + i);
/** The credential id of the test passkey. */
export const CREDENTIAL = Uint8Array.from({ length: 24 }, (_, i) => 0x33 + i);
/** The id the page gives a new method (the fake random source makes it). */
export const METHOD_ID = Uint8Array.from({ length: 16 }, (_, i) => 0xa0 + i);
/** Another passkey that the server already lists. */
export const OLD = Object.freeze({
  id: "5a".repeat(16),
  credential: filled(20, 0x44),
  salt: filled(32, 0x45),
  aaguid: "00".repeat(16),
  name: "Old laptop",
  synced: false,
  createdAt: 1_700_000_000,
});

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const sha256 = (bytes) => new Uint8Array(createHash("sha256").update(bytes).digest());
const buffer = (bytes) => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);

/** The dependencies of the WebAuthn calls: the fake credentials, a counting random source and a clock the test moves. */
export function ceremonyDeps(credentials, { origin = ORIGIN, clock = { at: 0 } } = {}) {
  let counter = 0;
  return {
    credentials,
    // The first draw is the id of the new method (16 bytes); the others are the challenges and the user handle.
    rand: (bytes) => {
      counter += 1;
      if (bytes.length === 16) bytes.set(METHOD_ID);
      else bytes.fill(0x10 + counter);
      return bytes;
    },
    now: () => clock.at,
    sha256: async (data) => sha256(data),
    origin,
    clock,
  };
}

/**
 * A fake `navigator.credentials`. `calls` has the options of every call. The options that change what the answer looks
 * like: `uv` (the UV flag), `be` and `bs` (the flags), `atCreate` (a PRF result at registration: true, false, or the bytes),
 * `output` (the result of the evaluation), `enabled` (the PRF extension is supported), `aaguid`, `host` (the relying party
 * of the answer), `fail` (a call that rejects: `{ create: DOMException name, get: name }`), `otherId` (the evaluation
 * answers for another credential).
 * @param {Record<string, any>} [options]
 */
export function fakeCredentials({
  uv = true, be = false, bs = false, atCreate = true, output = PRF_RESULT, enabled = true, aaguid = AAGUID, host = HOST, fail = {}, otherId = false,
  getUv = uv, getBe = be, clock = null, failAfter = 0, credential = CREDENTIAL, failTimes = Infinity,
} = {}) {
  const calls = { create: [], get: [] };
  const clientData = (type, challenge) => buffer(new TextEncoder().encode(JSON.stringify({ type, challenge: b64u.encode(new Uint8Array(challenge)), origin: ORIGIN, crossOrigin: false })));
  const flags = (verified, extra, eligible = be) => 0x01 | (verified ? 0x04 : 0) | (eligible ? 0x08 : 0) | (bs ? 0x10 : 0) | extra;
  let failing = failTimes;
  const reject = (name) => {
    failing -= 1;
    if (clock) clock.at += failAfter;
    return Promise.reject(Object.assign(new Error(name), { name }));
  };
  return {
    calls,
    async create(options) {
      calls.create.push(options);
      if (fail.create && failing > 0) return reject(fail.create);
      const id = credential;
      const data = new Uint8Array([
        ...sha256(new TextEncoder().encode(host)), flags(uv, 0x40), 0, 0, 0, 1, ...aaguid, 0, id.length, ...id, 0xa5, 0x01, 0x02,
      ]);
      const first = atCreate === false ? undefined : buffer(atCreate === true ? output : atCreate);
      return {
        type: "public-key",
        rawId: buffer(id),
        response: { clientDataJSON: clientData("webauthn.create", options.publicKey.challenge), getAuthenticatorData: () => buffer(data) },
        getClientExtensionResults: () => ({ prf: { enabled, ...(first === undefined ? {} : { results: { first } }) } }),
      };
    },
    async get(options) {
      calls.get.push(options);
      if (fail.get && failing > 0) return reject(fail.get);
      const data = new Uint8Array([...sha256(new TextEncoder().encode(host)), flags(getUv, 0, getBe), 0, 0, 0, 2]);
      return {
        type: "public-key",
        rawId: buffer(otherId ? filled(24, 0x99) : credential),
        response: { clientDataJSON: clientData("webauthn.get", options.publicKey.challenge), authenticatorData: buffer(data) },
        getClientExtensionResults: () => ({ prf: { results: output === null ? undefined : { first: buffer(output) } } }),
      };
    },
  };
}

/** The wire form of a passkey method of the server's list. */
const wireOf = (p) => ({
  method_id: p.id,
  method_type: 3,
  kek_generation: 1,
  wrap: b64u.encode(filled(72, 9)),
  credential_id: b64u.encode(p.credential),
  prf_salt: b64u.encode(p.salt),
  ...(p.aaguid === undefined ? {} : { aaguid: p.aaguid }),
  ...(p.createdAt === undefined ? {} : { created_at: p.createdAt }),
});

/**
 * A signed-in account with passkey methods. `world.methods` is what the server and the manifest hold (the fake core and
 * the fake server share it); `world.posts` and `world.deletes` are the signed requests the server received, with the bytes
 * the core wrote and the bytes `auth_sign` was given.
 * @param {{ passkeys?: any[], items?: Array<{ id: string, credential: Uint8Array }>, offered?: boolean, postStatus?: number, deleteStatus?: number, reauthUntil?: number | null, refuseWrap?: boolean }} [options]
 */
export async function passkeyWorld({ passkeys = [], items = [], offered = true, postStatus = 200, deleteStatus = 200, reauthUntil = null, refuseWrap = false } = {}) {
  /** What the manifest and the server hold. */
  const methods = { list: passkeys.map((p) => ({ ...p })), rev: 1 };
  const posts = [];
  const deletes = [];
  const signed = [];
  const adds = [];
  const wraps = [];
  const removes = [];
  /** The rows of the vault the fake core opens: id -> credential id of the passkey item. */
  const stored = new Map(items.map((item) => [item.id, item.credential]));
  let nextHandle = 1;
  const handles = new Map();

  const body = (text) => new TextEncoder().encode(text);
  const rowText = (rev) => `{"rev":${rev},"envelope":"${hex(filled(80, 4))}","tag":"${hex(filled(32, 5))}"}`;
  const listAnswer = () => answer(200, {
    methods: [
      { method_id: "11".repeat(16), method_type: 1, kek_generation: 1, wrap: b64u.encode(filled(104, 5)) },
      { method_id: "22".repeat(16), method_type: 2, kek_generation: 1, wrap: b64u.encode(filled(72, 6)) },
      ...methods.list.map(wireOf),
    ],
    pk_a: b64u.encode(filled(32, 3)),
    vk_epoch: 1,
    manifest: { rev: methods.rev, envelope: b64u.encode(filled(80, 4)), tag: b64u.encode(filled(32, 5)) },
  });
  const sent = (status, state, into) => {
    const request = state.requests.at(-1);
    into.push({ headers: request.headers, body: request.body });
    return status === 200 ? answer(200, { seq: 40 + into.length }) : answer(status, { error: status === 409 ? "write_conflict" : status === 403 ? "reauth_required" : "bad_request" });
  };

  const handlers = {
    prf_salt_new: () => SALT.slice(),
    prf_methods: () => methods.list.map((p) => ({
      method_id: hex16.decode(p.id), credential_id: p.credential, kek_generation: 1, name: p.name ?? null, synced: p.synced === true, bs: null,
    })),
    open_item: (itemId) => {
      const handle = nextHandle++;
      handles.set(handle, hex16.encode(itemId));
      return handle;
    },
    item_view: (handle) => ({ item_type: "login", name: "x", passkey: stored.has(handles.get(handle)) ? { rp_id: "example.test", cred_id: stored.get(handles.get(handle)) } : null }),
    close_item: (handle) => void handles.delete(handle),
    // The client wipes a secret array after it has copied it for the worker; the fake does the same.
    wrap_prf: (credentialId, salt, output, methodId, generation, aaguid, storedIds) => {
      const snapshot = output.slice();
      output.fill(0);
      wraps.push({ credentialId: credentialId.slice(), salt: salt.slice(), output: snapshot, methodId: methodId.slice(), generation, aaguid: aaguid.slice(), storedIds });
      if (refuseWrap || (Array.isArray(storedIds) && storedIds.some((id) => hex(id) === hex(credentialId)))) throw coded("invalid_state");
      return { method_id: methodId, kek_generation: generation, method: { type: "prf", credential_id: credentialId, prf_salt: salt }, wrap: filled(72, 9) };
    },
    manifest_add_method: (current, wrap, aaguid, label, be, bs) => {
      adds.push({ current, wrap, aaguid: aaguid.slice(), label, be, bs, body: null });
      const id = hex16.encode(wrap.method_id);
      const text = `{ "method_type": 3, "method_id":"${id}","wrap":"${hex(wrap.wrap)}","kek_generation":1,"credential_id":"${hex(wrap.method.credential_id)}","prf_salt":"${hex(wrap.method.prf_salt)}","aaguid":"${hex(aaguid)}","manifest":${rowText(current.rev + 1)} }`;
      const bytes = body(text);
      adds.at(-1).body = bytes;
      // What the manifest and the list will show once the server has taken it.
      adds.at(-1).apply = () => methods.list.push({ id, credential: wrap.method.credential_id, salt: wrap.method.prf_salt, aaguid: hex(aaguid), name: label.normalize("NFC").trim(), synced: be });
      return { op: "unlock-method.add", sealed: { rev: current.rev + 1, envelope: filled(80, 6), tag: filled(32, 7) }, body: bytes, pk_a: filled(32, 3) };
    },
    manifest_remove_method: (current, methodId) => {
      removes.push({ current, id: hex16.encode(methodId) });
      const text = `{"method_id":"${hex16.encode(methodId)}","manifest":${rowText(current.rev + 1)}}`;
      return { op: "unlock-method.remove", sealed: { rev: current.rev + 1, envelope: filled(80, 6), tag: filled(32, 7) }, body: body(text), pk_a: filled(32, 3) };
    },
    auth_sign: (op, nonce, bytes) => {
      signed.push({ op, bytes: bytes.slice() });
      return filled(64, 5);
    },
  };

  const overrides = {
    "GET /api/vault/unlock-methods": () => listAnswer(),
    "GET /api/vault/policy": () => answer(200, { pin: { allowed: true, after_restart: true, min_length: 6 }, prf: { enabled: offered } }),
    "POST /api/vault/unlock-methods": (_body, state) => {
      const status = typeof postStatus === "function" ? postStatus(posts.length) : postStatus;
      const result = sent(status, state, posts);
      if (status === 200) {
        adds.at(-1)?.apply?.();
        methods.rev += 1;
      }
      return result;
    },
  };
  const deleteHandler = (id) => (_body, state) => {
    const status = typeof deleteStatus === "function" ? deleteStatus(deletes.length) : deleteStatus;
    const result = sent(status, state, deletes);
    if (status === 200) {
      methods.list = methods.list.filter((m) => m.id !== id);
      methods.rev += 1;
    }
    return result;
  };
  // The ones the server lists, and the one the page makes for a new method.
  for (const id of [...passkeys.map((p) => p.id), hex16.encode(METHOD_ID)]) overrides[`DELETE /api/vault/unlock-methods/${id}`] = deleteHandler(id);

  const world = await signedInWorld({ handlers, overrides, reauthUntil });
  Object.assign(world, { methods, posts, deletes, signed, adds, wraps, removes, stored });
  // The rows of the vault this device holds: one per passkey item, so the flow can read their credential ids.
  const scope = { accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 1 };
  const db = await world.store.open();
  await cache.putRows(db, scope, items.map((item, index) => ({
    itemId: item.id, rev: 1, seq: index + 1, deleted: false, envelope: filled(40, 1), tag: filled(32, 2),
  })));
  world.scope = scope;
  return world;
}

/** A password check that answers `result` and leaves a mark in the world's log. */
export const reauthWith = (world, result = "ok") => async () => {
  world.log.push("reauth");
  return result;
};

/** Everything that is searched for a secret: the requests, the log, the calls to the core and the stored data. */
export const sentinelForms = (bytes) => [
  hex(bytes),
  b64u.encode(bytes),
  Buffer.from(bytes).toString("base64"),
  Buffer.from(bytes).toString("latin1"),
  JSON.stringify([...bytes]),
  [...bytes].join(","),
];
