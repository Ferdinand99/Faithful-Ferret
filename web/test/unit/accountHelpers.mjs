// Helpers for the tests of the account flows: a fake crypto client that records
// its calls, a fake server behind the real API client, the real local stores in
// a fresh in-memory IndexedDB, and a few DOM helpers for the pages.
import { createApi } from "../../src/api.mjs";
import { b64u, hex16 } from "../../src/b64.mjs";
import { createCryptoSession } from "../../src/crypto/session.mjs";
import storeDef from "../../src/services/store.service.mjs";
import { STORES, run, req } from "../../src/store/idb.mjs";
import { ACCOUNT, SERVER, VAULT, freshStore, pinnedRecord } from "./idbHelpers.mjs";
import { FakeElement, FakeText, fakeDocument } from "./helpers.mjs";

export { ACCOUNT, SERVER, VAULT, pinnedRecord };

// Test-only values; none of them is a real key, password or code.
export const EMAIL = "ada@example.test";
export const PASSWORD = "test-password-for-unit-tests-only";
export const SK_CODE = "FFS1-TESTA-TESTB-TESTC-TESTD-TESTE-TESTF";
export const RK_CODE = "FFR1-TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST";

export const filled = (length, value = 1) => new Uint8Array(length).fill(value);
const ID_PASSWORD = "11".repeat(16);
const ID_RECOVERY = "22".repeat(16);

/** An error with a code, as the crypto client rejects. */
export function coded(code) {
  return Object.assign(new Error(code), { code });
}

/** Whether every byte of an array is zero. */
export const wiped = (bytes) => bytes.every((n) => n === 0);

// ------------------------------------------------------------ the fake core

/**
 * The crypto client. Every call is logged (`vault.<method>`) and its
 * arguments are kept twice: `args` as they were passed (so a test can see that
 * a secret array was wiped afterwards) and `snapshot` as they were at the call.
 * `handlers` replace the defaults; a handler may throw.
 */
export function fakeClient({ log, skBit = true, handlers = {}, skCode = SK_CODE } = {}) {
  const calls = [];
  const defaults = {
    check_master_password: () => undefined,
    register_start: () => filled(32, 1),
    register_finish: () => ({ record: filled(192, 2), server_public_key: filled(32, 9), ksf_profile: 1 }),
    create_account: (_server, ids) => ({
      wraps: [
        { method_id: ids.password_method_id, kek_generation: 1, method: { type: "password", ksf_profile: 1 }, wrap: filled(104, 5) },
        { method_id: ids.recovery_method_id, kek_generation: 1, method: { type: "recovery" }, wrap: filled(72, 6) },
      ],
      manifest: { rev: 1, envelope: filled(80, 4), tag: filled(32, 5) },
      checkpoint: { seq: 1, digest: filled(32, 6), mac: filled(32, 7), entries: filled(40, 8) },
      pk_a: filled(32, 3),
      pk_r: filled(32, 10),
      registration_record: filled(192, 2),
      ksf_profile: 1,
      server_public_key: filled(32, 9),
      pinned: pinnedRecord({ skBit }),
    }),
    reveal_emergency_sheet: (server, email) => ({
      access: {
        server_url: server,
        email,
        account_id: ACCOUNT,
        ksf_profile: 1,
        secret_key_code: skBit ? skCode : null,
        qr_payload: "ferret-setup:v1?u=x",
      },
      recovery_key_code: RK_CODE,
    }),
    verify_recovery_setup: () => undefined,
    verify_secret_key_entry: () => undefined,
    clear_setup_secrets: () => undefined,
    login_start: () => filled(96, 1),
    login_finish: () => ({ ke3: filled(64, 2), server_public_key: filled(32, 9) }),
    unlock_password: () => ({ pinned: pinnedRecord({ skBit }) }),
    seed_pinned: (pinned) => pinned,
    check_server_methods: () => undefined,
    clear: () => undefined,
  };
  const snapshotOf = (value) => (value instanceof Uint8Array ? value.slice() : value);
  const vault = new Proxy(
    {},
    {
      get: (_, method) => async (...args) => {
        log?.push(`vault.${String(method)}`);
        calls.push({ method, args, snapshot: args.map(snapshotOf) });
        const handler = handlers[method] ?? defaults[method];
        return handler ? handler(...args) : undefined;
      },
    },
  );
  return {
    vault,
    calls,
    locked: 0,
    async lock() {
      log?.push("client.lock");
      this.locked += 1;
    },
    called: (method) => calls.filter((c) => c.method === method),
  };
}

// --------------------------------------------------------- the fake server

const json = (value, status = 200, headers = {}) =>
  new Response(typeof value === "string" ? value : JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });

/**
 * A fetch that answers like the vault server. `requests` records every call with
 * its parsed body; `overrides[path]` may return a Response for a path.
 */
export function fakeServer({ log, skHint = true, overrides = {} } = {}) {
  const state = { signedIn: false, requests: [] };
  const fetchImpl = async (url, init) => {
    const method = init.method;
    const body = init.body === undefined ? undefined : JSON.parse(typeof init.body === "string" ? init.body : new TextDecoder().decode(init.body));
    state.requests.push({ method, url, body, headers: init.headers });
    log?.push(`${method} ${url}`);
    const custom = overrides[`${method} ${url}`];
    if (custom) {
      const answer = custom(body, state);
      if (answer) return answer;
    }
    switch (`${method} ${url}`) {
      case "GET /api/auth/session":
        return state.signedIn ? json({ account_id: ACCOUNT, email: EMAIL, scope: "full", origin: "vault" }) : json({ error: "unauthorized" }, 401);
      case "POST /api/auth/opaque/register/start":
        return json({ registration_id: "ab".repeat(16), account_id: ACCOUNT, vault_id: VAULT, response: b64u.encode(filled(64, 3)), ksf_profile: 1 });
      case "POST /api/auth/opaque/register/finish":
        state.signedIn = true;
        return json({ account_id: ACCOUNT, vault_id: VAULT }, 201);
      case "POST /api/auth/opaque/login/start":
        return json({ login_id: "cd".repeat(16), ke2: b64u.encode(filled(320, 4)), ksf_profile: 1, sk_hint: skHint });
      case "POST /api/auth/opaque/login/finish":
        state.signedIn = true;
        return json({ account_id: ACCOUNT, vault_id: VAULT, vk_epoch: 1 });
      case "GET /api/vault/unlock-methods":
        return json({
          methods: [
            { method_id: ID_PASSWORD, method_type: 1, kek_generation: 1, wrap: b64u.encode(filled(104, 5)) },
            { method_id: ID_RECOVERY, method_type: 2, kek_generation: 1, wrap: b64u.encode(filled(72, 6)) },
          ],
          pk_a: b64u.encode(filled(32, 3)),
          vk_epoch: 1,
          manifest: { rev: 1, envelope: b64u.encode(filled(80, 4)), tag: b64u.encode(filled(32, 5)) },
        });
      case "POST /api/auth/logout":
        state.signedIn = false;
        return new Response(null, { status: 204 });
      default:
        return json({ error: "not_found" }, 404);
    }
  };
  return { fetchImpl, state, requests: state.requests };
}

// --------------------------------------------------------------- the scenario

/**
 * Everything a flow needs, wired: fake client, fake server behind the real API
 * client, the real stores in a fresh IndexedDB and a crypto session.
 */
export async function scenario({ skBit = true, skHint = true, handlers = {}, overrides = {}, sync, secrets, rand } = {}) {
  const log = [];
  const db = await freshStore();
  const client = fakeClient({ log, skBit, handlers });
  const server = fakeServer({ log, skHint, overrides });
  const api = createApi({ fetchImpl: server.fetchImpl });
  const base = storeDef.create({});
  const store = { ...base, open: async () => db.store };
  const session = createCryptoSession({
    client,
    api,
    store,
    serverUrl: SERVER,
    rand: rand ?? ((bytes) => globalThis.crypto.getRandomValues(bytes)),
    sync,
    secrets,
  });
  return { log, db, client, server, api, store, session, requests: server.requests };
}

/** Every record of every object store, as plain text, to look for secrets in. */
export async function dumpDatabase(dbStore) {
  const out = [];
  const seen = new WeakSet();
  const walk = (value) => {
    if (value === null || value === undefined) return;
    if (value instanceof Uint8Array) {
      out.push(Buffer.from(value).toString("latin1"));
      out.push(Buffer.from(value).toString("hex"));
      return;
    }
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") {
      out.push(String(value));
      return;
    }
    if (typeof value === "object") {
      if (seen.has(value)) return;
      seen.add(value);
      if (typeof CryptoKey !== "undefined" && value instanceof CryptoKey) {
        out.push(`CryptoKey:${value.type}:${value.extractable}`);
        return;
      }
      for (const [key, item] of Object.entries(value)) {
        out.push(key);
        walk(item);
      }
    }
  };
  await run(dbStore, STORES, "readonly", async (stores) => {
    for (const store of stores) walk(await req(store.getAll()));
  });
  return out.join("\n");
}

// ---------------------------------------------------------------- DOM helpers

/** A fake document whose elements start with the properties a real one has (`value` is "" and so on). */
export function accountDocument() {
  const document = fakeDocument();
  const create = document.createElement;
  document.createElement = (tag) => {
    const node = create(tag);
    node.value = "";
    node.checked = false;
    node.disabled = false;
    node.hidden = false;
    return node;
  };
  return document;
}

/** All nodes below `node` (and `node`). */
export function* walk(node) {
  yield node;
  for (const child of node.childNodes ?? []) yield* walk(child);
}

/** The text below a node. */
export function textOf(node) {
  let text = "";
  for (const n of walk(node)) if (n instanceof FakeText) text += `${n.data}\n`;
  return text;
}

/** The element with `data-role="role"` below `root`, or null. */
export function byRole(root, role) {
  for (const n of walk(root)) if (n instanceof FakeElement && n.getAttribute("data-role") === role) return n;
  return null;
}

/** Calls the listeners of `type` on `node`. */
export async function fire(node, type, event = {}) {
  for (const [kind, fn] of node.listeners) {
    if (kind === type) await fn({ preventDefault() {}, ...event });
  }
}

/** Waits until pending promises have run (a few turns of the event loop). */
export async function settle(times = 20) {
  for (let i = 0; i < times; i += 1) await new Promise((resolve) => setImmediate(resolve));
}

/** Waits until `check()` is true, for at most `ms` milliseconds (a slow machine needs more than a few turns). */
export async function until(check, ms = 15_000) {
  const end = Date.now() + ms;
  while (!check() && Date.now() < end) await new Promise((resolve) => setTimeout(resolve, 5));
  if (!check()) throw new Error("until: the condition did not become true");
}

export { hex16 };
