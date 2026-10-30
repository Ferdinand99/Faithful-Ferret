// Shared helpers of the Node tests of the WASM binding.
import { createRequire } from "node:module";
import { join } from "node:path";
import { root } from "./paths.mjs";

export { root };
const require = createRequire(import.meta.url);

/** The build with `test-support` (vector operations, a test server, probes). */
export const wasm = require(join(root, "bindings", "wasm", "pkg-node-test", "ferret_core_wasm.js"));

export const enc = new TextEncoder();
export const URL_ = "https://ferret.example";
export const PASSWORD = "correct horse battery staple";
export const PASSWORD_2 = "tr0ub4dor and three more words";

export const fill = (n, b) => new Uint8Array(n).fill(b);

export const IDS = {
  account_id: fill(16, 0x11),
  vault_id: fill(16, 0x22),
  password_method_id: fill(16, 0x70),
  recovery_method_id: fill(16, 0x71),
};
export const CTX = { account_id: IDS.account_id, vault_id: IDS.vault_id, vk_epoch: 1 };
export const NOW = 1_700_000_000_000;

/** Runs `fn` and returns the error it throws (the test fails if it does not). */
export function codeOf(fn) {
  try {
    fn();
  } catch (e) {
    return e;
  }
  throw new Error("expected a failure");
}

/** A new account: the server, the job, what `create_account` returned. */
export function newAccount(seed, { secretKey = true, password = PASSWORD } = {}) {
  const server = new wasm.TestServer(enc.encode(seed));
  const job = new wasm.UnlockJob();
  const request = job.register_start(enc.encode(password), {
    kind: secretKey ? "generate" : "none",
  });
  const response = server.register_response(IDS.account_id, request);
  const registration = job.register_finish(response, 1);
  const created = job.create_account(URL_, IDS);
  return { server, job, created, vault: created.vault, registration, record: registration.record };
}

/** The pin states. */
export const pinned = (record, extra = {}) => ({ kind: "pinned", record, ...extra });
export const firstUse = (skBit, extra = {}) => ({ kind: "first_use", sk_bit: skBit, ...extra });

/** Signs in with the password against `server`; returns `{ vault, pinned, job }`. */
export function signIn(server, record, password, skCode, pin, wrap, ctx = CTX) {
  const job = new wasm.UnlockJob();
  const ke1 = job.login_start(enc.encode(password), skCode);
  const ke2 = server.login_start(record, IDS.account_id, ke1);
  const finished = job.login_finish(ke2, 1, pin);
  server.login_finish(finished.ke3);
  const out = job.unlock_password(URL_, ctx, wrap, pin);
  return { ...out, job };
}

/** The sealed item `{ rev, envelope, tag }` as a row of the server. */
export const row = (itemId, sealed) => ({
  item_id: itemId,
  rev: sealed.rev,
  envelope: sealed.envelope,
  tag: sealed.tag,
});

export const LOGIN_DRAFT = {
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

/** The `existing` value of `passkey_create` that says no passkey is stored. */
export const NO_EXISTING = "no_existing";

/**
 * Makes a passkey and confirms it, as a client does after the server has
 * accepted the item. Returns `{ item, item_id, response, handle }`.
 */
export function passkeyCreate(vault, ...args) {
  const made = vault.passkey_create(...args);
  const done = vault.passkey_create_confirm(made.pending);
  return { item: made.item, item_id: made.item_id, response: done.response, handle: done.handle };
}

/**
 * A fresh sign-in with the master password for `account` (from `newAccount`)
 * and the one-time token of `reauth_grant` that it makes.
 */
export function reauthToken(account, password = PASSWORD) {
  const { server, vault, created, record } = account;
  const job = new wasm.UnlockJob();
  const ke1 = job.login_start(enc.encode(password), vault.reveal_secret_key_code());
  const ke2 = server.login_start(record, IDS.account_id, ke1);
  job.login_finish(ke2, 1, pinned(created.pinned));
  return job.reauth_grant(vault, created.wraps[0]);
}
