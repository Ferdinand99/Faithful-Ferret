// The message protocol between the page and the two workers, and the code that
// answers it. It has no dependency on a worker API: `createDispatcher` takes
// the loaded WASM module and returns a function from a request to a reply, so
// the workers are a few lines and the Node tests run the real thing.
//
// Request: { id, target: "vault" | "job", method, args }
// Reply:   { id, ok: true, value } | { id, ok: false, code }
//
// The vault worker is long-lived and holds the Vault and the UnlockJob. The job
// worker is short-lived and answers one call: `argon2_export_key`, the slow
// step of an export or an import file. A reply never carries anything but
// values and a code: no message text of an error ever leaves the worker.

/** Methods of the UnlockJob (sign in, registration, account flows). */
export const JOB_METHODS = new Set([
  "login_start",
  "login_finish",
  "unlock_password",
  "unlock_recovery",
  "unlock_prf",
  "pin_unlock",
  "register_start",
  "register_finish",
  "create_account",
  "change_password",
  "recover",
  "recover_sign",
  "recover_done",
  "rekey",
  "clear",
]);

/** Job methods that take the Vault as their first argument. */
export const NEEDS_VAULT = new Set(["change_password", "rekey"]);

/** Job methods whose result holds a `vault`: the worker keeps it. */
export const MAKES_VAULT = new Set([
  "unlock_password",
  "unlock_recovery",
  "unlock_prf",
  "pin_unlock",
  "create_account",
  "recover",
]);

/** Functions of the module that need no state. */
export const STATELESS = new Set([
  "setup_qr_build",
  "setup_qr_parse",
  "check_master_password",
  "check_code",
  "totp_parse",
  "import_header",
]);

/** The only function of the job worker. */
export const JOB_WORKER_FUNCTIONS = new Set(["argon2_export_key"]);

/**
 * Which arguments of a call are secrets: a `Uint8Array` there is wiped on the
 * sending side after it has been copied for the worker, and by the worker
 * after the call.
 */
export const SECRET_ARGS = {
  login_start: [0],
  register_start: [0],
  pin_unlock: [0, 3],
  unlock_prf: [2],
  wrap_pin: [0, 2],
  wrap_prf: [2],
  export_finish: [0],
  import_open: [1],
  argon2_export_key: [0, 4],
  check_master_password: [0],
};

/** Arguments that are master or export password text: a string is encoded. */
export const TEXT_ARGS = {
  login_start: [0],
  register_start: [0],
  pin_unlock: [0],
  argon2_export_key: [0, 4],
  check_master_password: [0],
  wrap_pin: [0],
};

/**
 * The arguments that the Rust side takes as `u32` (handles, indexes, profile
 * numbers). `wasm-bindgen` coerces a JavaScript value before Rust sees it
 * (`4294967297` becomes `1`, `1.9` becomes `1`, `"3"` becomes `3`), so they are
 * checked here: a number that is a whole number from 0 to 2^32 - 1. The second
 * item says whether the argument may be left out (`undefined` or `null`).
 */
export const U32_ARGS = {
  close_item: [[0, false]],
  item_view: [[0, false]],
  reveal_item_field: [[0, false], [1, false]],
  reveal_item_notes: [[0, false]],
  reveal_totp_secret: [[0, false]],
  totp_code: [[0, false]],
  encrypt_item: [[3, true]],
  passkey_create: [[8, true]],
  passkey_get: [[0, false]],
  import_view: [[0, false]],
  import_seal: [[0, false]],
  login_finish: [[1, false]],
  register_finish: [[1, false]],
  setup_qr_build: [[2, false]],
};

/** Throws `invalid_input` unless the `u32` arguments of a call are whole numbers in range. */
export function assertU32Args(method, args) {
  for (const [index, optional] of argsOf(U32_ARGS, method)) {
    const v = args[index];
    if (optional && (v === undefined || v === null)) continue;
    if (typeof v !== "number" || !Number.isInteger(v) || v < 0 || v > 0xffffffff) {
      throw new FerretError("invalid_input");
    }
  }
}

/**
 * The entry of a table for a method name, or nothing. A plain lookup would
 * find `constructor` and `toString` on the prototype of the table.
 */
export function argsOf(table, method) {
  return typeof method === "string" && Object.hasOwn(table, method) ? table[method] : [];
}

/** An error with a stable code and no data. */
export class FerretError extends Error {
  constructor(code) {
    super(code);
    this.name = "FerretError";
    this.code = code;
  }
}

/** Whether a string has no lone surrogate. */
export function isWellFormed(s) {
  if (typeof s.isWellFormed === "function") return s.isWellFormed();
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/**
 * Encodes password text as UTF-8. A string with a lone surrogate is
 * `invalid_input`: `TextEncoder` would turn it into U+FFFD without a word, and
 * a password that is changed on the way in cannot be typed again.
 */
export function encodeSecretText(text) {
  if (typeof text !== "string" || !isWellFormed(text)) {
    throw new FerretError("invalid_input");
  }
  return new TextEncoder().encode(text);
}

/** Throws `invalid_input` for a lone surrogate in any string of `value`. */
export function assertWellFormed(value, depth = 0) {
  if (typeof value === "string") {
    if (!isWellFormed(value)) throw new FerretError("invalid_input");
  } else if (value !== null && typeof value === "object" && depth < 8) {
    if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return;
    for (const v of Array.isArray(value) ? value : Object.values(value)) {
      assertWellFormed(v, depth + 1);
    }
  }
}

/** The `ArrayBuffer`s of every `Uint8Array` in a reply, to be transferred. */
export function transferables(value, out = new Set(), depth = 0) {
  if (value instanceof Uint8Array) {
    // Only a buffer the array owns entirely can be handed over.
    if (value.byteOffset === 0 && value.byteLength === value.buffer.byteLength) {
      out.add(value.buffer);
    }
  } else if (value !== null && typeof value === "object" && depth < 8) {
    for (const v of Array.isArray(value) ? value : Object.values(value)) {
      transferables(v, out, depth + 1);
    }
  }
  return [...out];
}

function codeOf(e) {
  return e && typeof e.code === "string" && /^[a-z0-9_]{1,64}$/.test(e.code) ? e.code : "internal";
}

function wipeSecretArgs(method, args) {
  for (const i of argsOf(SECRET_ARGS, method)) {
    if (args[i] instanceof Uint8Array) args[i].fill(0);
  }
}

function requireVault(vault) {
  if (!vault) throw new FerretError("vault_locked");
  return vault;
}

/**
 * The dispatcher of the vault worker.
 *
 * @param wasm the module (`import * as wasm from "../pkg-web/ferret_core_wasm.js"`
 *             after `init()`, or `require("../pkg-node/...")`)
 */
export function createDispatcher(wasm) {
  let vault = null;
  const job = new wasm.UnlockJob();
  const vaultMethods = new Set(
    Object.getOwnPropertyNames(wasm.Vault.prototype).filter(
      (n) =>
        n !== "constructor" &&
        n !== "free" &&
        !n.startsWith("__") &&
        typeof wasm.Vault.prototype[n] === "function",
    ),
  );

  const dropVault = () => {
    if (vault) {
      vault.lock();
      vault.free();
      vault = null;
    }
  };

  function call(method, args) {
    if (method === "lock") {
      dropVault();
      job.clear();
      return null;
    }
    if (STATELESS.has(method)) return wasm[method](...args);
    if (JOB_METHODS.has(method)) {
      const full = NEEDS_VAULT.has(method) ? [requireVault(vault), ...args] : args;
      const result = job[method](...full);
      if (MAKES_VAULT.has(method)) {
        dropVault();
        vault = result.vault;
        delete result.vault;
      }
      return result;
    }
    if (vaultMethods.has(method)) {
      return requireVault(vault)[method](...args);
    }
    throw new FerretError("invalid_input");
  }

  return function dispatch(request) {
    const id = request?.id;
    const args = Array.isArray(request?.args) ? request.args : [];
    try {
      if (request?.target !== "vault" || typeof request.method !== "string") {
        throw new FerretError("invalid_input");
      }
      assertU32Args(request.method, args);
      const value = call(request.method, args);
      return { reply: { id, ok: true, value }, transfer: transferables(value) };
    } catch (e) {
      return { reply: { id, ok: false, code: codeOf(e) }, transfer: [] };
    } finally {
      wipeSecretArgs(request?.method, args);
    }
  };
}

/** The dispatcher of the job worker: `argon2_export_key` and nothing else. */
export function createJobDispatcher(wasm) {
  return function dispatch(request) {
    const id = request?.id;
    const args = Array.isArray(request?.args) ? request.args : [];
    try {
      if (
        request?.target !== "job" ||
        typeof request.method !== "string" ||
        !JOB_WORKER_FUNCTIONS.has(request.method)
      ) {
        throw new FerretError("invalid_input");
      }
      const value = wasm[request.method](...args);
      return { reply: { id, ok: true, value }, transfer: transferables(value) };
    } catch (e) {
      return { reply: { id, ok: false, code: codeOf(e) }, transfer: [] };
    } finally {
      wipeSecretArgs(request?.method, args);
    }
  };
}
