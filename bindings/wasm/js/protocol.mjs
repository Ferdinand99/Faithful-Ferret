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
  "reauth_grant",
  "clear",
]);

/** Job methods that take the Vault as their first argument. */
export const NEEDS_VAULT = new Set(["change_password", "rekey", "reauth_grant"]);

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
  "ferret_aaguid",
  "prf_salt_new",
  "sync_memory_new",
  "sync_memory_prune",
]);

/**
 * The AAGUID that Ferret writes into every passkey it makes
 * (`dc704a44-b994-410c-a689-ed8d71a84ac3`). A test compares it with
 * `ferret_aaguid()` of the build. Pass the AAGUID of a new registration to
 * `wrap_prf`, which refuses Ferret's own.
 */
export const FERRET_AAGUID = Object.freeze([
  0xdc, 0x70, 0x4a, 0x44, 0xb9, 0x94, 0x41, 0x0c, 0xa6, 0x89, 0xed, 0x8d, 0x71, 0xa8, 0x4a, 0xc3,
]);

/**
 * The value of `existing` in `passkey_create` that says "no passkeys are
 * stored". An empty array is refused instead: "none" has to be a decision.
 */
export const NO_EXISTING = "no_existing";

/**
 * The value of `stored_credential_ids` in `wrap_prf` that says "the vault has
 * no passkey items". An empty array is refused instead, as for `existing`.
 */
export const NO_STORED_PASSKEYS = "no_stored_passkeys";

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
  reveal_plain_export: [3],
};

/**
 * The arguments that must be a `Uint8Array` when they reach the worker: the
 * secrets above (passwords have been encoded from text by then) and the
 * 32-byte keys. The second item says whether the argument may be left out
 * (`undefined` or `null`); the third whether an all-zero array is refused.
 *
 * All-zero is refused for a key because an array that is all zero is what a
 * secret array looks like after it has been wiped: the client wipes the
 * arrays it is given, so a call that is repeated with the same variable would
 * otherwise go through with a key of zeros (a PRF wrap the server could open,
 * an export under a known key). That call fails with `input_all_zero`, the
 * code that the core gives for the same input, so the two layers agree. A
 * value that is not a `Uint8Array` at all is `invalid_input`, the JavaScript
 * side's code for a wrong type.
 */
export const BYTES_ARGS = {
  login_start: [[0, false, false]],
  register_start: [[0, false, false]],
  pin_unlock: [[0, false, false], [3, true, true]],
  unlock_prf: [[2, false, true]],
  wrap_pin: [[0, false, false], [2, true, true]],
  wrap_prf: [[2, false, true]],
  export_finish: [[0, false, true]],
  import_open: [[1, false, true]],
  argon2_export_key: [[0, false, false], [4, true, false]],
  check_master_password: [[0, false, false]],
  reveal_plain_export: [[3, true, true]],
  // The rollback memory is public data (item ids and revision numbers), so it
  // is typed but neither wiped nor refused when it looks empty.
  verify_checkpoint: [[3, false, false]],
  accept_rows: [[2, false, false]],
  verify_tombstone: [[0, false, false], [2, false, false]],
  rekey: [[2, false, false]],
  sync_memory_prune: [[0, false, false]],
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
  passkey_create_confirm: [[0, false]],
  passkey_create_abort: [[0, false]],
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

/** The length of every key in `BYTES_ARGS`. */
const KEY_LENGTH = 32;

/** The largest integer a JavaScript number holds exactly (2^53). */
const MAX_SAFE = 9_007_199_254_740_992;
/** Plausible ceilings of a time: seconds and milliseconds since 1970 (year ~3300). */
const MAX_SECONDS = 4e10;
const MAX_MILLIS = 4e13;

/**
 * The arguments that the Rust side takes as `f64` (revisions, sequence
 * numbers, times). `wasm-bindgen` coerces a JavaScript value first: `null`,
 * `""` and `false` become 0 and `"5"` becomes 5, so they are checked here.
 * The second item is the kind:
 *
 * * `"u64"`: a whole number from 0 to 2^53 (a revision, a sequence number, a
 *   generation);
 * * `"seconds"`: a finite number from 0 to 4e10, unix seconds (a fraction is
 *   allowed; it is dropped);
 * * `"millis"`: a finite number from 0 to 4e13, unix milliseconds.
 *
 * A time in the wrong unit (`Date.now()` where seconds are meant) is above the
 * ceiling and is `invalid_input`.
 */
export const F64_ARGS = {
  open_item: [[1, "u64"]],
  encrypt_item: [[1, "u64"], [4, "millis"]],
  make_tombstone: [[1, "u64"]],
  verify_tombstone: [[1, "u64"]],
  make_checkpoint: [[0, "u64"]],
  verify_checkpoint: [[2, "u64"]],
  accept_older_state: [[2, "u64"]],
  accept_rows: [[1, "u64"]],
  totp_code: [[1, "seconds"]],
  wrap_prf: [[4, "u64"]],
  passkey_create: [[1, "u64"], [7, "millis"]],
  reveal_plain_export: [[4, "millis"]],
  reauth_grant: [[1, "millis"]],
  export_begin: [[1, "millis"]],
  import_seal: [[2, "u64"]],
};

/** Throws `invalid_input` unless the `f64` arguments of a call are numbers of their kind. */
export function assertF64Args(method, args) {
  for (const [index, kind] of argsOf(F64_ARGS, method)) {
    const v = args[index];
    const ok =
      typeof v === "number" &&
      Number.isFinite(v) &&
      v >= 0 &&
      (kind === "u64"
        ? Number.isInteger(v) && v <= MAX_SAFE
        : v <= (kind === "seconds" ? MAX_SECONDS : MAX_MILLIS));
    if (!ok) throw new FerretError("invalid_input");
  }
}

/**
 * Throws `invalid_input` unless the byte arguments of a call (`BYTES_ARGS`) are
 * `Uint8Array`s and the keys among them are not all zero (`input_all_zero`,
 * the code that the core gives for the same input).
 */
export function assertBytesArgs(method, args) {
  for (const [index, optional, rejectZero] of argsOf(BYTES_ARGS, method)) {
    const v = args[index];
    if (optional && (v === undefined || v === null)) continue;
    if (!(v instanceof Uint8Array)) throw new FerretError("invalid_input");
    // A key is 32 bytes. Another length keeps the code the core gives for it
    // (`input_too_short`, `input_too_long`): the length is checked first, the
    // zeros only in an array of the right length.
    if (rejectZero && v.length === KEY_LENGTH && v.every((b) => b === 0)) throw new FerretError("input_all_zero");
  }
}

/** All the type checks of the arguments of one call. */
export function assertArgTypes(method, args) {
  assertBytesArgs(method, args);
  assertU32Args(method, args);
  assertF64Args(method, args);
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

/**
 * The code of a failure. A `TypeError` is a call with a wrong argument that
 * `wasm-bindgen` refused (an `undefined` where a string is needed, a wrong
 * object): that is `invalid_input`, and the session goes on. Anything else
 * without a code (a trap or abort in WASM, a `RangeError` of a heap that could
 * not grow, a value that is not an `Error`) is `internal`, which ends the
 * worker.
 */
function codeOf(e) {
  if (e && typeof e.code === "string" && /^[a-z0-9_]{1,64}$/.test(e.code)) return e.code;
  return e instanceof TypeError ? "invalid_input" : "internal";
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
      assertArgTypes(request.method, args);
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
      assertBytesArgs(request.method, args);
      const value = wasm[request.method](...args);
      return { reply: { id, ok: true, value }, transfer: transferables(value) };
    } catch (e) {
      return { reply: { id, ok: false, code: codeOf(e) }, transfer: [] };
    } finally {
      wipeSecretArgs(request?.method, args);
    }
  };
}
