// The page's side of the two workers, as a Promise API:
//
//   const ferret = createClient();
//   const ke1 = await ferret.vault.login_start(password, skCode);
//   ...
//   const key = await ferret.job.argon2_export_key(pw, salt, kdf, "open");
//   await ferret.lock();
//
// * Two module workers: `vault` (long-lived; it holds the keys) and `job`
//   (short-lived; Argon2id of an export or an import file only). The job
//   worker is ended after every call, so its large heap is freed.
// * `lock()` ends the vault worker at once and starts a new one on the next
//   call: that releases the heap, which stays at its high-water mark until
//   then. It never waits for the worker, so it works while a long Argon2id or
//   an import is running. Every call that is waiting is rejected with
//   `locked`, and the job workers that are running are ended with it. Nothing
//   is asked of the worker first: a wipe that has to wait behind a running
//   call would be exactly the delay a lock must not have. Ending a worker
//   releases its memory to the browser; it does not overwrite it by hand.
// * A secret `Uint8Array` argument is copied for the worker, handed over with
//   `transfer`, and `fill(0)`-ed on this side; the worker wipes its copy after
//   the call. **A secret array can therefore be used once.** The array that
//   the caller keeps is all zero afterwards, and a second call with it is
//   `input_all_zero`, never a call with a key of zeros (the code is the one
//   the core gives for the same input; a value that is not a `Uint8Array` is
//   `invalid_input`, the JavaScript side's code for a wrong type). Arguments
//   that are keys
//   (PRF output, `K_exp`, the device PIN key, the export token) must be a
//   `Uint8Array` that is not all zero. Get a new one for every call, or pass
//   `.slice()`. A password given as a string is encoded after a
//   well-formedness check: a lone surrogate is `invalid_input`, never a
//   silent U+FFFD.
// * Numbers are checked before they are sent: handles and indexes are whole
//   numbers up to 2^32 - 1; revisions and sequence numbers whole numbers up to
//   2^53; times are milliseconds (below 4e13) or, for `totp_code`, seconds
//   (below 4e10). A wrong type or unit is `invalid_input`.
// * A failure is a `FerretError` with a stable `code` (see `error.rs`), plus
//   `worker_failed` when a worker dies and `internal` for anything else.
//   `invalid_input` (a call with a wrong argument, also one that
//   `wasm-bindgen` refuses with a `TypeError`) does not end the session.
// * An out-of-memory in Argon2id (`kdf_out_of_memory`) and an `internal` error
//   (a trap or abort in WASM, or anything that is not a code) end the worker
//   that reported it: a heap that failed to grow, or an instance that
//   aborted, is not reused. The vault is gone with it; the next call finds a
//   locked vault (`vault_locked`).
// * `ferret.vault.lock()` is the same as `ferret.lock()`: the worker is ended.
// * The result of `ferret.job.argon2_export_key` is `K_exp`. The caller passes
//   it on to `export_finish` or `import_open`, which wipe it, or `fill(0)`s it.
//
// Passkeys (the vault methods `passkey_create`, `passkey_get`):
//
// * `passkey_create` returns `{ item, item_id, pending }` and does not answer
//   the page. Upload `item`; when the server has accepted it, call
//   `passkey_create_confirm(pending)`, which returns `{ response, handle }`.
//   If the upload fails, call `passkey_create_abort(pending)`.
// * Its `existing` argument is `NO_EXISTING` (exported here) or a non-empty
//   array of `{ rp_id, id }` built from `item_view`'s `passkey.rp_id` and
//   `passkey.cred_id`; an empty array is `invalid_input`.
// * PRF results depend on user verification (two seeds, spec § 9.3): the same
//   salt gives different outputs with and without it.
//
// Plaintext export: `reveal_plain_export(rows, format, include_passkeys,
// token, now_ms)` needs a one-time token from
// `ferret.vault.reauth_grant(wrap, now_ms)` made right after a fresh
// `login_start`/`login_finish` with the master password (the same fresh
// sign-in a rekey needs). `now_ms` is the caller's clock in milliseconds. The
// token is good for 5 minutes from the grant and for one attempt: a missing,
// wrong, used, replaced or expired token is `reauth_required`, and so is a
// `now_ms` that is earlier than the time of the grant (the time cannot go
// backwards).
//
// Registering a passkey as an unlock method: `wrap_prf(credential_id, salt,
// prf_output, method_id, generation, aaguid, stored_credential_ids)` takes the
// AAGUID of the registration and the `cred_id` of every passkey item in the
// vault, and refuses (`invalid_state`) Ferret's own authenticator
// (`FERRET_AAGUID`) and any credential that Ferret stores: such a method could
// never open the vault it lives in. The AAGUID is the 16 bytes at offset 37 of
// the authenticator data that the client parsed from the registration (it is
// the client's claim: the binding cannot see the attestation). Say there are no
// stored passkeys with `NO_STORED_PASSKEYS` (exported here); an empty array is
// `invalid_input`, like `existing` of `passkey_create`.
//
// Error codes at the two layers: the core's codes are in `vectors/ERRORS.md`.
// The client adds `invalid_input` for a call whose arguments have the wrong
// type, shape or range, `worker_failed`, `locked` and `internal`. An all-zero
// key has one code at both layers, `input_all_zero` (the client checks it
// before it sends the call, the core checks it again). A salt of zeros is
// `input_all_zero` too.
//
// Passkey PRF salts: `prf_salt_new()` returns the 32 random bytes of a new
// registration. `wrap_prf` and `unlock_prf` refuse a salt of zeros.
//
// Rollback memory (`SyncMemory`): the client keeps it as bytes, in its own
// storage. `sync_memory_new()` makes an empty record for a device that has
// seen nothing of this vault. `vault.verify_checkpoint(checkpoint, rows,
// top_seq, memory)` and `vault.rekey(input, pinned, memory)` take the stored
// bytes as a required argument. The client returns the updated bytes as the
// field `newSyncMemory` (`verify_checkpoint` returns `{ newSyncMemory }`,
// `rekey` its plan with the field added): **store it, in place of the old
// bytes, before using the result** (before the rekey is uploaded, before the
// verified state is acted on). A caller that ignores it keeps the old floors
// and gets no progress; the memory is only as good as the storage it is kept
// in, and `sync_memory_new()` always starts from none. `accept_older_state`
// and `sync_memory_prune` return `newSyncMemory` as well. A
// checkpoint, a top seq or a row below what the device has seen is
// `checkpoint_seq_below_remembered`, `checkpoint_top_seq_below_remembered` or
// `checkpoint_rev_below_remembered`, and the memory is left as it was. Only
// `vault.accept_older_state(checkpoint, rows, top_seq)`, called after the user
// has confirmed that the server was restored to an older state, lowers the
// floors; it returns a new record. `sync_memory_prune(memory, ids)` drops the
// entries of items that no longer exist, so a full record can take new items.
//
// Unlock methods: `vault.check_server_methods(manifestRow, serverList)`
// compares the server's list with the manifest (`method_list_unknown`,
// `method_list_changed`, `method_list_missing`). `vault.manifest_add_method(
// currentRow, wrap)` and `vault.manifest_remove_method(currentRow, methodId)`
// return `{ op, sealed, body, pk_a }`: upload `sealed` and `body` and sign the
// request with `vault.auth_sign(op, nonce, body)`. Removing the last password
// or recovery method is `input_last_method`.

import {
  FerretError,
  SECRET_ARGS,
  TEXT_ARGS,
  argsOf,
  assertArgTypes,
  assertWellFormed,
  encodeSecretText,
} from "./protocol.mjs";

export { FERRET_AAGUID, FerretError, NO_EXISTING, NO_STORED_PASSKEYS } from "./protocol.mjs";

function defaultWorkers() {
  return {
    createVaultWorker: () =>
      new Worker(new URL("./vault.worker.mjs", import.meta.url), { type: "module" }),
    createJobWorker: () =>
      new Worker(new URL("./job.worker.mjs", import.meta.url), { type: "module" }),
  };
}

/** Copies the arguments for the worker: strings that are passwords become bytes. */
function prepare(method, args) {
  const textArgs = argsOf(TEXT_ARGS, method);
  const secretArgs = argsOf(SECRET_ARGS, method);
  const wipe = [];
  const out = args.map((arg, i) => {
    if (textArgs.includes(i) && typeof arg === "string") {
      return encodeSecretText(arg);
    }
    assertWellFormed(arg);
    if (arg instanceof Uint8Array) {
      // A real copy with its own buffer (`Buffer#slice` would only be a view).
      const copy = new Uint8Array(arg);
      if (secretArgs.includes(i)) wipe.push(arg);
      return copy;
    }
    return arg;
  });
  // Types and units of the numbers, `Uint8Array` for the secrets, and no key
  // that is all zero (a secret array that was wiped by an earlier call).
  assertArgTypes(method, out);
  const transfer = out.filter((a) => a instanceof Uint8Array).map((a) => a.buffer);
  return { out, transfer, wipe };
}

class WorkerChannel {
  constructor(target, create, onFatal) {
    this.target = target;
    this.create = create;
    this.onFatal = onFatal;
    this.worker = null;
    this.pending = new Map();
    this.nextId = 1;
  }

  start() {
    if (this.worker) return this.worker;
    const worker = this.create();
    worker.onmessage = (event) => {
      const reply = event.data;
      const waiter = this.pending.get(reply?.id);
      if (!waiter) return;
      this.pending.delete(reply.id);
      if (reply.ok) {
        waiter.resolve(reply.value);
      } else {
        waiter.reject(new FerretError(reply.code));
        if (reply.code === "kdf_out_of_memory" || reply.code === "internal") this.onFatal(this);
      }
    };
    const failed = () => this.fail("worker_failed");
    worker.onerror = failed;
    worker.onmessageerror = failed;
    this.worker = worker;
    return worker;
  }

  /** Ends the worker and rejects every call that is waiting for it. */
  fail(code) {
    const waiting = [...this.pending.values()];
    this.pending.clear();
    this.end();
    for (const w of waiting) w.reject(new FerretError(code));
  }

  end() {
    if (this.worker) {
      this.worker.onmessage = null;
      this.worker.onerror = null;
      this.worker.onmessageerror = null;
      this.worker.terminate();
      this.worker = null;
    }
  }

  call(method, args) {
    let prepared;
    try {
      prepared = prepare(method, args);
    } catch (e) {
      // Nothing is sent; the secrets the caller gave are wiped all the same.
      for (const i of argsOf(SECRET_ARGS, method)) {
        if (args[i] instanceof Uint8Array) args[i].fill(0);
      }
      return Promise.reject(e);
    }
    const { out, transfer, wipe } = prepared;
    return new Promise((resolve, reject) => {
      const id = this.nextId++;
      this.pending.set(id, { resolve, reject });
      try {
        this.start().postMessage({ id, target: this.target, method, args: out }, transfer);
      } catch {
        this.pending.delete(id);
        reject(new FerretError("worker_failed"));
      } finally {
        for (const a of wipe) a.fill(0);
      }
    });
  }
}

/**
 * The calls that return the rollback memory give it as `newSyncMemory`: the
 * caller must store it, in place of the bytes it passed in, before it uses
 * the result (before it uploads a rekey, or acts on a verified state). A
 * caller that keeps the old bytes only loses the progress of the floors; it
 * does not get a lower floor, but a fresh `sync_memory_new()` always starts
 * from none, so the memory is only as good as the storage it is kept in.
 */
function shapeResult(method, value) {
  switch (method) {
    case "verify_checkpoint":
    case "accept_older_state":
      return { newSyncMemory: value };
    case "sync_memory_prune":
      return { newSyncMemory: value.sync_memory, dropped: value.dropped };
    case "rekey": {
      const { sync_memory: newSyncMemory, ...plan } = value;
      return { ...plan, newSyncMemory };
    }
    default:
      return value;
  }
}

/**
 * Creates the client. `createVaultWorker` and `createJobWorker` make a worker
 * (anything with `postMessage`, `terminate` and `onmessage`); the defaults make
 * the module workers next to this file.
 */
export function createClient(options = {}) {
  const { createVaultWorker, createJobWorker } = { ...defaultWorkers(), ...options };
  const onFatal = (channel) => channel.fail("worker_failed");
  const vault = new WorkerChannel("vault", createVaultWorker, onFatal);

  // The job workers that are running (one per call).
  const jobChannels = new Set();

  // Ends the worker first and does not wait for it: a call that is still
  // running (a sign-in with Argon2id at 512 MiB, an import) is cut off, and so
  // is a worker that is stuck or still loading. The job workers that are
  // running are ended too, so an export key that is being made is not
  // returned after the lock. Terminating releases the memory of the workers
  // to the browser; it does not overwrite it, which the browser and the
  // operating system do when they hand the pages to someone else. The calls
  // that were waiting are rejected with `locked`.
  const lock = () => {
    vault.fail("locked");
    for (const channel of [...jobChannels]) channel.fail("locked");
    jobChannels.clear();
    return Promise.resolve();
  };

  const vaultProxy = new Proxy(
    {},
    {
      get: (_, method) => {
        if (typeof method !== "string") return undefined;
        // Locking must end the worker, never only drop the vault in it.
        if (method === "lock") return lock;
        return (...args) => vault.call(method, args).then((value) => shapeResult(method, value));
      },
    },
  );

  return {
    /** Every method of the `Vault`, the `UnlockJob` and the stateless functions. */
    vault: vaultProxy,

    /** The job worker: one call per worker, ended afterwards. */
    job: new Proxy(
      {},
      {
        get: (_, method) =>
          typeof method === "string"
            ? async (...args) => {
                const channel = new WorkerChannel("job", createJobWorker, (c) => c.fail("worker_failed"));
                jobChannels.add(channel);
                try {
                  return await channel.call(method, args);
                } finally {
                  jobChannels.delete(channel);
                  channel.end();
                }
              }
            : undefined,
      },
    ),

    /**
     * Locks: the vault is wiped, the vault worker is ended (which frees its
     * heap) and a new one starts with the next call.
     */
    lock,
  };
}
