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
// Encrypted export: `export_begin(rows, now_ms, kdf, token)` needs the same
// one-time token as the plaintext export (the file holds every secret of the
// vault, passkey keys and PRF seeds included); `now_ms` is the caller's clock
// and the time the token is checked against. Without a valid token it is
// `reauth_required`; `export_finish` needs none (only a draft that
// `export_begin` made can be finished).
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
// in, and `sync_memory_new()` always starts from none. `accept_older_state`,
// `accept_rows` and `sync_memory_prune` return `newSyncMemory` as well.
// `vault.accept_rows(rows, top_seq, memory)` takes the rows of an incremental
// `/changes` answer (the same row objects as `verify_checkpoint`; their tags
// and tombstones are checked) and raises the floors. A
// checkpoint, a top seq or a row below what the device has seen is
// `checkpoint_seq_below_remembered`, `checkpoint_top_seq_below_remembered` or
// `checkpoint_rev_below_remembered`, and the memory is left as it was. Only
// `vault.accept_older_state(checkpoint, rows, top_seq)`, called after the user
// has confirmed that the server was restored to an older state, lowers the
// floors; it returns a new record. `sync_memory_prune(memory, ids)` drops the
// entries of items that no longer exist, so a full record can take new items.
//
// Deleted items: `vault.verify_tombstone(itemId, rev, tomb)` resolves when the
// tombstone is valid for that item at that revision and rejects with
// `tombstone_invalid` otherwise (the item is then quarantined, its local copy
// is kept). An item id that is not 16 bytes is `invalid_input`.
//
// Folders: an item's folder names live in its encrypted body. `item_view`
// returns them as `folders: string[]` (`[]` for an item in no folder, also
// every item written before folders existed). In an `encrypt_item` draft,
// `folders` is the whole list: leave it out to keep the item's folders, pass
// `[]` to clear them. Each name is put in NFC and trimmed, 1 to 64 characters,
// with no control character, line or paragraph separator, bidirectional
// control, zero width space or byte order mark, at most 20 per item, no two
// equal when case is ignored (`folder_empty`, `folder_too_long`,
// `folder_bad_character`, `folder_too_many`, `folder_duplicate`). Group names
// across items with the same rule: the view's names are already in NFC, so
// compare them in lower case, character by character.
//
// Copying an item: `vault.copy_item(handle, newItemId, nowMs, device?)` seals a
// copy of the open item under `newItemId` (16 bytes of `crypto.getRandomValues`,
// not the item's own id and not the manifest id) and resolves
// `{ rev: 1, envelope, tag }`: the same body, a new item key. `device` is an
// optional public device name that the copy carries; without it the copy keeps
// the device of the original. The secrets are copied inside WASM and none of them reaches this
// side; the copy is not opened (call `open_item` for it). An item that holds a
// passkey is `invalid_state`, an item of a newer schema `read_only_schema`.
//
// Pages: `vault.match_page(pageUrl, handles)` resolves `[{ handle, how }]`, the
// open items among `handles` whose saved addresses match the page, with the
// best result per item (`how` is `"exact"`, `"host"` or `"domain"`). It reads the
// saved addresses only. A handle listed twice appears twice in the answer. A
// handle that is not open is `invalid_handle` for the whole call, and a list of
// more than 4096 handles is `invalid_input`. The
// matching rule is the core's alone: open the items for a match in batches
// (`open_item`), call `match_page`, and close each handle (`close_item`) right
// after. `page_origin(pageUrl)` resolves the origin text (`https://host`, the
// port only when it is not the default; `http` and IP hosts are accepted),
// `same_site(a, b)` a boolean (an address that is no web address is on no
// site) and `display_host(pageUrl)` `{ a_label, unicode }`: show the Unicode
// name, and the A-label next to it when they differ. An address that is no
// web address is `malformed_origin` for `page_origin` and `display_host`.
//
// Generator: `generate_password({ length, lower, upper, digits, symbols,
// min_each, avoid_ambiguous })` and `generate_passphrase({ words, separator,
// capitalize, number })` resolve `{ value, bits }`, a new password or
// passphrase (EFF large word list) from the core and its entropy estimate for
// display. They need no vault. Every key is required; options out of range are
// `generator_options`. Nothing outside the core makes a password.
//
// Comparing a field: `vault.item_field_equals(handle, fieldId, candidate)`
// resolves `true` when the first field of the open item with that id holds
// exactly the UTF-8 bytes of `candidate` (no normalisation), compared in
// constant time inside WASM, and `false` otherwise; the field is never sent
// back. `vault.items_with_field_value(handles, fieldId, candidate)` resolves
// the handles among `handles` for which it is `true`, in their order. A
// candidate over 4 KiB is `too_large`, one with a lone surrogate
// `invalid_input`. The binding wipes its copy of the candidate; the JavaScript
// string cannot be wiped.
//
// Earlier passwords: `item_view` has `password_history: [{ until }]`, newest
// first, at most five, the dates only; `vault.reveal_password_history(handle,
// index)` resolves one value, on the user's request. An edit draft with
// `keep_password_history: true` moves the password it replaces (the field
// with the id `password`) into the history inside WASM, dated `nowMs`; an
// unchanged password adds nothing, and the draft has no key for an earlier
// password.
//
// A new recovery key: `vault.renew_recovery(pinned, currentRecoveryWrap,
// manifestRow)` resolves `{ wrap, pk_r, manifest, pinned }`. The new key stays
// in the worker: show it with `vault.reveal_recovery_code()`, have it typed back
// with `vault.verify_recovery_setup(typed, wrap)` **before** the request is
// sent, sign the body with `vault.auth_sign("unlock-method.recovery.put", nonce,
// body)`, and store `pinned` once the server has accepted it. If the request is
// not sent, `vault.clear_setup_secrets()` drops the key.
//
// Import: `importPort()` returns a `MessagePort` to the vault worker for an
// import worker (transfer it there). It answers only
// `{ id, method: "encrypt_item", args: [itemId, 1, draft, NO_EXISTING, nowMs] }`
// with `{ id, ok: true, value: { rev, envelope, tag } }` or `{ id, ok: false,
// code }`: it seals new items and does nothing else, so the drafts of an import
// never pass through the page. It is closed (a last message `{ closed: true }`
// where the worker is still there to send it) when the vault is locked or
// another vault is opened, and with `lock()`. A port asked for while no vault
// is open is closed at once.
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
  IMPORT_PORT,
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

  /**
   * Hands the worker one end of a new channel as an import port and returns
   * the other end. No answer is awaited: a port the worker refuses is closed.
   */
  importPort() {
    const { port1, port2 } = new MessageChannel();
    try {
      this.start().postMessage({ id: this.nextId++, target: this.target, method: IMPORT_PORT, args: [] }, [port2]);
    } catch {
      port1.close();
      port2.close();
      throw new FerretError("worker_failed");
    }
    return port1;
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
    case "accept_rows":
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
  // The import ports handed out and not yet consumed. Ending the vault worker
  // closes their far end; a port that has not been transferred yet is closed
  // here as well (closing one that has been transferred does nothing). The
  // client holds them weakly, so a port the page has transferred and let go
  // of is not kept alive here; a port that closes leaves the set at once, and
  // `lock()` empties it.
  const importPorts = new Set();
  const dropPort = (ref) => importPorts.delete(ref);

  const lock = () => {
    for (const ref of [...importPorts]) {
      try {
        ref.deref()?.close();
      } catch {
        // Already closed or transferred.
      }
    }
    importPorts.clear();
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
     * A port to the vault worker that seals new items and nothing else, for an
     * import worker. See "Import" above.
     */
    importPort() {
      // Ports that have been collected are consumed: forget them.
      for (const ref of [...importPorts]) if (!ref.deref()) dropPort(ref);
      const port = vault.importPort();
      const ref = new WeakRef(port);
      importPorts.add(ref);
      port.addEventListener?.("close", () => dropPort(ref), { once: true });
      return port;
    },

    /** How many import ports the client still holds (for tests). */
    get openImportPorts() {
      return [...importPorts].filter((ref) => ref.deref()).length;
    },

    /**
     * Locks: the vault is wiped, the vault worker is ended (which frees its
     * heap) and a new one starts with the next call.
     */
    lock,
  };
}
