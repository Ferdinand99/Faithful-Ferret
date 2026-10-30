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
// * `lock()` ends the vault worker and starts a new one on the next call: that
//   is what frees the heap, which stays at its high-water mark until then.
// * A secret `Uint8Array` argument is copied for the worker, handed over with
//   `transfer`, and `fill(0)`-ed on this side; the worker wipes its copy after
//   the call. A password given as a string is encoded after a well-formedness
//   check: a lone surrogate is `invalid_input`, never a silent U+FFFD (U9).
// * A failure is a `FerretError` with a stable `code` (see `error.rs`), plus
//   `worker_failed` when a worker dies and `internal` for anything else.
// * An out-of-memory in Argon2id (`kdf_out_of_memory`) and an `internal` error
//   (a trap or abort in WASM, or anything that is not a code) end the worker
//   that reported it: a heap that failed to grow, or an instance that
//   aborted, is not reused. The vault is gone with it; the next call finds a
//   locked vault (`vault_locked`).
// * `ferret.vault.lock()` is the same as `ferret.lock()`: the worker is ended.
// * The result of `ferret.job.argon2_export_key` is `K_exp`. The caller passes
//   it on to `export_finish` or `import_open`, which wipe it, or `fill(0)`s it.

import {
  FerretError,
  SECRET_ARGS,
  TEXT_ARGS,
  argsOf,
  assertWellFormed,
  encodeSecretText,
} from "./protocol.mjs";

export { FerretError } from "./protocol.mjs";

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
      const copy = arg.slice();
      if (secretArgs.includes(i)) wipe.push(arg);
      return copy;
    }
    return arg;
  });
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
 * Creates the client. `createVaultWorker` and `createJobWorker` make a worker
 * (anything with `postMessage`, `terminate` and `onmessage`); the defaults make
 * the module workers next to this file.
 */
export function createClient(options = {}) {
  const { createVaultWorker, createJobWorker } = { ...defaultWorkers(), ...options };
  const onFatal = (channel) => channel.fail("worker_failed");
  const vault = new WorkerChannel("vault", createVaultWorker, onFatal);

  const lock = async () => {
    if (vault.worker) {
      try {
        await vault.call("lock", []);
      } catch {
        // The worker is ended either way.
      }
    }
    vault.fail("locked");
  };

  const vaultProxy = new Proxy(
    {},
    {
      get: (_, method) => {
        if (typeof method !== "string") return undefined;
        // Locking must end the worker, never only drop the vault in it.
        if (method === "lock") return lock;
        return (...args) => vault.call(method, args);
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
                try {
                  return await channel.call(method, args);
                } finally {
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
