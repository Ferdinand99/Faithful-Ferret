// Helpers for the tests of the import flow and page: a signed-in world whose session can start an import worker, the real
// worker body run in this process behind the worker interface, a port that plays the vault worker, an engine that records
// what it is given, and a fake core with the export-file calls. Every value here is a test value; none is a real key,
// password or item.
import { hex16 } from "../../src/b64.mjs";
import { createHandler } from "../../src/workers/import.worker.mjs";
import { coded } from "./accountHelpers.mjs";
import { answer, filled, GRANT, PASSWORD, signedInWorld } from "./securityHelpers.mjs";
import { sealedValue, vaultPort } from "./importHelpers.mjs";

export { answer, coded, filled, PASSWORD };

export const EXPORT_PASSWORD = "export-pass-for-unit-tests-1";
export const WINDOW = "ab".repeat(16);
export const NOW = 1_700_000_000_000;

/**
 * Makes workers that run the real worker body in this process, behind the interface of a `Worker`. `mode`: `real` answers as the
 * worker does, `silent` never answers (the vault worker died without a word), `error` fails to start, `garbage` answers
 * something that is not an answer.
 * @param {{ mode?: "real" | "silent" | "error" | "garbage", garbage?: unknown }} [options]
 */
export function workerFactory({ mode = "real", garbage = { id: 1, ok: true, sealed: "not a list", report: {} } } = {}) {
  /** @type {any[]} */
  const made = [];
  const create = () => {
    const handle = createHandler({ now: () => NOW });
    const worker = {
      terminated: false,
      onmessage: /** @type {any} */ (null),
      onerror: /** @type {any} */ (null),
      onmessageerror: /** @type {any} */ (null),
      posted: /** @type {Array<{ message: any, transfer: any }>} */ ([]),
      postMessage(/** @type {any} */ message, /** @type {any} */ transfer) {
        worker.posted.push({ message, transfer });
        if (mode === "silent") return;
        if (mode === "error") {
          setImmediate(() => worker.onerror?.(new Error("worker failed to start")));
          return;
        }
        setImmediate(async () => {
          const data = mode === "garbage" ? garbage : await handle(message);
          if (!worker.terminated) worker.onmessage?.({ data });
        });
      },
      terminate() {
        worker.terminated = true;
      },
    };
    made.push(worker);
    return worker;
  };
  return { create, made };
}

/**
 * A port that stands in for the vault worker and seals with a fake client of the sync tests, so that the sealed items open there.
 * @param {{ vault: { encrypt_item(id: Uint8Array, rev: number, draft: any, existing: any): Promise<any> } }} client
 */
export function sealingPort(client) {
  const port = vaultPort({ reply: () => undefined });
  const post = port.postMessage;
  port.postMessage = (/** @type {any} */ message) => {
    post(message);
    const [id, rev, draft] = message.args;
    void client.vault.encrypt_item(id, rev, draft, undefined).then((sealed) => {
      port.onmessage?.({ data: { id: message.id, ok: true, value: sealed } });
    });
  };
  return port;
}

/**
 * An engine that records what it is given. `used` is how many items the vault shows; `status` is what `importStatus` says.
 * With `log`, every call is also put in that list as `engine.<name>`, so a test can see its place among the requests.
 * @param {{ used?: number, status?: Partial<{ queued: number, refused: number, sent: number, total: number, failed: number, windowClosed: boolean }>, failImport?: any, log?: string[] }} [options]
 */
export function fakeImportEngine({ used = 0, status = {}, failImport = null, log = [] } = {}) {
  /** @type {Record<string, Set<(payload: any) => void>>} */
  const listeners = { import: new Set(), import_window_closed: new Set() };
  const engine = {
    used,
    calls: /** @type {string[]} */ ([]),
    imported: /** @type {Array<{ items: any[], windowId: string }>} */ ([]),
    resumed: /** @type {string[]} */ ([]),
    status: { queued: 0, refused: 0, sent: 0, total: 0, failed: 0, windowClosed: false, ...status },
    list: () => Array.from({ length: engine.used }, (_, n) => ({ id: n })),
    importStatus: () => engine.status,
    async importItems(/** @type {any[]} */ items, /** @type {{ windowId: string }} */ { windowId }) {
      engine.calls.push("importItems");
      log.push("engine.importItems");
      if (failImport) throw failImport;
      engine.imported.push({ items, windowId });
      return { queued: items.length };
    },
    async resumeImport(/** @type {{ windowId: string }} */ { windowId }) {
      engine.calls.push("resumeImport");
      log.push("engine.resumeImport");
      engine.resumed.push(windowId);
    },
    on(/** @type {string} */ event, /** @type {(payload: any) => void} */ fn) {
      listeners[event].add(fn);
      return () => void listeners[event].delete(fn);
    },
    emit(/** @type {string} */ event, /** @type {any} */ payload) {
      for (const fn of [...listeners[event]]) fn(payload);
    },
    listeners,
  };
  return engine;
}

/**
 * The calls the core makes for an export file, over a fake that remembers what it was given. `items` is how many the file holds;
 * the key made from `EXPORT_PASSWORD` is the one that opens it.
 * @param {{ items?: number, createdAt?: number }} [options]
 */
export function fakeExportFileCore({ items = 3, createdAt = NOW } = {}) {
  const key = filled(32, 9);
  const core = {
    headers: /** @type {number[]} */ ([]),
    opens: /** @type {Array<{ file: Uint8Array, key: Uint8Array }>} */ ([]),
    seals: /** @type {Array<{ index: number, id: Uint8Array, rev: number }>} */ ([]),
    closed: 0,
    jobs: /** @type {any[]} */ ([]),
    handlers: {
      import_header: (/** @type {Uint8Array} */ file) => {
        core.headers.push(file.length);
        return { salt: filled(16, 4), kdf: { m_kib: 262_144, t: 3, p: 1 }, created_at: createdAt };
      },
      import_open: (/** @type {Uint8Array} */ file, /** @type {Uint8Array} */ opened) => {
        core.opens.push({ file: file.slice(), key: opened.slice() });
        if (!opened.every((n, i) => n === key[i])) throw coded("decrypt");
        return { count: items, created_at: createdAt };
      },
      import_seal: (/** @type {number} */ index, /** @type {Uint8Array} */ id, /** @type {number} */ rev) => {
        core.seals.push({ index, id: id.slice(), rev });
        return { rev, envelope: new Uint8Array([0xe1, index & 0xff, 1, 2, 3]), tag: filled(32, (index & 0x7f) + 1) };
      },
      import_close: () => {
        core.closed += 1;
      },
    },
    job: {
      async argon2_export_key(/** @type {string} */ password, /** @type {Uint8Array} */ salt, /** @type {any} */ kdf, /** @type {string} */ mode, /** @type {string} */ masterPassword) {
        core.jobs.push({ password, salt, kdf, mode, masterPassword });
        return password === EXPORT_PASSWORD ? new Uint8Array(key) : filled(32, 1);
      },
    },
  };
  return core;
}

/**
 * A signed-in world whose session starts the real import worker body behind a fake worker, whose server opens import windows, and
 * whose client has a vault port and (with `file`) the calls the core makes for an export file.
 * @param {{
 *   mode?: "real" | "silent" | "error" | "garbage", garbage?: unknown,
 *   windowFor?: (body: { ops: number }, count: number) => Record<string, any> | Response,
 *   handlers?: Record<string, any>, overrides?: Record<string, any>, skBit?: boolean, file?: ReturnType<typeof fakeExportFileCore>,
 *   port?: (client: any) => any,
 * }} [options]
 */
export async function importWorld({ mode = "real", garbage, windowFor, handlers = {}, overrides = {}, skBit = true, file, port } = {}) {
  const workers = workerFactory(garbage === undefined ? { mode } : { mode, garbage });
  /** @type {Array<{ ops: number }>} */
  const windows = [];
  const fileCore = file ?? null;
  const world = await signedInWorld({
    skBit,
    createImportWorker: workers.create,
    handlers: { reauth_grant: () => new Uint8Array(GRANT), ...(fileCore?.handlers ?? {}), ...handlers },
    overrides: {
      "POST /api/sync/import": (/** @type {any} */ body) => {
        windows.push(body);
        const out = windowFor ? windowFor(body, windows.length) : { window_id: WINDOW, ops: body.ops, expires_in: 1800 };
        return out instanceof Response ? out : answer(200, out);
      },
      ...overrides,
    },
  });
  if (fileCore) world.client.job = fileCore.job;
  /** @type {any[]} */
  const ports = [];
  world.client.importPort = () => {
    const made = port ? port(world.client) : vaultPort({ reply: (/** @type {any} */ message) => ({ id: message.id, ok: true, value: sealedValue(message.id) }) });
    ports.push(made);
    return made;
  };
  return { ...world, workers, windows, ports, file: fileCore };
}

/** The 16-byte ids of items as the page passes them on, as hex. @param {Array<{ id: Uint8Array }>} sealed */
export const idsOf = (sealed) => sealed.map((item) => hex16.encode(item.id));
