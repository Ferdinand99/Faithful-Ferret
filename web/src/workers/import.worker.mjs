// The import worker. An import file is read here and nowhere else on the page: the main thread
// gives the worker the File and a port to the vault worker, the worker reads it, makes the drafts
// and sends them over the port, so no plain text of an import passes through the main thread.
//
// This is the place of the worker and nothing more: it answers every request with `unsupported`.
// The reader of the import formats comes with the import task, which replaces this file. The
// build starts it as /js/import.worker.mjs (a one-line module that loads this file), which is
// the address the page's Trusted Types policy lists (src/tt.mjs).

/**
 * The answer to a request: the id of the request, if it had one, and the code `unsupported`.
 * @param {unknown} message
 * @returns {{ id: number | string | null, ok: false, error: "unsupported" }}
 */
export function answer(message) {
  const id = message !== null && typeof message === "object" ? /** @type {{ id?: unknown }} */ (message).id : undefined;
  return { id: typeof id === "number" || typeof id === "string" ? id : null, ok: false, error: "unsupported" };
}

// Only inside a worker: importing the module anywhere else (the tests) starts nothing.
const scope = /** @type {any} */ (globalThis);
if (typeof scope.WorkerGlobalScope === "function" && scope instanceof scope.WorkerGlobalScope) {
  scope.onmessage = (/** @type {MessageEvent} */ event) => {
    scope.postMessage(answer(event.data));
  };
}
