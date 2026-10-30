// The Trusted Types policy `ferret`. The page's CSP has
// `require-trusted-types-for 'script'; trusted-types ferret`, and
// `new Worker(url)` is a sink: the only way to start a worker is a
// TrustedScriptURL from this policy, and the policy knows a fixed table of
// worker files. Browsers without Trusted Types get the same check and a plain
// string.

/** The workers of the first milestone; a later one adds an entry here. */
export const DEFAULT_WORKERS = Object.freeze({
  vault: "/js/vault.worker.mjs",
  job: "/js/job.worker.mjs",
});

/**
 * Returns the path when `input` names exactly one listed worker on this
 * origin, else throws.
 * @param {unknown} input
 * @param {ReadonlySet<string>} paths
 * @param {{ location: { href: string, origin: string } }} win
 */
function checkWorkerUrl(input, paths, win) {
  if (typeof input !== "string" || input.includes("..") || input.includes("\\") || input.includes("%")) {
    throw new TypeError("trusted types: worker URL refused");
  }
  const url = new URL(input, win.location.href);
  if (url.origin !== win.location.origin || url.search !== "" || url.hash !== "" || !paths.has(url.pathname)) {
    throw new TypeError("trusted types: worker URL refused");
  }
  return url.pathname;
}

/**
 * @param {any} [win]
 * @param {Record<string, string>} [allowed] worker name to path
 * @returns {{ available: boolean, workerUrl(name: string): string | object }}
 */
export function installTrustedTypes(win = window, allowed = DEFAULT_WORKERS) {
  const table = new Map(Object.entries(allowed));
  const paths = new Set(table.values());
  const lookup = (/** @type {string} */ name) => {
    const path = table.get(name);
    if (path === undefined) throw new TypeError(`trusted types: unknown worker ${String(name)}`);
    return path;
  };
  const factory = win.trustedTypes;
  if (!factory || typeof factory.createPolicy !== "function") {
    return {
      available: false,
      workerUrl: (name) => checkWorkerUrl(lookup(name), paths, win),
    };
  }
  const policy = factory.createPolicy("ferret", {
    createScriptURL: (/** @type {string} */ input) => checkWorkerUrl(input, paths, win),
  });
  return {
    available: true,
    workerUrl: (name) => policy.createScriptURL(lookup(name)),
  };
}
