// A hash router: `#/items/abc` is the path `/items/abc`. Route patterns are
// literal segments and `:name` parameters. A parameter value is only ever a
// string that is matched against a short allow-list of characters; it is
// never evaluated, never put into markup, and never decides which code runs.

const SEGMENT = /^[A-Za-z0-9_.-]{1,128}$/;
const PARAM_NAME = /^:[a-z][A-Za-z0-9]*$/;
const RAW_PATH = /^\/(?:[A-Za-z0-9_.~%:-]+(?:\/[A-Za-z0-9_.~%:-]+)*)?$/;

// The part after `?`: a short run of plain characters, read by the one screen that asks for it (the list keeps its
// filters there). It is never evaluated and never decides which route runs.
const QUERY = /^[A-Za-z0-9_.~%:,=&-]{0,256}$/;

/**
 * @typedef {{ path: string }} PathRoute
 * @typedef {{ route: any, params: Record<string, string>, path: string, query: string, found: boolean }} Match
 */

/**
 * `#/a/b` gives `/a/b`; an empty hash gives `/`. Anything that is not a plain
 * path (a query, a double slash, odd characters) gives null.
 * @param {string} hash
 * @returns {string | null}
 */
export function parseHash(hash) {
  if (typeof hash !== "string") return null;
  const raw = hash.startsWith("#") ? hash.slice(1) : hash;
  if (raw === "") return "/";
  return RAW_PATH.test(raw) ? raw : null;
}

/**
 * `#/items?type=login` gives the path `/items` and the query `type=login`. The path follows the rules of
 * `parseHash`; the query is a short run of plain characters. Anything else gives null.
 * @param {string} hash
 * @returns {{ path: string, query: string } | null}
 */
export function parseLocation(hash) {
  if (typeof hash !== "string") return null;
  const raw = hash.startsWith("#") ? hash.slice(1) : hash;
  const cut = raw.indexOf("?");
  const pathPart = cut < 0 ? raw : raw.slice(0, cut);
  const query = cut < 0 ? "" : raw.slice(cut + 1);
  const path = parseHash(pathPart);
  return path !== null && QUERY.test(query) ? { path, query } : null;
}

/** @param {string} segment @returns {string | null} */
function decodeSegment(segment) {
  let value;
  try {
    value = decodeURIComponent(segment);
  } catch {
    return null;
  }
  return SEGMENT.test(value) && value !== "." && value !== ".." ? value : null;
}

/**
 * @template {PathRoute} R
 * @param {readonly R[]} routes
 * @param {string} path
 * @returns {{ route: R, params: Record<string, string> } | null}
 */
export function matchRoute(routes, path) {
  if (!RAW_PATH.test(path)) return null;
  const parts = path === "/" ? [] : path.slice(1).split("/");
  const decoded = parts.map(decodeSegment);
  if (decoded.some((v) => v === null)) return null;
  // Fewer parameters win, so `/items/new` beats `/items/:id`.
  const ordered = routes
    .map((route, index) => ({ route, index, patterns: route.path === "/" ? [] : route.path.slice(1).split("/") }))
    .sort((a, b) => countParams(a.patterns) - countParams(b.patterns) || a.index - b.index);
  for (const { route, patterns } of ordered) {
    if (patterns.length !== parts.length) continue;
    /** @type {Record<string, string>} */
    const params = Object.create(null);
    let ok = true;
    for (let i = 0; i < patterns.length && ok; i++) {
      const pattern = patterns[i];
      if (pattern.startsWith(":")) {
        if (!PARAM_NAME.test(pattern)) ok = false;
        else params[pattern.slice(1)] = /** @type {string} */ (decoded[i]);
      } else if (pattern !== decoded[i]) {
        ok = false;
      }
    }
    if (ok) return { route, params };
  }
  return null;
}

/** A path whose every segment decodes to a plain value. @param {string} path */
function isPlainPath(path) {
  return RAW_PATH.test(path) && (path === "/" || path.slice(1).split("/").every((s) => decodeSegment(s) !== null));
}

/** @param {string[]} patterns */
function countParams(patterns) {
  return patterns.filter((p) => p.startsWith(":")).length;
}

/**
 * @param {{ routes: readonly any[], notFound: any, onChange: (match: Match) => void, win?: any }} options
 * @returns {{
 *   go(path: string): void, replace(path: string): void, start(): void, current(): string, query(): string,
 *   watchQuery(fn: (query: string) => void): () => void,
 * }}
 */
export function createRouter({ routes, notFound, onChange, win = globalThis }) {
  let path = "/";
  let query = "";
  let started = false;
  /** Screens that follow the query of their own address: only they are told when the query alone changes. @type {Set<(query: string) => void>} */
  const watchers = new Set();

  /** @param {boolean} [force] a `go` to the address that is shown builds the screen again, whatever follows its query */
  function handle(force = false) {
    const parsed = parseLocation(win.location.hash);
    const hit = parsed === null ? null : matchRoute(routes, parsed.path);
    const nextPath = parsed?.path ?? "/";
    const nextQuery = parsed?.query ?? "";
    // The same screen with another query (a filter was changed, or back/forward moved between two): the screen that
    // follows its query is told and is not built again; any other screen is built as it is for a new address.
    if (!force && started && hit && nextPath === path && watchers.size > 0) {
      const changed = nextQuery !== query;
      query = nextQuery;
      if (changed) for (const fn of [...watchers]) fn(query);
      // A watcher that found its screen gone has let go: then the screen is built (a lock and an unlock leave nothing to follow the query).
      if (watchers.size > 0) return;
    }
    path = nextPath;
    query = nextQuery;
    watchers.clear();
    if (hit) onChange({ route: hit.route, params: hit.params, path, query, found: true });
    else onChange({ route: notFound, params: Object.create(null), path, query, found: false });
  }

  /** @param {unknown} target @returns {string} `#/path?query` */
  function hashOf(target) {
    if (typeof target !== "string") throw new TypeError("router: not a path");
    const cut = target.indexOf("?");
    const pathPart = cut < 0 ? target : target.slice(0, cut);
    const queryPart = cut < 0 ? "" : target.slice(cut + 1);
    if (!isPlainPath(pathPart) || !QUERY.test(queryPart)) throw new TypeError("router: not a path");
    return `#${target}`;
  }

  return {
    go(target) {
      const hash = hashOf(target);
      if (win.location.hash === hash) {
        if (started) handle(true);
        return;
      }
      win.location.hash = hash;
    },
    /** Like `go`, but the address it leaves does not stay in the history (a redirect). @param {string} target */
    replace(target) {
      const hash = hashOf(target);
      if (win.location.hash === hash) {
        if (started) handle(true);
        return;
      }
      if (typeof win.location.replace === "function") win.location.replace(hash);
      else win.location.hash = hash;
    },
    /**
     * Follows the query of the screen that is shown: `fn` is called when only the query changes, and the screen is
     * not built again. The watchers are dropped when another screen is built.
     * @param {(query: string) => void} fn
     */
    watchQuery(fn) {
      watchers.add(fn);
      return () => void watchers.delete(fn);
    },
    query: () => query,
    start() {
      if (started) return;
      started = true;
      win.addEventListener("hashchange", handle);
      handle();
    },
    current() {
      return path;
    },
  };
}
