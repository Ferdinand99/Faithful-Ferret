// A hash router: `#/items/abc` is the path `/items/abc`. Route patterns are
// literal segments and `:name` parameters. A parameter value is only ever a
// string that is matched against a short allow-list of characters; it is
// never evaluated, never put into markup, and never decides which code runs.

const SEGMENT = /^[A-Za-z0-9_.-]{1,128}$/;
const PARAM_NAME = /^:[a-z][A-Za-z0-9]*$/;
const RAW_PATH = /^\/(?:[A-Za-z0-9_.~%:-]+(?:\/[A-Za-z0-9_.~%:-]+)*)?$/;

/**
 * @typedef {{ path: string }} PathRoute
 * @typedef {{ route: any, params: Record<string, string>, path: string, found: boolean }} Match
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
 * @returns {{ go(path: string): void, start(): void, current(): string }}
 */
export function createRouter({ routes, notFound, onChange, win = globalThis }) {
  let path = "/";
  let started = false;

  function handle() {
    const parsed = parseHash(win.location.hash);
    const hit = parsed === null ? null : matchRoute(routes, parsed);
    path = parsed ?? "/";
    if (hit) onChange({ route: hit.route, params: hit.params, path, found: true });
    else onChange({ route: notFound, params: Object.create(null), path, found: false });
  }

  return {
    go(target) {
      if (typeof target !== "string" || !isPlainPath(target)) {
        throw new TypeError("router: not a path");
      }
      const hash = `#${target}`;
      if (win.location.hash === hash) {
        if (started) handle();
        return;
      }
      win.location.hash = hash;
    },
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
