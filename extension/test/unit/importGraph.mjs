// The import graph of a built package (a Map of path -> bytes), read with the
// reader the build uses (scripts/lib/imports.mjs). Not a test file (the runner
// picks up *.test.mjs only).
import { posix } from "node:path";
import { importsOf, scriptsOf } from "../../scripts/lib/imports.mjs";

export { importsOf, scriptsOf };

/**
 * @param {Map<string, Buffer>} files path -> bytes
 * @param {{ skip?: (path: string) => boolean }} [options] files whose own imports are not read (the WASM package)
 * @returns {{
 *   edges: Map<string, Array<{ specifier: string, target: string | null }>>,
 *   hidden: string[],
 *   scripts: Map<string, string[]>,
 * }} `target` is null for a specifier that is not a relative path
 */
export function readGraph(files, { skip = () => false } = {}) {
  /** @type {Map<string, Array<{ specifier: string, target: string | null }>>} */
  const edges = new Map();
  /** @type {string[]} */
  const hidden = [];
  /** @type {Map<string, string[]>} */
  const scripts = new Map();
  for (const [path, bytes] of files) {
    if (skip(path)) continue;
    if (/\.html$/.test(path)) {
      scripts.set(path, scriptsOf(path, bytes.toString("utf8")));
    } else if (/\.(?:mjs|js)$/.test(path)) {
      const { specifiers, hidden: count } = importsOf(bytes.toString("utf8"));
      if (count > 0) hidden.push(path);
      edges.set(
        path,
        specifiers.map((specifier) => ({
          specifier,
          target: /^\.\.?\//.test(specifier) ? posix.normalize(posix.join(posix.dirname(path), specifier)) : null,
        })),
      );
    }
  }
  return { edges, hidden, scripts };
}

/**
 * Every file reachable from `roots` (the roots included), following the edges.
 *
 * @param {Map<string, Array<{ specifier: string, target: string | null }>>} edges
 * @param {Iterable<string>} roots
 * @returns {Set<string>}
 */
export function reach(edges, roots) {
  const seen = new Set(roots);
  const queue = [...seen];
  while (queue.length > 0) {
    const path = /** @type {string} */ (queue.pop());
    for (const { target } of edges.get(path) ?? []) {
      if (target !== null && !seen.has(target)) {
        seen.add(target);
        queue.push(target);
      }
    }
  }
  return seen;
}
