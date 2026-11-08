// Reads the import graph of a built package (a Map of path -> bytes). Not a test
// file (the runner picks up *.test.mjs only).
//
// Static imports, `export ... from`, side-effect imports and `import("...")`
// with a string literal are edges. An `import(...)` that cannot be followed is
// reported, and the tests fail on it: a dynamic import that hides its target is
// a way around the graph. That covers an argument that is not a string literal,
// one inside a template literal, and any `import(` in the code that the reader
// did not recognise (the count of the text must equal the count of what was
// understood), so a tokenizer blind spot fails closed.
import { posix } from "node:path";

const TOKEN = /\/\*[\s\S]*?\*\/|\/\/[^\n]*|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\[\s\S]|[^`\\])*`|\b(import|export)\b/g;
const SPEC = String.raw`(["'])([^"'\\\n]*)\1`;
const META = /^\s*\.\s*meta\b/;
const DYNAMIC_LITERAL = new RegExp(String.raw`^\s*\(\s*${SPEC}\s*[,)]`);
const DYNAMIC_OTHER = /^\s*\(/;
const SIDE_EFFECT = new RegExp(String.raw`^\s*${SPEC}`);
const IMPORT_FROM = new RegExp(String.raw`^\s*[\w$\s,*{}]*?\bfrom\s*${SPEC}`);
const EXPORT_FROM = new RegExp(String.raw`^\s*(?:\*(?:\s+as\s+[\w$]+)?|\{[^}]*\})\s*from\s*${SPEC}`);

/**
 * @param {string} source
 * @returns {{ specifiers: string[], hidden: number }} the specifiers in order, and the number of dynamic imports that name no literal
 */
export function importsOf(source) {
  /** @type {string[]} */
  const specifiers = [];
  let hidden = 0;
  let understood = 0;
  // The source without its comments (a comment is not code), for the cross-check below.
  let code = "";
  let copied = 0;
  for (const match of source.matchAll(TOKEN)) {
    const keyword = match[1];
    if (!keyword) {
      if (match[0].startsWith("/*") || match[0].startsWith("//")) {
        const at = /** @type {number} */ (match.index);
        code += source.slice(copied, at);
        copied = at + match[0].length;
      }
      continue;
    }
    const rest = source.slice(/** @type {number} */ (match.index) + keyword.length);
    if (keyword === "import") {
      if (META.test(rest)) continue;
      const dynamic = DYNAMIC_LITERAL.exec(rest);
      if (dynamic) {
        specifiers.push(dynamic[2]);
        understood += 1;
        continue;
      }
      if (DYNAMIC_OTHER.test(rest)) {
        hidden += 1;
        understood += 1;
        continue;
      }
      const found = SIDE_EFFECT.exec(rest) ?? IMPORT_FROM.exec(rest);
      if (found) specifiers.push(found[2]);
    } else {
      const found = EXPORT_FROM.exec(rest);
      if (found) specifiers.push(found[2]);
    }
  }
  // Every `import(` in the code must have been understood above; one that sits
  // in a template literal, a string or after a regular expression that
  // confused the reader is counted as hidden.
  code += source.slice(copied);
  const textual = (code.match(/\bimport\s*\(/g) ?? []).length;
  if (textual > understood) hidden += textual - understood;
  return { specifiers, hidden };
}

/** The scripts a page loads: `<script src="...">`, resolved against the page. @param {string} page @param {string} html @returns {string[]} */
export function scriptsOf(page, html) {
  return [...html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)].map((m) => posix.normalize(posix.join(posix.dirname(page), m[1])));
}

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
