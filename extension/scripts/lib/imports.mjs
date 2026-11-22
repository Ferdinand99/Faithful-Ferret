// Reads the imports of a module and the scripts of a page, without running or
// bundling anything. The build uses it to check that a package holds every file
// its code imports, and the unit tests use it to read the import graph.
//
// Static imports, `export ... from`, side-effect imports and `import("...")`
// with a string literal are edges. An `import(...)` that cannot be followed is
// reported as hidden, and the tests fail on it: a dynamic import that hides its
// target is a way around the graph. That covers an argument that is not a
// string literal, one inside a template literal, and any `import(` in the code
// that the reader did not recognise (the count of the text must equal the count
// of what was understood), so a tokenizer blind spot fails closed.
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

/**
 * The scripts a page loads: `<script src="...">`, resolved against the page.
 * @param {string} page the page's path in the package
 * @param {string} html
 * @returns {string[]}
 */
export function scriptsOf(page, html) {
  return [...html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)].map((m) =>
    m[1].startsWith("/") ? posix.normalize(m[1].slice(1)) : posix.normalize(posix.join(posix.dirname(page), m[1])),
  );
}

/**
 * The relative imports and page scripts in a package that point at a file it
 * does not hold. Files for which `skip(path)` is true are not read (the WASM
 * package, which is checked by its SHA-256).
 *
 * @param {Map<string, Buffer>} files path -> bytes
 * @param {(path: string) => boolean} [skip]
 * @returns {string[]} one line per dangling edge
 */
export function danglingImports(files, skip = () => false) {
  /** @type {string[]} */
  const problems = [];
  for (const [path, bytes] of files) {
    if (skip(path)) continue;
    /** @type {string[]} */
    let targets = [];
    if (/\.html$/.test(path)) {
      targets = scriptsOf(path, bytes.toString("utf8"));
    } else if (/\.(?:mjs|js)$/.test(path)) {
      targets = importsOf(bytes.toString("utf8"))
        .specifiers.filter((s) => /^\.\.?\//.test(s))
        .map((s) => posix.normalize(posix.join(posix.dirname(path), s)));
    }
    for (const target of targets) {
      if (!files.has(target)) problems.push(`${path}: imports ${target}, which is not in the package`);
    }
  }
  return problems;
}
