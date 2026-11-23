// Joins a content script and the modules it imports into one classic script.
//
// Why: a script that the extension injects (`scripting.executeScript` with a
// file) is a classic script, so it cannot use `import`. It also cannot load
// module files at run time: Firefox refuses `import()` of an extension file in a
// content script unless the file is web-accessible, and no file of this
// extension is web-accessible (a page must not be able to load any of it). So
// the build writes the closure of imports as one file.
//
// Each module keeps its own scope, as in a real module: it becomes a function
// that returns an object with its exports, and a module that imports names
// reads them from the object of the module it imports. A top-level name of one
// module (`origin`, say) never shadows a global in another.
//
// The joiner reads only what the content script's own files use, and refuses
// everything else instead of guessing:
//
// - `import { a, b } from "./x.mjs"` and `import "./x.mjs"`: named, no `as`,
//   and every name must be exported by that module;
// - `export function|const|class ...` and `export { a, b }` (no `as`, no
//   `export let`, because the importer gets a copy of the value); a name in an
//   export list must be declared at the top of its module by `function`,
//   `const` or `class`, or be imported (so no `let a; export { a }` and no name
//   that does not exist);
// - no identifier of the form `__m<number>`, the names the joined script gives
//   the modules;
// - no line inside a comment, a string or a template literal that starts with
//   `import` or `export` (the joiner reads those forms line by line, and such a
//   line would be edited as if it were code);
// - a closure of at most the files `allowed` names, and no cycle.
//
// Not allowed: `import()`, `import.meta`, default or namespace imports,
// re-exports, `export default`. The output is compiled (not run) once, so a
// bundle that does not parse fails the build and not the injection.
//
// `slim` (the capture script, which runs in every https page and has a size
// budget): the modules are joined without the lines that only explain them.
// Comments that stand on lines of their own, the indentation of every line
// outside a multi-line string or template literal, and blank lines are left
// out. Code is never touched, and a line that ends in a backslash (a string
// continued on the next line, where indentation counts) is refused.
import { posix } from "node:path";
import vm from "node:vm";
import { importsOf } from "./imports.mjs";

/** The module the content script starts from, and the file that is written. */
export const CONTENT_ENTRY = "content/entry.mjs";
export const CONTENT_BUNDLE = "content/fill.inject.js";
/** The capture script: the same joiner, another entry, and the size budget of a script that runs in every page. */
export const CAPTURE_ENTRY = "content/capture.entry.mjs";
export const CAPTURE_BUNDLE = "content/capture.inject.js";
export const CAPTURE_MAX_BYTES = 40 * 1024;

/**
 * The files a content script may be built from: its own folder and the message
 * protocol with the schema checker. No other shared module, nothing of the
 * background, no store, no crypto.
 * @param {string} path
 */
export const contentMayInclude = (path) =>
  (path.startsWith("content/") && path.endsWith(".mjs")) || path === "shared/protocol.mjs" || path === "shared/schema.mjs";

const IMPORT = /^import\s*(?:\{([^}]*)\}\s*from\s*)?(["'])([^"'\n]+)\2[ \t]*;?[ \t]*$/gm;
const EXPORT_DECLARATION = /^export\s+(?:async\s+function|function|const|class)\s+([A-Za-z_$][\w$]*)/gm;
const EXPORT_LIST = /^export\s*\{([^}]*)\}[ \t]*;?[ \t]*$/gm;
const NAME = /^[A-Za-z_$][\w$]*$/;
/** Comments, strings and template literals, and the `import` and `export` keywords outside them (as imports.mjs reads them). */
const TOKEN = /\/\*[\s\S]*?\*\/|\/\/[^\n]*|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\[\s\S]|[^`\\])*`|\b(import|export)\b/g;
/** A line that starts with `import` or `export`, up to that word. */
const LINE_KEYWORD = /^[ \t]*(?=(?:import|export)\b)/gm;

/**
 * Refuses a line that starts with `import` or `export` inside a comment, a string or a template literal.
 * @param {string} path @param {string} source
 */
function checkKeywordLines(path, source) {
  /** @type {Set<number>} */
  const code = new Set();
  for (const match of source.matchAll(TOKEN)) {
    if (match[1]) code.add(/** @type {number} */ (match.index));
  }
  for (const match of source.matchAll(LINE_KEYWORD)) {
    const at = /** @type {number} */ (match.index) + match[0].length;
    if (!code.has(at)) {
      const line = source.slice(0, at).split("\n").length;
      throw new Error(`content script: ${path}: line ${line} starts with import or export inside a comment, a string or a template literal`);
    }
  }
}

/**
 * The source without the lines that only explain it (see `slim` in the head of the file).
 * @param {string} path @param {string} source
 */
export function slimSource(path, source) {
  const lines = source.split("\n");
  /** @type {number[]} */
  const starts = [];
  for (let at = 0, i = 0; i < lines.length; at += lines[i].length + 1, i += 1) starts.push(at);
  const lineAt = (/** @type {number} */ offset) => {
    let low = 0;
    let high = starts.length - 1;
    while (low < high) {
      const mid = (low + high + 1) >> 1;
      if (starts[mid] <= offset) low = mid;
      else high = mid - 1;
    }
    return low;
  };
  /** Lines that are only a comment. @type {Set<number>} */
  const dropped = new Set();
  /** Lines that start inside a multi-line literal or share a line with code: kept exactly as they are. @type {Set<number>} */
  const verbatim = new Set();
  for (const match of source.matchAll(TOKEN)) {
    const text = match[0];
    if (match[1]) continue;
    const start = /** @type {number} */ (match.index);
    const end = start + text.length;
    const first = lineAt(start);
    const last = lineAt(Math.max(start, end - 1));
    if (!text.startsWith("//") && !text.startsWith("/*")) {
      for (let i = first + 1; i <= last; i += 1) verbatim.add(i);
      continue;
    }
    const alone = source.slice(starts[first], start).trim() === "" && source.slice(end, starts[last] + lines[last].length).trim() === "";
    for (let i = first; i <= last; i += 1) {
      if (alone) dropped.add(i);
      else if (i > first) verbatim.add(i);
    }
  }
  /** @type {string[]} */
  const out = [];
  for (let i = 0; i < lines.length; i += 1) {
    if (dropped.has(i)) continue;
    if (verbatim.has(i)) {
      out.push(lines[i]);
      continue;
    }
    if (/\\\s*$/.test(lines[i])) throw new Error(`content script: ${path}: line ${i + 1} ends in a backslash`);
    const line = lines[i].trim();
    if (line !== "") out.push(line);
  }
  return out.join("\n");
}

/** @param {string} list the inside of `{ ... }` @param {string} where @returns {string[]} */
function names(list, where) {
  const out = list.split(",").map((n) => n.trim()).filter((n) => n !== "");
  for (const name of out) {
    if (!NAME.test(name)) throw new Error(`content script: ${where}: only plain names in an import or export list (${name})`);
  }
  return out;
}

/**
 * @param {string} entry the entry module's path in the package
 * @param {Map<string, Buffer>} files path -> bytes
 * @param {(path: string) => boolean} [allowed]
 * @param {{ slim?: boolean, name?: string }} [options] `slim`: see the head of the file; `name`: the file the script is compiled as
 * @returns {string} the classic script
 */
export function classicScript(entry, files, allowed = contentMayInclude, options = {}) {
  /** @type {Array<{ path: string, variable: string, code: string, exports: string[] }>} */
  const order = [];
  /** @type {Map<string, { variable: string, exports: string[] }>} */
  const done = new Map();
  /** @type {string[]} */
  const stack = [];

  /** @param {string} path @returns {{ variable: string, exports: string[] }} */
  const visit = (path) => {
    if (stack.includes(path)) throw new Error(`content script: an import cycle through ${path}`);
    const known = done.get(path);
    if (known) return known;
    if (!allowed(path)) throw new Error(`content script: ${path} is not allowed in a content script`);
    const bytes = files.get(path);
    if (!bytes) throw new Error(`content script: ${path} is not in the package`);
    const source = bytes.toString("utf8");
    if (/\b__m\d+\b/.test(source)) throw new Error(`content script: ${path} uses a name of the form __m<number>, which the joined script keeps for its modules`);
    checkKeywordLines(path, source);
    const reader = importsOf(source);
    if (reader.hidden > 0) throw new Error(`content script: ${path} has an import() with no string literal`);
    stack.push(path);
    /** @type {string[]} */
    const specifiers = [];
    /** @type {Array<{ target: string, wanted: string[] }>} */
    const wanted = [];
    let code = (options.slim ? slimSource(path, source) : source).replace(IMPORT, (_, list, __, specifier) => {
      if (!/^\.\.?\//.test(specifier)) throw new Error(`content script: ${path} imports ${specifier} (only relative imports)`);
      specifiers.push(specifier);
      wanted.push({
        target: posix.normalize(posix.join(posix.dirname(path), specifier)),
        wanted: typeof list === "string" ? names(list, path) : [],
      });
      return "";
    });
    // Every import the reader sees (also `import()` and anything the pattern above
    // did not match), in the same order, must have been handled here.
    if (JSON.stringify(specifiers) !== JSON.stringify(reader.specifiers)) {
      throw new Error(`content script: ${path} has an import form that is not supported`);
    }
    /** @type {string[]} */
    const exported = [];
    if (/^export\s+let\b/m.test(code)) throw new Error(`content script: ${path}: export let is not supported`);
    code = code.replace(EXPORT_DECLARATION, (all, name) => {
      exported.push(name);
      return all.replace(/^export\s+/, "");
    });
    /** @type {string[]} */
    const listed = [];
    code = code.replace(EXPORT_LIST, (_, list) => {
      listed.push(...names(list, path));
      return "";
    });
    // A listed name is a copy for the importer, so it must be a binding that never changes.
    const imported = new Set(wanted.flatMap((w) => w.wanted));
    for (const name of listed) {
      const declared = new RegExp(String.raw`^(?:async\s+function|function|const|class)\s+${name.replaceAll("$", "\$")}(?![\w$])`, "m");
      if (!imported.has(name) && !declared.test(code)) {
        throw new Error(`content script: ${path}: export { ${name} } needs a top-level function, const or class of that name, or an import`);
      }
    }
    exported.push(...listed);
    if (/^\s*(?:import|export)\b/m.test(code)) throw new Error(`content script: ${path} has an import or export form that is not supported`);
    if (/\bimport\s*\.\s*meta\b/.test(code)) throw new Error(`content script: ${path} uses import.meta`);

    // The importing lines come first in the module's function.
    let header = "";
    for (const { target, wanted: list } of wanted) {
      const module = visit(target);
      for (const name of list) {
        if (!module.exports.includes(name)) throw new Error(`content script: ${path} imports ${name}, which ${target} does not export`);
      }
      if (list.length > 0) header += `const { ${list.join(", ")} } = ${module.variable};\n`;
    }
    stack.pop();
    // A module is numbered when it is finished, so a dependency has a lower number.
    const own = { variable: `__m${done.size}`, exports: [...new Set(exported)] };
    done.set(path, own);
    order.push({ path, variable: own.variable, code: header + code.trim(), exports: own.exports });
    return own;
  };
  visit(entry);

  const text = [
    "// Generated by scripts/build.mjs: the content script and the modules it imports, joined into one",
    "// classic script. Do not edit.",
    `// Files: ${order.map((o) => o.path).join(", ")}`,
    "(() => {",
    '"use strict";',
    ...order.map((o) => `// ---- ${o.path}\nconst ${o.variable} = (() => {\n${o.code}\nreturn { ${o.exports.join(", ")} };\n})();\n`),
    "})();",
    "",
  ].join("\n");
  try {
    new vm.Script(text, { filename: options.name ?? CONTENT_BUNDLE });
  } catch (error) {
    throw new Error(`content script: the joined script does not parse: ${/** @type {Error} */ (error).message}`);
  }
  return text;
}
