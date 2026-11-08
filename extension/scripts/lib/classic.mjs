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
//   `export let`, because the importer gets a copy of the value);
// - a closure of at most the files `allowed` names, and no cycle.
//
// Not allowed: `import()`, `import.meta`, default or namespace imports,
// re-exports, `export default`. The output is compiled (not run) once, so a
// bundle that does not parse fails the build and not the injection.
import { posix } from "node:path";
import vm from "node:vm";
import { importsOf } from "./imports.mjs";

/** The module the content script starts from, and the file that is written. */
export const CONTENT_ENTRY = "content/entry.mjs";
export const CONTENT_BUNDLE = "content/fill.inject.js";

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
 * @returns {string} the classic script
 */
export function classicScript(entry, files, allowed = contentMayInclude) {
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
    const reader = importsOf(source);
    if (reader.hidden > 0) throw new Error(`content script: ${path} has an import() with no string literal`);
    stack.push(path);
    /** @type {string[]} */
    const specifiers = [];
    /** @type {Array<{ target: string, wanted: string[] }>} */
    const wanted = [];
    let code = source.replace(IMPORT, (_, list, __, specifier) => {
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
    code = code.replace(EXPORT_LIST, (_, list) => {
      exported.push(...names(list, path));
      return "";
    });
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
    new vm.Script(text, { filename: CONTENT_BUNDLE });
  } catch (error) {
    throw new Error(`content script: the joined script does not parse: ${/** @type {Error} */ (error).message}`);
  }
  return text;
}
