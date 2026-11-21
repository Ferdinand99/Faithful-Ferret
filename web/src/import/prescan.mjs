// The first look at an import file's text, and the one way the import reads JSON.
//
// `JSON.parse` has no limit of its own: a file of 50 MiB of `[` makes it recurse until the
// engine gives up (a `RangeError`, or worse in some engines), and a file of a few million
// small values takes the memory of the worker. So the text is scanned first, without building
// anything, for how deep it nests and how many elements it has. Only a text that passes the
// scan goes to `JSON.parse`, and what comes out is copied into objects that have no prototype,
// so a key like `__proto__` can never reach `Object.prototype` (Spec: Fase 1 § 5.2, F-31, applied
// to imports; Global Constraint 46).

import { ImportError, MAX_DEPTH, MAX_FILE_BYTES, MAX_ITEMS, MAX_NODES, overFieldBound } from "./limits.mjs";

/** The keys that no export has and that attack the prototype chain of a plain object. */
const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/** The structural characters of JSON and the quote: everything else in a text is a value. */
const TOKEN = /["{}[\],]/g;

/**
 * Counts how deep a JSON text nests and how many elements it has, without parsing it, and refuses
 * a text over the bounds. It is not a validator: a text that passes may still be invalid JSON,
 * and `JSON.parse` says so afterwards.
 *
 * A text that starts with the signature of a ZIP file (`PK\x03\x04`) is `import_zip`.
 *
 * Bounds (from `limits.mjs`): `MAX_DEPTH` levels of objects and arrays, `MAX_ITEMS` elements in any
 * one array or members in any one object, `MAX_NODES` values in all.
 * @param {string} text
 * @returns {{ depth: number, nodes: number }} the deepest level reached and the number of values
 */
export function prescan(text) {
  if (typeof text !== "string") throw new ImportError("import_bad_json");
  if (text.startsWith("PK\u0003\u0004")) throw new ImportError("import_zip");
  if (text.length > MAX_FILE_BYTES) throw new ImportError("import_too_large");
  // The count of commas in the container at each level; one comma more than the elements minus one.
  const commas = new Int32Array(MAX_DEPTH + 2);
  let depth = 0;
  let deepest = 0;
  let nodes = 0;
  TOKEN.lastIndex = 0;
  let match;
  while ((match = TOKEN.exec(text)) !== null) {
    const c = text.charCodeAt(match.index);
    if (c === 34) {
      // A string: jump to the quote that ends it (one that no odd run of backslashes escapes).
      let from = match.index + 1;
      for (;;) {
        const end = text.indexOf('"', from);
        if (end < 0) return { depth: deepest, nodes }; // unterminated: JSON.parse says so
        let slashes = 0;
        while (text.charCodeAt(end - 1 - slashes) === 92) slashes++;
        if (slashes % 2 === 0) {
          TOKEN.lastIndex = end + 1;
          break;
        }
        from = end + 1;
      }
    } else if (c === 123 || c === 91) {
      depth++;
      if (depth > MAX_DEPTH) throw new ImportError("import_too_deep");
      if (depth > deepest) deepest = depth;
      commas[depth] = 0;
      if (++nodes > MAX_NODES) throw new ImportError("import_too_many");
    } else if (c === 125 || c === 93) {
      if (depth > 0) depth--;
    } else if (c === 44) {
      if (++commas[depth] >= MAX_ITEMS) throw new ImportError("import_too_many");
      if (++nodes > MAX_NODES) throw new ImportError("import_too_many");
    }
  }
  return { depth: deepest, nodes };
}

/**
 * Parses an import file's text as JSON, safely.
 *
 * 1. A byte order mark is dropped, then the text is scanned ({@link prescan}) before `JSON.parse`.
 * 2. `JSON.parse` failing is an `ImportError`: a `SyntaxError` is `import_bad_json`, a
 *    `RangeError` (the engine's own limit) is `import_too_deep`. No other error leaves this function.
 * 3. The result is copied into arrays and objects that have no prototype. A key named `__proto__`,
 *    `constructor` or `prototype` anywhere is `import_bad_key`; a key or a text over
 *    `MAX_FIELD_BYTES` is `import_field_too_large`.
 * @param {string} text
 * @returns {unknown}
 */
export function safeJsonParse(text) {
  if (typeof text !== "string") throw new ImportError("import_bad_json");
  const body = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  prescan(body);
  /** @type {unknown} */
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (error) {
    if (error instanceof RangeError) throw new ImportError("import_too_deep");
    throw new ImportError("import_bad_json");
  }
  return detach(parsed, 0);
}

/**
 * A copy of a parsed value in which every object has no prototype.
 * @param {unknown} value
 * @param {number} depth
 * @returns {unknown}
 */
function detach(value, depth) {
  if (typeof value === "string") {
    if (overFieldBound(value)) throw new ImportError("import_field_too_large");
    return value;
  }
  if (value === null || typeof value !== "object") return value;
  if (depth >= MAX_DEPTH) throw new ImportError("import_too_deep");
  if (Array.isArray(value)) return value.map((item) => detach(item, depth + 1));
  const copy = Object.create(null);
  for (const key of Object.keys(value)) {
    if (DANGEROUS_KEYS.has(key)) throw new ImportError("import_bad_key");
    if (overFieldBound(key)) throw new ImportError("import_field_too_large");
    copy[key] = detach(/** @type {Record<string, unknown>} */ (value)[key], depth + 1);
  }
  return copy;
}
