// A tiny schema checker for the extension's messages. Plain ESM, no
// dependencies, so the same file runs in the background, in extension pages and
// in a content script.
//
// Rules:
// - Every object schema lists every key it accepts. A key it does not list is
//   refused ("deny unknown fields"), also `__proto__` and `constructor`.
// - Every string, array and integer has an upper bound. A schema without one
//   cannot be built.
// - The checker copies the keys it knows into a new object. The caller never
//   gets the parsed input back.
// - An error carries the path of the field and never its value, because a value
//   can be a secret.

/**
 * @typedef {{ kind: "string", min: number, max: number, pattern: RegExp | null, oneOf: readonly string[] | null }} StringSchema
 * @typedef {{ kind: "boolean" }} BooleanSchema
 * @typedef {{ kind: "integer", min: number, max: number }} IntegerSchema
 * @typedef {{ kind: "array", item: Schema, min: number, max: number }} ArraySchema
 * @typedef {{ kind: "object", shape: Readonly<Record<string, Schema>>, optional: readonly string[] }} ObjectSchema
 * @typedef {StringSchema | BooleanSchema | IntegerSchema | ArraySchema | ObjectSchema} Schema
 */

/** The reasons a message is refused. */
export const ERROR_CODES = Object.freeze([
  "unknown_type",
  "too_large",
  "bad_shape",
  "bad_version",
]);

export class ProtocolError extends Error {
  /**
   * @param {"unknown_type" | "too_large" | "bad_shape" | "bad_version"} code
   * @param {string} [path] where in the message the problem is (never a value)
   */
  constructor(code, path) {
    super(path ? `${code} at ${path}` : code);
    this.name = "ProtocolError";
    this.code = code;
    this.path = path ?? "";
  }
}

const KEY_NAME = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;

/** @param {unknown} n */
function finiteBound(n) {
  return typeof n === "number" && Number.isSafeInteger(n) && n >= 0;
}

/**
 * @param {{ max: number, min?: number, pattern?: RegExp, oneOf?: readonly string[] }} opts
 * @returns {StringSchema}
 */
export function string(opts) {
  const min = opts.min ?? 0;
  if (!finiteBound(opts.max) || !finiteBound(min) || min > opts.max) {
    throw new TypeError("string schema needs a finite max");
  }
  const oneOf = opts.oneOf ? Object.freeze([...opts.oneOf]) : null;
  if (oneOf && oneOf.some((v) => typeof v !== "string" || v.length > opts.max)) {
    throw new TypeError("string schema enum is out of bounds");
  }
  return Object.freeze({
    kind: "string",
    min,
    max: opts.max,
    pattern: opts.pattern ?? null,
    oneOf,
  });
}

/** @returns {BooleanSchema} */
export function boolean() {
  return Object.freeze({ kind: "boolean" });
}

/**
 * @param {{ min: number, max: number }} opts
 * @returns {IntegerSchema}
 */
export function integer(opts) {
  if (
    !Number.isSafeInteger(opts.min) ||
    !Number.isSafeInteger(opts.max) ||
    opts.min > opts.max
  ) {
    throw new TypeError("integer schema needs finite bounds");
  }
  return Object.freeze({ kind: "integer", min: opts.min, max: opts.max });
}

/**
 * @param {Schema} item
 * @param {{ max: number, min?: number }} opts
 * @returns {ArraySchema}
 */
export function array(item, opts) {
  const min = opts.min ?? 0;
  if (!finiteBound(opts.max) || !finiteBound(min) || min > opts.max) {
    throw new TypeError("array schema needs a finite max");
  }
  return Object.freeze({ kind: "array", item, min, max: opts.max });
}

/**
 * @param {Record<string, Schema>} shape
 * @param {{ optional?: readonly string[] }} [opts]
 * @returns {ObjectSchema}
 */
export function object(shape, opts = {}) {
  const optional = Object.freeze([...(opts.optional ?? [])]);
  for (const key of Object.keys(shape)) {
    if (!KEY_NAME.test(key)) throw new TypeError("bad key name in schema");
  }
  for (const key of optional) {
    if (!Object.hasOwn(shape, key)) throw new TypeError("optional key not in schema");
  }
  return Object.freeze({
    kind: "object",
    shape: Object.freeze({ ...shape }),
    optional,
  });
}

/**
 * Check `value` against `schema` and return a fresh copy that holds only the
 * keys the schema lists.
 *
 * @param {Schema} schema
 * @param {unknown} value
 * @param {string} [path]
 * @returns {any}
 */
export function validate(schema, value, path = "body") {
  switch (schema.kind) {
    case "string": {
      if (typeof value !== "string") throw new ProtocolError("bad_shape", path);
      if (value.length < schema.min || value.length > schema.max) {
        throw new ProtocolError("bad_shape", path);
      }
      if (schema.oneOf && !schema.oneOf.includes(value)) {
        throw new ProtocolError("bad_shape", path);
      }
      if (schema.pattern && !schema.pattern.test(value)) {
        throw new ProtocolError("bad_shape", path);
      }
      return value;
    }
    case "boolean": {
      if (typeof value !== "boolean") throw new ProtocolError("bad_shape", path);
      return value;
    }
    case "integer": {
      if (typeof value !== "number" || !Number.isSafeInteger(value)) {
        throw new ProtocolError("bad_shape", path);
      }
      if (value < schema.min || value > schema.max) {
        throw new ProtocolError("bad_shape", path);
      }
      return value;
    }
    case "array": {
      if (!Array.isArray(value)) throw new ProtocolError("bad_shape", path);
      if (value.length < schema.min || value.length > schema.max) {
        throw new ProtocolError("bad_shape", path);
      }
      const out = [];
      for (let i = 0; i < value.length; i += 1) {
        out.push(validate(schema.item, value[i], `${path}[${i}]`));
      }
      return out;
    }
    case "object": {
      if (!isPlainObject(value)) throw new ProtocolError("bad_shape", path);
      const record = /** @type {Record<string, unknown>} */ (value);
      for (const key of Object.keys(record)) {
        if (!Object.hasOwn(schema.shape, key)) {
          throw new ProtocolError("bad_shape", `${path}.${key.slice(0, 32)}`);
        }
      }
      /** @type {Record<string, unknown>} */
      const out = {};
      for (const key of Object.keys(schema.shape)) {
        if (!Object.hasOwn(record, key)) {
          if (schema.optional.includes(key)) continue;
          throw new ProtocolError("bad_shape", `${path}.${key}`);
        }
        out[key] = validate(schema.shape[key], record[key], `${path}.${key}`);
      }
      return out;
    }
    default:
      throw new ProtocolError("bad_shape", path);
  }
}

/** @param {unknown} value */
function isPlainObject(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Visit every node of a schema, depth first. Used by the tests to check the
 * caps and the key names of every schema.
 *
 * @param {Schema} schema
 * @param {(node: Schema, path: string) => void} visit
 * @param {string} [path]
 */
export function walk(schema, visit, path = "body") {
  visit(schema, path);
  if (schema.kind === "array") {
    walk(schema.item, visit, `${path}[]`);
  } else if (schema.kind === "object") {
    for (const key of Object.keys(schema.shape)) {
      walk(schema.shape[key], visit, `${path}.${key}`);
    }
  }
}

/**
 * Every object key a schema accepts, at any depth.
 *
 * @param {Schema} schema
 * @returns {string[]}
 */
export function keysOf(schema) {
  /** @type {string[]} */
  const keys = [];
  walk(schema, (node) => {
    if (node.kind === "object") keys.push(...Object.keys(node.shape));
  });
  return keys;
}
