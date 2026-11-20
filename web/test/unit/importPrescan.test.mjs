// The first look at an import file (depth and size before JSON.parse) and the safe parse.
import assert from "node:assert/strict";
import { test } from "node:test";
import { ImportError, MAX_DEPTH, MAX_FIELD_BYTES, MAX_ITEMS, MAX_NODES } from "../../src/import/limits.mjs";
import { prescan, safeJsonParse } from "../../src/import/prescan.mjs";
import { fixture } from "./importHelpers.mjs";

const refusal = (code) => (error) => error instanceof ImportError && error.code === code;

test("depth_and_item_count_are_refused_by_the_prescan_before_json_parse", () => {
  const original = JSON.parse;
  let parsed = 0;
  JSON.parse = (...args) => {
    parsed++;
    return original(...args);
  };
  try {
    // Depth: 16 levels pass, 17 do not.
    assert.deepEqual(prescan("[".repeat(MAX_DEPTH) + "]".repeat(MAX_DEPTH)).depth, MAX_DEPTH);
    assert.throws(() => safeJsonParse("[".repeat(MAX_DEPTH + 1) + "]".repeat(MAX_DEPTH + 1)), refusal("import_too_deep"));
    // The case that makes JSON.parse itself fail: a file that is only opening brackets.
    assert.throws(() => safeJsonParse("[".repeat(5_000_000)), refusal("import_too_deep"));
    assert.throws(() => safeJsonParse('{"a":'.repeat(1_000)), refusal("import_too_deep"));
    // The real file of the fixtures that is too deep.
    assert.throws(() => safeJsonParse(fixture("huge-depth.json")), refusal("import_too_deep"));

    // Item count: one array with more than MAX_ITEMS elements, or one object with more than MAX_ITEMS members.
    const ok = `[${"0,".repeat(MAX_ITEMS - 1)}0]`;
    assert.doesNotThrow(() => prescan(ok));
    const tooMany = `[${"0,".repeat(MAX_ITEMS)}0]`;
    assert.throws(() => safeJsonParse(tooMany), refusal("import_too_many"));
    const members = `{${Array.from({ length: MAX_ITEMS + 1 }, (_, i) => `"k${i}":0`).join(",")}}`;
    assert.throws(() => safeJsonParse(members), refusal("import_too_many"));
    // Many small arrays that together hold too many values.
    const inner = `[${"0,".repeat(999)}0]`;
    const nested = `[${Array.from({ length: 3_000 }, () => inner).join(",")}]`;
    assert.throws(() => safeJsonParse(nested), refusal("import_too_many"));
  } finally {
    JSON.parse = original;
  }
  // Not one of those texts reached JSON.parse.
  assert.equal(parsed, 0);
});

test("the_bound_on_values_holds_where_it_is_and_one_more_is_refused", () => {
  // MAX_ITEMS arrays of k values each, in an array: 10 000 + 10 000 k values for the prescan.
  const arrays = (k) => `[${Array.from({ length: MAX_ITEMS }, () => `[${"0,".repeat(k - 1)}0]`).join(",")}]`;
  const k = MAX_NODES / MAX_ITEMS - 1;
  assert.deepEqual(prescan(arrays(k)).nodes, MAX_NODES);
  assert.throws(() => prescan(arrays(k + 1)), refusal("import_too_many"));
});

test("the_prescan_does_not_count_brackets_and_commas_inside_strings", () => {
  const text = JSON.stringify({ items: [{ name: "[[[[[[[[[[[[[[[[[[[[[[[[,,,,,,,,,,,,,]]]]]", notes: 'a "quoted" {] , \\ backslash', other: "\\\\" }] });
  assert.deepEqual(prescan(text), { depth: 3, nodes: prescan(text).nodes });
  assert.equal(safeJsonParse(text).items[0].other, "\\\\");
  // An escaped quote does not end the string; an escaped backslash before a quote does.
  assert.equal(prescan('["a\\"[[[[[[[[[[[[[[[[[[[[["]').depth, 1);
  assert.equal(prescan('["a\\\\","[[[[[[[[[[[[[[[[[[[[[["]').depth, 1);
});

test("a_range_error_from_json_parse_is_an_import_error", () => {
  const original = JSON.parse;
  try {
    JSON.parse = () => {
      throw new RangeError("Maximum call stack size exceeded");
    };
    assert.throws(() => safeJsonParse("[]"), refusal("import_too_deep"));
    JSON.parse = () => {
      throw new SyntaxError("Unexpected token");
    };
    assert.throws(() => safeJsonParse("[]"), refusal("import_bad_json"));
    // Whatever else goes wrong is an import error too, with no text of the original.
    JSON.parse = () => {
      throw new Error("secret text from the file");
    };
    assert.throws(
      () => safeJsonParse("[]"),
      (error) => error instanceof ImportError && error.code === "import_bad_json" && !error.message.includes("secret"),
    );
  } finally {
    JSON.parse = original;
  }
  assert.throws(() => safeJsonParse("{not json"), refusal("import_bad_json"));
  assert.throws(() => safeJsonParse(""), refusal("import_bad_json"));
  assert.throws(() => safeJsonParse(/** @type {any} */ (5)), refusal("import_bad_json"));
});

test("hostile_keys_are_refused_and_object_prototype_is_untouched", () => {
  for (const text of [
    '{"__proto__":{"polluted":true}}',
    '{"a":{"__proto__":{"polluted":true}}}',
    '{"a":[{"b":{"constructor":{"prototype":{"polluted":true}}}}]}',
    '{"prototype":1}',
    '{"constructor":1}',
  ]) {
    assert.throws(() => safeJsonParse(text), refusal("import_bad_key"), text);
  }
  assert.throws(() => safeJsonParse(fixture("hostile.json")), refusal("import_bad_key"));
  // Nothing was added to Object.prototype by any of them, or by what a normal parse gives.
  assert.equal(Object.prototype.polluted, undefined);
  assert.equal({}.polluted, undefined);
  assert.equal({}.isAdmin, undefined);
  assert.deepEqual(Object.getOwnPropertyNames(Object.prototype).filter((n) => /polluted|isAdmin/.test(n)), []);

  // What comes out has no prototype at every level, so a key can only ever be its own.
  const out = safeJsonParse('{"a":{"b":[{"c":1}]},"toString":"text","hasOwnProperty":2}');
  assert.equal(Object.getPrototypeOf(out), null);
  assert.equal(Object.getPrototypeOf(out.a), null);
  assert.equal(Object.getPrototypeOf(out.a.b[0]), null);
  assert.equal(out.toString, "text");
  assert.equal(out.hasOwnProperty, 2);
  assert.equal(Array.isArray(out.a.b), true);
});

test("a_zip_export_is_refused_with_a_clear_text", () => {
  const error = (() => {
    try {
      safeJsonParse("PK\u0003\u0004\u0014\u0000\u0000\u0000\u0008\u0000");
    } catch (e) {
      return e;
    }
  })();
  assert.ok(error instanceof ImportError);
  assert.equal(error.code, "import_zip");
  assert.match(error.message, /ZIP/);
  assert.match(error.message, /\.json or \.csv/);
  assert.throws(() => prescan("PK\u0003\u0004"), refusal("import_zip"));
  // A text that merely starts with the letters is JSON that is not valid, not a ZIP file.
  assert.throws(() => safeJsonParse("PK"), refusal("import_bad_json"));
});

test("a_byte_order_mark_is_dropped_and_values_are_bounded", () => {
  assert.deepEqual(Object.assign({}, safeJsonParse('﻿{"a":1}')), { a: 1 });
  assert.throws(() => safeJsonParse(JSON.stringify({ v: "a".repeat(MAX_FIELD_BYTES + 1) })), refusal("import_field_too_large"));
  assert.throws(() => safeJsonParse(JSON.stringify({ ["k".repeat(MAX_FIELD_BYTES + 1)]: 1 })), refusal("import_field_too_large"));
  assert.doesNotThrow(() => safeJsonParse(JSON.stringify({ v: "a".repeat(MAX_FIELD_BYTES) })));
  // The real fixtures pass.
  for (const name of ["small.json", "every-type.json", "encrypted.json", "password-protected.json", "schemes.json"]) {
    assert.doesNotThrow(() => safeJsonParse(fixture(name)), name);
  }
});
