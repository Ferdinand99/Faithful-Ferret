import assert from "node:assert/strict";
import { test } from "node:test";

import {
  CONTENT_TYPES,
  MAX_MESSAGE_BYTES,
  PROTOCOL_VERSION,
  ProtocolError,
  PUSH_TYPES,
  UI_PORT,
  UI_TYPES,
  decode,
  encode,
} from "../../src/shared/protocol.mjs";
import { keysOf, walk } from "../../src/shared/schema.mjs";

/** @param {Record<string, unknown>} over */
function envelope(over = {}) {
  return JSON.stringify({ v: 1, id: "req-1", type: "lock", body: {}, ...over });
}

/** @param {() => unknown} fn @param {string} code */
function refuses(fn, code) {
  assert.throws(fn, (err) => {
    assert.ok(err instanceof ProtocolError, "a ProtocolError");
    assert.equal(err.code, code);
    return true;
  });
}

const frameReport = {
  request_id: "r1",
  self_origin: "https://example.com",
  fields: [
    { kind: "username", id: "f1" },
    { kind: "password", id: "f2" },
  ],
};
const fillField = {
  request_id: "r1",
  field: "password",
  value: "correct horse",
  expect: { origin: "https://example.com", frameUrl: "https://example.com/login" },
};

test("constants have the agreed values", () => {
  assert.equal(PROTOCOL_VERSION, 1);
  assert.equal(MAX_MESSAGE_BYTES, 65_536);
  assert.equal(UI_PORT, "ferret-ui");
});

test("encode and decode round-trip on every table", () => {
  const raw = encode("frame_report", frameReport, { id: "abc" });
  assert.deepEqual(decode(raw, CONTENT_TYPES), {
    id: "abc",
    type: "frame_report",
    body: frameReport,
  });
  const push = encode("fill_field", fillField);
  assert.equal(decode(push, PUSH_TYPES).body.value, "correct horse");
  const reply = encode("state", { state: "locked" }, { id: "s1", reply: true });
  assert.deepEqual(decode(reply, UI_TYPES, { reply: true }).body, { state: "locked" });
  assert.match(JSON.parse(encode("lock", {})).id, /^[A-Za-z0-9_-]{1,64}$/);
});

test("encode refuses a body that does not fit its schema", () => {
  refuses(() => encode("nope", {}), "unknown_type");
  refuses(() => encode("lock", { extra: 1 }), "bad_shape");
  refuses(() => encode("lock", {}, { id: "bad id" }), "bad_shape");
  // A content type has no reply.
  refuses(() => encode("frame_report", frameReport, { reply: true }), "unknown_type");
});

test("decode_refuses_unknown_types_extra_keys_wrong_version_and_oversized_messages", () => {
  // Unknown types, also names that exist on Object.prototype.
  for (const type of ["nope", "__proto__", "constructor", "toString", "hasOwnProperty", ""]) {
    refuses(() => decode(envelope({ type }), UI_TYPES), "unknown_type");
  }
  // Extra keys, in the envelope and in the body.
  refuses(() => decode(envelope({ extra: 1 }), UI_TYPES), "bad_shape");
  refuses(() => decode(envelope({ body: { extra: 1 } }), UI_TYPES), "bad_shape");
  refuses(
    () => decode('{"v":1,"id":"a","type":"lock","body":{"__proto__":{}}}', UI_TYPES),
    "bad_shape",
  );
  refuses(
    () => decode('{"v":1,"id":"a","type":"lock","body":{"constructor":1}}', UI_TYPES),
    "bad_shape",
  );
  // A missing key.
  for (const key of ["v", "id", "type", "body"]) {
    const parsed = JSON.parse(envelope());
    delete parsed[key];
    refuses(() => decode(JSON.stringify(parsed), UI_TYPES), "bad_shape");
  }
  // The version.
  refuses(() => decode(envelope({ v: 2 }), UI_TYPES), "bad_version");
  refuses(() => decode(envelope({ v: 0 }), UI_TYPES), "bad_version");
  refuses(() => decode(envelope({ v: -1 }), UI_TYPES), "bad_version");
  refuses(() => decode(envelope({ v: "1" }), UI_TYPES), "bad_shape");
  refuses(() => decode(envelope({ v: 1.5 }), UI_TYPES), "bad_shape");
  refuses(() => decode(envelope({ v: null }), UI_TYPES), "bad_shape");
  // A newer version is refused as such, also with a type we do not know.
  refuses(() => decode(envelope({ v: 2, type: "nope" }), UI_TYPES), "bad_version");
  // Size: by length, and by bytes for multi-byte text.
  refuses(() => decode("x".repeat(MAX_MESSAGE_BYTES + 1), UI_TYPES), "too_large");
  const wide = "é".repeat(MAX_MESSAGE_BYTES / 2);
  assert.ok(wide.length < MAX_MESSAGE_BYTES);
  refuses(() => decode(envelope({ body: { query: wide } }), UI_TYPES), "too_large");
  // Not a message.
  for (const raw of [undefined, null, 1, {}, [], "", "{", "null", "[]", "1", '"x"']) {
    refuses(() => decode(/** @type {any} */ (raw), UI_TYPES), "bad_shape");
  }
  refuses(() => decode(envelope({ id: "has space" }), UI_TYPES), "bad_shape");
  refuses(() => decode(envelope({ id: "a".repeat(65) }), UI_TYPES), "bad_shape");
  refuses(() => decode(envelope({ id: 1 }), UI_TYPES), "bad_shape");
  refuses(() => decode(envelope({ type: 1 }), UI_TYPES), "bad_shape");
  // The same message passes when it is right.
  assert.equal(decode(envelope(), UI_TYPES).type, "lock");
});

test("an error never carries the value that caused it", () => {
  const secret = "Z".repeat(2000);
  try {
    decode(envelope({ type: "unlock", body: { mp: secret } }), UI_TYPES);
    assert.fail("should refuse");
  } catch (err) {
    assert.ok(err instanceof ProtocolError);
    assert.ok(!err.message.includes("ZZZ"));
    assert.equal(err.path, "body.mp");
  }
});

test("a_content_type_on_the_ui_port_and_a_ui_type_from_a_content_script_are_both_refused", () => {
  const content = encode("frame_report", frameReport);
  const result = encode("fill_result", { request_id: "r1", ok: true });
  const ui = encode("lock", {});
  const fill = encode("fill", { ref: "h1", tab_id: 1, frame_id: 0 });
  const push = encode("fill_field", fillField);
  // A content type on the UI port.
  refuses(() => decode(content, UI_TYPES), "unknown_type");
  refuses(() => decode(result, UI_TYPES), "unknown_type");
  // A UI type from a content script.
  refuses(() => decode(ui, CONTENT_TYPES), "unknown_type");
  refuses(() => decode(fill, CONTENT_TYPES), "unknown_type");
  // The push type is not accepted on either inbound channel.
  refuses(() => decode(push, UI_TYPES), "unknown_type");
  refuses(() => decode(push, CONTENT_TYPES), "unknown_type");
  // And the inbound types are not accepted by a content script.
  refuses(() => decode(ui, PUSH_TYPES), "unknown_type");
  refuses(() => decode(content, PUSH_TYPES), "unknown_type");
  // A content type has no reply on any table.
  refuses(() => decode(content, CONTENT_TYPES, { reply: true }), "unknown_type");
  // No name is in two tables.
  const names = [UI_TYPES, CONTENT_TYPES, PUSH_TYPES].flatMap((t) => Object.keys(t));
  assert.equal(new Set(names).size, names.length);
});

test("fill_field_is_the_only_type_with_a_value_and_it_holds_one_value", () => {
  /** @type {string[]} */
  const holders = [];
  for (const table of [UI_TYPES, CONTENT_TYPES, PUSH_TYPES]) {
    for (const [type, def] of Object.entries(table)) {
      for (const schema of [def.request, def.reply]) {
        if (schema && keysOf(schema).includes("value")) holders.push(type);
      }
    }
  }
  assert.deepEqual(holders, ["fill_field"]);

  // The body holds one value: one string, no array, nothing nested but `expect`.
  const def = /** @type {any} */ (PUSH_TYPES.fill_field.request);
  /** @type {string[]} */
  const arrays = [];
  walk(def, (node, path) => {
    if (node.kind === "array") arrays.push(path);
  });
  assert.deepEqual(arrays, []);
  assert.deepEqual(Object.keys(def.shape), ["request_id", "field", "value", "expect"]);
  assert.equal(def.shape.value.kind, "string");

  const ok = decode(encode("fill_field", fillField), PUSH_TYPES);
  assert.equal(ok.body.value, "correct horse");
  const raw = (/** @type {unknown} */ body) =>
    JSON.stringify({ v: 1, id: "a", type: "fill_field", body });
  refuses(() => decode(raw({ ...fillField, value: ["a", "b"] }), PUSH_TYPES), "bad_shape");
  refuses(() => decode(raw({ ...fillField, value: { a: "b" } }), PUSH_TYPES), "bad_shape");
  refuses(() => decode(raw({ ...fillField, values: ["a"] }), PUSH_TYPES), "bad_shape");
  refuses(() => decode(raw({ ...fillField, other: "b" }), PUSH_TYPES), "bad_shape");
  refuses(() => decode(raw({ ...fillField, value: "x".repeat(2049) }), PUSH_TYPES), "bad_shape");
  refuses(() => decode(raw({ ...fillField, field: "vk" }), PUSH_TYPES), "bad_shape");
  const noExpect = /** @type {any} */ ({ ...fillField });
  delete noExpect.expect;
  refuses(() => decode(raw(noExpect), PUSH_TYPES), "bad_shape");
});

test("a content script cannot send a message type that carries a value", () => {
  // The two content types carry ids, a flag and one origin, nothing else.
  assert.deepEqual(keysOf(CONTENT_TYPES.frame_report.request).sort(), [
    "fields",
    "id",
    "kind",
    "request_id",
    "self_origin",
  ]);
  assert.deepEqual(keysOf(CONTENT_TYPES.fill_result.request).sort(), [
    "ok",
    "reason",
    "request_id",
  ]);
});
