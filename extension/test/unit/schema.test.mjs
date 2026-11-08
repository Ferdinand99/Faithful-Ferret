import assert from "node:assert/strict";
import { test } from "node:test";

import {
  CONTENT_TYPES,
  FORBIDDEN_KEYS,
  MAX_MESSAGE_BYTES,
  PUSH_TYPES,
  SECRET_KEY_EXCEPTIONS,
  TYPED_CREDENTIAL_KEYS,
  UI_TYPES,
  decode,
  encode,
} from "../../src/shared/protocol.mjs";
import {
  ProtocolError,
  array,
  boolean,
  integer,
  keysOf,
  object,
  string,
  validate,
  walk,
} from "../../src/shared/schema.mjs";

/** Every schema in every table, with the type, channel and direction it belongs to. */
function allSchemas() {
  /** @type {{ type: string, channel: string, direction: string, schema: any }[]} */
  const out = [];
  const tables = { ui: UI_TYPES, content: CONTENT_TYPES, push: PUSH_TYPES };
  for (const [channel, table] of Object.entries(tables)) {
    for (const [type, def] of Object.entries(table)) {
      out.push({ type, channel, direction: "request", schema: def.request });
      if (def.reply) out.push({ type, channel, direction: "reply", schema: def.reply });
    }
  }
  return out;
}

/** @param {() => unknown} fn */
function refusesShape(fn) {
  assert.throws(fn, (err) => err instanceof ProtocolError && err.code === "bad_shape");
}

test("schemas_cap_every_string_and_array", () => {
  let strings = 0;
  let arrays = 0;
  for (const { type, direction, schema } of allSchemas()) {
    assert.equal(schema.kind, "object", `${type} ${direction} is an object`);
    walk(schema, (node, path) => {
      const where = `${type} ${direction} ${path}`;
      if (node.kind === "string") {
        strings += 1;
        assert.ok(Number.isSafeInteger(node.max), `${where}: finite max`);
        assert.ok(node.max <= MAX_MESSAGE_BYTES, `${where}: max within a message`);
        assert.ok(node.min <= node.max, `${where}: min <= max`);
      } else if (node.kind === "array") {
        arrays += 1;
        assert.ok(Number.isSafeInteger(node.max), `${where}: finite max`);
        assert.ok(node.max <= 1000, `${where}: small array cap`);
      } else if (node.kind === "integer") {
        assert.ok(Number.isSafeInteger(node.min) && Number.isSafeInteger(node.max), where);
      }
    });
  }
  assert.ok(strings > 10 && arrays >= 3, "the walk found the schemas");

  // A schema cannot be built without a cap.
  assert.throws(() => string(/** @type {any} */ ({})), TypeError);
  assert.throws(() => string({ max: Infinity }), TypeError);
  assert.throws(() => string({ max: -1 }), TypeError);
  // A stateful pattern would alternate between pass and fail.
  assert.throws(() => string({ max: 8, pattern: /a/g }), TypeError);
  assert.throws(() => string({ max: 8, pattern: /a/y }), TypeError);
  assert.doesNotThrow(() => string({ max: 8, pattern: /a/i }));
  assert.throws(() => string({ max: 1.5 }), TypeError);
  assert.throws(() => array(boolean(), /** @type {any} */ ({})), TypeError);
  assert.throws(() => array(boolean(), { max: Infinity }), TypeError);
  assert.throws(() => integer({ min: 0, max: Infinity }), TypeError);
  assert.throws(() => object({ "a b": boolean() }), TypeError);
  assert.throws(() => object({ a: boolean() }, { optional: ["b"] }), TypeError);

  // A string and an array over their caps are refused.
  const raw = (/** @type {string} */ type, /** @type {unknown} */ body) =>
    JSON.stringify({ v: 1, id: "a", type, body });
  refusesShape(() => decode(raw("search", { query: "q".repeat(257) }), UI_TYPES));
  assert.equal(decode(raw("search", { query: "q".repeat(256) }), UI_TYPES).type, "search");
  const field = { kind: "username", id: "f" };
  const report = (/** @type {number} */ n) => ({
    request_id: "r",
    self_origin: "https://a.example",
    fields: Array.from({ length: n }, () => field),
  });
  assert.equal(decode(raw("frame_report", report(64)), CONTENT_TYPES).type, "frame_report");
  refusesShape(() => decode(raw("frame_report", report(65)), CONTENT_TYPES));
  refusesShape(() =>
    decode(
      raw("frame_report", { ...report(1), self_origin: "h".repeat(301) }),
      CONTENT_TYPES,
    ),
  );
});

test("no_ui_or_content_type_can_carry_a_secret_field", () => {
  const typed = new Map(
    Object.entries(TYPED_CREDENTIAL_KEYS).map(([type, keys]) => [type, new Set(keys)]),
  );
  const seenTyped = new Set();
  for (const { type, channel, direction, schema } of allSchemas()) {
    const allowed = new Set(
      /** @type {Record<string, readonly string[]>} */ (SECRET_KEY_EXCEPTIONS)[type] ?? [],
    );
    for (const key of keysOf(schema)) {
      const where = `${channel}/${type} ${direction}: ${key}`;
      if (allowed.has(key)) {
        assert.equal(channel, "push", `${where}: only the push type carries a value`);
        continue;
      }
      assert.ok(!FORBIDDEN_KEYS.includes(key), `${where}: forbidden key`);
      assert.ok(!/pass|secret|token|seed|^vk$|^ik$|totp_|key$/i.test(key), `${where}: secret-like name`);
      if (typed.get(type)?.has(key)) {
        // What the user types goes one way: an extension page to the background.
        assert.equal(channel, "ui", `${where}: typed in a page only`);
        assert.equal(direction, "request", `${where}: never in a reply`);
        seenTyped.add(`${type}.${key}`);
      } else {
        assert.ok(!/^(mp|sk|qr_text)$/.test(key), `${where}: typed credential outside its type`);
      }
    }
  }
  assert.deepEqual(
    [...seenTyped].sort(),
    ["sign_in.mp", "sign_in.qr_text", "sign_in.sk", "unlock.mp"],
  );
  assert.deepEqual(FORBIDDEN_KEYS, ["password", "value", "secret", "totp_secret", "vk"]);

  // And the decoder refuses them where they are not in the schema.
  const raw = (/** @type {string} */ type, /** @type {unknown} */ body) =>
    JSON.stringify({ v: 1, id: "a", type, body });
  const report = { request_id: "r", self_origin: "https://a.example", fields: [] };
  for (const key of [...FORBIDDEN_KEYS, "mp", "sk", "origin", "url", "top_origin"]) {
    refusesShape(() => decode(raw("frame_report", { ...report, [key]: "x" }), CONTENT_TYPES));
    refusesShape(() =>
      decode(raw("fill_result", { request_id: "r", ok: true, [key]: "x" }), CONTENT_TYPES),
    );
    refusesShape(() => decode(raw("state", { [key]: "x" }), UI_TYPES));
    refusesShape(() =>
      decode(raw("copy", { ref: "h", field: "password", [key]: "x" }), UI_TYPES),
    );
  }
  // A reply to the page never has a value, only handles and flags.
  refusesShape(() =>
    decode(
      raw("candidates", { handles: [{ ref: "h", name: "n", password: "x" }] }),
      UI_TYPES,
      { reply: true },
    ),
  );
});

test("the checker copies what it keeps and refuses what it does not know", () => {
  const schema = object(
    { a: string({ max: 4 }), b: integer({ min: 0, max: 9 }) },
    { optional: ["b"] },
  );
  const input = { a: "xy" };
  const out = validate(schema, input);
  assert.deepEqual(out, { a: "xy" });
  assert.notEqual(out, input);
  assert.deepEqual(validate(schema, { a: "x", b: 3 }), { a: "x", b: 3 });
  for (const bad of [
    { a: "xyzzy" },
    { a: "x", b: 10 },
    { a: "x", b: 1.5 },
    { a: "x", b: Number.NaN },
    { a: "x", b: "3" },
    { a: "x", c: 1 },
    { b: 1 },
    { a: 1 },
    [],
    null,
    "a",
    Object.create({ a: "x" }),
  ]) {
    refusesShape(() => validate(schema, bad));
  }
  const withPattern = string({ max: 8, pattern: /^[a-z]+$/, min: 1 });
  assert.equal(validate(withPattern, "abc"), "abc");
  refusesShape(() => validate(withPattern, ""));
  refusesShape(() => validate(withPattern, "ABC"));
  const list = array(boolean(), { max: 2 });
  assert.deepEqual(validate(list, [true, false]), [true, false]);
  refusesShape(() => validate(list, [true, false, true]));
  refusesShape(() => validate(list, [1]));
  // Nested failures name the path and never the value.
  assert.throws(
    () => validate(object({ xs: list }), { xs: [true, "secret-value"] }),
    (err) =>
      err instanceof ProtocolError &&
      err.path === "body.xs[1]" &&
      !err.message.includes("secret-value"),
  );
});

test("every UI request and reply round-trips with a sample body", () => {
  const samples = {
    state: [{}, { state: "unlocked", server: "https://vault.example", lock_at: 1_700_000_000_000 }],
    lock: [{}, { ok: true }],
    sign_in: [
      { server: "https://vault.example", email: "a@example.com", mp: "pw", sk: "A3-XXXX" },
      { ok: false, reason: "bad_credentials" },
    ],
    unlock: [{ mp: "pw" }, { ok: true }],
    candidates: [
      { tab_id: 1, frame_id: 0 },
      { handles: [{ ref: "h1", name: "Example", username: "me", insecure: false }] },
    ],
    search: [{ query: "ex" }, { handles: [] }],
    fill: [{ ref: "h1", tab_id: 1, frame_id: 0 }, { ok: true }],
    copy: [{ ref: "h1", field: "totp" }, { ok: true }],
    settings: [{ lock_minutes: 15 }, { lock_minutes: 15 }],
  };
  assert.deepEqual(Object.keys(samples).sort(), Object.keys(UI_TYPES).sort());
  for (const [type, [request, reply]] of Object.entries(samples)) {
    const req = decode(encode(type, request, { id: "i1" }), UI_TYPES);
    assert.deepEqual(req, { id: "i1", type, body: request });
    const rep = decode(encode(type, reply, { id: "i1", reply: true }), UI_TYPES, { reply: true });
    assert.deepEqual(rep, { id: "i1", type, body: reply });
  }
});
