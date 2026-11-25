import assert from "node:assert/strict";
import { test } from "node:test";

import {
  CONTENT_TYPES,
  FORBIDDEN_KEYS,
  MAX_BYTES_BY_TYPE,
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
  nullable,
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
      if (typed.get(type)?.has(key)) {
        // What the user types goes one way: an extension page to the background. (A typed key may be a forbidden name,
        // `password` and `pin`, and then SECRET_KEY_EXCEPTIONS names exactly this type for it.)
        assert.equal(channel, "ui", `${where}: typed in a page only`);
        assert.equal(direction, "request", `${where}: never in a reply`);
        if (FORBIDDEN_KEYS.includes(key)) assert.ok(allowed.has(key), `${where}: a forbidden name needs its exception`);
        seenTyped.add(`${type}.${key}`);
        continue;
      }
      if (allowed.has(key)) {
        // The fill value goes down to a page (push); what the person typed into a form goes up (content); the generator's
        // reply carries the value the core has just made. Nothing else.
        const generatorReply = channel === "ui" && type === "generate" && direction === "reply";
        const revealReply = channel === "ui" && type === "offer_reveal" && direction === "reply";
        const codeReply = channel === "ui" && type === "item_code" && direction === "reply";
        assert.equal(generatorReply || revealReply || codeReply || channel === (type === "form_capture" ? "content" : "push"), true, `${where}: only the push type, the generator's, the offer's and the one-time code's replies and the capture's typed password carry a value`);
        if (type === "form_capture") assert.equal(direction, "request", `${where}: never in a reply`);
        continue;
      }
      assert.ok(!FORBIDDEN_KEYS.includes(key), `${where}: forbidden key`);
      assert.ok(!/pass|secret|token|seed|^vk$|^ik$|totp_|key$/i.test(key), `${where}: secret-like name`);
      assert.ok(!/^(mp|sk|qr_text|secret_key)$/.test(key), `${where}: typed credential outside its type`);
    }
  }
  assert.deepEqual(
    [...seenTyped].sort(),
    ["pin_set.mp", "pin_set.pin", "pin_set.sk", "pin_unlock.pin", "prf_unlock.prf_output", "sign_in.mp", "sign_in.qr_text", "sign_in.sk", "unlock.mp", "unlock.sk"],
  );
  assert.deepEqual(FORBIDDEN_KEYS, ["password", "current_password", "value", "secret", "totp_secret", "code", "vk", "pin", "prf_output"]);

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
  // The one-time code mark of a row is a boolean and nothing else: never the code or its seed.
  const rowReply = (/** @type {unknown} */ mark) => raw("search", { handles: [{ ref: "h2", name: "n", has_totp: mark }], total: 1 });
  assert.equal(decode(rowReply(true), UI_TYPES, { reply: true }).type, "search");
  assert.equal(decode(rowReply(false), UI_TYPES, { reply: true }).type, "search");
  for (const mark of ["492039", 1, null, { code: "492039" }]) refusesShape(() => decode(rowReply(mark), UI_TYPES, { reply: true }));
  refusesShape(() => decode(raw("search", { handles: [{ ref: "h2", name: "n", totp_secret: "JBSWY3DP" }], total: 1 }), UI_TYPES, { reply: true }));
  // A reply to the page never has a value, only references, names and flags.
  refusesShape(() =>
    decode(
      raw("candidates", { insecure: false, items: [{ ref: "h", name: "n", how: "host", frame_id: 0, password: "x" }], grant: [] }),
      UI_TYPES,
      { reply: true },
    ),
  );
  refusesShape(() =>
    decode(
      raw("candidates", { insecure: false, items: [{ ref: "h", name: "n", how: "host", frame_id: 0, handle: 3 }], grant: [] }),
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
    state: [{}, { state: "unlocked", server: "https://vault.example", host: "vault.example", host_a_label: "vault.example", account: "a@example.com", lock_at: 1_700_000_000_000 }],
    server_check: [{ server: "vault.example" }, { ok: true, server: "https://vault.example", host: "vault.example", host_a_label: "vault.example" }],
    lock: [{}, { ok: true }],
    sign_in: [
      { server: "https://vault.example", email: "a@example.com", mp: "pw", sk: "A3-XXXX", sk_bit: true, remember_sk: false, qr_text: "ferret-setup:v1" },
      { ok: true, account_email: "a@example.com", server: "https://vault.example" },
    ],
    unlock: [{ mp: "pw", sk: "A3-XXXX" }, { ok: false, reason: "wrong_credentials" }],
    candidates: [
      { tab_id: 1, frame_id: 0 },
      {
        handles: [{ ref: "h1", name: "Example", username: "me", insecure: false, favorite: true, type: "login", site: true, next: true, frame_id: 0 }],
        host: { a_label: "login.example.net", unicode: "login.example.net" },
        insecure: false,
        grant: [{ origin: "https://sso.example.net", host: { a_label: "sso.example.net", unicode: "sso.example.net" } }],
      },
    ],
    grant_check: [
      { origin: "https://sso.example.net" },
      { ok: true, origin: "https://sso.example.net", host: { a_label: "sso.example.net", unicode: "sso.example.net" }, pattern: "https://sso.example.net/*" },
    ],
    search: [{ query: "ex", favorites: true, type: "login", offset: 40, automatic: true }, { handles: [{ ref: "h2", name: "Example", has_totp: true }], total: 41 }],
    fill: [{ ref: "h1", tab_id: 1, frame_id: 0, only: "totp" }, { ok: true }],
    item_code: [{ ref: "h1", automatic: true }, { ok: true, code: "081804", seconds_left: 21 }],
    copy: [{ ref: "h1", field: "totp" }, { ok: true }],
    item: [{ ref: "h1" }, { ok: true, name: "Example", username: "me", type: "login", favorite: false, urls: ["https://example.com/login"], copyable: ["username", "password", "totp"] }],
    open_site: [{ ref: "h1" }, { ok: false, reason: "no_site" }],
    settings: [{ lock_seconds: 900 }, { lock_seconds: 900 }],
    sync_state: [{}, { running: true, status: "idle", live: "live", halted: "server_restored", warnings: ["rev_lower_than_local"], pending: 2, blocked: 1, conflicts: 1 }],
    sync_retry: [{}, { ok: false, reason: "sync_still_halted" }],
    sync_older_preview: [{}, { ok: true, reupload: 3, conflicts: 1, manifest_older: false }],
    sync_accept_older: [{ confirmed: true }, { ok: true, reuploaded: 3, conflicts: 1, manifest_older: true, unreadable: 0 }],
    forget_preview: [{ server: "https://vault.example" }, { ok: true, pending: 2, shared: false }],
    forget_server: [{ server: "https://vault.example" }, { ok: true }],
    sync_items: [{}, { items: [{ ref: "h1", name: "Example", username: "me", state: "blocked", reason: "quota_exceeded" }, { ref: "h2", name: "Other", state: "conflict" }], total: 2 }],
    item_conflict: [
      { ref: "h2" },
      {
        ok: true,
        mine: { deleted: false, name: "Other", username: "me", modified: 1_700_000_000_000, device: "Ferret for Firefox (Windows)" },
        theirs: { deleted: true },
        differs: [{ what: "name" }, { what: "field", label: "Recovery e-mail" }, { what: "hidden" }],
      },
    ],
    item_resolve: [{ ref: "h2", choice: "mine" }, { ok: false, reason: "conflict_changed" }],
    item_discard: [{ ref: "h1" }, { ok: true }],
    generate: [
      { kind: "password", length: 20, lower: true, upper: true, digits: true, symbols: true, min_each: 1, avoid_ambiguous: false },
      { ok: true, generation_id: "g1", value: "Zq9!sample", kind: "password", bits: 100, expires_at: 1_700_000_900_000 },
    ],
    generate_copy: [{ generation_id: "g1" }, { ok: true }],
    fill_generated: [{ generation_id: "g1", tab_id: 7, frame_id: 0 }, { ok: true, length: 20, offer: true }],
    capture_settings: [
      { enable: true, never_remove: "shop.example.net", auto_open: false },
      { ok: true, on: true, permission: true, never: ["shop.example.net"], auto_open: false, auto_open_state: "fails" },
    ],
    offer_list: [
      { tab_id: 7 },
      {
        ok: true,
        offers: [{ offer_id: "a1".repeat(16), kind: "signup", host: { a_label: "shop.example.net", unicode: "shop.example.net" }, username: "me", generated: true, incognito: false }],
        notice: "frame_hidden",
      },
    ],
    offer_classify: [
      { offer_id: "a1".repeat(16) },
      {
        ok: true,
        action: "update",
        targets: [{ id: "b2".repeat(16), rev: 2, name: "Shop", username: "me", how: "host" }],
        domain_only: [{ id: "c3".repeat(16), rev: 1, name: "Shop shared", host: null }],
        reused: [{ name: "Other", host: { a_label: "other.example.org", unicode: "other.example.org" } }],
        username_from: "typed",
      },
    ],
    folder_names: [{}, { ok: true, folders: ["Work", "Private"] }],
    offer_save: [{ offer_id: "a1".repeat(16), name: "Shop", username: "me", folder: "Work" }, { ok: true, pending: true }],
    offer_update: [
      { offer_id: "a1".repeat(16), id: "b2".repeat(16), rev: 2, picked: true },
      {
        ok: false,
        reason: "item_changed",
        classification: { action: "save", targets: [], domain_only: [], reused: [], username_from: null },
      },
    ],
    offer_dismiss: [{ offer_id: "a1".repeat(16) }, { ok: true }],
    offer_never: [{ offer_id: "a1".repeat(16) }, { ok: false, reason: "not_offered" }],
    offer_reveal: [{ offer_id: "a1".repeat(16) }, { ok: true, value: "Zq9!sample" }],
    unlock_policy: [
      {},
      {
        pin_state: { allowed: true, after_restart: true, min_length: 6, set: true, location: "disk", failures_left: 4, wait_ms: 5000, offline_ok: true },
        prf: { enabled: false },
      },
    ],
    pin_set: [{ mp: "p", sk: "FFS1-X", pin: "123456", location: "disk", acknowledged: true }, { ok: false, reason: "wrong_credentials" }],
    pin_unlock: [{ pin: "123456" }, { ok: false, reason: "wrong_pin", left: 3, wait_ms: 5000 }],
    pin_off: [{}, { ok: true }],
    prf_options: [{}, { ok: true, rp_id: "vault.example.com", credentials: [{ id: "AQID", salt: "a".repeat(43) }] }],
    prf_window: [{}, { ok: true }],
    passkey_never: [{ request_id: "ab".repeat(16) }, { ok: true }],
    prf_unlock: [{ credential_id: "AQID", prf_output: "b".repeat(43) }, { ok: false, reason: "prf_failed" }],
    passkey_pending: [
      { request_id: "a1".repeat(16) },
      {
        ok: true,
        request: {
          request_id: "a1".repeat(16),
          kind: "get",
          mediation: "optional",
          origin: "https://rp.example",
          rp_id: null,
          rp_name: null,
          user_name: null,
          user_display_name: null,
          user_verification: "preferred",
          credentials: 0,
          prf: false,
          expires_in: 300000,
          foreign: false,
          incognito: false,
        },
      },
    ],
    passkey_site: [
      { request_id: "a1".repeat(16) },
      { ok: true, site: { origin: "https://xn--bcher-kva.example", host_unicode: "bücher.example", rp_id: "xn--bcher-kva.example", rp_id_unicode: "bücher.example" } },
    ],
    passkey_cancel: [{ request_id: "a1".repeat(16) }, { ok: false, reason: "gone" }],
    passkey_browser: [{ request_id: "a1".repeat(16) }, { ok: true }],
  };
  assert.deepEqual(Object.keys(samples).sort(), Object.keys(UI_TYPES).sort());
  for (const [type, [request, reply]] of Object.entries(samples)) {
    const req = decode(encode(type, request, { id: "i1" }), UI_TYPES);
    assert.deepEqual(req, { id: "i1", type, body: request });
    const rep = decode(encode(type, reply, { id: "i1", reply: true }), UI_TYPES, { reply: true });
    assert.deepEqual(rep, { id: "i1", type, body: reply });
  }
});

test("content_to_background_secrets_are_allowed_only_in_form_capture", () => {
  // Both keys are forbidden names, and the one place that may carry them is the capture of a submitted form.
  assert.ok(FORBIDDEN_KEYS.includes("password") && FORBIDDEN_KEYS.includes("current_password"));
  assert.deepEqual({ ...SECRET_KEY_EXCEPTIONS }, {
    fill_field: ["value"], generate: ["value"], form_capture: ["password", "current_password"], offer_reveal: ["value"], item_code: ["code"],
    pin_set: ["pin"], pin_unlock: ["pin"], prf_unlock: ["prf_output"],
  });
  // The name `pin` has exactly two exceptions (GC50): the requests of `pin_set` and `pin_unlock`. No reply carries it, and the
  // rule and the state in the reply of `unlock_policy` are `pin_state`.
  assert.deepEqual(
    Object.entries(SECRET_KEY_EXCEPTIONS).filter(([, keys]) => keys.includes("pin")).map(([type]) => type),
    ["pin_set", "pin_unlock"],
  );
  assert.ok(FORBIDDEN_KEYS.includes("pin") && !FORBIDDEN_KEYS.includes("pin_state"));
  /** @type {string[]} */
  const holders = [];
  for (const { type, channel, direction, schema } of allSchemas()) {
    for (const key of keysOf(schema)) {
      if (FORBIDDEN_KEYS.includes(key)) holders.push(`${channel}/${type}/${direction}/${key}`);
    }
  }
  assert.deepEqual(holders.sort(), [
    "content/form_capture/request/current_password",
    "content/form_capture/request/password",
    "push/fill_field/request/value",
    "ui/generate/reply/value",
    "ui/item_code/reply/code",
    "ui/offer_reveal/reply/value",
    "ui/pin_set/request/pin",
    "ui/pin_unlock/request/pin",
    "ui/prf_unlock/request/prf_output",
  ]);
  // Not a UI type and not a push type: the capture is accepted on the content channel only, and has no reply.
  const raw = (/** @type {string} */ type, /** @type {unknown} */ body) => JSON.stringify({ v: 1, id: "a", type, body });
  const capture = {
    capture_id: "c1", self_origin: "https://a.example", kind: "change", username: "anna", username_from: "typed",
    password: "new-secret", current_password: "old-secret",
  };
  assert.deepEqual(decode(raw("form_capture", capture), CONTENT_TYPES).body, capture);
  for (const table of [UI_TYPES, PUSH_TYPES]) {
    assert.throws(() => decode(raw("form_capture", capture), table), (err) => err instanceof ProtocolError && err.code === "unknown_type");
  }
  assert.throws(() => decode(raw("form_capture", capture), CONTENT_TYPES, { reply: true }), (err) => err instanceof ProtocolError && err.code === "unknown_type");
  assert.equal(CONTENT_TYPES.form_capture.reply, undefined);
  // Every other content type refuses both keys, and so does the capture for any other name of a secret.
  for (const type of ["frame_report", "fill_result", "form_gone", "page_ready"]) {
    for (const key of ["password", "current_password"]) {
      const body = { frame_report: { request_id: "r", self_origin: "https://a.example", fields: [] }, fill_result: { request_id: "r", ok: true }, form_gone: { capture_id: "c" }, page_ready: {} }[type];
      refusesShape(() => decode(raw(type, { ...body, [key]: "x" }), CONTENT_TYPES));
    }
  }
  for (const key of ["value", "secret", "totp_secret", "vk", "mp", "sk", "url", "origin"]) {
    refusesShape(() => decode(raw("form_capture", { ...capture, [key]: "x" }), CONTENT_TYPES));
  }
  // The values are strings or null, never missing, never another type.
  for (const key of ["username", "username_from", "password", "current_password"]) {
    assert.equal(decode(raw("form_capture", { ...capture, [key]: null }), CONTENT_TYPES).body[key], null);
    const missing = /** @type {any} */ ({ ...capture });
    delete missing[key];
    refusesShape(() => decode(raw("form_capture", missing), CONTENT_TYPES));
    refusesShape(() => decode(raw("form_capture", { ...capture, [key]: 7 }), CONTENT_TYPES));
    refusesShape(() => decode(raw("form_capture", { ...capture, [key]: ["x"] }), CONTENT_TYPES));
  }
  refusesShape(() => decode(raw("form_capture", { ...capture, kind: "otp" }), CONTENT_TYPES));
  refusesShape(() => decode(raw("form_capture", { ...capture, username_from: "fill" }), CONTENT_TYPES));
  // The limits: a user name up to 512, a password up to 1 024, a message up to 4 KiB.
  assert.equal(decode(raw("form_capture", { ...capture, username: "u".repeat(512), password: "p".repeat(1024), current_password: "c".repeat(1024) }), CONTENT_TYPES).type, "form_capture");
  refusesShape(() => decode(raw("form_capture", { ...capture, username: "u".repeat(513) }), CONTENT_TYPES));
  refusesShape(() => decode(raw("form_capture", { ...capture, password: "p".repeat(1025) }), CONTENT_TYPES));
  refusesShape(() => decode(raw("form_capture", { ...capture, current_password: "c".repeat(1025) }), CONTENT_TYPES));
  refusesShape(() => decode(raw("form_capture", { ...capture, password: "" }), CONTENT_TYPES));
  assert.equal(MAX_BYTES_BY_TYPE.form_capture, 4096);
  const wide = { ...capture, username: "å".repeat(512), password: "å".repeat(1024), current_password: "å".repeat(1024) };
  assert.throws(() => decode(raw("form_capture", wide), CONTENT_TYPES), (err) => err instanceof ProtocolError && err.code === "too_large");
  assert.throws(() => encode("form_capture", wide), (err) => err instanceof ProtocolError && err.code === "too_large");
  // An error names the path and never the value.
  assert.throws(
    () => decode(raw("form_capture", { ...capture, password: "x".repeat(1025) }), CONTENT_TYPES),
    (err) => err instanceof ProtocolError && err.path === "body.password" && !err.message.includes("xxx"),
  );
  // The nullable schema itself.
  const maybe = object({ a: nullable(string({ max: 3 })) });
  assert.deepEqual(validate(maybe, { a: null }), { a: null });
  assert.deepEqual(validate(maybe, { a: "ab" }), { a: "ab" });
  refusesShape(() => validate(maybe, {}));
  refusesShape(() => validate(maybe, { a: "abcd" }));
  refusesShape(() => validate(maybe, { a: undefined }));
});
