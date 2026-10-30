// The wire contract, from the web side. The files in
// crates/ferret-server/tests/fixtures/wire/ are the same ones the Rust tests
// read (crates/ferret-server/tests/wire_contract.rs): both sides read the same
// valid examples and refuse the same inputs from invalid.json, with the same
// code, so the server and the web vault cannot drift apart.
//
// The rules below are the reference for the web client's own reader of server
// answers and the writer of requests: a strict JSON reader (repeated fields and
// numbers such as 1.0 or 1e3 are refused, which JSON.parse does not do) and a
// field-by-field description of every shape.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { SERVER_HEADERS_JSON } from "../serve.mjs";
import { files } from "../../../crates/ferret-server/tests/fixtures/wire/generate.mjs";

const DIR = join(SERVER_HEADERS_JSON, "..");
const NOT_SHAPES = ["headers.json", "generate.mjs", "error_codes.json", "invalid.json"];

const read = (name) => readFileSync(join(DIR, name), "utf8");
const parseFile = (name) => JSON.parse(read(name));

// ------------------------------------------------------------- refusals

/** A refusal carries the code of the answer. */
class Refusal extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.code = code;
  }
}
const refuse = (message, code = "bad_request") => {
  throw new Refusal(code, message);
};

// ----------------------------------------------------------- JSON reader

const MAX_INT = Number.MAX_SAFE_INTEGER; // 2^53 - 1
const WHITE = new Set([" ", "\t", "\n", "\r"]);

/**
 * Reads JSON text strictly: a repeated field is refused, and so is every number
 * that is not a whole number from 0 to 2^53 - 1 written without a sign,
 * fraction or exponent (the wire has no other numbers).
 */
function readJson(text) {
  try {
    JSON.parse(text); // the syntax
  } catch (error) {
    refuse(`not JSON: ${error.message}`);
  }
  let at = 0;
  const skip = () => {
    while (WHITE.has(text[at])) at += 1;
  };
  const string = () => {
    const pattern = /"(?:[^"\\]|\\.)*"/y;
    pattern.lastIndex = at;
    const hit = pattern.exec(text);
    at = pattern.lastIndex;
    return JSON.parse(hit[0]);
  };
  const value = () => {
    skip();
    const c = text[at];
    if (c === "{") {
      at += 1;
      const out = Object.create(null);
      skip();
      if (text[at] === "}") {
        at += 1;
        return out;
      }
      for (;;) {
        skip();
        const key = string();
        if (Object.hasOwn(out, key)) refuse(`repeated field ${key}`);
        skip();
        at += 1; // ":"
        out[key] = value();
        skip();
        const next = text[at];
        at += 1;
        if (next === "}") return out;
      }
    }
    if (c === "[") {
      at += 1;
      const out = [];
      skip();
      if (text[at] === "]") {
        at += 1;
        return out;
      }
      for (;;) {
        out.push(value());
        skip();
        const next = text[at];
        at += 1;
        if (next === "]") return out;
      }
    }
    if (c === '"') return string();
    const pattern = /true|false|null|-?[0-9][0-9.eE+-]*/y;
    pattern.lastIndex = at;
    const token = pattern.exec(text)[0];
    at = pattern.lastIndex;
    if (token === "true") return true;
    if (token === "false") return false;
    if (token === "null") return null;
    if (!/^(0|[1-9][0-9]*)$/.test(token) || Number(token) > MAX_INT) {
      refuse(`not a wire integer: ${token}`);
    }
    return Number(token);
  };
  return value();
}

// ----------------------------------------------------------------- rules

/** Strict base64url without padding: the alphabet, no spare bits. */
function decode(text, code = "bad_request") {
  if (typeof text !== "string") refuse("not a string");
  if (!/^[A-Za-z0-9_-]*$/.test(text)) refuse("not base64url", code);
  const bytes = Buffer.from(text, "base64url");
  if (bytes.toString("base64url") !== text) refuse("not canonical base64url", code);
  return bytes;
}

// A field check is a function that refuses a value it does not accept.
const b = (text) => void decode(text);
const bytes = (n, code = "bad_request") => (text) => {
  const got = decode(text, code).length;
  if (got !== n) refuse(`expected ${n} bytes, got ${got}`, code);
};
const b32 = bytes(32);
const id = (text) => {
  if (typeof text !== "string" || !/^[0-9a-f]{32}$/.test(text)) refuse("not an id");
};
const int = (max = MAX_INT) => (n) => {
  if (!Number.isSafeInteger(n) || n < 0 || n > max) refuse("not a wire integer");
};
const str = (s) => {
  if (typeof s !== "string") refuse("not a string");
};
const bool = (v) => {
  if (typeof v !== "boolean") refuse("not a boolean");
};
const oneOf = (...words) => (v) => {
  if (!words.includes(v)) refuse(`not one of ${words}`);
};
const list = (spec) => (v) => {
  if (!Array.isArray(v)) refuse("not a list");
  for (const item of v) shape(spec, item);
};
const nested = (spec) => (v) => shape(spec, v);
const FORBIDDEN_IN_NAME = /[\p{Cc}؜​‎‏‪-‮⁠⁦-⁩﻿]/u;
const deviceName = (v) => {
  str(v);
  if ([...v].length > 64) refuse("device_name is longer than 64 characters");
  if (FORBIDDEN_IN_NAME.test(v)) refuse("device_name has a control or invisible character");
};
const next = (v) => {
  str(v);
  const n = [...v].length;
  if (n < 1 || n > 512) refuse("next is empty or longer than 512 characters");
};
const methodType = (v) => {
  int(3)(v);
  if (v < 1) refuse("method_type is 1, 2 or 3");
};

/** `[field, check, optional]`, in the order the server writes them. */
const wrap = [
  ["method_id", id],
  ["method_type", methodType],
  ["kek_generation", int()],
  ["wrap", b],
  ["credential_id", b, true],
  ["prf_salt", b32, true],
];
const sealedRow = [["rev", int()], ["envelope", b], ["tag", b32]];
const checkpoint = [["seq", int()], ["digest", b32], ["mac", b32], ["entries", b]];
const head = [["seq", int()], ["digest", b32], ["mac", b32]];
const change = [
  ["id", id], ["rev", int()], ["seq", int()], ["deleted", bool],
  ["blob", b, true], ["tag", b32, true], ["tomb", bytes(40, "tombstone_invalid"), true],
];

const SHAPES = {
  sealed_row: sealedRow,
  wrap,
  checkpoint,
  checkpoint_head: head,
  register_start_req: [
    ["setup_token", str, true], ["email", str], ["request", bytes(32, "malformed_registration_request")],
  ],
  register_start_res: [
    ["registration_id", id], ["account_id", id], ["vault_id", id],
    ["response", bytes(64)], ["ksf_profile", int(255)],
  ],
  register_finish_req: [
    ["registration_id", id], ["device_id", id], ["device_name", deviceName, true],
    ["record", bytes(192, "malformed_registration_record")], ["ksf_profile", int(2 ** 32 - 1)], ["sk_bit", bool],
    ["wraps", list(wrap)], ["manifest", nested(sealedRow)], ["checkpoint", nested(checkpoint)],
    ["pk_a", b32], ["pk_r", b32],
  ],
  register_finish_res: [["account_id", id], ["vault_id", id]],
  login_start_req: [
    ["email", str], ["ke1", bytes(96, "malformed_ke1")], ["purpose", oneOf("login", "reauth"), true],
  ],
  login_start_res: [["login_id", id], ["ke2", bytes(320)], ["ksf_profile", int(255)], ["sk_hint", bool]],
  login_finish_req: [
    ["login_id", id], ["ke3", bytes(64, "malformed_ke3")], ["device_id", id], ["device_name", deviceName, true],
  ],
  login_finish_res: [["account_id", id], ["vault_id", id], ["vk_epoch", int()]],
  handoff_req: [["purpose", oneOf("login", "reauth")], ["next", next], ["challenge", b32]],
  handoff_res: [["code", bytes(32)], ["expires_in", int()]],
  redeem_req: [["code", str]],
  handoff_redeem_res: [["next", str]],
  session_res: [
    ["account_id", id, true], ["email", str], ["scope", str], ["origin", oneOf("vault", "admin")],
  ],
  methods_res: [["methods", list(wrap)], ["pk_a", b32], ["vk_epoch", int()], ["manifest", nested(sealedRow)]],
  change,
  changes_res: [
    ["changes", list(change)], ["latest_seq", int()], ["vk_epoch", int()], ["restore_epoch", int()],
    ["checkpoint", nested(head), true], ["has_more", bool],
  ],
  put_item_req: [
    ["base_rev", int()], ["blob", b, true], ["tag", b32, true], ["deleted", bool, true],
    ["tomb", bytes(40, "tombstone_invalid"), true], ["idem", id], ["resurrect", bool, true],
  ],
  put_item_res: [["rev", int()], ["seq", int()], ["replayed", bool]],
  conflict_res: [["current_rev", int()], ["blob", b, true], ["tag", b32, true], ["deleted", bool]],
  error_res: [["error", str]],
};

/** Checks that `value` has only the fields of `spec` and that each is valid. */
function shape(spec, value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) refuse("not an object");
  const names = spec.map(([name]) => name);
  for (const key of Object.keys(value)) {
    if (!names.includes(key)) refuse(`unknown field ${key}`);
  }
  for (const [name, check, optional] of spec) {
    const present = name in value && !(optional && value[name] === null);
    if (!present) {
      if (!optional) refuse(`missing field ${name}`);
      continue;
    }
    check(value[name]);
  }
}

/** Reads `text` as the shape `kind`. */
function readWire(kind, text) {
  const value = readJson(text);
  shape(SHAPES[kind], value);
  return value;
}

/** A hand-over code: 43 characters of strict base64url that decode to 32 bytes. */
function handoffCode(code) {
  str(code);
  if (code.length !== 43) refuse("a hand-over code has 43 characters", "handoff_invalid");
  if (decode(code, "handoff_invalid").length !== 32) refuse("not 32 bytes", "handoff_invalid");
}

/** The check that comes with a shape once it is read. */
function checkStep(kind, value) {
  if (kind === "redeem_req") handoffCode(value.code);
  if (kind !== "put_item_req") return;
  const has = (key) => value[key] !== undefined && value[key] !== null;
  if (value.resurrect === true) refuse("resurrect is not supported yet");
  const live = has("blob") && has("tag") && !has("tomb") && value.deleted !== true;
  const gone = !has("blob") && !has("tag") && has("tomb") && value.deleted === true;
  if (!live && !gone) refuse("a put request is a live row or a tombstone, never both");
}

const kindOf = (name) => name.split(".")[0];
const fixtures = () =>
  readdirSync(DIR)
    .filter((name) => name.endsWith(".json") && !NOT_SHAPES.includes(name))
    .sort();
const errorCodes = () => parseFile("error_codes.json");

/** Runs `fn` and returns the code it refuses with; fails if it does not refuse. */
function refusalOf(fn) {
  try {
    fn();
  } catch (error) {
    if (error instanceof Refusal) return error.code;
    throw error;
  }
  return null;
}

// ----------------------------------------------------------------- tests

test("every_fixture_roundtrips_byte_for_byte", () => {
  const all = fixtures();
  assert.ok(all.length >= 30);
  for (const name of all) {
    const kind = kindOf(name);
    assert.ok(kind in SHAPES, `no shape for ${name}`);
    const text = read(name);
    const value = readWire(kind, text);
    assert.equal(`${JSON.stringify(value)}\n`, text, name);
  }
  assert.deepEqual([...new Set(all.map(kindOf))].sort(), Object.keys(SHAPES).sort());
});

test("the_fixtures_are_what_generate_mjs_makes", () => {
  const made = files();
  for (const [name, text] of Object.entries(made)) assert.equal(read(name), text, name);
  for (const name of readdirSync(DIR)) {
    assert.ok(name in made || ["headers.json", "generate.mjs"].includes(name), `${name} is not generated`);
  }
});

test("every_fixture_passes_its_own_check", () => {
  for (const name of fixtures()) {
    const value = readWire(kindOf(name), read(name));
    if (name === "put_item_req.resurrect.json") {
      // It reads, and this version of the server refuses it.
      assert.equal(refusalOf(() => checkStep(kindOf(name), value)), "bad_request");
    } else {
      checkStep(kindOf(name), value);
    }
  }
});

test("invalid_inputs_are_refused_at_their_layer_with_their_code", () => {
  const cases = parseFile("invalid.json");
  assert.ok(cases.length >= 200, `found only ${cases.length} cases`);
  assert.equal(new Set(cases.map((c) => c.name)).size, cases.length, "a case name is used twice");
  const codes = errorCodes();
  for (const c of cases) {
    const label = `${c.name} (${c.why})`;
    assert.deepEqual(Object.keys(c), ["name", "shape", "json", "layer", "error", "why"], label);
    assert.ok(c.why.length > 0, label);
    assert.ok(codes.includes(c.error), `${label}: ${c.error} is not a listed code`);
    assert.ok(c.shape in SHAPES, label);
    if (c.layer === "parse") {
      assert.equal(refusalOf(() => readWire(c.shape, c.json)), c.error, label);
    } else {
      assert.equal(c.layer, "validate", label);
      const value = readWire(c.shape, c.json); // reads without error
      assert.equal(refusalOf(() => checkStep(c.shape, value)), c.error, label);
    }
  }
  assert.deepEqual([...new Set(cases.map((c) => c.layer))].sort(), ["parse", "validate"]);
  const used = new Set(cases.map((c) => c.error));
  for (const code of [
    "bad_request", "handoff_invalid", "malformed_ke1", "malformed_ke3",
    "malformed_registration_request", "malformed_registration_record", "tombstone_invalid",
  ]) {
    assert.ok(used.has(code), `no case for ${code}`);
  }
  const shapes = new Set(cases.map((c) => c.shape));
  for (const kind of Object.keys(SHAPES)) assert.ok(shapes.has(kind), `no invalid case for ${kind}`);
});

test("b64url_rejects_padding_standard_alphabet_and_whitespace", () => {
  assert.equal(decode("AAEC").length, 3);
  assert.equal(decode("").length, 0);
  assert.equal(decode("-_8").toString("hex"), "fbff");
  for (const bad of ["AA==", "+/8", "AA EC", " AAEC", "AAEC\n", "AB", "A", "AAECé"]) {
    assert.equal(refusalOf(() => decode(bad)), "bad_request", JSON.stringify(bad));
  }
});

test("hex16_rejects_uppercase_short_and_long", () => {
  id("00010a0f10a0f0ff123456789abcdef0");
  for (const bad of [
    "00010A0F10A0F0FF123456789ABCDEF0",
    "00010a0f10a0f0ff123456789abcde",
    "00010a0f10a0f0ff123456789abcdef00",
    "",
    "00010a0f10a0f0ff123456789abcdef\n",
  ]) {
    assert.equal(refusalOf(() => id(bad)), "bad_request", JSON.stringify(bad));
  }
});

test("integers_are_whole_numbers_up_to_2_pow_53_minus_1_written_plainly", () => {
  assert.equal(readJson("9007199254740991"), 9007199254740991);
  for (const bad of ["9007199254740992", "-1", "-0", "1.5", "1.0", "1e3", "1E3", "01"]) {
    assert.equal(refusalOf(() => readJson(bad)), "bad_request", bad);
  }
  assert.equal(refusalOf(() => readJson('{"a":1,"a":2}')), "bad_request");
  assert.equal(refusalOf(() => readJson('{"a":{"b":1,"b":1}}')), "bad_request");
  assert.equal(refusalOf(() => readJson("")), "bad_request");
});

test("lengths_match_the_spec", () => {
  const len = (text) => decode(text).length;
  assert.equal(len(parseFile("login_start_req.json").ke1), 96);
  assert.equal(len(parseFile("login_start_res.json").ke2), 320);
  assert.equal(len(parseFile("login_finish_req.json").ke3), 64);
  assert.equal(len(parseFile("register_start_req.json").request), 32);
  assert.equal(len(parseFile("register_start_res.json").response), 64);
  const finish = parseFile("register_finish_req.json");
  assert.equal(len(finish.record), 192);
  const [password, recovery] = finish.wraps;
  assert.equal([password.method_type, recovery.method_type].join(), "1,2");
  assert.equal(len(password.wrap), 104);
  assert.equal(len(recovery.wrap), 72);
  assert.equal(len(parseFile("put_item_req.tombstone.json").tomb), 40);
  assert.equal(len(parseFile("change.deleted.json").tomb), 40);
  assert.equal(len(parseFile("put_item_req.live.json").tag), 32);
  for (const field of ["pk_a", "pk_r"]) assert.equal(len(finish[field]), 32);
  assert.equal(len(finish.manifest.tag), 32);
  const entries = decode(finish.checkpoint.entries);
  assert.equal(entries.length, 56);
  assert.equal(decode(finish.checkpoint.digest).toString("hex"), createHash("sha256").update(entries).digest("hex"));
  assert.equal(len(finish.checkpoint.mac), 32);
});

test("put_item_requires_exactly_one_form", () => {
  const live = readWire("put_item_req", read("put_item_req.live.json"));
  const gone = readWire("put_item_req", read("put_item_req.tombstone.json"));
  checkStep("put_item_req", live);
  checkStep("put_item_req", gone);
  checkStep("put_item_req", { ...live, deleted: false });
  checkStep("put_item_req", { ...live, resurrect: false });
  checkStep("put_item_req", { ...live, tomb: null });
  for (const bad of [
    { ...live, tomb: gone.tomb },
    { ...live, tomb: gone.tomb, deleted: true },
    { ...gone, blob: live.blob, tag: live.tag },
    { ...gone, deleted: false },
    { base_rev: 0, idem: live.idem },
    { ...live, resurrect: true },
    { ...gone, resurrect: true },
  ]) {
    assert.equal(refusalOf(() => checkStep("put_item_req", bad)), "bad_request");
  }
});

test("error_codes_are_stable_and_unique", () => {
  const codes = errorCodes();
  assert.equal(new Set(codes).size, codes.length);
  for (const code of codes) assert.match(code, /^[a-z0-9_]+$/);
  for (const needed of [
    "manifest_not_writable", "tombstone_invalid", "insecure_transport", "handoff_invalid",
    "malformed_ke1", "malformed_ke3", "malformed_registration_request", "malformed_registration_record",
  ]) {
    assert.ok(codes.includes(needed), needed);
  }
  assert.ok(codes.includes(parseFile("error_res.json").error));
});

test("device_id_is_required_and_device_name_is_optional_and_at_most_64_chars", () => {
  for (const name of ["register_finish_req.json", "login_finish_req.json"]) {
    const kind = kindOf(name);
    const { device_id, ...without } = parseFile(name);
    assert.ok(device_id);
    assert.equal(refusalOf(() => shape(SHAPES[kind], without)), "bad_request", name);
    const { device_name, ...unnamed } = parseFile(name);
    assert.ok(device_name);
    shape(SHAPES[kind], unnamed);
    shape(SHAPES[kind], { ...parseFile(name), device_name: null });
    for (const [text, ok] of [
      ["a".repeat(64), true],
      ["å".repeat(64), true],
      ["", true],
      ["a‍b", true], // a zero-width joiner is part of some scripts
      ["a".repeat(65), false],
      ["å".repeat(65), false],
      ["tab\there", false],
      ["phone‮knil", false],
      ["phone⁦x", false],
      ["pho​ne", false],
      ["﻿phone", false],
    ]) {
      const code = refusalOf(() => shape(SHAPES[kind], { ...parseFile(name), device_name: text }));
      assert.equal(code, ok ? null : "bad_request", JSON.stringify(text));
    }
  }
  for (const name of ["register_finish_req.minimal.json", "login_finish_req.minimal.json"]) {
    assert.equal("device_name" in parseFile(name), false);
  }
});

test("handoff_code_is_43_chars_base64url", () => {
  const { code } = parseFile("handoff_res.json");
  assert.equal(code.length, 43);
  assert.equal(decode(code).length, 32);
  assert.equal(parseFile("redeem_req.json").code, code);
  handoffCode(code);
  for (const bad of [code.slice(0, 42), `${code}A`, `${code.slice(0, 42)}=`, `${code.slice(0, 42)}B`, ""]) {
    assert.equal(refusalOf(() => handoffCode(bad)), "handoff_invalid", bad);
  }
});
