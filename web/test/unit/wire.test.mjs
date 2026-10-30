// The wire contract, from the web side. The files in
// crates/ferret-server/tests/fixtures/wire/ are the same ones the Rust tests
// read (crates/ferret-server/tests/wire_contract.rs): both sides check them
// against the same rules, so the server and the web vault cannot drift apart.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { SERVER_HEADERS_JSON } from "../serve.mjs";
import { files } from "../../../crates/ferret-server/tests/fixtures/wire/generate.mjs";

const DIR = join(SERVER_HEADERS_JSON, "..");
const NOT_SHAPES = ["headers.json", "generate.mjs", "error_codes.json"];

const read = (name) => readFileSync(join(DIR, name), "utf8");
const parse = (name) => JSON.parse(read(name));

// ---------------------------------------------------------------- rules

/** Strict base64url without padding: the alphabet, no spare bits. */
function b64(text) {
  assert.equal(typeof text, "string", "base64url value is a string");
  assert.match(text, /^[A-Za-z0-9_-]*$/, `not base64url: ${text}`);
  const bytes = Buffer.from(text, "base64url");
  assert.equal(bytes.toString("base64url"), text, `not canonical: ${text}`);
  return bytes;
}
const hex = (text) => {
  assert.match(text, /^[0-9a-f]{32}$/, `not an id: ${text}`);
  return text;
};
const size = (n) => (text) => assert.equal(b64(text).length, n);
const int = (n) => assert.ok(Number.isSafeInteger(n) && n >= 0, `not a wire integer: ${n}`);

// A field spec is a function that checks one value.
const id = hex;
const b = (text) => void b64(text);
const b32 = size(32);
const str = (s) => assert.equal(typeof s, "string");
const bool = (v) => assert.equal(typeof v, "boolean");
const oneOf = (...words) => (v) => assert.ok(words.includes(v), `${v} is not one of ${words}`);
const list = (spec) => (v) => {
  assert.ok(Array.isArray(v));
  for (const item of v) shape(spec, item);
};
const nested = (spec) => (v) => shape(spec, v);
const deviceName = (v) => {
  str(v);
  assert.ok([...v].length <= 64, "device_name is at most 64 characters");
  assert.ok(!/\p{Cc}/u.test(v), "device_name has no control characters");
};

/** `[field, check, optional]` in the order the server writes them. */
const wrap = [
  ["method_id", id],
  ["method_type", (v) => assert.ok([1, 2, 3].includes(v))],
  ["kek_generation", int],
  ["wrap", b],
  ["credential_id", b, true],
  ["prf_salt", b32, true],
];
const sealedRow = [["rev", int], ["envelope", b], ["tag", b32]];
const checkpoint = [["seq", int], ["digest", b32], ["mac", b32], ["entries", b]];
const head = [["seq", int], ["digest", b32], ["mac", b32]];
const change = [
  ["id", id], ["rev", int], ["seq", int], ["deleted", bool],
  ["blob", b, true], ["tag", b32, true], ["tomb", b, true],
];

const SHAPES = {
  sealed_row: sealedRow,
  wrap,
  checkpoint,
  checkpoint_head: head,
  register_start_req: [["setup_token", str, true], ["email", str], ["request", size(32)]],
  register_start_res: [
    ["registration_id", id], ["account_id", id], ["vault_id", id],
    ["response", size(64)], ["ksf_profile", int],
  ],
  register_finish_req: [
    ["registration_id", id], ["device_id", id], ["device_name", deviceName, true],
    ["record", size(192)], ["ksf_profile", int], ["sk_bit", bool],
    ["wraps", list(wrap)], ["manifest", nested(sealedRow)], ["checkpoint", nested(checkpoint)],
    ["pk_a", b32], ["pk_r", b32],
  ],
  login_start_req: [["email", str], ["ke1", size(96)], ["purpose", oneOf("login", "reauth"), true]],
  login_start_res: [["login_id", id], ["ke2", size(320)], ["ksf_profile", int], ["sk_hint", bool]],
  login_finish_req: [
    ["login_id", id], ["ke3", size(64)], ["device_id", id], ["device_name", deviceName, true],
  ],
  login_finish_res: [["account_id", id], ["vault_id", id], ["vk_epoch", int]],
  handoff_req: [["purpose", oneOf("login", "reauth")], ["next", str], ["challenge", b32]],
  handoff_res: [["code", size(32)], ["expires_in", int]],
  redeem_req: [["code", size(32)]],
  handoff_redeem_res: [["next", str]],
  session_res: [["account_id", id, true], ["email", str], ["scope", str], ["origin", oneOf("vault", "admin")]],
  methods_res: [["methods", list(wrap)], ["pk_a", b32], ["vk_epoch", int], ["manifest", nested(sealedRow)]],
  change,
  changes_res: [
    ["changes", list(change)], ["latest_seq", int], ["vk_epoch", int], ["restore_epoch", int],
    ["checkpoint", nested(head), true], ["has_more", bool],
  ],
  put_item_req: [
    ["base_rev", int], ["blob", b, true], ["tag", b32, true], ["deleted", bool, true],
    ["tomb", size(40), true], ["idem", id],
  ],
  put_item_res: [["rev", int], ["seq", int], ["replayed", bool]],
  conflict_res: [["current_rev", int], ["blob", b, true], ["tag", b32, true], ["deleted", bool]],
  error_res: [["error", str]],
};

/** Checks that `value` has exactly the fields of `spec`, in order, each valid. */
function shape(spec, value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value), "an object");
  const names = spec.map(([name]) => name);
  const keys = Object.keys(value);
  for (const key of keys) assert.ok(names.includes(key), `unknown field ${key}`);
  assert.deepEqual(
    keys,
    names.filter((name) => name in value),
    "fields are in the order of the server",
  );
  for (const [name, check, optional] of spec) {
    if (!(name in value)) {
      assert.ok(optional, `missing field ${name}`);
      continue;
    }
    check(value[name]);
  }
}

const fixtures = () =>
  readdirSync(DIR)
    .filter((name) => name.endsWith(".json") && !NOT_SHAPES.includes(name))
    .sort()
    .map((name) => [name, name.split(".")[0]]);

// ---------------------------------------------------------------- tests

test("every_fixture_roundtrips_byte_for_byte", () => {
  const all = fixtures();
  assert.ok(all.length >= 30);
  for (const [name, kind] of all) {
    assert.ok(kind in SHAPES, `no shape for ${name}`);
    const text = read(name);
    assert.equal(`${JSON.stringify(JSON.parse(text))}\n`, text, name);
    shape(SHAPES[kind], JSON.parse(text));
  }
  assert.deepEqual([...new Set(all.map(([, kind]) => kind))].sort(), Object.keys(SHAPES).sort());
});

test("the_fixtures_are_what_generate_mjs_makes", () => {
  const made = files();
  for (const [name, text] of Object.entries(made)) assert.equal(read(name), text, name);
  for (const name of readdirSync(DIR)) {
    assert.ok(name in made || NOT_SHAPES.includes(name), `${name} is not generated`);
  }
});

test("unknown_fields_are_rejected_in_every_request_type", () => {
  for (const [name, kind] of fixtures()) {
    const value = { ...parse(name), x: 1 };
    assert.throws(() => shape(SHAPES[kind], value), /unknown field x/, name);
  }
});

test("b64url_rejects_padding_standard_alphabet_and_whitespace", () => {
  assert.equal(b64("AAEC").length, 3);
  assert.equal(b64("").length, 0);
  for (const bad of ["AA==", "+/8", "AA EC", " AAEC", "AAEC\n", "AB"]) {
    assert.throws(() => b64(bad), undefined, bad);
  }
});

test("hex16_rejects_uppercase_short_and_long", () => {
  hex("00010a0f10a0f0ff123456789abcdef0");
  for (const bad of [
    "00010A0F10A0F0FF123456789ABCDEF0",
    "00010a0f10a0f0ff123456789abcde",
    "00010a0f10a0f0ff123456789abcdef00",
    "",
  ]) {
    assert.throws(() => hex(bad), undefined, bad);
  }
});

test("lengths_match_the_spec", () => {
  assert.equal(b64(parse("login_start_req.json").ke1).length, 96);
  assert.equal(b64(parse("login_start_res.json").ke2).length, 320);
  assert.equal(b64(parse("login_finish_req.json").ke3).length, 64);
  const finish = parse("register_finish_req.json");
  assert.equal(b64(finish.record).length, 192);
  const [password, recovery] = finish.wraps;
  assert.equal([password.method_type, recovery.method_type].join(), "1,2");
  assert.equal(b64(password.wrap).length, 104);
  assert.equal(b64(recovery.wrap).length, 72);
  assert.equal(b64(parse("put_item_req.tombstone.json").tomb).length, 40);
  assert.equal(b64(parse("change.deleted.json").tomb).length, 40);
  assert.equal(b64(parse("put_item_req.live.json").tag).length, 32);
  for (const field of ["pk_a", "pk_r"]) assert.equal(b64(finish[field]).length, 32);
  assert.equal(b64(finish.manifest.tag).length, 32);
  const entries = b64(finish.checkpoint.entries);
  assert.equal(entries.length, 56);
  assert.equal(b64(finish.checkpoint.digest).toString("hex"), createHash("sha256").update(entries).digest("hex"));
  assert.equal(b64(finish.checkpoint.mac).length, 32);
});

test("put_item_requires_exactly_one_form", () => {
  // The same rule as `PutItemReq::validate` in the server.
  const form = (r) => {
    const live = r.blob !== undefined && r.tag !== undefined && r.tomb === undefined && r.deleted !== true;
    const gone = r.blob === undefined && r.tag === undefined && r.tomb !== undefined && r.deleted === true;
    return live ? "live" : gone ? "deleted" : null;
  };
  assert.equal(form(parse("put_item_req.live.json")), "live");
  assert.equal(form(parse("put_item_req.tombstone.json")), "deleted");
  const live = parse("put_item_req.live.json");
  const gone = parse("put_item_req.tombstone.json");
  assert.equal(form({ ...live, tomb: gone.tomb }), null);
  assert.equal(form({ ...live, tomb: gone.tomb, deleted: true }), null);
  assert.equal(form({ ...gone, blob: live.blob, tag: live.tag }), null);
  assert.equal(form({ ...gone, deleted: false }), null);
  assert.equal(form({ base_rev: 0, idem: live.idem }), null);
});

test("error_codes_are_stable_and_unique", () => {
  const codes = parse("error_codes.json");
  assert.equal(new Set(codes).size, codes.length);
  for (const code of codes) assert.match(code, /^[a-z0-9_]+$/);
  for (const needed of ["manifest_not_writable", "tombstone_invalid", "insecure_transport", "handoff_invalid"]) {
    assert.ok(codes.includes(needed), needed);
  }
  assert.ok(codes.includes(parse("error_res.json").error));
});

test("device_id_is_required_and_device_name_is_optional_and_at_most_64_chars", () => {
  for (const name of ["register_finish_req.json", "login_finish_req.json"]) {
    const kind = name.split(".")[0];
    const { device_id, ...without } = parse(name);
    assert.ok(device_id);
    assert.throws(() => shape(SHAPES[kind], without), /missing field device_id/, name);
    const { device_name, ...unnamed } = parse(name);
    assert.ok(device_name);
    shape(SHAPES[kind], unnamed);
    shape(SHAPES[kind], { ...parse(name), device_name: "a".repeat(64) });
    shape(SHAPES[kind], { ...parse(name), device_name: "å".repeat(64) });
    assert.throws(() => shape(SHAPES[kind], { ...parse(name), device_name: "a".repeat(65) }));
    assert.throws(() => shape(SHAPES[kind], { ...parse(name), device_name: "tab\there" }));
  }
  for (const name of ["register_finish_req.minimal.json", "login_finish_req.minimal.json"]) {
    assert.equal("device_name" in parse(name), false);
  }
});

test("handoff_code_is_43_chars_base64url", () => {
  const { code } = parse("handoff_res.json");
  assert.equal(code.length, 43);
  assert.equal(b64(code).length, 32);
  assert.equal(parse("redeem_req.json").code, code);
  const handoffCode = (text) => {
    assert.equal(text.length, 43);
    return b64(text);
  };
  assert.equal(handoffCode(code).length, 32);
  for (const bad of [code.slice(0, 42), `${code}A`, `${code.slice(0, 42)}=`, `${code.slice(0, 42)}B`, ""]) {
    assert.throws(() => handoffCode(bad), undefined, bad);
  }
});
