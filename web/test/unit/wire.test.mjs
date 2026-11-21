// The wire contract, from the web side. The files in
// crates/ferret-server/tests/fixtures/wire/ are the same ones the Rust tests
// read (crates/ferret-server/tests/wire_contract.rs): both sides read the same
// valid examples and refuse the same inputs from invalid.json, with the same
// code, so the server and the web vault cannot drift apart. The reader, the
// shapes and the encodings under test are the ones the vault itself uses
// (src/wire.mjs, src/b64.mjs).
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { SERVER_HEADERS_JSON } from "../serve.mjs";
import { files, STATUS_OF } from "../../../crates/ferret-server/tests/fixtures/wire/generate.mjs";
import { b64u, hex16, WireError } from "../../src/b64.mjs";
import {
  checkStep, encodeWire, encodeWireBytes, ERROR_STATUS, handoffCode, MAX_BATCH_OPS, MAX_SIGNED_BODY, NONCE_LEN,
  PASSWORD_WRAP_LEN, PROOF_LEN, readJson, readWire, RECOVERY_WRAP_LEN, REDEEM_SCOPE, SESSION_SCOPES, SHAPES, shape,
} from "../../src/wire.mjs";
import { ACCESS_TOKEN_SECS, MAX_DEVICE_LIST, MAX_DEVICES, PLATFORMS, TOKEN_CHARS } from "../../src/wire.mjs";

const DIR = join(SERVER_HEADERS_JSON, "..");
const NOT_SHAPES = [
  "headers.json", "generate.mjs", "error_codes.json", "error_statuses.json", "invalid.json", "dpop_jwk.json",
];

const read = (name) => readFileSync(join(DIR, name), "utf8");
const parseFile = (name) => JSON.parse(read(name));

/** Strict base64url as a Buffer, so the tests can compare hex. */
const decode = (text, code) => Buffer.from(b64u.decode(text, code));
const id = (text) => void hex16.decode(text);

/** The shape of a fixture: the name before the first dot; `<shape>.device.json` is `<shape>_device`. */
const kindOf = (name) => {
  const [kind, variant] = name.split(".");
  return variant === "device" ? `${kind}_device` : kind;
};
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
    if (error instanceof WireError) return error.code;
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

/** Every string leaf of a parsed value. */
function* strings(value) {
  if (typeof value === "string") yield value;
  else if (Array.isArray(value)) for (const item of value) yield* strings(item);
  else if (value !== null && typeof value === "object") for (const item of Object.values(value)) yield* strings(item);
}

test("wire_fixtures_decode_and_reencode_identically", () => {
  let texts = 0;
  for (const name of fixtures()) {
    const kind = kindOf(name);
    const text = read(name);
    const value = readWire(kind, text);
    assert.equal(`${encodeWire(kind, value)}
`, text, name);
    // Every text that decodes as base64url encodes back to the same text.
    for (const leaf of strings(value)) {
      let bytes;
      try {
        bytes = b64u.decode(leaf);
      } catch {
        continue; // not a bytes field (an e-mail, a word)
      }
      assert.equal(b64u.encode(bytes), leaf, `${name}: ${leaf}`);
      texts += 1;
    }
  }
  assert.ok(texts > 100, `only ${texts} byte fields were checked`);
});

test("b64u_agrees_with_the_platform_for_every_length", () => {
  for (let n = 0; n <= 70; n += 1) {
    const raw = new Uint8Array(n).map((_, i) => (i * 37 + n * 11) & 0xff);
    const text = b64u.encode(raw);
    assert.equal(text, Buffer.from(raw).toString("base64url"), `length ${n}`);
    assert.deepEqual(b64u.decode(text), raw, `length ${n}`);
  }
  assert.throws(() => b64u.decode(null), WireError);
  assert.throws(() => hex16.encode(new Uint8Array(15)), TypeError);
  assert.equal(hex16.encode(hex16.decode("00010a0f10a0f0ff123456789abcdef0")), "00010a0f10a0f0ff123456789abcdef0");
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
    checkStep(kindOf(name), value);
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

test("b64u_rejects_padding_plus_slash_and_whitespace", () => {
  assert.equal(decode("AAEC").length, 3);
  assert.equal(decode("").length, 0);
  assert.equal(decode("-_8").toString("hex"), "fbff");
  for (const bad of ["AA==", "+/8", "AA EC", " AAEC", "AAEC\n", "AB", "A", "AAECé"]) {
    assert.equal(refusalOf(() => decode(bad)), "bad_request", JSON.stringify(bad));
  }
});

test("hex16_rejects_uppercase_and_wrong_length", () => {
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
    { ...gone, resurrect: true },
  ]) {
    assert.equal(refusalOf(() => checkStep("put_item_req", bad)), "bad_request");
  }
});

test("resurrect_is_accepted_only_with_a_live_body", () => {
  const live = readWire("put_item_req", read("put_item_req.live.json"));
  const gone = readWire("put_item_req", read("put_item_req.tombstone.json"));
  const asking = readWire("put_item_req", read("put_item_req.resurrect.json"));
  // The fixture is a live row that asks, written against the tombstone's revision.
  assert.equal(asking.resurrect, true);
  assert.ok(asking.blob && asking.tag && !asking.tomb && asking.deleted === undefined);
  assert.equal(asking.base_rev, gone.base_rev);
  for (const ok of [live, asking, { ...live, resurrect: true }, { ...live, resurrect: false }, gone, { ...gone, resurrect: false }]) {
    checkStep("put_item_req", ok);
  }
  for (const bad of [
    { ...gone, resurrect: true },
    { base_rev: gone.base_rev, idem: gone.idem, deleted: true, tomb: gone.tomb, resurrect: true },
  ]) {
    assert.equal(refusalOf(() => checkStep("put_item_req", bad)), "bad_request");
  }
  // The invalid case of the shared fixtures is the tombstone that asks.
  const cases = parseFile("invalid.json");
  const found = cases.find((c) => c.name === "put resurrect true on a tombstone");
  assert.ok(found && found.shape === "put_item_req");
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
  assert.equal(parseFile("handoff_redeem_req.json").code, code);
  handoffCode(code);
  for (const bad of [code.slice(0, 42), `${code}A`, `${code.slice(0, 42)}=`, `${code.slice(0, 42)}B`, ""]) {
    assert.equal(refusalOf(() => handoffCode(bad)), "handoff_invalid", bad);
  }
});

test("encode_wire_bytes_is_the_utf8_of_the_text", () => {
  const value = readWire("put_item_req", read("put_item_req.live.json"));
  const text = encodeWire("put_item_req", value);
  const bytes = encodeWireBytes("put_item_req", value);
  assert.ok(bytes instanceof Uint8Array);
  assert.equal(Buffer.from(bytes).toString("utf8"), text);
  assert.equal(refusalOf(() => encodeWireBytes("put_item_req", { ...value, tomb: value.blob })), "tombstone_invalid");
});

test("a_conflict_answer_is_a_live_row_or_a_deleted_one", () => {
  for (const name of ["conflict_res.live.json", "conflict_res.deleted.json", "conflict_res.absent.json"]) {
    checkStep("conflict_res", parseFile(name));
  }
  const live = parseFile("conflict_res.live.json");
  for (const bad of [
    { ...live, blob: undefined },
    { ...live, tag: null },
    { ...live, deleted: true },
    { current_rev: 1, deleted: true, tag: live.tag },
    { ...live, current_rev: 0 },
    { current_rev: 0, deleted: false, blob: live.blob },
    { current_rev: 0, deleted: false, tag: live.tag },
    { current_rev: 4, deleted: false },
    { current_rev: 0, deleted: true },
  ]) {
    assert.equal(refusalOf(() => checkStep("conflict_res", bad)), "bad_request");
  }
});

test("a_conflict_against_a_row_that_is_not_there_is_valid_and_carries_no_row", () => {
  const absent = parseFile("conflict_res.absent.json");
  assert.deepEqual(absent, { current_rev: 0, deleted: false });
  const live = parseFile("conflict_res.live.json");
  const result = (fields) => ({ results: [{ status: 409, ...fields }] });
  checkStep("batch_res", result(absent));
  checkStep("batch_res", result({ current_rev: 4, deleted: false, blob: live.blob, tag: live.tag }));
  checkStep("batch_res", result({ current_rev: 5, deleted: true }));
  for (const bad of [
    { current_rev: 0, deleted: false, blob: live.blob },
    { current_rev: 0, deleted: false, tag: live.tag },
    { current_rev: 0, deleted: false, blob: live.blob, tag: live.tag },
    { current_rev: 4, deleted: false },
    { current_rev: 4, deleted: false, blob: live.blob },
    { current_rev: 5, deleted: true, blob: live.blob, tag: live.tag },
    { current_rev: 0, deleted: true },
  ]) {
    assert.equal(refusalOf(() => checkStep("batch_res", result(bad))), "bad_request", JSON.stringify(bad));
  }
  const cases = parseFile("invalid.json");
  for (const name of ["conflict_res: current_rev 0 with blob and tag", "conflict_res: current_rev 4 live without blob", "batch result: conflict absent with a blob"]) {
    assert.ok(cases.some((c) => c.name === name), name);
  }
});

// ------------------------------------------------------- the sync shapes

const M3_SHAPES = [
  "batch_req_import", "challenge_res", "reregister_start_req", "reregister_start_res", "password_put_req",
  "password_put_res", "recovery_put_req", "recovery_put_res", "recovery_res", "recover_req", "recover_res", "redeem_req", "redeem_res",
  "import_window_req", "import_window_res",
];
/** The fixtures that came with the third milestone (the shapes above and the session answer that grew a field). */
const M3_FIXTURES = [
  "batch_req_import.json", "challenge_res.json", "import_window_req.json", "import_window_res.json",
  "password_put_req.json", "password_put_res.json", "recover_req.json", "recover_res.json",
  "recovery_put_req.json", "recovery_put_res.json", "recovery_res.json", "redeem_req.json", "redeem_res.json",
  "reregister_start_req.json", "reregister_start_res.json", "session_res.json",
];

const M2_SHAPES = [
  "batch_req", "batch_res", "checkpoint_put_req", "checkpoint_put_res", "checkpoint_stale_res", "items_res", "sync_event",
  "restore_epoch_changed_res", "restore_rows_res",
];
const m2Fixtures = () => fixtures().filter((name) => M2_SHAPES.includes(kindOf(name)));

/** Whether a `null` is anywhere in `value`. */
const hasNull = (value) =>
  value === null || (typeof value === "object" && Object.values(value).some((item) => hasNull(item)));

test("m2_fixtures_decode_and_reencode_identically", () => {
  assert.deepEqual(m2Fixtures(), [
    "batch_req.json", "batch_res.json", "batch_res.restore_epoch_changed.json", "checkpoint_put_req.json",
    "checkpoint_put_req.restore_epoch.json", "checkpoint_put_res.json", "checkpoint_stale_res.json",
    "items_res.json", "items_res.last.json", "restore_epoch_changed_res.json", "restore_rows_res.empty.json",
    "restore_rows_res.json", "restore_rows_res.last.json", "sync_event.json",
  ]);
  for (const name of m2Fixtures()) {
    const kind = kindOf(name);
    const text = read(name);
    const value = readWire(kind, text);
    assert.equal(`${JSON.stringify(value)}\n`, text, name);
    assert.equal(`${encodeWire(kind, value)}\n`, text, name);
    checkStep(kind, value);
  }
  for (const kind of M2_SHAPES) assert.ok(kind in SHAPES, kind);
});

test("a_checkpoint_upload_has_whole_sorted_entries_and_the_digest_of_them", () => {
  const upload = readWire("checkpoint_put_req", read("checkpoint_put_req.json"));
  const entries = decode(upload.entries);
  assert.equal(entries.length % 56, 0);
  assert.ok(entries.length > 0 && entries.length <= 50_000 * 56);
  assert.equal(decode(upload.digest).toString("hex"), createHash("sha256").update(entries).digest("hex"));
  let last = null;
  for (let at = 0; at < entries.length; at += 56) {
    const entryId = entries.subarray(at, at + 16);
    assert.ok(last === null || Buffer.compare(last, entryId) < 0, "ids rise strictly");
    last = entryId;
    assert.ok(entries.readBigUInt64BE(at + 16) >= 1n, "a revision starts at 1");
  }
  assert.equal(MAX_BATCH_OPS, 100);
});

test("batch_op_resurrect_is_accepted_only_with_a_live_body", () => {
  const batch = readWire("batch_req", read("batch_req.json"));
  const [live, resurrecting, gone] = batch.ops;
  assert.equal(live.resurrect, undefined);
  assert.equal(resurrecting.resurrect, true);
  assert.ok(resurrecting.blob && resurrecting.tag);
  for (const op of [live, resurrecting, { ...live, resurrect: false }, gone, { ...gone, resurrect: false }]) {
    checkStep("batch_req", { ops: [op] });
  }
  for (const bad of [
    { ...gone, resurrect: true },
    { id: gone.id, base_rev: 1, idem: gone.idem, deleted: true, tomb: gone.tomb, resurrect: true },
  ]) {
    assert.equal(refusalOf(() => checkStep("batch_req", { ops: [live, bad] })), "bad_request");
    assert.equal(refusalOf(() => encodeWire("batch_req", { ops: [bad] })), "bad_request");
  }
});

test("batch_req_rejects_zero_and_101_ops_unknown_fields_and_an_op_with_both_forms", () => {
  const batch = readWire("batch_req", read("batch_req.json"));
  const [live, , gone] = batch.ops;
  const ops = (n) => ({ ops: Array.from({ length: n }, () => live) });
  checkStep("batch_req", batch);
  checkStep("batch_req", ops(1));
  checkStep("batch_req", ops(MAX_BATCH_OPS));
  for (const n of [0, MAX_BATCH_OPS + 1]) {
    assert.equal(refusalOf(() => checkStep("batch_req", ops(n))), "bad_request", `${n} operations`);
  }
  // Unknown fields, in the batch and in an operation; a missing field.
  assert.equal(refusalOf(() => shape(SHAPES.batch_req, { ...batch, x: 1 })), "bad_request");
  assert.equal(refusalOf(() => shape(SHAPES.batch_req, { ops: [{ ...live, x: 1 }] })), "bad_request");
  for (const field of ["id", "idem", "base_rev"]) {
    const { [field]: dropped, ...without } = live;
    assert.ok(dropped !== undefined);
    assert.equal(refusalOf(() => shape(SHAPES.batch_req, { ops: [without] })), "bad_request", field);
  }
  assert.equal(refusalOf(() => shape(SHAPES.batch_req, {})), "bad_request");
  assert.equal(refusalOf(() => shape(SHAPES.batch_req, { ops: null })), "bad_request");
  // An operation with both forms, or with neither.
  for (const bad of [
    { ...live, tomb: gone.tomb },
    { ...live, tomb: gone.tomb, deleted: true },
    { id: live.id, base_rev: 1, idem: live.idem },
    { id: live.id, base_rev: 1, idem: live.idem, deleted: true },
    { id: live.id, base_rev: 1, idem: live.idem, tomb: gone.tomb },
    { id: live.id, base_rev: 1, idem: live.idem, blob: live.blob },
    { ...gone, deleted: false },
    { ...gone, blob: live.blob, tag: live.tag },
  ]) {
    shape(SHAPES.batch_req, { ops: [bad] }); // it reads
    assert.equal(refusalOf(() => checkStep("batch_req", { ops: [live, bad] })), "bad_request");
  }
  // A `null` is a field that is left out.
  checkStep("batch_req", { ops: [{ ...live, tomb: null, deleted: null, resurrect: null }] });
});

test("batch_result_has_exactly_one_form_and_no_null_fields", () => {
  const fixture = readWire("batch_res", read("batch_res.json"));
  assert.equal(fixture.results.length, 6);
  assert.ok(!hasNull(fixture));
  const forms = {
    stored: ["status", "rev", "seq", "replayed"],
    conflictLive: ["status", "current_rev", "blob", "tag", "deleted"],
    conflictDeleted: ["status", "current_rev", "deleted"],
    refused: ["status", "error"],
  };
  const expected = ["stored", "stored", "conflictLive", "conflictDeleted", "refused", "refused"];
  fixture.results.forEach((result, at) => {
    assert.deepEqual(Object.keys(result), forms[expected[at]], `result ${at}`);
  });
  assert.deepEqual(fixture.results.map((r) => r.status), [200, 200, 409, 409, 422, 400]);
  checkStep("batch_res", fixture);
  const stored0 = fixture.results[0];
  assert.equal(refusalOf(() => checkStep("batch_res", { results: [] })), "bad_request");
  assert.equal(refusalOf(() => checkStep("batch_res", { results: Array.from({ length: 101 }, () => stored0) })), "bad_request");
  checkStep("batch_res", { results: Array.from({ length: 100 }, () => stored0) });

  const [stored, , conflictLive, conflictDeleted, refused] = fixture.results;
  for (const bad of [
    { status: 200 },
    { status: 200, rev: 2, seq: 5 },
    { ...stored, status: 409 },
    { ...stored, status: 201 },
    { ...stored, error: "internal" },
    { ...stored, current_rev: 2 },
    { ...conflictLive, status: 200 },
    { ...conflictLive, tag: undefined },
    { ...conflictLive, blob: undefined },
    { status: 409, current_rev: 4, deleted: false },
    { ...conflictDeleted, blob: conflictLive.blob },
    { ...conflictLive, deleted: true },
    { status: 409, current_rev: 4, blob: conflictLive.blob, tag: conflictLive.tag },
    { status: 409, deleted: true },
    { ...conflictDeleted, rev: 2 },
    { ...conflictDeleted, error: "conflict" },
    { ...refused, status: 200 },
    { ...refused, status: 399 },
    { ...refused, status: 600 },
    { ...refused, error: "" },
    { ...refused, rev: 2 },
    { ...refused, deleted: false },
    { ...stored, rev: 0 },
    { status: 400, error: "idem_reuse" },
    { status: 422, error: "bad_request" },
    { status: 400, error: "not_a_code" },
    { status: 500, error: "not_a_code" },
    { status: 409, error: "conflict" },
    { status: 409, error: "checkpoint_stale" },
    { status: 409, error: "registration_closed" },
  ]) {
    assert.equal(refusalOf(() => checkStep("batch_res", { results: [stored, bad] })), "bad_request", JSON.stringify(bad));
  }
  // A `null` is a field that is left out.
  checkStep("batch_res", { results: [{ ...stored, error: null, current_rev: null }] });
  // Every code with a status other than 409 is a good refusal with its own status.
  for (const [code, status] of Object.entries(ERROR_STATUS)) {
    const run = () => checkStep("batch_res", { results: [{ status, error: code }] });
    if (status === 409) assert.equal(refusalOf(run), "bad_request", code);
    else run();
  }
});

test("items_res_next_after_is_32_lower_hex_or_absent", () => {
  const page = readWire("items_res", read("items_res.json"));
  assert.match(page.next_after, /^[0-9a-f]{32}$/);
  assert.equal(page.has_more, true);
  assert.equal(page.items.length, 2);
  assert.ok(page.items.some((row) => row.deleted));
  const last = readWire("items_res", read("items_res.last.json"));
  assert.equal("next_after" in last, false);
  assert.equal(last.has_more, false);
  // `next_after` is there exactly when `has_more` is true.
  checkStep("items_res", page);
  checkStep("items_res", last);
  checkStep("items_res", { ...last, next_after: null });
  assert.equal(refusalOf(() => checkStep("items_res", { ...page, next_after: undefined })), "bad_request");
  assert.equal(refusalOf(() => checkStep("items_res", { ...page, next_after: null })), "bad_request");
  assert.equal(refusalOf(() => checkStep("items_res", { ...last, next_after: page.next_after })), "bad_request");
  shape(SHAPES.items_res, { ...last, next_after: null });
  for (const bad of [
    page.next_after.toUpperCase(),
    page.next_after.slice(1),
    `${page.next_after}0`,
    "",
    `0x${page.next_after.slice(2)}`,
    5,
  ]) {
    assert.equal(refusalOf(() => shape(SHAPES.items_res, { ...page, next_after: bad })), "bad_request", String(bad));
  }
});

test("sync_event_payload_is_seq_only", () => {
  const event = readWire("sync_event", read("sync_event.json"));
  assert.deepEqual(Object.keys(event), ["seq"]);
  assert.equal(event.seq, 7);
  for (const bad of [
    '{"seq":7,"vault":"x"}', '{"seq":7,"x":1}', "{}", '{"seq":"7"}', '{"seq":-1}', '{"seq":9007199254740992}', '{"seq":1.5}',
  ]) {
    assert.equal(refusalOf(() => readWire("sync_event", bad)), "bad_request", bad);
  }
});

test("checkpoint_answers_are_the_seq_and_the_stale_code", () => {
  assert.equal(readWire("checkpoint_put_res", read("checkpoint_put_res.json")).seq, 7);
  const stale = readWire("checkpoint_stale_res", read("checkpoint_stale_res.json"));
  assert.deepEqual({ ...stale }, { error: "checkpoint_stale", stored_seq: 9 });
  assert.ok(errorCodes().includes(stale.error));
  for (const bad of [
    '{"error":"conflict","stored_seq":9}',
    '{"error":"","stored_seq":9}',
    '{"error":"checkpoint_stale"}',
    '{"error":"checkpoint_stale","stored_seq":9,"x":1}',
  ]) {
    assert.equal(refusalOf(() => readWire("checkpoint_stale_res", bad)), "bad_request", bad);
  }
});

test("new_codes_have_their_status", () => {
  const statuses = parseFile("error_statuses.json");
  const codes = errorCodes();
  for (const [code, status] of [
    ["busy", 503], ["checkpoint_stale", 409], ["checkpoint_invalid", 422], ["restore_epoch_changed", 409],
    ["reauth_required", 403], ["second_factor_required", 403], ["write_conflict", 409], ["import_window_open", 409],
    ["import_window_invalid", 409],
  ]) {
    assert.ok(codes.includes(code), code);
    assert.equal(statuses[code], status, code);
    assert.equal(STATUS_OF[code], status, code);
  }
  // They come after the codes of the first version, so that list is unchanged.
  assert.ok(codes.indexOf("busy") + 1 === codes.indexOf("checkpoint_stale"));
  assert.ok(codes.indexOf("checkpoint_invalid") < codes.indexOf("restore_epoch_changed"));
  // The codes of the third milestone follow, in this order (the codes of device tokens come after them).
  const m3 = codes.indexOf("reauth_required");
  assert.deepEqual(codes.slice(m3, m3 + 5), [
    "reauth_required", "second_factor_required", "write_conflict", "import_window_open", "import_window_invalid",
  ]);
  assert.ok(codes.indexOf("restore_epoch_changed") < codes.indexOf("reauth_required"));
});

test("restore_epoch_changed_has_status_409_on_both_sides", () => {
  const statuses = parseFile("error_statuses.json");
  assert.ok(errorCodes().includes("restore_epoch_changed"));
  assert.equal(statuses.restore_epoch_changed, 409);
  assert.equal(STATUS_OF.restore_epoch_changed, 409);
  assert.equal(ERROR_STATUS.restore_epoch_changed, 409);
  // The answer to a single write, a checkpoint upload and (in a result) to an operation of a batch.
  const answer = readWire("restore_epoch_changed_res", read("restore_epoch_changed_res.json"));
  assert.deepEqual({ ...answer }, { error: "restore_epoch_changed", restore_epoch: 3 });
  for (const bad of [
    '{"error":"conflict","restore_epoch":3}',
    '{"error":"","restore_epoch":3}',
    '{"error":"restore_epoch_changed"}',
    '{"error":"restore_epoch_changed","restore_epoch":-1}',
    '{"error":"restore_epoch_changed","restore_epoch":9007199254740992}',
    '{"error":"restore_epoch_changed","restore_epoch":3,"x":1}',
  ]) {
    assert.equal(refusalOf(() => readWire("restore_epoch_changed_res", bad)), "bad_request", bad);
  }
  // In a batch it is its own form: 409, the code and the epoch, never mixed with another form.
  const batch = readWire("batch_res", read("batch_res.restore_epoch_changed.json"));
  checkStep("batch_res", batch);
  const [stored, changed] = batch.results;
  assert.deepEqual({ ...changed }, { status: 409, error: "restore_epoch_changed", restore_epoch: 3 });
  for (const bad of [
    { ...changed, status: 422 },
    { ...changed, status: 200 },
    { status: 409, error: "restore_epoch_changed" },
    { ...changed, rev: 2 },
    { ...changed, current_rev: 2 },
    { ...changed, deleted: true },
    { status: 422, error: "idem_reuse", restore_epoch: 3 },
    { ...stored, restore_epoch: 3 },
    { status: 409, current_rev: 5, deleted: true, restore_epoch: 3 },
    { status: 409, restore_epoch: 3 },
  ]) {
    assert.equal(refusalOf(() => checkStep("batch_res", { results: [stored, bad] })), "bad_request", JSON.stringify(bad));
  }
});

test("m2_fixtures_with_restore_seq_roundtrip_in_rust_and_js", () => {
  const changes = readWire("changes_res", read("changes_res.json"));
  assert.equal(changes.restore_seq, 4);
  assert.deepEqual(Object.keys(changes).slice(2, 5), ["vk_epoch", "restore_epoch", "restore_seq"]);
  const empty = readWire("changes_res", read("changes_res.empty.json"));
  assert.deepEqual([empty.restore_epoch, empty.restore_seq], [0, 0]);
  const listing = readWire("items_res", read("items_res.json"));
  assert.deepEqual([listing.restore_epoch, listing.restore_seq], [2, 4]);
  const lastPage = readWire("items_res", read("items_res.last.json"));
  assert.deepEqual([lastPage.restore_epoch, lastPage.restore_seq], [0, 0]);
  // Both answers refuse a missing restore_seq and a number that is not a wire integer.
  for (const [kind, value] of [["changes_res", changes], ["items_res", listing]]) {
    const { restore_seq: dropped, ...without } = value;
    assert.equal(dropped, 4);
    assert.equal(refusalOf(() => shape(SHAPES[kind], without)), "bad_request", kind);
    for (const bad of [-1, 1.5, "4", 2 ** 53]) {
      assert.equal(refusalOf(() => shape(SHAPES[kind], { ...value, restore_seq: bad })), "bad_request", `${kind} ${bad}`);
    }
  }
  // The frozen rows: a live row has a hash, a tombstone has none.
  const page = readWire("restore_rows_res", read("restore_rows_res.json"));
  assert.equal(page.rows.length, 2);
  assert.deepEqual(page.rows.map((row) => "hash" in row).sort(), [false, true]);
  for (const row of page.rows) {
    if ("hash" in row) assert.equal(decode(row.hash).length, 32);
    assert.ok(row.rev >= 1 && row.seq >= 1);
  }
  assert.match(page.next_after, /^[0-9a-f]{32}$/);
  assert.equal(page.next_after, page.rows[1].id);
  assert.ok(page.rows[0].id < page.rows[1].id, "item id order");
  checkStep("restore_rows_res", page);
  const last = readWire("restore_rows_res", read("restore_rows_res.last.json"));
  assert.equal("next_after" in last, false);
  checkStep("restore_rows_res", last);
  checkStep("restore_rows_res", { ...last, next_after: null });
  const never = readWire("restore_rows_res", read("restore_rows_res.empty.json"));
  assert.deepEqual({ ...never }, { restore_epoch: 0, restore_seq: 0, rows: [], has_more: false });
  checkStep("restore_rows_res", never);
  assert.equal(refusalOf(() => checkStep("restore_rows_res", { ...page, next_after: undefined })), "bad_request");
  assert.equal(refusalOf(() => checkStep("restore_rows_res", { ...last, next_after: page.next_after })), "bad_request");
  const tombstone = page.rows.find((row) => !("hash" in row));
  const hashed = page.rows.find((row) => "hash" in row);
  for (const bad of [
    { ...hashed, extra: 1 },
    { ...tombstone, hash: b64u.encode(new Uint8Array(31)) },
    { ...tombstone, hash: b64u.encode(new Uint8Array(33)) },
    { ...tombstone, id: tombstone.id.toUpperCase() },
    { id: tombstone.id, seq: 1 },
    { id: tombstone.id, rev: 1 },
  ]) {
    assert.equal(refusalOf(() => shape(SHAPES.restore_rows_res, { ...page, rows: [bad] })), "bad_request", JSON.stringify(bad));
  }
  assert.equal(refusalOf(() => shape(SHAPES.restore_rows_res, { ...page, x: 1 })), "bad_request");
  // `null` is a field that is left out (a tombstone has no hash).
  shape(SHAPES.restore_rows_res, { ...page, rows: [{ ...tombstone, hash: null }] });
});

test("put_batch_and_checkpoint_requests_carry_an_optional_restore_epoch", () => {
  const put = readWire("put_item_req", read("put_item_req.restore_epoch.json"));
  assert.equal(put.restore_epoch, 2);
  assert.deepEqual(Object.keys(put).at(-1), "restore_epoch");
  checkStep("put_item_req", put);
  assert.equal(encodeWire("put_item_req", put), read("put_item_req.restore_epoch.json").trimEnd());
  const plain = readWire("put_item_req", read("put_item_req.live.json"));
  assert.equal("restore_epoch" in plain, false, "a client without the condition still works");
  checkStep("put_item_req", plain);
  checkStep("put_item_req", { ...plain, restore_epoch: null });
  const batch = readWire("batch_req", read("batch_req.json"));
  assert.equal(batch.ops[0].restore_epoch, 2);
  assert.equal("restore_epoch" in batch.ops[1], false);
  const upload = readWire("checkpoint_put_req", read("checkpoint_put_req.restore_epoch.json"));
  assert.equal(upload.restore_epoch, 2);
  assert.equal(encodeWire("checkpoint_put_req", upload), read("checkpoint_put_req.restore_epoch.json").trimEnd());
  const bare = readWire("checkpoint_put_req", read("checkpoint_put_req.json"));
  assert.equal("restore_epoch" in bare, false);
  for (const bad of [-1, 1.5, "2", true, [2], 2 ** 53]) {
    assert.equal(refusalOf(() => shape(SHAPES.put_item_req, { ...put, restore_epoch: bad })), "bad_request", String(bad));
    assert.equal(refusalOf(() => shape(SHAPES.batch_req, { ops: [{ ...batch.ops[0], restore_epoch: bad }] })), "bad_request", String(bad));
    assert.equal(refusalOf(() => shape(SHAPES.checkpoint_put_req, { ...upload, restore_epoch: bad })), "bad_request", String(bad));
  }
});

test("error_statuses_json_matches_code_status", () => {
  const statuses = parseFile("error_statuses.json");
  const codes = errorCodes();
  assert.deepEqual(Object.entries(statuses), codes.map((code) => [code, STATUS_OF[code]]));
  assert.equal(Object.keys(STATUS_OF).length, codes.length, "no status for a code that is not listed");
  // The copy the reader checks refusals against is the same table.
  assert.deepEqual(Object.entries(ERROR_STATUS), Object.entries(statuses));
  for (const [code, status] of Object.entries(statuses)) {
    assert.ok(Number.isInteger(status) && status >= 400 && status <= 599, `${code}: ${status}`);
  }
});

test("invalid_cases_are_refused_the_same_way_in_rust_and_js", () => {
  const cases = parseFile("invalid.json").filter((c) => M2_SHAPES.includes(c.shape));
  assert.ok(cases.length >= 100, `found only ${cases.length} cases`);
  const codes = errorCodes();
  for (const c of cases) {
    const label = `${c.name} (${c.why})`;
    assert.ok(codes.includes(c.error), label);
    if (c.layer === "parse") {
      assert.equal(refusalOf(() => readWire(c.shape, c.json)), c.error, label);
    } else {
      assert.equal(c.layer, "validate", label);
      const value = readWire(c.shape, c.json); // reads without error
      assert.equal(refusalOf(() => checkStep(c.shape, value)), c.error, label);
    }
  }
  for (const kind of M2_SHAPES) assert.ok(cases.some((c) => c.shape === kind), kind);
  for (const kind of ["batch_req", "batch_res"]) {
    assert.ok(cases.some((c) => c.shape === kind && c.layer === "validate"), kind);
  }
  assert.ok(cases.some((c) => c.error === "tombstone_invalid"));

  // The shapes of the third milestone, the same way.
  const m3 = parseFile("invalid.json").filter((c) => M3_SHAPES.includes(c.shape));
  assert.ok(m3.length >= 150, `found only ${m3.length} cases`);
  for (const c of m3) {
    const label = `${c.name} (${c.why})`;
    assert.ok(codes.includes(c.error), label);
    if (c.layer === "parse") {
      assert.equal(refusalOf(() => readWire(c.shape, c.json)), c.error, label);
    } else {
      assert.equal(c.layer, "validate", label);
      const value = readWire(c.shape, c.json); // reads without error
      assert.equal(refusalOf(() => checkStep(c.shape, value)), c.error, label);
    }
  }
  for (const kind of M3_SHAPES) assert.ok(m3.some((c) => c.shape === kind), kind);
  for (const kind of ["recovery_res", "batch_req_import"]) {
    assert.ok(m3.some((c) => c.shape === kind && c.layer === "validate"), kind);
  }
  for (const code of ["malformed_registration_request", "malformed_registration_record"]) {
    assert.ok(m3.some((c) => c.error === code), code);
  }
});

// ---------------------------------------------------- the third milestone

/** `value` without `field`. */
const without = (value, field) => {
  const { [field]: dropped, ...rest } = value;
  assert.ok(dropped !== undefined, field);
  return rest;
};

test("m3_fixtures_decode_and_reencode_identically", () => {
  const all = fixtures();
  for (const name of M3_FIXTURES) assert.ok(all.includes(name), `${name} is missing`);
  for (const name of M3_FIXTURES) {
    const kind = kindOf(name);
    const text = read(name);
    const value = readWire(kind, text);
    assert.equal(`${JSON.stringify(value)}\n`, text, name);
    assert.equal(`${encodeWire(kind, value)}\n`, text, name);
    checkStep(kind, value);
    assert.ok(!hasNull(value), name);
  }
  for (const kind of M3_SHAPES) {
    assert.ok(kind in SHAPES, kind);
    assert.ok(all.some((name) => kindOf(name) === kind), `no fixture for ${kind}`);
  }
  // The first field of each request is the one the server writes first.
  assert.deepEqual(Object.keys(parseFile("password_put_req.json")), [
    "registration_record", "ksf_profile", "wrap", "kek_generation", "manifest",
  ]);
  assert.deepEqual(Object.keys(parseFile("recover_req.json")), [
    "registration_record", "ksf_profile", "pw_wrap", "rk_wrap", "pw_kek_generation", "rk_kek_generation",
    "pk_r_new", "manifest",
  ]);
  assert.deepEqual(Object.keys(parseFile("recovery_put_req.json")), ["wrap", "kek_generation", "pk_r", "manifest"]);
});

test("m3_lengths_match_the_spec", () => {
  // Spec: Fase 1 § 4.6 (the signed bodies) and § 4.3 (the wraps).
  assert.deepEqual([MAX_SIGNED_BODY, NONCE_LEN, PROOF_LEN], [256 * 1024, 32, 64]);
  assert.deepEqual([PASSWORD_WRAP_LEN, RECOVERY_WRAP_LEN], [104, 72]);
  const len = (text) => decode(text).length;
  const challenge = parseFile("challenge_res.json");
  assert.equal(len(challenge.nonce), NONCE_LEN);
  assert.equal(challenge.expires_in, 300);
  const password = parseFile("password_put_req.json");
  assert.deepEqual([len(password.registration_record), len(password.wrap)], [192, 104]);
  assert.equal(password.kek_generation, 2);
  assert.equal(password.manifest.rev, 2);
  const recovery = parseFile("recovery_put_req.json");
  assert.deepEqual([len(recovery.wrap), len(recovery.pk_r)], [72, 32]);
  const recover = parseFile("recover_req.json");
  assert.deepEqual([len(recover.registration_record), len(recover.pw_wrap), len(recover.rk_wrap), len(recover.pk_r_new)], [192, 104, 72, 32]);
  assert.equal(len(parseFile("reregister_start_req.json").registration_request), 32);
  assert.equal(len(parseFile("reregister_start_res.json").registration_response), 64);
  const read_back = parseFile("recovery_res.json");
  assert.equal(read_back.wrap.method_type, 2);
  assert.equal(len(read_back.wrap.wrap), RECOVERY_WRAP_LEN);
  // The client sends the generations of both new wraps: the AAD binds them.
  assert.deepEqual([recover.pw_kek_generation, recover.rk_kek_generation], [2, 2]);
  assert.deepEqual({ ...parseFile("password_put_res.json") }, { kek_generation: 2, seq: 9 });
  assert.deepEqual({ ...readWire("recovery_put_res", read("recovery_put_res.json")) }, { kek_generation: 3, seq: 10 });
  assert.deepEqual({ ...parseFile("recover_res.json") }, { session_ended: true, seq: 9 });
  const window = parseFile("import_window_res.json");
  assert.deepEqual([window.ops, window.expires_in], [250, 1800]);
  assert.equal(parseFile("import_window_req.json").ops, 250);
  assert.equal(parseFile("batch_req_import.json").import_window, window.window_id);
  assert.ok(errorCodes().includes("import_window_invalid"));
});

test("password_put_req_refuses_wrong_lengths_and_unknown_fields", () => {
  const base = parseFile("password_put_req.json");
  const refused = (value) => refusalOf(() => shape(SHAPES.password_put_req, value));
  assert.equal(refused(base), null);
  for (const [field, size, code] of [
    ["registration_record", 192, "malformed_registration_record"],
    ["wrap", 104, "bad_request"],
  ]) {
    for (const wrong of [0, size - 1, size + 1, 2 * size]) {
      assert.equal(refused({ ...base, [field]: b64u.encode(new Uint8Array(wrong)) }), code, `${field} with ${wrong} bytes`);
    }
    assert.equal(refused({ ...base, [field]: `${b64u.encode(new Uint8Array(size))}=` }), code, `${field} with padding`);
    assert.equal(refused({ ...base, [field]: 5 }), "bad_request");
  }
  // The wrap of a recovery key is not a wrap of a password.
  assert.equal(refused({ ...base, wrap: b64u.encode(new Uint8Array(72)) }), "bad_request");
  for (const bad of [256, -1, "1", 1.5]) assert.equal(refused({ ...base, ksf_profile: bad }), "bad_request", String(bad));
  assert.equal(refused({ ...base, ksf_profile: 255 }), null);
  for (const bad of [2 ** 32, -1, "2", 1.5]) assert.equal(refused({ ...base, kek_generation: bad }), "bad_request", String(bad));
  assert.equal(refused({ ...base, kek_generation: 2 ** 32 - 1 }), null);
  assert.equal(refused({ ...base, x: 1 }), "bad_request");
  assert.equal(refused({ ...base, manifest: { ...base.manifest, x: 1 } }), "bad_request");
  for (const field of Object.keys(base)) assert.equal(refused(without(base, field)), "bad_request", field);
  // The answer has the same two integers.
  const answer = parseFile("password_put_res.json");
  for (const bad of [{ ...answer, kek_generation: 2 ** 32 }, { ...answer, seq: 2 ** 53 }, { ...answer, x: 1 }, without(answer, "seq")]) {
    assert.equal(refusalOf(() => shape(SHAPES.password_put_res, bad)), "bad_request", JSON.stringify(bad));
  }
});

test("recovery_put_req_refuses_a_password_sized_wrap", () => {
  const base = parseFile("recovery_put_req.json");
  const refused = (value) => refusalOf(() => shape(SHAPES.recovery_put_req, value));
  assert.equal(refused(base), null);
  for (const wrong of [0, 71, 73, 104]) {
    assert.equal(refused({ ...base, wrap: b64u.encode(new Uint8Array(wrong)) }), "bad_request", `a wrap of ${wrong} bytes`);
  }
  for (const wrong of [0, 31, 33, 64]) {
    assert.equal(refused({ ...base, pk_r: b64u.encode(new Uint8Array(wrong)) }), "bad_request", `a key of ${wrong} bytes`);
  }
  assert.equal(refused({ ...base, kek_generation: 2 ** 32 }), "bad_request");
  assert.equal(refused({ ...base, x: 1 }), "bad_request");
  for (const field of Object.keys(base)) assert.equal(refused(without(base, field)), "bad_request", field);
  // The answer of the recovery read: the wrap is the recovery method, 72 bytes.
  const answer = readWire("recovery_res", read("recovery_res.json"));
  checkStep("recovery_res", answer);
  // A recovery wrap has no passkey field.
  for (const field of ["credential_id", "prf_salt"]) {
    const passkey = { ...answer, wrap: { ...answer.wrap, [field]: b64u.encode(new Uint8Array(32)) } };
    shape(SHAPES.recovery_res, passkey); // it reads
    assert.equal(refusalOf(() => checkStep("recovery_res", passkey)), "bad_request", field);
  }
  for (const [methodType, wrapLen] of [[1, 72], [3, 72], [2, 104], [2, 71], [2, 0]]) {
    const changed = { ...answer, wrap: { ...answer.wrap, method_type: methodType, wrap: b64u.encode(new Uint8Array(wrapLen)) } };
    shape(SHAPES.recovery_res, changed); // it reads
    assert.equal(refusalOf(() => checkStep("recovery_res", changed)), "bad_request", `type ${methodType}, ${wrapLen} bytes`);
  }
});

test("recover_req_needs_every_field", () => {
  const base = parseFile("recover_req.json");
  const refused = (value) => refusalOf(() => shape(SHAPES.recover_req, value));
  assert.deepEqual(Object.keys(base).sort(), [
    "ksf_profile", "manifest", "pk_r_new", "pw_kek_generation", "pw_wrap", "registration_record", "rk_kek_generation", "rk_wrap",
  ]);
  assert.equal(refused(base), null);
  for (const field of Object.keys(base)) {
    assert.equal(refused(without(base, field)), "bad_request", field);
    assert.equal(refused({ ...base, [field]: null }), "bad_request", `${field} null`);
  }
  assert.equal(refused({ ...base, x: 1 }), "bad_request");
  // The two wraps are not interchangeable.
  assert.equal(refused({ ...base, pw_wrap: b64u.encode(new Uint8Array(72)) }), "bad_request");
  assert.equal(refused({ ...base, rk_wrap: b64u.encode(new Uint8Array(104)) }), "bad_request");
  for (const [field, size] of [["registration_record", 192], ["pw_wrap", 104], ["rk_wrap", 72], ["pk_r_new", 32]]) {
    for (const wrong of [size - 1, size + 1]) {
      assert.notEqual(refused({ ...base, [field]: b64u.encode(new Uint8Array(wrong)) }), null, `${field} ${wrong}`);
    }
  }
  assert.equal(refused({ ...base, ksf_profile: 256 }), "bad_request");
  // The two generations are 32-bit whole numbers.
  for (const field of ["pw_kek_generation", "rk_kek_generation"]) {
    for (const bad of [2 ** 32, -1, "2", 1.5]) assert.equal(refused({ ...base, [field]: bad }), "bad_request", `${field} ${bad}`);
    assert.equal(refused({ ...base, [field]: 2 ** 32 - 1 }), null, field);
  }
  const answer = parseFile("recover_res.json");
  for (const bad of ['{"session_ended":true}', '{"session_ended":"yes","seq":1}', '{"session_ended":true,"seq":1,"x":1}']) {
    assert.equal(refusalOf(() => readWire("recover_res", bad)), "bad_request", bad);
  }
  assert.equal(refusalOf(() => shape(SHAPES.recover_res, answer)), null);
});

test("batch_req_without_import_window_is_the_m2_shape", () => {
  const plain = readWire("batch_req", read("batch_req.json"));
  assert.equal("import_window" in plain, false);
  assert.equal(encodeWire("batch_req", plain), read("batch_req.json").trimEnd());
  // `null` is a field that is left out.
  checkStep("batch_req", { ...plain, import_window: null });
  const imported = readWire("batch_req_import", read("batch_req_import.json"));
  const window = parseFile("import_window_res.json");
  assert.equal(imported.import_window, window.window_id);
  assert.deepEqual(Object.keys(imported), ["ops", "import_window"]);
  checkStep("batch_req_import", imported);
  // The count and the form of the operations are the same rules.
  assert.equal(refusalOf(() => checkStep("batch_req_import", { ...imported, ops: [] })), "bad_request");
  assert.equal(refusalOf(() => checkStep("batch_req_import", { ...imported, ops: Array.from({ length: 101 }, () => imported.ops[0]) })), "bad_request");
  // The window is an id: lower-case hexadecimal, 32 characters.
  for (const bad of [window.window_id.toUpperCase(), "00", 5, ""]) {
    assert.equal(refusalOf(() => shape(SHAPES.batch_req_import, { ...imported, import_window: bad })), "bad_request", String(bad));
    assert.equal(refusalOf(() => shape(SHAPES.batch_req, { ...plain, import_window: bad })), "bad_request", String(bad));
  }
  assert.equal(refusalOf(() => shape(SHAPES.batch_req_import, { ...imported, x: 1 })), "bad_request");
});

test("session_res_scope_is_one_of_the_four_scopes", () => {
  assert.deepEqual([...SESSION_SCOPES], ["full", "pending_2fa", "account_reset", "unverified"]);
  const base = parseFile("session_res.json");
  for (const scope of SESSION_SCOPES) {
    assert.equal(refusalOf(() => shape(SHAPES.session_res, { ...base, scope })), null, scope);
  }
  for (const bad of ["", "Full", "FULL", "admin", "reset", "full ", 1, null]) {
    assert.equal(refusalOf(() => shape(SHAPES.session_res, { ...base, scope: bad })), "bad_request", JSON.stringify(bad));
  }
  // The time of the fresh check is an optional whole number.
  assert.equal(base.reauth_until, 1800000300);
  assert.equal("reauth_until" in parseFile("session_res.admin.json"), false);
  shape(SHAPES.session_res, { ...base, reauth_until: null });
  for (const bad of [-1, 1.5, "1800000300", 2 ** 53]) {
    assert.equal(refusalOf(() => shape(SHAPES.session_res, { ...base, reauth_until: bad })), "bad_request", String(bad));
  }
  // Whether the user is an administrator is a boolean, and `null` is absent (the Rust side agrees).
  assert.equal(base.admin, true);
  shape(SHAPES.session_res, { ...base, admin: null });
  shape(SHAPES.session_res, { ...base, admin: false });
  for (const bad of ["true", 1, []]) {
    assert.equal(refusalOf(() => shape(SHAPES.session_res, { ...base, admin: bad })), "bad_request", JSON.stringify(bad));
  }
  // The scope of a redeemed code is the one reset scope.
  assert.equal(REDEEM_SCOPE, "account_reset");
  assert.ok(SESSION_SCOPES.includes(REDEEM_SCOPE));
  assert.equal(readWire("redeem_res", read("redeem_res.json")).scope, "account_reset");
  for (const bad of ["full", "pending_2fa", "unverified", "", "Account_reset"]) {
    assert.equal(refusalOf(() => shape(SHAPES.redeem_res, { scope: bad })), "bad_request", bad);
  }
});

test("sign_in_code_and_import_window_bodies_have_the_fields_of_the_plan", () => {
  const redeem = readWire("redeem_req", read("redeem_req.json"));
  assert.deepEqual(Object.keys(redeem), ["email", "code"]);
  for (const bad of [
    '{"email":"a@b.c"}', '{"code":"x"}', '{"email":"a@b.c","code":5}', '{"email":"a@b.c","code":"x","x":1}',
    '{"code":"x","next":"/"}',
  ]) {
    assert.equal(refusalOf(() => readWire("redeem_req", bad)), "bad_request", bad);
  }
  for (const bad of ["{}", '{"ops":-1}', '{"ops":4294967296}', '{"ops":"250"}', '{"ops":1.5}', '{"ops":1,"x":1}']) {
    assert.equal(refusalOf(() => readWire("import_window_req", bad)), "bad_request", bad);
  }
  assert.equal(readWire("import_window_req", '{"ops":4294967295}').ops, 4294967295);
  const window = parseFile("import_window_res.json");
  for (const field of Object.keys(window)) {
    assert.equal(refusalOf(() => shape(SHAPES.import_window_res, without(window, field))), "bad_request", field);
  }
  const answer = parseFile("recovery_res.json");
  assert.equal(answer.account_id, parseFile("login_finish_res.json").account_id);
  assert.equal(answer.vault_id, parseFile("login_finish_res.json").vault_id);
});

// ------------------------------------------------------- devices and tokens

const M5A_SHAPES = [
  "login_finish_req_device", "login_finish_res_device", "token_refresh_req", "token_res", "token_revoke_req",
  "devices_res", "revoke_all_res",
];
const M5A_FIXTURES = [
  "devices_res.empty.json", "devices_res.json", "devices_res.more.json", "login_finish_req.device.json", "login_finish_res.device.json",
  "revoke_all_res.json", "token_refresh_req.json", "token_res.json", "token_revoke_req.json",
];

test("m5a_fixtures_decode_and_reencode_identically", () => {
  const all = fixtures();
  assert.deepEqual(all.filter((name) => M5A_SHAPES.includes(kindOf(name))), M5A_FIXTURES);
  for (const name of M5A_FIXTURES) {
    const kind = kindOf(name);
    const text = read(name);
    const value = readWire(kind, text);
    assert.equal(`${JSON.stringify(value)}\n`, text, name);
    assert.equal(`${encodeWire(kind, value)}\n`, text, name);
    checkStep(kind, value);
    assert.ok(!hasNull(value), name);
  }
  for (const kind of M5A_SHAPES) assert.ok(kind in SHAPES, kind);
  // The device body is the cookie body's shape name with `_device`; the cookie fixtures read as before.
  assert.equal(kindOf("login_finish_req.device.json"), "login_finish_req_device");
  assert.equal(kindOf("login_finish_req.reauth.json"), "login_finish_req");
  const device = readWire("login_finish_req_device", read("login_finish_req.device.json"));
  assert.deepEqual(Object.keys(device), ["login_id", "ke3", "client", "device_name", "platform"]);
  assert.equal(device.client, "device");
  assert.equal(refusalOf(() => readWire("login_finish_req", read("login_finish_req.device.json"))), "bad_request");
  assert.equal(refusalOf(() => readWire("login_finish_req_device", read("login_finish_req.json"))), "bad_request");
  // The tokens: the renewal uses the sign-in's refresh token, the sign-out the renewal's.
  const login = readWire("login_finish_res_device", read("login_finish_res.device.json"));
  const renewed = readWire("token_res", read("token_res.json"));
  assert.equal(login.token_type, "DPoP");
  assert.equal(login.expires_in, ACCESS_TOKEN_SECS);
  assert.equal(readWire("token_refresh_req", read("token_refresh_req.json")).refresh_token, login.refresh_token);
  assert.equal(readWire("token_revoke_req", read("token_revoke_req.json")).refresh_token, renewed.refresh_token);
  assert.equal(login.account_id, parseFile("login_finish_res.json").account_id);
  // The list: a device with tokens, this browser, and a browser with no name.
  const list = readWire("devices_res", read("devices_res.json"));
  assert.equal(list.devices[0].kind, "device");
  assert.equal(list.devices[0].id, login.device_id);
  assert.equal(list.devices.filter((row) => row.current).length, 1);
  assert.ok(list.devices.some((row) => row.name === "" && !("platform" in row)));
});

test("token_codes_are_401_on_both_sides", () => {
  const statuses = parseFile("error_statuses.json");
  const codes = errorCodes();
  const added = ["dpop_invalid", "token_expired", "token_reused", "device_revoked"];
  for (const code of added) {
    assert.equal(statuses[code], 401, code);
    assert.equal(STATUS_OF[code], 401, code);
    assert.equal(ERROR_STATUS[code], 401, code);
  }
  // They close the list, after the codes of the third milestone.
  assert.deepEqual(codes.slice(-4), added);
  assert.equal(codes.indexOf("import_window_invalid") + 1, codes.indexOf("dpop_invalid"));
  // A refused operation of a batch may carry them, with their status.
  for (const code of added) checkStep("batch_res", { results: [{ status: 401, error: code }] });
});

test("m5a_invalid_cases_are_refused_the_same_way_in_rust_and_js", () => {
  const cases = parseFile("invalid.json").filter((c) => M5A_SHAPES.includes(c.shape));
  assert.ok(cases.length >= 100, `found only ${cases.length} cases`);
  for (const c of cases) {
    const label = `${c.name} (${c.why})`;
    if (c.layer === "parse") {
      assert.equal(refusalOf(() => readWire(c.shape, c.json)), c.error, label);
    } else {
      const value = readWire(c.shape, c.json);
      assert.equal(refusalOf(() => checkStep(c.shape, value)), c.error, label);
    }
  }
  for (const kind of M5A_SHAPES) assert.ok(cases.some((c) => c.shape === kind), kind);
  assert.ok(cases.some((c) => c.shape === "login_finish_req_device" && c.error === "malformed_ke3"));
  for (const name of [
    "token_refresh_req refresh_token 42 characters", "token_refresh_req refresh_token 44 characters",
    "token_refresh_req refresh_token padded", "token_refresh_req refresh_token spare bits",
    "token_res token_type \"Bearer\"", "login_finish_req_device device_name empty",
    "login_finish_req_device device_name 65 characters", "login_finish_req_device platform \"freebsd\"",
    "devices_res with 201 devices", "devices_res kind \"browser\"",
  ]) {
    assert.ok(cases.some((c) => c.name === name), name);
  }
});

test("tokens_are_43_strict_base64url_characters_and_token_type_is_dpop", () => {
  assert.equal(TOKEN_CHARS, 43);
  const good = b64u.encode(new Uint8Array(32).fill(0x5a));
  const refreshed = (value) => refusalOf(() => shape(SHAPES.token_refresh_req, { refresh_token: value }));
  assert.equal(refreshed(good), null);
  const spare = good.at(-1) === "B" ? "C" : "B";
  for (const bad of [
    good.slice(0, 42), `${good}A`, `${good.slice(0, 42)}=`, `${good}=`, `${good.slice(0, 42)}${spare}`,
    `+${good.slice(1)}`, `/${good.slice(1)}`, ` ${good.slice(1)}`, "", 5, null, [good],
  ]) {
    assert.equal(refreshed(bad), "bad_request", JSON.stringify(bad));
  }
  const renewed = parseFile("token_res.json");
  for (const bad of ["dpop", "DPOP", "Bearer", "", " DPoP", 1, null]) {
    assert.equal(refusalOf(() => shape(SHAPES.token_res, { ...renewed, token_type: bad })), "bad_request", String(bad));
  }
  assert.equal(refusalOf(() => shape(SHAPES.token_res, { ...renewed, expires_in: 2 ** 32 })), "bad_request");
});

test("device_names_and_platforms_follow_the_server", () => {
  assert.deepEqual(PLATFORMS, ["windows", "macos", "linux", "android", "ios", "chromeos", "other"]);
  assert.ok(Object.isFrozen(PLATFORMS));
  const device = parseFile("login_finish_req.device.json");
  const signIn = (fields) => refusalOf(() => shape(SHAPES.login_finish_req_device, { ...device, ...fields }));
  for (const platform of PLATFORMS) assert.equal(signIn({ platform }), null, platform);
  for (const platform of ["Windows", "freebsd", "", null, 1]) assert.equal(signIn({ platform }), "bad_request", String(platform));
  // The name of a device that signs in: 1 to 64 characters (code points), nothing hidden.
  for (const [name, ok] of [
    ["a", true], ["a".repeat(64), true], ["\u{1d11e}".repeat(64), true], ["a\u200db", true],
    ["", false], ["a".repeat(65), false], ["\u{1d11e}".repeat(65), false], ["tab\there", false],
    ["phone\u202eknil", false], ["pho\u200bne", false], [null, false],
  ]) {
    assert.equal(signIn({ device_name: name }), ok ? null : "bad_request", JSON.stringify(name));
  }
  // The body of a device has no device_id, purpose or key.
  for (const field of ["device_id", "purpose", "jwk"]) {
    assert.equal(signIn({ [field]: "x" }), "bad_request", field);
  }
  // In the list, a browser with no name has `""`; the platform may be left out.
  const list = parseFile("devices_res.json");
  const row = list.devices[0];
  const listed = (fields) => refusalOf(() => shape(SHAPES.devices_res, { devices: [{ ...row, ...fields }] }));
  assert.equal(listed({ name: "" }), null); // it reads; the row rule is a check of its own
  assert.equal(listed({ platform: null }), null);
  // The row rule: a device with tokens has a name and a platform, a browser has no platform.
  const checked = (devices) => refusalOf(() => checkStep("devices_res", { devices }));
  const browser = list.devices[1];
  assert.equal(checked([row, browser, { ...browser, name: "" }]), null);
  assert.equal(checked([{ ...row, name: "" }]), "bad_request");
  assert.equal(checked([{ ...row, platform: undefined }]), "bad_request");
  assert.equal(checked([{ ...browser, platform: "linux" }]), "bad_request");
  for (const name of ["nul\u0000", "\u0000"]) assert.equal(listed({ name }), "bad_request", JSON.stringify(name));
  assert.equal(listed({ name: "a".repeat(65) }), "bad_request");
  assert.equal(listed({ kind: "browser" }), "bad_request");
});

test("the_device_list_has_at_most_200_rows", () => {
  assert.equal(MAX_DEVICES, 20);
  assert.equal(MAX_DEVICE_LIST, 200);
  const row = parseFile("devices_res.json").devices[0];
  const rows = (n) => ({ devices: Array.from({ length: n }, () => row) });
  assert.equal(refusalOf(() => shape(SHAPES.devices_res, rows(MAX_DEVICE_LIST))), null);
  assert.equal(refusalOf(() => shape(SHAPES.devices_res, rows(MAX_DEVICE_LIST + 1))), "bad_request");
  assert.equal(refusalOf(() => shape(SHAPES.devices_res, rows(0))), null);
  // A longer list is cut, and `more` says how many rows were left out: only on a full list, at least 1.
  const cut = readWire("devices_res", read("devices_res.more.json"));
  assert.equal(cut.devices.length, MAX_DEVICE_LIST);
  assert.ok(cut.more >= 1);
  checkStep("devices_res", cut);
  const more = (devices, value) => refusalOf(() => checkStep("devices_res", { devices, more: value }));
  assert.equal(more(cut.devices, 1), null);
  assert.equal(more(cut.devices, null), null);
  assert.equal(more(cut.devices, 0), "bad_request");
  assert.equal(more(cut.devices.slice(1), 3), "bad_request");
  for (const bad of [-1, 2 ** 32, "3", 1.5]) {
    assert.equal(refusalOf(() => shape(SHAPES.devices_res, { ...cut, more: bad })), "bad_request", String(bad));
  }
  assert.equal("more" in parseFile("devices_res.json"), false);
});

test("the_dpop_jwk_fixture_is_a_public_p256_key_and_its_thumbprint", async () => {
  const { jwk, jkt, ...rest } = parseFile("dpop_jwk.json");
  assert.deepEqual(rest, {});
  assert.deepEqual(Object.keys(jwk), ["kty", "crv", "x", "y"]);
  // RFC 7638 § 3: the required members in lexical order, no white space.
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  assert.equal(createHash("sha256").update(canonical).digest("base64url"), jkt);
  assert.equal(decode(jkt).length, 32);
  // It is a point of P-256: the platform imports it as a public key.
  const { createPublicKey } = await import("node:crypto");
  const key = createPublicKey({ key: jwk, format: "jwk" });
  assert.equal(key.type, "public");
  assert.equal(key.asymmetricKeyDetails.namedCurve, "prime256v1");
});

test("an_answer_read_for_a_device_drops_unknown_fields_at_every_depth_and_nothing_else", () => {
  const b = (/** @type {number} */ n, /** @type {number} */ fill) => Buffer.alloc(n, fill).toString("base64url");
  const methods = {
    methods: [{ method_id: "11".repeat(16), method_type: 1, kek_generation: 1, wrap: b(104, 5), later: 1 }],
    pk_a: b(32, 3),
    vk_epoch: 1,
    manifest: { rev: 1, envelope: b(80, 4), tag: b(32, 5), later: { deep: true } },
    later: [1, 2],
  };
  const text = JSON.stringify(methods);
  // The web vault refuses every unknown field, as before; the default is to refuse.
  assert.throws(() => readWire("methods_res", text), WireError);
  assert.throws(() => readWire("methods_res", text, { unknown: "refuse" }), WireError);
  // A device client reads what it knows, at every depth: the value it gets has no other field.
  const read = readWire("methods_res", text, { unknown: "ignore" });
  assert.deepEqual(Object.keys(read), ["methods", "pk_a", "vk_epoch", "manifest"]);
  assert.deepEqual(Object.keys(read.methods[0]), ["method_id", "method_type", "kek_generation", "wrap"]);
  assert.deepEqual(Object.keys(read.manifest), ["rev", "envelope", "tag"]);
  // ...and the strict check passes on what it got.
  assert.doesNotThrow(() => shape(SHAPES.methods_res, read));
  // The rows of the list of devices too.
  const devices = readWire("devices_res", JSON.stringify({
    devices: [{ id: "33".repeat(16), kind: "web", name: "", created_at: 1, last_seen: 2, current: true, later: "x" }],
    later: 1,
  }), { unknown: "ignore" });
  assert.deepEqual(Object.keys(devices.devices[0]), ["id", "kind", "name", "created_at", "last_seen", "current"]);

  // Everything else is as strict as ever: a repeated field, a missing field, a known field of the wrong type or value.
  const strict = (/** @type {string} */ kind, /** @type {string} */ body) => assert.throws(() => readWire(kind, body, { unknown: "ignore" }), WireError, body);
  strict("token_res", `{"access_token":"${"A".repeat(43)}","access_token":"${"A".repeat(43)}","refresh_token":"${"A".repeat(43)}","token_type":"DPoP","expires_in":900}`);
  strict("token_res", `{"refresh_token":"${"A".repeat(43)}","token_type":"DPoP","expires_in":900,"later":1}`);
  strict("token_res", `{"access_token":"${"A".repeat(43)}","refresh_token":"${"A".repeat(43)}","token_type":"Bearer","expires_in":900}`);
  strict("token_res", `{"access_token":"${"A".repeat(43)}","refresh_token":"${"A".repeat(43)}","token_type":"DPoP","expires_in":-1}`);
  strict("methods_res", JSON.stringify({ ...methods, manifest: { ...methods.manifest, tag: b(31, 5) } }));
  strict("methods_res", JSON.stringify({ ...methods, methods: [{ ...methods.methods[0], method_type: 9 }] }));
  strict("methods_res", "[]");
  strict("methods_res", JSON.stringify({ ...methods, manifest: "x" }));
  strict("methods_res", '{"a":1.5}');
  assert.throws(() => readWire("token_res", "{}", /** @type {any} */ ({ unknown: "keep" })), TypeError);
  // Requests are written strictly on every client.
  assert.throws(() => encodeWire("token_refresh_req", { refresh_token: "A".repeat(43), later: 1 }), WireError);
});
