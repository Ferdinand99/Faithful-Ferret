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
import { checkStep, encodeWire, encodeWireBytes, ERROR_STATUS, handoffCode, MAX_BATCH_OPS, readJson, readWire, SHAPES, shape } from "../../src/wire.mjs";

const DIR = join(SERVER_HEADERS_JSON, "..");
const NOT_SHAPES = ["headers.json", "generate.mjs", "error_codes.json", "error_statuses.json", "invalid.json"];

const read = (name) => readFileSync(join(DIR, name), "utf8");
const parseFile = (name) => JSON.parse(read(name));

/** Strict base64url as a Buffer, so the tests can compare hex. */
const decode = (text, code) => Buffer.from(b64u.decode(text, code));
const id = (text) => void hex16.decode(text);

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
    if (name === "put_item_req.resurrect.json") {
      // It reads; a request that asks for it is refused before it is sent.
      assert.equal(refusalOf(() => encodeWire(kind, value)), "bad_request");
    } else {
      assert.equal(`${encodeWire(kind, value)}
`, text, name);
    }
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

test("encode_wire_bytes_is_the_utf8_of_the_text", () => {
  const value = readWire("put_item_req", read("put_item_req.live.json"));
  const text = encodeWire("put_item_req", value);
  const bytes = encodeWireBytes("put_item_req", value);
  assert.ok(bytes instanceof Uint8Array);
  assert.equal(Buffer.from(bytes).toString("utf8"), text);
  assert.equal(refusalOf(() => encodeWireBytes("put_item_req", { ...value, tomb: value.blob })), "tombstone_invalid");
});

test("a_conflict_answer_is_a_live_row_or_a_deleted_one", () => {
  for (const name of ["conflict_res.live.json", "conflict_res.deleted.json"]) {
    checkStep("conflict_res", parseFile(name));
  }
  const live = parseFile("conflict_res.live.json");
  for (const bad of [
    { ...live, blob: undefined },
    { ...live, tag: null },
    { ...live, deleted: true },
    { current_rev: 1, deleted: true, tag: live.tag },
  ]) {
    assert.equal(refusalOf(() => checkStep("conflict_res", bad)), "bad_request");
  }
});

// ------------------------------------------------------- the sync shapes

const M2_SHAPES = [
  "batch_req", "batch_res", "checkpoint_put_req", "checkpoint_put_res", "checkpoint_stale_res", "items_res", "sync_event",
];
const m2Fixtures = () => fixtures().filter((name) => M2_SHAPES.includes(kindOf(name)));

/** Whether a `null` is anywhere in `value`. */
const hasNull = (value) =>
  value === null || (typeof value === "object" && Object.values(value).some((item) => hasNull(item)));

test("m2_fixtures_decode_and_reencode_identically", () => {
  assert.deepEqual(m2Fixtures(), [
    "batch_req.json", "batch_res.json", "checkpoint_put_req.json", "checkpoint_put_res.json",
    "checkpoint_stale_res.json", "items_res.json", "items_res.last.json", "sync_event.json",
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
  for (const [code, status] of [["busy", 503], ["checkpoint_stale", 409], ["checkpoint_invalid", 422]]) {
    assert.ok(codes.includes(code), code);
    assert.equal(statuses[code], status, code);
    assert.equal(STATUS_OF[code], status, code);
  }
  // They come after the codes of the first version, so that list is unchanged.
  assert.deepEqual(codes.slice(-4), ["gone", "busy", "checkpoint_stale", "checkpoint_invalid"]);
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
});
