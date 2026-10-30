// Writes the wire fixtures in this directory, the same bytes every time:
//
//   node generate.mjs           write the files
//   node generate.mjs --check   fail if a file differs from what this script makes
//
// The bytes are synthetic (SHA-256 of a label and a counter) but have the right
// lengths: KE1 96, KE2 320, KE3 64, OPAQUE record 192, password wrap 104,
// recovery wrap 72, tombstone 40, tags, digests, MACs and public keys 32. A
// field is written in the order of the Rust struct, so `JSON.stringify` and
// serde write the same text.
//
// `headers.json` is not made here.
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const DIR = dirname(fileURLToPath(import.meta.url));

/** `n` deterministic bytes for `label`. */
export function bytes(label, n) {
  const out = Buffer.alloc(n);
  let filled = 0;
  for (let counter = 0; filled < n; counter += 1) {
    const block = createHash("sha256").update(`ferret wire fixture/${label}/${counter}`).digest();
    block.copy(out, filled, 0, Math.min(block.length, n - filled));
    filled += block.length;
  }
  return out;
}

const b64 = (label, n) => bytes(label, n).toString("base64url");
const id = (label) => bytes(label, 16).toString("hex");

/** An envelope-sized blob: header (version 1, suite 1, kind), then bytes. */
const envelope = (label, kind, n) =>
  Buffer.concat([Buffer.from([1, 1, kind]), bytes(label, n - 3)]).toString("base64url");

const entries = bytes("checkpoint entries", 56); // one entry: id 16, rev 8, SHA-256 32
const digest = createHash("sha256").update(entries).digest("base64url");

const passwordWrap = () => ({
  method_id: id("method password"),
  method_type: 1,
  kek_generation: 1,
  wrap: b64("wrap password", 104),
});
const recoveryWrap = () => ({
  method_id: id("method recovery"),
  method_type: 2,
  kek_generation: 1,
  wrap: b64("wrap recovery", 72),
});
const passkeyWrap = () => ({
  method_id: id("method passkey"),
  method_type: 3,
  kek_generation: 2,
  wrap: b64("wrap passkey", 104),
  credential_id: b64("credential", 32),
  prf_salt: b64("prf salt", 32),
});
const manifest = () => ({
  rev: 1,
  envelope: envelope("manifest", 2, 160),
  tag: b64("manifest tag", 32),
});
const checkpoint = () => ({
  seq: 1,
  digest,
  mac: b64("checkpoint mac", 32),
  entries: entries.toString("base64url"),
});
const head = () => ({ seq: 7, digest: b64("head digest", 32), mac: b64("head mac", 32) });
const liveChange = () => ({
  id: id("item one"),
  rev: 2,
  seq: 5,
  deleted: false,
  blob: envelope("item one", 1, 200),
  tag: b64("item one tag", 32),
});
const deletedChange = () => ({
  id: id("item two"),
  rev: 3,
  seq: 6,
  deleted: true,
  tomb: b64("item two tomb", 40),
});

/** Every fixture: file name -> object. The type is the name before the first dot. */
export function fixtures() {
  return {
    "sealed_row.json": manifest(),
    "wrap.password.json": passwordWrap(),
    "wrap.recovery.json": recoveryWrap(),
    "wrap.passkey.json": passkeyWrap(),
    "checkpoint.json": checkpoint(),
    "checkpoint_head.json": head(),
    "register_start_req.json": {
      setup_token: "setup-token-0123456789",
      email: "ada@example.test",
      request: b64("registration request", 32),
    },
    "register_start_req.no_token.json": {
      email: "ada@example.test",
      request: b64("registration request", 32),
    },
    "register_start_res.json": {
      registration_id: id("registration"),
      account_id: id("account"),
      vault_id: id("vault"),
      response: b64("registration response", 64),
      ksf_profile: 1,
    },
    "register_finish_req.json": {
      registration_id: id("registration"),
      device_id: id("device"),
      device_name: "Firefox on a laptop",
      record: b64("opaque record", 192),
      ksf_profile: 1,
      sk_bit: true,
      wraps: [passwordWrap(), recoveryWrap()],
      manifest: manifest(),
      checkpoint: checkpoint(),
      pk_a: b64("pk a", 32),
      pk_r: b64("pk r", 32),
    },
    "register_finish_req.minimal.json": {
      registration_id: id("registration"),
      device_id: id("device"),
      record: b64("opaque record", 192),
      ksf_profile: 1,
      sk_bit: false,
      wraps: [passwordWrap(), recoveryWrap()],
      manifest: manifest(),
      checkpoint: checkpoint(),
      pk_a: b64("pk a", 32),
      pk_r: b64("pk r", 32),
    },
    "register_finish_res.json": { account_id: id("account"), vault_id: id("vault") },
    "login_start_req.json": {
      email: "ada@example.test",
      ke1: b64("ke1", 96),
    },
    "login_start_req.reauth.json": {
      email: "ada@example.test",
      ke1: b64("ke1", 96),
      purpose: "reauth",
    },
    "login_start_res.json": {
      login_id: id("login"),
      ke2: b64("ke2", 320),
      ksf_profile: 1,
      sk_hint: true,
    },
    "login_finish_req.json": {
      login_id: id("login"),
      ke3: b64("ke3", 64),
      device_id: id("device"),
      device_name: "Firefox on a laptop",
    },
    "login_finish_req.minimal.json": {
      login_id: id("login"),
      ke3: b64("ke3", 64),
      device_id: id("device"),
    },
    "login_finish_res.json": {
      account_id: id("account"),
      vault_id: id("vault"),
      vk_epoch: 1,
    },
    "handoff_req.json": {
      purpose: "login",
      next: "/admin",
      challenge: b64("handoff challenge", 32),
    },
    "handoff_req.reauth.json": {
      purpose: "reauth",
      next: "/admin/users",
      challenge: b64("handoff challenge", 32),
    },
    "handoff_res.json": { code: b64("handoff code", 32), expires_in: 60 },
    "redeem_req.json": { code: b64("handoff code", 32) },
    "handoff_redeem_res.json": { next: "/admin" },
    "session_res.json": {
      account_id: id("account"),
      email: "ada@example.test",
      scope: "full",
      origin: "vault",
    },
    "session_res.admin.json": {
      email: "ada@example.test",
      scope: "full",
      origin: "admin",
    },
    "methods_res.json": {
      methods: [passwordWrap(), recoveryWrap(), passkeyWrap()],
      pk_a: b64("pk a", 32),
      vk_epoch: 1,
      manifest: manifest(),
    },
    "changes_res.json": {
      changes: [liveChange(), deletedChange()],
      latest_seq: 7,
      vk_epoch: 1,
      restore_epoch: 0,
      checkpoint: head(),
      has_more: true,
    },
    "changes_res.empty.json": {
      changes: [],
      latest_seq: 0,
      vk_epoch: 1,
      restore_epoch: 0,
      has_more: false,
    },
    "change.live.json": liveChange(),
    "change.deleted.json": deletedChange(),
    "put_item_req.live.json": {
      base_rev: 1,
      blob: envelope("item one", 1, 200),
      tag: b64("item one tag", 32),
      idem: id("idem one"),
    },
    "put_item_req.tombstone.json": {
      base_rev: 2,
      deleted: true,
      tomb: b64("item two tomb", 40),
      idem: id("idem two"),
    },
    "put_item_req.resurrect.json": {
      base_rev: 2,
      deleted: true,
      tomb: b64("item two tomb", 40),
      idem: id("idem three"),
      resurrect: true,
    },
    "put_item_res.json": { rev: 2, seq: 5, replayed: false },
    "put_item_res.replayed.json": { rev: 2, seq: 5, replayed: true },
    "conflict_res.live.json": {
      current_rev: 4,
      blob: envelope("item one", 1, 200),
      tag: b64("item one tag", 32),
      deleted: false,
    },
    "conflict_res.deleted.json": { current_rev: 5, deleted: true },
    "error_res.json": { error: "unauthorized" },
  };
}

/** The golden list of error codes. */
export const ERROR_CODES = [
  "unauthorized",
  "denied",
  "forbidden",
  "insecure_transport",
  "handoff_invalid",
  "manifest_not_writable",
  "malformed_registration_request",
  "malformed_registration_record",
  "malformed_ke1",
  "malformed_ke3",
  "malformed_login_id",
  "malformed_nonce",
  "malformed_proof",
  "malformed_login_name",
  "malformed_recovery_key",
  "registration_closed",
  "throttled",
  "profile_rejected",
  "unsupported_envelope",
  "tombstone_invalid",
  "too_large",
  "quota_exceeded",
  "idem_reuse",
  "conflict",
  "protocol_header_missing",
  "forbidden_origin",
  "not_found",
  "bad_request",
  "internal",
];

/**
 * Inputs that must be refused, in `invalid.json`. Each case is
 * `{name, shape, json, layer, error, why}`:
 *
 * - `json` is the raw text a client sends (it can hold a repeated field or `1.0`,
 *   which a parsed value cannot).
 * - `layer` is `parse` (reading the text as the shape fails) or `validate`
 *   (reading succeeds and the check that comes with the shape fails:
 *   `PutItemReq::validate`, the hand-over code).
 * - `error` is the code of the answer: the code of the field for a fixed size
 *   (`malformed_ke1`, `tombstone_invalid`, ...), `handoff_invalid` for a
 *   hand-over code, `bad_request` for everything else.
 *
 * Both the Rust and the web tests assert that every case is refused at its
 * layer with its code.
 */
export function invalidCases() {
  const all = fixtures();
  const cases = [];
  const names = new Set();
  const add = (name, shape, json, layer, error, why) => {
    if (names.has(name)) throw new Error(`two cases named ${name}`);
    names.add(name);
    cases.push({ name, shape, json, layer, error, why });
  };
  const clone = (file) => structuredClone(all[file]);
  const text = (value) => JSON.stringify(value);
  /** The fixture `file` with `fields` set (a value of `undefined` removes the field). */
  const with_ = (file, fields) => {
    const value = clone(file);
    for (const [key, v] of Object.entries(fields)) {
      if (v === undefined) delete value[key];
      else value[key] = v;
    }
    return text(value);
  };
  const parse = (name, shape, json, why, error = "bad_request") =>
    add(name, shape, json, "parse", error, why);
  const validate = (name, shape, json, why, error = "bad_request") =>
    add(name, shape, json, "validate", error, why);

  // Not JSON, or not an object.
  for (const [name, json] of [
    ["empty text", ""],
    ["open object", "{"],
    ["text after the value", `${text(all["error_res.json"])} x`],
    ["a second value", `${text(all["error_res.json"])}${text(all["error_res.json"])}`],
    ["an array", "[]"],
    ["null", "null"],
    ["a string", '"unauthorized"'],
    ["a number", "5"],
    ["a trailing comma", '{"error":"x",}'],
  ]) {
    parse(`not an object: ${name}`, "error_res", json, "the text is not one JSON object");
  }
  parse("leading zero", "put_item_res", '{"rev":01,"seq":1,"replayed":false}', "JSON has no leading zeros");

  // Base64url: the blob of a live row has no fixed size.
  for (const [name, value] of [
    ["padding two", "AA=="],
    ["padding one", "AAE="],
    ["standard alphabet", "+/8"],
    ["padding after the right alphabet", "-_8="],
    ["space inside", "AA EC"],
    ["leading space", " AAEC"],
    ["trailing space", "AAEC "],
    ["trailing newline", "AAEC\n"],
    ["tab inside", "AA\tEC"],
    ["spare bits are not zero", "AB"],
    ["one character", "A"],
    ["non-ASCII", "AAEC\u00e9"],
  ]) {
    parse(`blob ${name}`, "put_item_req", with_("put_item_req.live.json", { blob: value }), "not strict base64url");
  }
  for (const [name, value] of [
    ["31 bytes", b64("short tag", 31)],
    ["33 bytes", b64("long tag", 33)],
    ["empty", ""],
    ["padded", `${b64("tag", 32)}=`],
  ]) {
    parse(`tag ${name}`, "put_item_req", with_("put_item_req.live.json", { tag: value }), "a tag is 32 bytes");
  }
  parse(
    "envelope with padding",
    "sealed_row",
    with_("sealed_row.json", { envelope: "AA==" }),
    "not strict base64url",
  );

  // Ids.
  for (const [name, value] of [
    ["upper case", id("idem one").toUpperCase()],
    ["one upper-case digit", id("idem one").replace(/[a-f]/, (c) => c.toUpperCase())],
    ["short", id("idem one").slice(0, 30)],
    ["one short", id("idem one").slice(0, 31)],
    ["long", `${id("idem one")}00`],
    ["one long", `${id("idem one")}0`],
    ["empty", ""],
    ["0x prefix", `0x${id("idem one").slice(2)}`],
    ["trailing space", `${id("idem one").slice(0, 31)} `],
    ["not hexadecimal", `${id("idem one").slice(0, 31)}g`],
    ["32 bytes of non-ASCII text", "\u00e9".repeat(16)],
    ["a number", 5],
  ]) {
    parse(`idem ${name}`, "put_item_req", with_("put_item_req.live.json", { idem: value }), "an id is 32 lower-case hexadecimal characters");
  }
  parse("device_id upper case", "login_finish_req", with_("login_finish_req.json", { device_id: id("device").toUpperCase() }), "an id is lower case");
  parse("item id upper case", "change", with_("change.live.json", { id: id("item one").toUpperCase() }), "an id is lower case");
  parse("account_id short", "session_res", with_("session_res.json", { account_id: id("account").slice(1) }), "an id is 32 characters");

  // Integers are whole numbers up to 2^53 - 1.
  const base = text(all["put_item_req.live.json"]);
  const withRev = (literal) => base.replace('"base_rev":1', `"base_rev":${literal}`);
  if (withRev("X") === base) throw new Error("base_rev is not 1");
  for (const [name, literal] of [
    ["2^53", "9007199254740992"],
    ["2^64 - 1", "18446744073709551615"],
    ["negative", "-1"],
    ["negative zero", "-0"],
    ["fraction", "1.5"],
    ["one point zero", "1.0"],
    ["exponent", "1e3"],
    ["capital exponent", "1E3"],
    ["a string", '"1"'],
    ["true", "true"],
    ["null", "null"],
    ["an array", "[1]"],
  ]) {
    parse(`base_rev ${name}`, "put_item_req", withRev(literal), "an integer is whole, not negative and at most 2^53 - 1");
  }
  parse("kek_generation 2^53", "wrap", with_("wrap.password.json", { kek_generation: 9007199254740992 }), "an integer is at most 2^53 - 1");
  parse("ksf_profile 256 in an answer", "login_start_res", with_("login_start_res.json", { ksf_profile: 256 }), "ksf_profile is a byte");
  parse("ksf_profile 2^32 in a request", "register_finish_req", with_("register_finish_req.json", { ksf_profile: 4294967296 }), "ksf_profile is 32 bits");
  parse("ksf_profile negative", "register_finish_req", with_("register_finish_req.json", { ksf_profile: -1 }), "an integer is not negative");
  parse("expires_in 1.0", "handoff_res", text(all["handoff_res.json"]).replace('"expires_in":60', '"expires_in":60.0'), "an integer has no fraction");

  // Unknown fields: at the top of every shape, then inside parts.
  for (const [file, value] of Object.entries(all)) {
    const shape = file.split(".")[0];
    parse(`unknown field in ${file}`, shape, text({ ...value, x: 1 }), "an unknown field is refused");
  }
  const nested = (name, shape, file, path, why) => {
    const value = clone(file);
    let at = value;
    for (const step of path) at = at[step];
    at.x = 1;
    parse(name, shape, text(value), why);
  };
  nested("unknown field in a wrap of register_finish_req", "register_finish_req", "register_finish_req.json", ["wraps", 0], "an unknown field is refused inside a part");
  nested("unknown field in the manifest of register_finish_req", "register_finish_req", "register_finish_req.json", ["manifest"], "an unknown field is refused inside a part");
  nested("unknown field in the checkpoint of register_finish_req", "register_finish_req", "register_finish_req.json", ["checkpoint"], "an unknown field is refused inside a part");
  nested("unknown field in a method of methods_res", "methods_res", "methods_res.json", ["methods", 2], "an unknown field is refused inside a part");
  nested("unknown field in the manifest of methods_res", "methods_res", "methods_res.json", ["manifest"], "an unknown field is refused inside a part");
  nested("unknown field in a change of changes_res", "changes_res", "changes_res.json", ["changes", 1], "an unknown field is refused inside a part");
  nested("unknown field in the checkpoint of changes_res", "changes_res", "changes_res.json", ["checkpoint"], "an unknown field is refused inside a part");

  // Repeated fields.
  parse(
    "repeated base_rev",
    "put_item_req",
    base.replace('"base_rev":1', '"base_rev":1,"base_rev":2'),
    "a repeated field is refused",
  );
  parse(
    "repeated error",
    "error_res",
    '{"error":"unauthorized","error":"internal"}',
    "a repeated field is refused",
  );
  parse(
    "repeated rev in the manifest",
    "register_finish_req",
    text(all["register_finish_req.json"]).replace('"manifest":{"rev":1', '"manifest":{"rev":1,"rev":1'),
    "a repeated field is refused inside a part",
  );

  // Missing fields.
  parse("register_finish_req without device_id", "register_finish_req", with_("register_finish_req.json", { device_id: undefined }), "device_id is required");
  parse("login_finish_req without device_id", "login_finish_req", with_("login_finish_req.json", { device_id: undefined }), "device_id is required");
  parse("put_item_req without idem", "put_item_req", with_("put_item_req.live.json", { idem: undefined }), "idem is required");
  parse("put_item_req without base_rev", "put_item_req", with_("put_item_req.live.json", { base_rev: undefined }), "base_rev is required");
  parse("register_finish_req without manifest", "register_finish_req", with_("register_finish_req.json", { manifest: undefined }), "manifest is required");
  parse("login_start_req without ke1", "login_start_req", with_("login_start_req.json", { ke1: undefined }), "ke1 is required", "bad_request");
  parse("session_res without email", "session_res", with_("session_res.json", { email: undefined }), "email is required");
  parse("changes_res without has_more", "changes_res", with_("changes_res.json", { has_more: undefined }), "has_more is required");
  parse("conflict_res without deleted", "conflict_res", with_("conflict_res.live.json", { deleted: undefined }), "deleted is required");

  // Wrong types.
  parse("email is a number", "login_start_req", with_("login_start_req.json", { email: 5 }), "email is a string");
  parse("sk_bit is a string", "register_finish_req", with_("register_finish_req.json", { sk_bit: "true" }), "sk_bit is a boolean");
  parse("wraps is an object", "register_finish_req", with_("register_finish_req.json", { wraps: {} }), "wraps is a list");
  parse("deleted is a string", "put_item_req", with_("put_item_req.tombstone.json", { deleted: "true" }), "deleted is a boolean");
  parse("resurrect is a string", "put_item_req", with_("put_item_req.live.json", { resurrect: "true" }), "resurrect is a boolean");
  parse("replayed is a number", "put_item_res", with_("put_item_res.json", { replayed: 0 }), "replayed is a boolean");
  parse("changes holds a string", "changes_res", with_("changes_res.json", { changes: ["x"] }), "a change is an object");

  // Device names: at most 64 characters, nothing that hides or reorders text.
  for (const [shape, file] of [
    ["register_finish_req", "register_finish_req.minimal.json"],
    ["login_finish_req", "login_finish_req.minimal.json"],
  ]) {
    for (const [name, value] of [
      ["65 characters", "a".repeat(65)],
      ["65 characters, 130 bytes", "\u00e5".repeat(65)],
      ["a tab", "tab\there"],
      ["a newline", "line\nbreak"],
      ["a NUL", "nul\u0000"],
      ["a right-to-left override", "phone\u202eknil"],
      ["a bidirectional isolate", "phone\u2066x"],
      ["a zero-width space", "pho\u200bne"],
      ["a byte order mark", "\ufeffphone"],
      ["a number", 5],
      ["a list", ["x"]],
    ]) {
      parse(`${shape} device_name ${name}`, shape, with_(file, { device_name: value }), "a device name has at most 64 characters and no control or invisible ones");
    }
  }

  // Enumerations.
  for (const value of ["Login", "delete", "", 1]) {
    parse(`login purpose ${JSON.stringify(value)}`, "login_start_req", with_("login_start_req.reauth.json", { purpose: value }), "purpose is login or reauth");
  }
  for (const value of ["Login", "delete", ""]) {
    parse(`handoff purpose ${JSON.stringify(value)}`, "handoff_req", with_("handoff_req.json", { purpose: value }), "purpose is login or reauth");
  }
  for (const value of [0, 4, 256, -1, "1", 1.5]) {
    parse(`method_type ${JSON.stringify(value)}`, "wrap", with_("wrap.password.json", { method_type: value }), "method_type is 1, 2 or 3");
  }
  for (const value of ["other", "Vault", "", 1]) {
    parse(`session origin ${JSON.stringify(value)}`, "session_res", with_("session_res.json", { origin: value }), "origin is vault or admin");
  }

  // Fixed sizes. The code is the one the server answers with for the field.
  const sized = (field, shape, file, size, code) => {
    for (const [name, n] of [["one short", size - 1], ["one long", size + 1], ["empty", 0]]) {
      parse(`${shape} ${field} ${name}`, shape, with_(file, { [field]: b64(`${field} ${name}`, n) }), `${field} is ${size} bytes`, code);
    }
    parse(`${shape} ${field} with padding`, shape, with_(file, { [field]: `${b64(`${field} pad`, size)}=` }), `${field} is strict base64url`, code);
  };
  sized("ke1", "login_start_req", "login_start_req.json", 96, "malformed_ke1");
  sized("ke3", "login_finish_req", "login_finish_req.json", 64, "malformed_ke3");
  sized("request", "register_start_req", "register_start_req.json", 32, "malformed_registration_request");
  sized("record", "register_finish_req", "register_finish_req.json", 192, "malformed_registration_record");
  sized("ke2", "login_start_res", "login_start_res.json", 320, "bad_request");
  sized("response", "register_start_res", "register_start_res.json", 64, "bad_request");
  sized("tomb", "put_item_req", "put_item_req.tombstone.json", 40, "tombstone_invalid");
  sized("tomb", "change", "change.deleted.json", 40, "tombstone_invalid");

  // A hand-over `next` has 1 to 512 characters.
  parse("next empty", "handoff_req", with_("handoff_req.json", { next: "" }), "next has 1 to 512 characters");
  parse("next 513 characters", "handoff_req", with_("handoff_req.json", { next: "/".repeat(513) }), "next has 1 to 512 characters");
  parse("next is a number", "handoff_req", with_("handoff_req.json", { next: 5 }), "next is a string");

  // A put request has exactly one form, and asks for no resurrection.
  const blob = b64("form blob", 20);
  const tag = b64("form tag", 32);
  const tomb = b64("form tomb", 40);
  const idem = id("form idem");
  const put = (fields) => text({ base_rev: 1, ...fields, idem });
  for (const [name, fields] of [
    ["blob, tag and tomb", { blob, tag, tomb }],
    ["blob, tag, deleted true and tomb", { blob, tag, deleted: true, tomb }],
    ["nothing", {}],
    ["deleted true only", { deleted: true }],
    ["deleted false with tomb", { deleted: false, tomb }],
    ["tomb without deleted", { tomb }],
    ["blob without tag", { blob }],
    ["tag without blob", { tag }],
    ["deleted true with blob and tag", { deleted: true, blob, tag }],
    ["deleted true, tomb and tag", { deleted: true, tomb, tag }],
    ["deleted true, tomb and blob", { deleted: true, tomb, blob }],
    ["deleted false only", { deleted: false }],
    ["blob, tag and deleted true", { blob, tag, deleted: true }],
  ]) {
    validate(`put form: ${name}`, "put_item_req", put(fields), "a put request is a live row (blob, tag) or a tombstone (deleted true, tomb), never both");
  }
  validate("put resurrect true on a live row", "put_item_req", put({ blob, tag, resurrect: true }), "resurrect is not supported yet");
  validate("put resurrect true on a tombstone", "put_item_req", put({ deleted: true, tomb, resurrect: true }), "resurrect is not supported yet");

  // A hand-over code is 43 characters of strict base64url that decode to 32 bytes.
  const code = all["redeem_req.json"].code;
  for (const [name, value] of [
    ["42 characters", code.slice(0, 42)],
    ["44 characters", `${code}A`],
    ["padding", `${code.slice(0, 42)}=`],
    ["standard alphabet", `+${code.slice(1)}`],
    ["spare bits are not zero", `${code.slice(0, 42)}B`],
    ["space", ` ${code.slice(1)}`],
    ["empty", ""],
    ["non-ASCII", `\u00e9${code.slice(1)}`],
  ]) {
    validate(`handoff code ${name}`, "redeem_req", with_("redeem_req.json", { code: value }), "a hand-over code is 43 characters of strict base64url", "handoff_invalid");
  }

  return cases;
}

/** File name -> exact text of every generated file. */
export function files() {
  const out = {};
  for (const [name, value] of Object.entries(fixtures())) out[name] = `${JSON.stringify(value)}\n`;
  out["error_codes.json"] = `${JSON.stringify(ERROR_CODES)}\n`;
  out["invalid.json"] = `[\n${invalidCases().map((c) => JSON.stringify(c)).join(",\n")}\n]\n`;
  return out;
}

/** Files in this directory that this script does not make. */
export const NOT_GENERATED = ["headers.json", "generate.mjs"];

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const wanted = files();
  if (process.argv.includes("--check")) {
    const bad = [];
    for (const [name, text] of Object.entries(wanted)) {
      let have = null;
      try {
        have = readFileSync(join(DIR, name), "utf8");
      } catch {}
      if (have !== text) bad.push(name);
    }
    for (const name of readdirSync(DIR)) {
      if (!(name in wanted) && !NOT_GENERATED.includes(name)) bad.push(`${name} (not generated)`);
    }
    if (bad.length > 0) {
      console.error(`wire fixtures out of date: ${bad.join(", ")}`);
      process.exit(1);
    }
  } else {
    for (const [name, text] of Object.entries(wanted)) writeFileSync(join(DIR, name), text);
  }
}
