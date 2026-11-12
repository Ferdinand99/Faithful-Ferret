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

/**
 * A checkpoint as it is uploaded after a sync: three entries, sorted by item
 * id, each the item id (16), the revision as 8 bytes big endian and the hash
 * of the envelope (32).
 */
const checkpointEntries = () => {
  const rows = [
    ["entry one", 2],
    ["entry two", 1],
    ["entry three", 5],
  ].map(([label, rev]) => ({ item: bytes(label, 16), rev, hash: bytes(`${label} hash`, 32) }));
  rows.sort((x, y) => Buffer.compare(x.item, y.item));
  return Buffer.concat(
    rows.map(({ item, rev, hash }) => {
      const rev8 = Buffer.alloc(8);
      rev8.writeBigUInt64BE(BigInt(rev));
      return Buffer.concat([item, rev8, hash]);
    }),
  );
};
const checkpointPut = () => {
  const all = checkpointEntries();
  return {
    seq: 7,
    digest: createHash("sha256").update(all).digest("base64url"),
    mac: b64("checkpoint put mac", 32),
    entries: all.toString("base64url"),
  };
};
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

/**
 * The frozen rows of a restore, in item id order: a live item (with the
 * SHA-256 of its envelope) and a tombstone (no hash).
 */
const frozenRows = () =>
  [
    { id: id("item one"), rev: 2, seq: 3, hash: b64("item one hash", 32) },
    { id: id("item two"), rev: 3, seq: 4 },
  ].sort((x, y) => (x.id < y.id ? -1 : 1));

/** Changes in item id order, as the listing writes them. */
const listed = () => [liveChange(), deletedChange()].sort((x, y) => (x.id < y.id ? -1 : 1));

/** The operations of a batch: a live row, a row that asks to bring an item back, a tombstone. */
const batchLive = () => ({
  id: id("item one"),
  base_rev: 1,
  blob: envelope("item one", 1, 200),
  tag: b64("item one tag", 32),
  idem: id("idem one"),
  restore_epoch: 2,
});
const batchResurrect = () => ({
  id: id("item three"),
  base_rev: 3,
  blob: envelope("item three", 1, 180),
  tag: b64("item three tag", 32),
  idem: id("idem three"),
  resurrect: true,
});
const batchDeleted = () => ({
  id: id("item two"),
  base_rev: 2,
  deleted: true,
  tomb: b64("item two tomb", 40),
  idem: id("idem two"),
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
    "login_finish_req.reauth.json": {
      login_id: id("login"),
      ke3: b64("ke3", 64),
      device_id: id("device"),
      device_name: "Firefox on a laptop",
      purpose: "reauth",
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
      restore_epoch: 2,
      restore_seq: 4,
      checkpoint: head(),
      has_more: true,
    },
    "changes_res.empty.json": {
      changes: [],
      latest_seq: 0,
      vk_epoch: 1,
      restore_epoch: 0,
      restore_seq: 0,
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
    // A live row that asks to bring a deleted item back, written against the
    // revision of the tombstone ("put_item_req.tombstone.json" is at rev 2).
    "put_item_req.resurrect.json": {
      base_rev: 2,
      blob: envelope("item two", 1, 200),
      tag: b64("item two tag", 32),
      idem: id("idem three"),
      resurrect: true,
    },
    // A live row written on the condition that the vault is at restore epoch 2.
    "put_item_req.restore_epoch.json": {
      base_rev: 1,
      blob: envelope("item one", 1, 200),
      tag: b64("item one tag", 32),
      idem: id("idem one"),
      restore_epoch: 2,
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
    // A write against a row that is not there: revision 0, no blob, no tag.
    "conflict_res.absent.json": { current_rev: 0, deleted: false },
    "error_res.json": { error: "unauthorized" },
    "batch_req.json": { ops: [batchLive(), batchResurrect(), batchDeleted()] },
    "batch_res.json": {
      results: [
        { status: 200, rev: 2, seq: 5, replayed: false },
        { status: 200, rev: 3, seq: 6, replayed: true },
        {
          status: 409,
          current_rev: 4,
          blob: envelope("item one", 1, 200),
          tag: b64("item one tag", 32),
          deleted: false,
        },
        { status: 409, current_rev: 5, deleted: true },
        { status: 422, error: "idem_reuse" },
        { status: 400, error: "bad_request" },
      ],
    },
    "checkpoint_put_req.json": checkpointPut(),
    "checkpoint_put_req.restore_epoch.json": { ...checkpointPut(), restore_epoch: 2 },
    // The answer to a write that names another restore epoch than the vault's.
    "restore_epoch_changed_res.json": { error: "restore_epoch_changed", restore_epoch: 3 },
    // An operation of a batch that named another restore epoch, in its own place.
    "batch_res.restore_epoch_changed.json": {
      results: [
        { status: 200, rev: 2, seq: 5, replayed: false },
        { status: 409, error: "restore_epoch_changed", restore_epoch: 3 },
      ],
    },
    "restore_rows_res.json": {
      restore_epoch: 2,
      restore_seq: 4,
      rows: frozenRows(),
      next_after: frozenRows()[1].id,
      has_more: true,
    },
    "restore_rows_res.last.json": {
      restore_epoch: 2,
      restore_seq: 4,
      rows: [frozenRows()[1]],
      has_more: false,
    },
    // A vault that was never restored.
    "restore_rows_res.empty.json": {
      restore_epoch: 0,
      restore_seq: 0,
      rows: [],
      has_more: false,
    },
    "checkpoint_put_res.json": { seq: 7 },
    "checkpoint_stale_res.json": { error: "checkpoint_stale", stored_seq: 9 },
    "items_res.json": {
      items: listed(),
      as_of_seq: 7,
      vk_epoch: 1,
      restore_epoch: 2,
      restore_seq: 4,
      next_after: listed()[1].id,
      has_more: true,
    },
    "items_res.last.json": {
      items: [deletedChange()],
      as_of_seq: 7,
      vk_epoch: 1,
      restore_epoch: 0,
      restore_seq: 0,
      has_more: false,
    },
    "sync_event.json": { seq: 7 },
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
  "gone",
  "busy",
  "checkpoint_stale",
  "checkpoint_invalid",
  "restore_epoch_changed",
];

/**
 * The HTTP status of each error code (error_statuses.json, in the order of
 * ERROR_CODES). The server checks it against its status table, and the web
 * vault against what its client does with each status.
 */
export const STATUS_OF = {
  unauthorized: 401,
  denied: 401,
  forbidden: 403,
  insecure_transport: 400,
  handoff_invalid: 400,
  manifest_not_writable: 403,
  malformed_registration_request: 400,
  malformed_registration_record: 400,
  malformed_ke1: 400,
  malformed_ke3: 400,
  malformed_login_id: 400,
  malformed_nonce: 400,
  malformed_proof: 400,
  malformed_login_name: 400,
  malformed_recovery_key: 400,
  registration_closed: 409,
  throttled: 429,
  profile_rejected: 422,
  unsupported_envelope: 422,
  tombstone_invalid: 422,
  too_large: 413,
  quota_exceeded: 413,
  idem_reuse: 422,
  conflict: 409,
  protocol_header_missing: 400,
  forbidden_origin: 403,
  not_found: 404,
  bad_request: 400,
  internal: 500,
  gone: 410,
  busy: 503,
  checkpoint_stale: 409,
  checkpoint_invalid: 422,
  restore_epoch_changed: 409,
};

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
  parse("changes_res without restore_seq", "changes_res", with_("changes_res.json", { restore_seq: undefined }), "restore_seq is required");
  parse("changes_res restore_seq 2^53", "changes_res", with_("changes_res.json", { restore_seq: 9007199254740992 }), "an integer is at most 2^53 - 1");
  parse("changes_res restore_seq negative", "changes_res", with_("changes_res.json", { restore_seq: -1 }), "an integer is not negative");
  parse("changes_res restore_seq is a string", "changes_res", with_("changes_res.json", { restore_seq: "4" }), "restore_seq is a number");
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
  for (const value of ["Login", "delete", "", 1]) {
    parse(`login finish purpose ${JSON.stringify(value)}`, "login_finish_req", with_("login_finish_req.reauth.json", { purpose: value }), "purpose is login or reauth");
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

  // A put request has exactly one form, and only a live row asks to bring an item back.
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
  validate("put resurrect true on a tombstone", "put_item_req", put({ deleted: true, tomb, resurrect: true }), "only a live row asks to bring an item back");

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

  // A batch: the parts of an operation, then the number and the form of the
  // operations. Every operation is read like a put request, with the item id in
  // the body.
  const batchWith = (op, fields) => {
    const value = clone("batch_req.json");
    const next = { ...value.ops[op] };
    for (const [key, v] of Object.entries(fields)) {
      if (v === undefined) delete next[key];
      else next[key] = v;
    }
    value.ops[op] = next;
    return text(value);
  };
  parse("batch ops is not a list", "batch_req", text({ ops: {} }), "ops is a list");
  parse("batch ops is null", "batch_req", text({ ops: null }), "ops is a list");
  parse("batch without ops", "batch_req", "{}", "ops is required");
  parse("batch ops holds a string", "batch_req", text({ ops: ["x"] }), "an operation is an object");
  parse("batch op without id", "batch_req", batchWith(0, { id: undefined }), "id is required");
  parse("batch op without idem", "batch_req", batchWith(0, { idem: undefined }), "idem is required");
  parse("batch op without base_rev", "batch_req", batchWith(0, { base_rev: undefined }), "base_rev is required");
  parse("batch op id upper case", "batch_req", batchWith(0, { id: id("item one").toUpperCase() }), "an id is lower case");
  parse("batch op id short", "batch_req", batchWith(0, { id: id("item one").slice(1) }), "an id is 32 characters");
  parse("batch op idem upper case", "batch_req", batchWith(0, { idem: id("idem one").toUpperCase() }), "an id is lower case");
  parse("batch op blob with padding", "batch_req", batchWith(0, { blob: "AA==" }), "not strict base64url");
  parse("batch op tag 31 bytes", "batch_req", batchWith(0, { tag: b64("short tag", 31) }), "a tag is 32 bytes");
  parse("batch op base_rev 2^53", "batch_req", batchWith(0, { base_rev: 9007199254740992 }), "an integer is at most 2^53 - 1");
  parse("batch op base_rev negative", "batch_req", batchWith(0, { base_rev: -1 }), "an integer is not negative");
  parse("batch op resurrect is a string", "batch_req", batchWith(1, { resurrect: "true" }), "resurrect is a boolean");
  parse("batch op deleted is a string", "batch_req", batchWith(2, { deleted: "true" }), "deleted is a boolean");
  for (const [name, n] of [["one short", 39], ["one long", 41], ["empty", 0]]) {
    parse(`batch op tomb ${name}`, "batch_req", batchWith(2, { tomb: b64(`batch tomb ${name}`, n) }), "tomb is 40 bytes", "tombstone_invalid");
  }
  parse(
    "repeated base_rev in a batch op",
    "batch_req",
    text(all["batch_req.json"]).replace('"base_rev":1', '"base_rev":1,"base_rev":1'),
    "a repeated field is refused inside a part",
  );
  const batchOf = (n) => text({ ops: Array.from({ length: n }, (_, i) => ({ ...clone("batch_req.json").ops[2], id: id(`bulk ${i}`), idem: id(`bulk idem ${i}`) })) });
  validate("batch with no operations", "batch_req", text({ ops: [] }), "a batch has 1 to 100 operations");
  validate("batch with 101 operations", "batch_req", batchOf(101), "a batch has 1 to 100 operations");
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
    ["resurrect true on a tombstone", { deleted: true, tomb, resurrect: true }],
  ]) {
    const op = { id: id("form item"), base_rev: 1, ...fields, idem };
    validate(`batch op form: ${name}`, "batch_req", text({ ops: [batchLive(), op] }), "an operation is a live row (blob, tag) or a tombstone (deleted true, tomb), never both, and only a live row asks to bring an item back");
  }

  // The results of a batch: one form each, with the status that goes with it.
  const results = (...list) => text({ results: list });
  const stored = { status: 200, rev: 2, seq: 5, replayed: false };
  const conflictLive = { status: 409, current_rev: 4, blob: envelope("item one", 1, 200), tag: b64("item one tag", 32), deleted: false };
  const conflictDeleted = { status: 409, current_rev: 5, deleted: true };
  const refused = { status: 422, error: "idem_reuse" };
  parse("batch results is not a list", "batch_res", text({ results: {} }), "results is a list");
  parse("batch without results", "batch_res", "{}", "results is required");
  parse("batch result is a string", "batch_res", text({ results: ["x"] }), "a result is an object");
  parse("batch result without status", "batch_res", results({ rev: 2, seq: 5, replayed: false }), "status is required");
  parse("batch result status is a string", "batch_res", results({ ...stored, status: "200" }), "status is a number");
  parse("batch result status 65536", "batch_res", results({ ...stored, status: 65536 }), "status fits in 16 bits");
  parse("batch result rev 2^53", "batch_res", results({ ...stored, rev: 9007199254740992 }), "an integer is at most 2^53 - 1");
  parse("batch result seq negative", "batch_res", results({ ...stored, seq: -1 }), "an integer is not negative");
  parse("batch result replayed is a number", "batch_res", results({ ...stored, replayed: 0 }), "replayed is a boolean");
  parse("batch result blob with padding", "batch_res", results({ ...conflictLive, blob: "AA==" }), "not strict base64url");
  parse("batch result tag 31 bytes", "batch_res", results({ ...conflictLive, tag: b64("short tag", 31) }), "a tag is 32 bytes");
  parse("batch result deleted is a string", "batch_res", results({ ...conflictDeleted, deleted: "true" }), "deleted is a boolean");
  parse("batch result error is a number", "batch_res", results({ ...refused, error: 5 }), "error is a string");
  parse("batch result unknown field", "batch_res", results({ ...stored, x: 1 }), "an unknown field is refused inside a part");
  for (const [name, result] of [
    ["status only", { status: 200 }],
    ["stored without seq", { status: 200, rev: 2, replayed: false }],
    ["stored without replayed", { status: 200, rev: 2, seq: 5 }],
    ["stored with status 409", { ...stored, status: 409 }],
    ["stored with status 201", { ...stored, status: 201 }],
    ["stored with an error", { ...stored, error: "bad_request" }],
    ["stored with current_rev", { ...stored, current_rev: 2 }],
    ["conflict with status 200", { ...conflictLive, status: 200 }],
    ["conflict with status 422", { ...conflictLive, status: 422 }],
    ["conflict live without tag", { status: 409, current_rev: 4, blob: conflictLive.blob, deleted: false }],
    ["conflict live without blob", { status: 409, current_rev: 4, tag: conflictLive.tag, deleted: false }],
    ["conflict live with neither", { status: 409, current_rev: 4, deleted: false }],
    ["conflict absent with a blob", { status: 409, current_rev: 0, blob: conflictLive.blob, deleted: false }],
    ["conflict absent with a tag", { status: 409, current_rev: 0, tag: conflictLive.tag, deleted: false }],
    ["conflict absent with blob and tag", { ...conflictLive, current_rev: 0 }],
    ["conflict deleted at current_rev 0", { status: 409, current_rev: 0, deleted: true }],
    ["conflict deleted with blob and tag", { ...conflictLive, deleted: true }],
    ["conflict deleted with a tag", { status: 409, current_rev: 5, tag: conflictLive.tag, deleted: true }],
    ["conflict without deleted", { status: 409, current_rev: 4, blob: conflictLive.blob, tag: conflictLive.tag }],
    ["conflict without current_rev", { status: 409, deleted: true }],
    ["conflict with rev", { ...conflictDeleted, rev: 2 }],
    ["conflict with an error", { ...conflictDeleted, error: "conflict" }],
    ["refused with status 200", { ...refused, status: 200 }],
    ["refused with status 399", { ...refused, status: 399 }],
    ["refused with status 600", { ...refused, status: 600 }],
    ["refused with an empty error", { ...refused, error: "" }],
    ["refused with rev", { ...refused, rev: 2 }],
    ["refused with a blob", { ...refused, blob: conflictLive.blob }],
    ["refused with deleted", { ...refused, deleted: false }],
    ["stored with rev 0", { ...stored, rev: 0 }],
    ["refused with the status of another code", { status: 400, error: "idem_reuse" }],
    ["refused with 422 for a 400 code", { status: 422, error: "bad_request" }],
    ["refused with an unknown code", { status: 400, error: "not_a_code" }],
    ["refused with an unknown code and status 500", { status: 500, error: "not_a_code" }],
    ["refused with status 409 and the code conflict", { status: 409, error: "conflict" }],
    ["refused with status 409 and the code checkpoint_stale", { status: 409, error: "checkpoint_stale" }],
    ["refused with status 409 and the code registration_closed", { status: 409, error: "registration_closed" }],
  ]) {
    validate(`batch result: ${name}`, "batch_res", results(stored, result), "a result is stored (200, rev, seq, replayed), a conflict (409, current_rev, deleted, and blob and tag for a live row) or refused (an error code with the status of that code, never 409), and carries no field of another form");
  }
  // The answer of a single write: the same rule for the row it describes.
  const conflictRes = (fields) => text({ ...fields });
  const liveRow = { blob: envelope("item one", 1, 200), tag: b64("item one tag", 32) };
  const conflictWhy = "a conflict answer is a live row (blob and tag, current_rev at least 1), a deleted one (current_rev at least 1) or an absent one (current_rev 0, not deleted): neither blob nor tag";
  validate("conflict_res: current_rev 0 with blob and tag", "conflict_res", conflictRes({ current_rev: 0, ...liveRow, deleted: false }), conflictWhy);
  validate("conflict_res: current_rev 0 with a blob", "conflict_res", conflictRes({ current_rev: 0, blob: liveRow.blob, deleted: false }), conflictWhy);
  validate("conflict_res: current_rev 4 live without blob", "conflict_res", conflictRes({ current_rev: 4, tag: liveRow.tag, deleted: false }), conflictWhy);
  validate("conflict_res: current_rev 4 live without blob and tag", "conflict_res", conflictRes({ current_rev: 4, deleted: false }), conflictWhy);
  validate("conflict_res: deleted at current_rev 0", "conflict_res", conflictRes({ current_rev: 0, deleted: true }), conflictWhy);
  validate("conflict_res: deleted with blob and tag", "conflict_res", conflictRes({ current_rev: 5, ...liveRow, deleted: true }), conflictWhy);
  const manyResults = (n) => text({ results: Array.from({ length: n }, (_, i) => ({ ...stored, rev: i + 1 })) });
  validate("batch results: none", "batch_res", text({ results: [] }), "a batch answer has 1 to 100 results");
  validate("batch results: 101", "batch_res", manyResults(101), "a batch answer has 1 to 100 results");

  // The condition on the restore epoch: the same number rules in the three requests.
  for (const [what, shape, file] of [
    ["put_item_req", "put_item_req", "put_item_req.restore_epoch.json"],
    ["batch_req operation", "batch_req", "batch_req.json"],
    ["checkpoint_put_req", "checkpoint_put_req", "checkpoint_put_req.restore_epoch.json"],
  ]) {
    const withEpoch = (literal) => {
      const raw = text(all[file]);
      const marked = raw.replace('"restore_epoch":2', `"restore_epoch":${literal}`);
      if (marked === raw) throw new Error(`no restore_epoch in ${what}`);
      return marked;
    };
    for (const [name, literal] of [
      ["2^53", "9007199254740992"],
      ["negative", "-1"],
      ["a fraction", "1.5"],
      ["a string", '"2"'],
      ["true", "true"],
      ["an array", "[2]"],
    ]) {
      parse(`${what} restore_epoch ${name}`, shape, withEpoch(literal), "restore_epoch is a whole number from 0 to 2^53 - 1");
    }
  }

  // A checkpoint upload, the answers, the listing and an event.
  parse("checkpoint_put_req digest 31 bytes", "checkpoint_put_req", with_("checkpoint_put_req.json", { digest: b64("short digest", 31) }), "a digest is 32 bytes");
  parse("checkpoint_put_req mac 33 bytes", "checkpoint_put_req", with_("checkpoint_put_req.json", { mac: b64("long mac", 33) }), "a MAC is 32 bytes");
  parse("checkpoint_put_req entries with padding", "checkpoint_put_req", with_("checkpoint_put_req.json", { entries: "AA==" }), "not strict base64url");
  parse("checkpoint_put_req seq 2^53", "checkpoint_put_req", with_("checkpoint_put_req.json", { seq: 9007199254740992 }), "an integer is at most 2^53 - 1");
  parse("checkpoint_put_req without entries", "checkpoint_put_req", with_("checkpoint_put_req.json", { entries: undefined }), "entries is required");
  parse("checkpoint_put_req without seq", "checkpoint_put_req", with_("checkpoint_put_req.json", { seq: undefined }), "seq is required");
  parse("checkpoint_put_res seq negative", "checkpoint_put_res", with_("checkpoint_put_res.json", { seq: -1 }), "an integer is not negative");
  parse("checkpoint_put_res without seq", "checkpoint_put_res", "{}", "seq is required");
  parse("checkpoint_stale_res with another code", "checkpoint_stale_res", with_("checkpoint_stale_res.json", { error: "conflict" }), "the code is checkpoint_stale");
  parse("checkpoint_stale_res with an empty code", "checkpoint_stale_res", with_("checkpoint_stale_res.json", { error: "" }), "the code is checkpoint_stale");
  parse("checkpoint_stale_res without stored_seq", "checkpoint_stale_res", with_("checkpoint_stale_res.json", { stored_seq: undefined }), "stored_seq is required");
  parse("checkpoint_stale_res stored_seq 1.5", "checkpoint_stale_res", with_("checkpoint_stale_res.json", { stored_seq: 1.5 }), "an integer is whole");
  parse("items_res next_after upper case", "items_res", with_("items_res.json", { next_after: listed()[1].id.toUpperCase() }), "an id is lower case");
  parse("items_res next_after short", "items_res", with_("items_res.json", { next_after: listed()[1].id.slice(1) }), "an id is 32 characters");
  parse("items_res next_after is a number", "items_res", with_("items_res.json", { next_after: 5 }), "an id is a string");
  parse("items_res without as_of_seq", "items_res", with_("items_res.json", { as_of_seq: undefined }), "as_of_seq is required");
  parse("items_res without restore_epoch", "items_res", with_("items_res.json", { restore_epoch: undefined }), "restore_epoch is required");
  parse("items_res without restore_seq", "items_res", with_("items_res.json", { restore_seq: undefined }), "restore_seq is required");
  parse("items_res restore_seq 2^53", "items_res", with_("items_res.json", { restore_seq: 9007199254740992 }), "an integer is at most 2^53 - 1");
  parse("items_res restore_seq 1.5", "items_res", with_("items_res.json", { restore_seq: 1.5 }), "an integer is whole");
  parse("items_res without has_more", "items_res", with_("items_res.json", { has_more: undefined }), "has_more is required");
  parse("items_res has_more is a string", "items_res", with_("items_res.json", { has_more: "true" }), "has_more is a boolean");
  validate("items_res: more rows without next_after", "items_res", with_("items_res.json", { next_after: undefined }), "next_after is there exactly when has_more is true");
  validate("items_res: the last page with next_after", "items_res", with_("items_res.last.json", { next_after: listed()[1].id }), "next_after is there exactly when has_more is true");
  parse("items_res items holds a string", "items_res", with_("items_res.json", { items: ["x"] }), "an item is an object");
  parse("items_res as_of_seq 2^53", "items_res", with_("items_res.json", { as_of_seq: 9007199254740992 }), "an integer is at most 2^53 - 1");
  nested("items_res: unknown field in an item", "items_res", "items_res.json", ["items", 0], "an unknown field is refused inside a part");
  nested("batch_req: unknown field in an operation", "batch_req", "batch_req.json", ["ops", 0], "an unknown field is refused inside a part");
  // The answer to a write that names another restore epoch.
  parse("restore_epoch_changed_res with another code", "restore_epoch_changed_res", with_("restore_epoch_changed_res.json", { error: "conflict" }), "the code is restore_epoch_changed");
  parse("restore_epoch_changed_res with an empty code", "restore_epoch_changed_res", with_("restore_epoch_changed_res.json", { error: "" }), "the code is restore_epoch_changed");
  parse("restore_epoch_changed_res without restore_epoch", "restore_epoch_changed_res", with_("restore_epoch_changed_res.json", { restore_epoch: undefined }), "restore_epoch is required");
  parse("restore_epoch_changed_res restore_epoch 2^53", "restore_epoch_changed_res", with_("restore_epoch_changed_res.json", { restore_epoch: 9007199254740992 }), "an integer is at most 2^53 - 1");
  parse("restore_epoch_changed_res restore_epoch negative", "restore_epoch_changed_res", with_("restore_epoch_changed_res.json", { restore_epoch: -1 }), "an integer is not negative");
  // A batch result that names the epoch has its own form.
  const epochResult = { status: 409, error: "restore_epoch_changed", restore_epoch: 3 };
  for (const [name, result] of [
    ["restore_epoch_changed with status 422", { ...epochResult, status: 422 }],
    ["restore_epoch_changed with status 200", { ...epochResult, status: 200 }],
    ["restore_epoch_changed without restore_epoch", { status: 409, error: "restore_epoch_changed" }],
    ["restore_epoch_changed with rev", { ...epochResult, rev: 2 }],
    ["restore_epoch_changed with current_rev", { ...epochResult, current_rev: 2 }],
    ["restore_epoch_changed with deleted", { ...epochResult, deleted: true }],
    ["restore_epoch on a refusal", { status: 422, error: "idem_reuse", restore_epoch: 3 }],
    ["restore_epoch on a stored result", { ...stored, restore_epoch: 3 }],
    ["restore_epoch on a conflict", { ...conflictDeleted, restore_epoch: 3 }],
    ["restore_epoch alone", { status: 409, restore_epoch: 3 }],
  ]) {
    validate(`batch result: ${name}`, "batch_res", results(stored, result), "a result that names the restore epoch has status 409, the code restore_epoch_changed and the epoch, and no field of another form");
  }
  parse("batch result restore_epoch 2^53", "batch_res", results({ ...epochResult, restore_epoch: 9007199254740992 }), "an integer is at most 2^53 - 1");

  // The frozen rows of a restore.
  parse("restore_rows_res without restore_epoch", "restore_rows_res", with_("restore_rows_res.json", { restore_epoch: undefined }), "restore_epoch is required");
  parse("restore_rows_res without restore_seq", "restore_rows_res", with_("restore_rows_res.json", { restore_seq: undefined }), "restore_seq is required");
  parse("restore_rows_res without rows", "restore_rows_res", with_("restore_rows_res.json", { rows: undefined }), "rows is required");
  parse("restore_rows_res without has_more", "restore_rows_res", with_("restore_rows_res.json", { has_more: undefined }), "has_more is required");
  parse("restore_rows_res has_more is a string", "restore_rows_res", with_("restore_rows_res.json", { has_more: "true" }), "has_more is a boolean");
  parse("restore_rows_res rows is an object", "restore_rows_res", with_("restore_rows_res.json", { rows: {} }), "rows is a list");
  parse("restore_rows_res rows holds a string", "restore_rows_res", with_("restore_rows_res.json", { rows: ["x"] }), "a row is an object");
  parse("restore_rows_res restore_seq 2^53", "restore_rows_res", with_("restore_rows_res.json", { restore_seq: 9007199254740992 }), "an integer is at most 2^53 - 1");
  parse("restore_rows_res next_after upper case", "restore_rows_res", with_("restore_rows_res.json", { next_after: frozenRows()[1].id.toUpperCase() }), "an id is lower case");
  parse("restore_rows_res next_after short", "restore_rows_res", with_("restore_rows_res.json", { next_after: frozenRows()[1].id.slice(1) }), "an id is 32 characters");
  validate("restore_rows_res: more rows without next_after", "restore_rows_res", with_("restore_rows_res.json", { next_after: undefined }), "next_after is there exactly when has_more is true");
  validate("restore_rows_res: the last page with next_after", "restore_rows_res", with_("restore_rows_res.last.json", { next_after: frozenRows()[1].id }), "next_after is there exactly when has_more is true");
  const rowsWith = (index, fields) => {
    const value = clone("restore_rows_res.json");
    for (const [key, v] of Object.entries(fields)) {
      if (v === undefined) delete value.rows[index][key];
      else value.rows[index][key] = v;
    }
    return text(value);
  };
  const live = frozenRows().findIndex((row) => row.hash !== undefined);
  parse("restore_rows_res row hash 31 bytes", "restore_rows_res", rowsWith(live, { hash: b64("short hash", 31) }), "a hash is 32 bytes");
  parse("restore_rows_res row hash 33 bytes", "restore_rows_res", rowsWith(live, { hash: b64("long hash", 33) }), "a hash is 32 bytes");
  parse("restore_rows_res row hash with padding", "restore_rows_res", rowsWith(live, { hash: `${b64("hash", 32)}=` }), "not strict base64url");
  parse("restore_rows_res row id upper case", "restore_rows_res", rowsWith(0, { id: frozenRows()[0].id.toUpperCase() }), "an id is lower case");
  parse("restore_rows_res row without id", "restore_rows_res", rowsWith(0, { id: undefined }), "id is required");
  parse("restore_rows_res row without rev", "restore_rows_res", rowsWith(0, { rev: undefined }), "rev is required");
  parse("restore_rows_res row without seq", "restore_rows_res", rowsWith(0, { seq: undefined }), "seq is required");
  parse("restore_rows_res row rev 2^53", "restore_rows_res", rowsWith(0, { rev: 9007199254740992 }), "an integer is at most 2^53 - 1");
  parse("restore_rows_res row seq negative", "restore_rows_res", rowsWith(0, { seq: -1 }), "an integer is not negative");
  nested("restore_rows_res: unknown field in a row", "restore_rows_res", "restore_rows_res.json", ["rows", 0], "an unknown field is refused inside a part");

  parse("sync_event seq is a string", "sync_event", with_("sync_event.json", { seq: "7" }), "seq is a number");
  parse("sync_event without seq", "sync_event", "{}", "seq is required");
  parse("sync_event seq 2^53", "sync_event", with_("sync_event.json", { seq: 9007199254740992 }), "an integer is at most 2^53 - 1");
  parse("sync_event seq negative", "sync_event", with_("sync_event.json", { seq: -1 }), "an integer is not negative");
  parse("sync_event with a second field", "sync_event", text({ seq: 7, vault: id("vault") }), "an event carries the sequence number and nothing else");

  return cases;
}

/** File name -> exact text of every generated file. */
export function files() {
  const out = {};
  for (const [name, value] of Object.entries(fixtures())) out[name] = `${JSON.stringify(value)}\n`;
  out["error_codes.json"] = `${JSON.stringify(ERROR_CODES)}\n`;
  const statuses = ERROR_CODES.map((code) => {
    if (!Number.isInteger(STATUS_OF[code])) throw new Error(`no status for ${code}`);
    return [code, STATUS_OF[code]];
  });
  out["error_statuses.json"] = `${JSON.stringify(Object.fromEntries(statuses))}\n`;
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
