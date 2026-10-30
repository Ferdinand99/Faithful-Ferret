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

/** File name -> exact text of every generated file. */
export function files() {
  const out = {};
  for (const [name, value] of Object.entries(fixtures())) out[name] = `${JSON.stringify(value)}\n`;
  out["error_codes.json"] = `${JSON.stringify(ERROR_CODES)}\n`;
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
