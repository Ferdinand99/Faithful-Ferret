// Writes ct/wasm-allow.toml from the hits of a scan, with a reason for each.
//
//   node ct/wasm-scan.mjs <module.wat> x --no-gate --json hits.json
//   node ct/wasm-allow-gen.mjs hits.json --existing ct/wasm-allow.toml > new.toml
//   node ct/wasm-allow-gen.mjs hits.json --existing ct/wasm-allow.toml \
//        --approve 'ferret_core::wrap::unwrap_vk=a person's reason' > new.toml
//
// One entry per function and kind of hit, `max` the number of hits there are
// now. Reviewing a change of the file means reading its diff: a new function,
// a new kind of hit or a higher `max` is a new instruction in our code that
// can take a time that depends on its operands.
//
// A regenerated file must not bless what a person has not looked at. For a
// function in a module that handles key material (KEY below, and every export
// shim and function without a name, which may hold inlined key code) the
// generator refuses to add an entry, to add a kind of hit or to raise a `max`
// unless the existing file has that entry with at least that `max`, or the
// function is passed with `--approve 'function=reason'`; the reason of the
// person goes into the entry, marked `APPROVED: ` (ct/wasm-allow-baseline.mjs
// looks for the mark when a pull request is compared with its base). Entries that already exist keep the reason that
// the file has (so a reason written by hand stays); a new entry gets the reason
// of the table below, by module, and a hit in a module that the table does not
// know stops the generator. `--table-reasons` ignores the existing reasons (to
// rewrite them all from the table). CI regenerates the file and fails on a diff.

import { readFileSync } from "node:fs";
import { KEY } from "./wasm-key.mjs";

const argv = process.argv.slice(2);
const option = (name) => {
  const values = [];
  argv.forEach((a, i) => {
    if (a === name) values.push(argv[i + 1]);
  });
  return values;
};
const hitsPath = argv.find((a, i) => !a.startsWith("--") && !["--existing", "--approve"].includes(argv[i - 1]));
const hits = JSON.parse(readFileSync(hitsPath, "utf8")).hits;
const approvals = new Map(
  option("--approve").map((a) => {
    const at = a.indexOf("=");
    if (at < 1 || a.slice(at + 1).trim().length < 20) {
      console.error(`--approve needs 'function=reason' with a reason of at least 20 characters: ${a}`);
      process.exit(2);
    }
    return [a.slice(0, at), a.slice(at + 1)];
  }),
);
const tableReasons = argv.includes("--table-reasons");

/** The `[[allow]]` entries of an existing file, by function and instruction. */
function parseExisting(path) {
  const entries = new Map();
  let cur = null;
  for (const raw of readFileSync(path, "utf8").replace(/\r\n/g, "\n").split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (line === "[[allow]]") {
      cur = {};
      continue;
    }
    const m = line.match(/^(\w+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(\d+))$/);
    if (!m || !cur) throw new Error(`cannot read "${raw}" in ${path}`);
    cur[m[1]] = m[2] !== undefined ? m[2].replace(/\\(.)/g, "$1") : Number(m[3]);
    if (cur.function !== undefined && cur.instruction !== undefined && cur.max !== undefined && cur.reason !== undefined) {
      entries.set(`${cur.function}\u0000${cur.instruction}`, cur);
    }
  }
  return entries;
}
const existingPath = option("--existing")[0];
const existing = existingPath ? parseExisting(existingPath) : new Map();

/** Modules that handle key material, passwords, codes or tags (ct/wasm-key.mjs). */

const R1 = "ACCEPTED RESIDUAL RISK (TRIAGE.md R1). The master password is normalized to NFKD and checked for assigned code points with the tables of unicode-normalization and unicode-general-category: lookups and branches keyed by the characters of the password, not constant time. Once per unlock, in the user's own worker. No table-free NFKD exists, and the result has to be byte-identical to other implementations.";
const R2 = "ACCEPTED RESIDUAL RISK (TRIAGE.md R2). The one-time code is the dynamic truncation of the HMAC output taken modulo 10^digits (RFC 4226 section 5.3). The dividend is the HMAC output of this one code, not the TOTP secret; the code is shown to the user and sent to a server. The offset of the truncation is the low nibble of that HMAC output, an index into this code's own digest.";
const R3 = "ACCEPTED RESIDUAL RISK (TRIAGE.md R3). Reading the text of an otpauth URI, which holds the TOTP secret, with ordinary string functions: splitting on `?`, `&`, `=` and `%`, the names of parameters, the digits of numbers. The letters of the secret itself go through ct/harness/base32.rs without a branch or a table. The same text is a JavaScript string that cannot be wiped or made constant time.";
const R4 = "ACCEPTED RESIDUAL RISK (TRIAGE.md R4). The decrypted item body (CBOR), its views and the plaintext export: after the AEAD has accepted the data, in the user's own worker. Branches are on the CBOR structure and the type of a field, loads copy bytes of slices at `base + index`, tables are the hexadecimal digits and the escapes of the JSON and CSV writers, divisions are pointer differences over element sizes and row counts. Bytes of a password or a note are copied, not used as an address.";
const R6 = "ACCEPTED RESIDUAL RISK (TRIAGE.md R6). The `argon2` crate, inlined into our wrapper `prim::argon2::argon2id`; third-party code that this project does not re-verify. Argon2id addresses memory by data by design.";
const PUBLIC_ENUM = "A match on an enum (the unlock method, the error kind, the pinned field, the operation) or the labels of the TLV builder (public ASCII constants), and loads and element-size divisions on slices whose lengths are public. The key commitment, the tags and the MACs are compared by ct_eq, which has no hit.";
const PUBLIC_TEXT = "Public text: server addresses, QR text, origins, relying party ids, the public suffix list, the client data JSON, base64url and hexadecimal output of public values. The loop counter or a length is the index; the prefix of a recovery or secret key code (`FFR1`, `FFS1`) is compared with the constant prefix byte by byte, and the letters of the key itself go through ct/harness/crockford.rs, which has no hit.";
const GLUE = "The glue to JavaScript: serde field and variant names of the call (public strings), the kind of an error, the unlock method, the user verification mode, element sizes of the lists it converts. These are the structure of a call, not the key material behind it.";

const SHIM = "This is the export shim that wasm-bindgen makes (multivalue and externref conversions); wasm-opt inlined the glue of the call and parts of the code it calls into it. The hits are of the kinds of the modules the export uses, whose entries are above and whose reasoning applies; the count is exact, so one more hit fails the scan.";

const COUNT = "the copy of the typed characters into a fixed buffer at `base + count`, and the read of the constant prefix bytes at `base + loop counter`: the index is a count, a character is only stored";
const LENGTH_ORDER = "a match on how the length of the typed code compares with the expected length (too short, too long, right), and on the error kind: public lengths. The letters of the key are read by crockford::decode_symbols, which wasm-opt left as a call and which has no hit";
const METHOD = "a match on the unlock method (password, recovery key, passkey, PIN, device), a public tag of the call";
/** Reasons written for a function and a kind of hit, before the ones by module. */
const SPECIFIC = {
  "ferret_core::codes::decode_secret_key|br_table": `The typed secret key code: ${LENGTH_ORDER}.`,
  "ferret_core::codes::decode_recovery_key|br_table": `The typed recovery key code: ${LENGTH_ORDER}.`,
  "ferret_core::codes::decode_secret_key|i32.load(indexed)": `The typed secret key code: ${COUNT}.`,
  "ferret_core::codes::decode_recovery_key|i32.load(indexed)": `The typed recovery key code: ${COUNT}.`,
  "ferret_core::codes::decode_secret_key|i32.load(const-add)": "The typed secret key code: the prefix `FFS1` is compared with the constant prefix, byte `i` of the typed text (folded by normalize_byte) against byte `i` of the static prefix, i being the loop counter; the branch on the comparison is on the prefix, which is public (the typed letters of the key come after it).",
  "ferret_core::codes::decode_recovery_key|i32.load(const-add)": "The typed recovery key code: the prefix `FFR1` is compared with the constant prefix, byte `i` of the typed text (folded by normalize_byte) against byte `i` of the static prefix, i being the loop counter; the branch on the comparison is on the prefix, which is public (the typed letters of the key come after it).",
  "ferret_core::envelope::encrypt_manifest|i32.div_u": "The length of the list of manifest entries divided by the size of one entry, when the vectors are sized: element sizes of a public list (the entries are public data of the manifest).",
  "ferret_core::integrity::checkpoint::verify_checkpoint|br_table": "A match on the state of a row (live or deleted) of the checkpoint, which the server states; the MAC and the digest are compared by mac_eq, which has no hit.",
  "ferret_core::integrity::checkpoint::verify_checkpoint|i32.div_u": "The length of the checkpoint entries divided by the size of one entry (a public length of a public blob).",
  "ferret_core::integrity::checkpoint::verify_checkpoint|i32.load(indexed)": "Walking the rows of the checkpoint at `base + index`: the rows are public data that the server stores; the index is the loop counter.",
  "ferret_core::integrity::proof::proof_message|i32.load(static-table)": "The static label and name of the operation, chosen by a match on the operation (public); the account id, nonce and hash are copied by the TLV builder, not used as an address.",
  "ferret_core::integrity::rekey::manifest_next|i32.div_u": "Iterating the manifest's list of unlock methods to find the highest key generation: the element size of a public list.",
  "ferret_core::pinning::MethodKey>::of|br_table": "A match on the unlock method of a record (password, recovery key, passkey, or a local method that has no floor): a public tag.",
  "ferret_core::pinning::Pinned>::after_flow|br_table": "A match on the kind of method key (password, recovery key, passkey) of a floor that is checked and raised: a public tag; the generation numbers are public counters.",
  "ferret_core::secret::PrfOutput>::from_slice|br_table": "A match on how the length of the bytes handed in compares with 32 (too short, too long, right): a public length. The bytes are copied into the key, not used as an address.",
  "ferret_core::text::password::MasterPassword>::opaque_input|br_table": `A match on whether a password policy was checked and which one, and whether a secret key is present: public flags. The password bytes are copied into the wiped buffer.`,
  "ferret_core::tlv::Tlv>::label|i32.load(indexed)": "The bytes of a label (a public ASCII constant such as `ferret/v1/wrap`) are read at `base + index` while they are copied into the message.",
  "ferret_core::wrap::wrap_aad|br_table": `Building the AAD of a wrap: ${METHOD}.`,
  "ferret_core::wrap::wrap_vk|br_table": `Wrapping the vault key: ${METHOD}; the key commitment is compared by commit_eq, which has no hit.`,
  "ferret_core::wrap::unwrap_vk|br_table": `Opening a wrap: ${METHOD}; the key commitment is compared by commit_eq, which has no hit, before the AEAD is opened.`,
};

const JS_STRUCTURE = "the structure of a call from JavaScript, not key bytes: key material arrives as byte arrays that are copied";
/** Reasons written for a named function of the binding or of `sheet`, for every kind of hit in it. */
const BY_PATH = {
  "ferret_core_wasm::convert::check": `The check of the shape of a JavaScript argument before it is read: a match on the shape (any, list, object) and on the kind of the JS value; ${JS_STRUCTURE}.`,
  "ferret_core_wasm::convert::from_js": `serde-wasm-bindgen's reading of a JS value into a Rust type, inlined: a match on the kind of each value (number, string, array, object) and on field names; ${JS_STRUCTURE}.`,
  "ferret_core_wasm::convert::PinArg>::core": "Converting the pin argument of an unlock flow to the core's type: a match on first use against a pinned record; public tags and counters.",
  "ferret_core_wasm::convert::PinnedDto>::of": "Converting a pinned record to a JS object: a match on the kind of method key of each floor, and element-size divisions of the list of floors (public counters).",
  "ferret_core_wasm::convert::WrapDto>::core": "Converting a wrap record from JS to the core's type: a match on the unlock method (a public tag); the wrap bytes are copied.",
  "ferret_core_wasm::convert::WrapDto>::of": "Converting a wrap record to a JS object: a match on the unlock method (a public tag); the wrap bytes are copied.",
  "ferret_core_wasm::export::items_of": "Decrypting the rows of an export request: matches on the result and the error kind of each decrypt_item (inlined) and on the row; the keys are inside decrypt_item and the AEAD, not addresses here.",
  "ferret_core_wasm::item::build_body": "Building an item body from the JS draft: matches on the item type and the field kind, and element-size divisions of the lists of fields and URLs; the field values are copied.",
  "ferret_core_wasm::item::ViewDto>::of": "Building the JS view of an item body: element-size divisions of the lists of fields and URLs that are mapped; the field values are copied.",
  "ferret_core_wasm::job::bind_to_qr": "Binding a pin to the setup QR: a match on first use against a pinned record and on whether a QR was scanned; the server key and the secret-key bit are compared, not used as an address.",
  "ferret_core_wasm::passkey::user_verification": "A match on the user verification mode a caller names (required, preferred, discouraged): a public string turned into an enum.",
  "ferret_core_wasm::vault::Inner>::open": "Registering an opened item under a handle: the handle is a counter, the map is a BTreeMap keyed by it (its node search is the indexed load); the item body is moved in, not used as an address.",
  "ferret_core_wasm::vault::Vault>::passkey_create": "Creating a passkey: wasm-opt inlined the passkey code into this method, so the hits are of the kinds of the passkey::origin, client_data and psl entries (matches on the user verification mode and the error kind, base64url and element-size divisions, loads of public text such as the origin and the relying party id) and of the conversions of its arguments. The credential key and the PRF output are made and held by ferret_core and the p256 crate (third-party, counted under other crates), not read through these hits. The count is exact, so one more hit fails the scan and the generator refuses it.",
  "ferret_core::sheet::parse_server_address": "Reading the server address the user typed or scanned: scheme, host and port checks, and the IPv4 form, on public text; the index is the loop counter. The emergency sheet carries the key as a Crockford code that codes.rs reads, not through this function.",
  "ferret_core::sheet::parse_setup_qr": "Reading the setup QR text (`ferret-setup:v1?u=...&a=...&k=...&s=...&o=...`): matches on the parameter names and loads at `base + index` of public text (server address, account id, server public key, the secret-key bit).",
  "ferret_core::sheet::push_hex": "Lower-case hexadecimal output, with a table of the 16 digits, of the account id and the server public key for the setup QR: both are public, so the nibble that indexes the table is public.",
  "ferret_core::sheet::setup_qr_payload": "Building the setup QR text: the same hexadecimal table, inlined from push_hex, for the account id and the server public key (public).",
};

/** The reason for a function path, or null. */
function reason(path, ins) {
  if (BY_PATH[path]) return BY_PATH[path];
  const specific = SPECIFIC[`${path}|${ins}`];
  if (specific) return specific;
  if (/^ferret_core::text::unicode::normalize_password$/.test(path)) return R1;
  if (/^ferret_core::totp::totp_code$/.test(path)) return R2;
  if (/^ferret_core::totp::(totp_seconds_left)$/.test(path)) return "The seconds left in the period: the remainder of the clock time by the period. Both are public.";
  if (/^ferret_core::totp::/.test(path) || /^ferret_core_wasm::item::normalize_otpauth$/.test(path)) return R3;
  if (/^ferret_core::item::pad::scan::unpad_scan$/.test(path)) return "The load of the byte at `base + index` in the scan of the padding; the index is the loop counter, which runs over the whole buffer whatever it holds. The byte it reads is never used as an address.";
  if (/^ferret_core::prim::argon2::/.test(path)) return R6;
  if (/^ferret_core::(cbor|item|export)::/.test(path)) return R4;
  if (/^ferret_core::(codes|sheet|passkey)::/.test(path)) return PUBLIC_TEXT;
  if (/^ferret_core::(wrap|pinning|secret|error|integrity|ids|tlv|envelope|text::password)::/.test(path)) return PUBLIC_ENUM;
  if (/^ferret_core_wasm::/.test(path)) return GLUE;
  if (/ shim$/.test(path)) return /totp/.test(path) ? R2 + " " + SHIM : SHIM;
  if (path === "unnamed") return "A function without a name in the module (made by wasm-opt or wasm-bindgen): a jump table or a table index of the externref table or of the glue; not attributable to a module of ours, counted exactly.";
  if (path === "__externref_table_alloc") return "The free list of the externref table that wasm-bindgen generates: an index into the table of JavaScript values, public.";
  return null;
}

const escapeRegex = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const toml = (text) => text.replace(/\\/g, "\\\\").replace(/"/g, '\\"');

const merged = new Map();
for (const { norm, ins, count } of hits) {
  const key = `${norm}\u0000${ins}`;
  merged.set(key, { norm, ins, count: (merged.get(key)?.count ?? 0) + count });
}

let out = `# What ct/wasm-scan.mjs accepts in the WebAssembly build,
# GENERATED by ct/wasm-allow-gen.mjs from a scan of the module at the optimisation
# level that is shipped (wasm-bindgen, wasm-opt -Oz, names kept). Do not edit by
# hand: read the diff of a regenerated file instead.
#
# The scan lists, for every function of ferret_core and ferret_core_wasm (and every
# function without a name), integer division and remainder, floating point
# division and square root, \`br_table\`, and loads that look up a table. Each hit
# has to be here, with the reason that its operands are public (or, where they
# are not, why it is accepted), and \`max\` is exact: one more hit in the function,
# or a new function with a hit, fails the scan. The test is
# \`wasm_scan_only_allowlisted\`. The positive controls of the scan are
# ct/wasm-selftest.mjs and ct/wasm-fixtures.
#
# Fields: \`function\` is a regular expression on the path of the function (names as
# wasm-bindgen demangles them, without the crate hashes and generic arguments),
# \`instruction\` a regular expression on the kind of hit (\`i32.div_u\`, \`br_table\`,
# \`i32.load(indexed)\`, \`i32.load(static-table)\`, \`i32.load(const-add)\`, ...),
# \`max\` the number of hits, and \`reason\` why they are acceptable.
`;
const missing = [];
const refused = [];
const used = new Set();
for (const { norm, ins, count } of [...merged.values()].sort((a, b) => a.norm.localeCompare(b.norm) || a.ins.localeCompare(b.ins))) {
  const fnKey = "^" + escapeRegex(norm) + "$";
  const insKey = escapeRegex(ins);
  const old = existing.get(`${fnKey}\u0000${insKey}`);
  const approved = approvals.get(norm);
  if (approved !== undefined) used.add(norm);
  let why;
  if (old && !tableReasons) {
    why = old.reason;
  } else {
    why = reason(norm, ins);
  }
  // A key-handling function: nothing new and nothing more without a person.
  if (KEY.test(norm) || /^ferret_core::item::pad::/.test(norm)) {
    const same = old && count <= old.max;
    if (!same) {
      if (approved === undefined) {
        refused.push(`${norm} / ${ins}: ${old ? `max ${old.max} -> ${count}` : `new entry, ${count}`}`);
        continue;
      }
      why = `APPROVED: ${approved}`;
    }
  }
  if (why === null) {
    missing.push(`${norm} / ${ins}`);
    continue;
  }
  out += `\n[[allow]]\nfunction = "${toml(fnKey)}"\ninstruction = "${toml(insKey)}"\nmax = ${count}\nreason = "${toml(why)}"\n`;
}
for (const fn of approvals.keys()) if (!used.has(fn)) missing.push(`--approve names a function with no hit: ${fn}`);
if (refused.length) {
  console.error(
    "a function that handles key material has a new hit or more hits than the file allows; " +
      "look at the code, and pass --approve 'function=reason' with a reason in your own words:\n  " +
      refused.join("\n  "),
  );
  process.exit(3);
}
if (missing.length) {
  console.error("no reason for:\n  " + missing.join("\n  "));
  process.exit(1);
}
process.stdout.write(out);
