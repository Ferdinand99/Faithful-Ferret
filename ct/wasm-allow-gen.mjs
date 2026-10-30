// Writes ct/wasm-allow.toml from the hits of a scan, with a reason for each.
//
//   node ct/wasm-scan.mjs <module.wat> x --no-gate --json hits.json
//   node ct/wasm-allow-gen.mjs hits.json > ct/wasm-allow.toml
//
// One entry per function and kind of hit, `max` the number of hits there are
// now. Reviewing a change of the file means reading its diff: a new function,
// a new kind of hit or a higher `max` is a new instruction in our code that
// can take a time that depends on its operands. The reasons come from the
// table below, by module; a hit in a module that the table does not know makes
// the generator stop, so that somebody has to decide what it is.

import { readFileSync } from "node:fs";

const hits = JSON.parse(readFileSync(process.argv[2], "utf8")).hits;

const R1 = "ACCEPTED RESIDUAL RISK (TRIAGE.md R1). The master password is normalized to NFKD and checked for assigned code points with the tables of unicode-normalization and unicode-general-category: lookups and branches keyed by the characters of the password, not constant time. Once per unlock, in the user's own worker. No table-free NFKD exists, and the result has to be byte-identical to other implementations.";
const R2 = "ACCEPTED RESIDUAL RISK (TRIAGE.md R2). The one-time code is the dynamic truncation of the HMAC output taken modulo 10^digits (RFC 4226 section 5.3). The dividend is the HMAC output of this one code, not the TOTP secret; the code is shown to the user and sent to a server. The offset of the truncation is the low nibble of that HMAC output, an index into this code's own digest.";
const R3 = "ACCEPTED RESIDUAL RISK (TRIAGE.md R3). Reading the text of an otpauth URI, which holds the TOTP secret, with ordinary string functions: splitting on `?`, `&`, `=` and `%`, the names of parameters, the digits of numbers. The letters of the secret itself go through ct/harness/base32.rs without a branch or a table. The same text is a JavaScript string that cannot be wiped or made constant time.";
const R4 = "ACCEPTED RESIDUAL RISK (TRIAGE.md R4). The decrypted item body (CBOR), its views and the plaintext export: after the AEAD has accepted the data, in the user's own worker. Branches are on the CBOR structure and the type of a field, loads copy bytes of slices at `base + index`, tables are the hexadecimal digits and the escapes of the JSON and CSV writers, divisions are pointer differences over element sizes and row counts. Bytes of a password or a note are copied, not used as an address.";
const R6 = "ACCEPTED RESIDUAL RISK (TRIAGE.md R6). The `argon2` crate, inlined into our wrapper `prim::argon2::argon2id`; third-party code that this project does not re-verify (plan section 10 point 6). Argon2id addresses memory by data by design.";
const PUBLIC_ENUM = "A match on an enum (the unlock method, the error kind, the pinned field, the operation) or the labels of the TLV builder (public ASCII constants), and loads and element-size divisions on slices whose lengths are public. The key commitment, the tags and the MACs are compared by ct_eq, which has no hit.";
const PUBLIC_TEXT = "Public text: server addresses, QR text, origins, relying party ids, the public suffix list, the client data JSON, base64url and hexadecimal output of public values. The loop counter or a length is the index; the prefix of a recovery or secret key code (`FFR1`, `FFS1`) is compared with the constant prefix byte by byte, and the letters of the key itself go through ct/harness/crockford.rs, which has no hit.";
const GLUE = "The glue to JavaScript: serde field and variant names of the call (public strings), the kind of an error, the unlock method, the user verification mode, element sizes of the lists it converts. These are the structure of a call, not the key material behind it.";

const SHIM = "This is the export shim that wasm-bindgen makes (multivalue and externref conversions); wasm-opt inlined the glue of the call and parts of the code it calls into it. The hits are of the kinds of the modules the export uses, whose entries are above and whose reasoning applies; the count is exact, so one more hit fails the scan.";

/** The reason for a function path, or null. */
function reason(path, ins) {
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

let out = `# What ct/wasm-scan.mjs accepts in the WebAssembly build (plan section 10 point 4),
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
for (const { norm, ins, count } of [...merged.values()].sort((a, b) => a.norm.localeCompare(b.norm) || a.ins.localeCompare(b.ins))) {
  const why = reason(norm, ins);
  if (why === null) {
    missing.push(`${norm} / ${ins}`);
    continue;
  }
  out += `\n[[allow]]\nfunction = "${toml("^" + escapeRegex(norm) + "$")}"\ninstruction = "${toml(escapeRegex(ins))}"\nmax = ${count}\nreason = "${toml(why)}"\n`;
}
if (missing.length) {
  console.error("no reason for:\n  " + missing.join("\n  "));
  process.exit(1);
}
process.stdout.write(out);
