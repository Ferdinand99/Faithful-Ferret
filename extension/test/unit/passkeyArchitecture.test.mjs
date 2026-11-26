// The architecture rule of the passkey provider (GC60), over every source file of the extension and of the web vault, not only
// the script in the page's world: no code outside the Rust core signs for a passkey, imports a passkey's key, or builds the
// authenticator data or the client data of an answer. The core does all of it (`passkey_get`, `passkey_create`, ...); the
// JavaScript only carries the bytes it is given, checks what the browser gave back, and maps them to the page's own shapes.
//
// These are text scans, the way the other architecture tests are: a new file that names one of these things fails here, and
// the person who adds it has to read why the list is what it is, and add the file with a reason.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const ROOTS = [join(repo, "extension", "src"), join(repo, "web", "src")];

/** The text without block comments and without whole-line `//` comments (a note may name what the code must not do). @param {string} text */
const code = (text) => text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");

/** Every source file of both packages, by path from the repository root, with its code (comments left out). @returns {Map<string, string>} */
function sources() {
  /** @type {Map<string, string>} */
  const out = new Map();
  const walk = (/** @type {string} */ dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (/\.(?:mjs|js|html)$/.test(entry.name)) out.set(relative(repo, path).replaceAll("\\", "/"), code(readFileSync(path, "utf8")));
    }
  };
  for (const root of ROOTS) walk(root);
  return out;
}

/**
 * The files whose code matches, other than the ones allowed.
 * @param {Map<string, string>} files @param {RegExp} pattern @param {string[]} allowed
 */
const strangers = (files, pattern, allowed) => [...files].filter(([path, text]) => pattern.test(text) && !allowed.includes(path)).map(([path]) => path);

/** The files that use WebCrypto for more than a SHA-256 digest (a hash cannot sign), each with what it does, for the person who has to add one. */
const SUBTLE_USERS = Object.freeze({
  "web/src/auth/deviceKey.mjs": "the device key: it makes the P-256 pair, and checks that the pair still works",
  "web/src/auth/dpop.mjs": "DPoP proofs for the server (signed with the device key)",
  "web/src/flows/deviceSecret.mjs": "the device secret: an AES-GCM key that never leaves the browser's key store",
});

/** The files that name a part of an answer, each with what it does with it. */
const ANSWER_WORDS = Object.freeze({
  "extension/src/shared/webauthnWire.mjs": "the mapping of the wire to the page's shapes and back",
  "extension/src/shared/contentProtocol.mjs": "the schema of the answer on the content port (length limits only)",
  "extension/src/content/passkeyResponse.mjs": "the bridge: copies the bytes into the page's own PublicKeyCredential",
  "extension/src/background/passkeyFlow.mjs": "carries the core's create answer to the bridge",
  "extension/src/background/passkeyGet.mjs": "carries the core's get answer to the bridge",
  "web/src/flows/passkeyAnswer.mjs": "reads the browser's own answer and checks it (type, challenge, origin, rp id hash, flags)",
  "web/src/flows/passkeyCeremony.mjs": "asks the browser's authenticator and checks what it gave back",
});

test("no_file_signs_or_imports_a_key_for_a_passkey_outside_the_core", () => {
  const files = sources();
  // The scan sees the whole tree (not vacuous).
  assert.ok(files.size > 100, `${files.size} files`);
  assert.ok(files.has("web/src/auth/dpop.mjs") && files.has("extension/src/background/passkeyRequests.mjs"));
  for (const path of Object.keys(SUBTLE_USERS)) assert.ok(files.has(path), `${path} is gone: take it off the list`);
  // WebCrypto is used only for digests and for the keys of the device (its proofs, its secret), never a passkey.
  assert.deepEqual(strangers(files, /\bsubtle\b(?!\s*\.\s*digest\b)|\bSubtleCrypto\b/, Object.keys(SUBTLE_USERS)), [], "a file uses WebCrypto that is not on the list");
  // Signing, and every other way to make or load a key: only the device's own proofs and the device key's own generate and
  // export, never a passkey's.
  const calls = (/** @type {string} */ names) => new RegExp(`\\.\\s*(?:${names})\\s*\\(`);
  assert.deepEqual(strangers(files, calls("sign"), ["web/src/auth/deviceKey.mjs", "web/src/auth/dpop.mjs"]), [], "sign");
  assert.deepEqual(strangers(files, calls("importKey|unwrapKey|wrapKey|deriveKey|deriveBits"), ["web/src/auth/deviceKey.mjs"]), [], "importKey and its kin");
  assert.deepEqual(strangers(files, calls("generateKey|exportKey"), ["web/src/auth/deviceKey.mjs", "web/src/flows/deviceSecret.mjs"]), [], "generateKey and exportKey");
  // The files of the device's own keys have nothing to do with a passkey.
  for (const path of ["web/src/auth/deviceKey.mjs", "web/src/auth/dpop.mjs", "web/src/flows/deviceSecret.mjs"]) {
    assert.doesNotMatch(files.get(path) ?? "", /passkey|webauthn/i, `${path} has nothing to do with a passkey`);
  }
  // A key is not parsed or built in JavaScript either: no PKCS#8 and no COSE key anywhere but the device key.
  assert.deepEqual(strangers(files, /\bpkcs8\b|\bPKCS#?8\b|\bcose_key\b|\bcoseKey\b/i, ["web/src/auth/deviceKey.mjs"]), [], "a key format");
});

test("no_file_builds_the_authenticator_data_or_the_client_data_of_an_answer", () => {
  const files = sources();
  // Where the words of an answer appear at all, each with what it does there. The core makes the bytes; these carry them
  // (`shared/webauthnWire.mjs` maps the core's names to the page's), or check what the browser gave back (the web vault's
  // hand-over to the browser's own authenticator, and its verification of that result).
  const words =
    /\bclient_data_json\b|\bclientDataJSON\b|\bclientData\b|\bauthenticator_data\b|\bauthenticatorData\b|\bgetAuthenticatorData\b|\battestation_object\b|\battestationObject\b|\bgetPublicKey\b|\bgetPublicKeyAlgorithm\b/;
  assert.deepEqual(strangers(files, words, Object.keys(ANSWER_WORDS)), [], "a file names a part of an answer that is not on the list");
  for (const path of Object.keys(ANSWER_WORDS)) assert.ok(files.has(path), `${path} is gone: take it off the list`);
  // The files that carry the bytes make none: no hash, no JSON of a client data, no flags or counters.
  for (const path of [
    "extension/src/shared/webauthnWire.mjs",
    "extension/src/content/passkeyResponse.mjs",
    "extension/src/background/passkeyFlow.mjs",
    "extension/src/background/passkeyGet.mjs",
  ]) {
    const text = files.get(path) ?? "";
    assert.doesNotMatch(text, /\.digest\s*\(|\bJSON\s*\.\s*stringify\b|webauthn\.(?:get|create)/, `${path} makes no client data`);
    assert.doesNotMatch(text, /\b(?:rpIdHash|rp_id_hash|signCount|sign_count)\b\s*[:=]/, `${path} builds no authenticator data`);
  }
  // The client data's type strings, which only a builder or a checker of the data has a reason to write, are in the two web
  // flows that check the browser's result, and nowhere else.
  assert.deepEqual(strangers(files, /["'`]webauthn\.(?:get|create)["'`]/, ["web/src/flows/passkeyAnswer.mjs", "web/src/flows/passkeyCeremony.mjs"]), [], "a client data type");
  // No object of a client data is built for the page.
  assert.deepEqual(strangers(files, /\bcrossOrigin\s*:|\btopOrigin\s*:/, []), [], "a client data object");
});

test("the_scan_finds_what_it_is_meant_to_find", () => {
  // Plants: each rule fires on a file made for it (the helper that the rules above use, on text).
  const plant = (/** @type {string} */ text) => new Map([["web/src/flows/evil.mjs", code(text)]]);
  assert.deepEqual(strangers(plant("await crypto.subtle.sign(alg, key, data);"), /\bsubtle\b/, []), ["web/src/flows/evil.mjs"]);
  assert.deepEqual(strangers(plant("const s = await k.sign (alg, key, data);"), new RegExp("\\.\\s*(?:sign)\\s*\\("), []), ["web/src/flows/evil.mjs"]);
  assert.deepEqual(strangers(plant("out.authenticator_data = bytes;"), /\bauthenticator_data\b/, []), ["web/src/flows/evil.mjs"]);
  // A comment is not code.
  assert.deepEqual(strangers(plant("// subtle.sign is not used here\n/* clientDataJSON */"), /\bsubtle\b|\bclientDataJSON\b/, []), []);
});
