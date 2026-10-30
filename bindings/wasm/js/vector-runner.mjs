// Runs the test vectors through the WASM build.
//
// * `parseOps` reads `vectors/OPS.md`: the table that says, for every `op`, the
//   WASM method that runs it. A case whose `op` is not in the table is a
//   failure, so a new op cannot be forgotten by this runner.
// * `runVectorFile` runs one file of `ferret-vectors/1` (a file of
//   `vectors/internal/`) through `test_run_case` of a build with the
//   `test-support` feature, and compares the output with `expect` (or the
//   error code with `expect_error`) and checks that every recorded random
//   draw was used.
// * `runExternal` runs the third-party files (`vectors/external/`) in their
//   own formats, with a small adapter for each.
//
// The module has no dependency on Node or on a browser: the caller gives it
// the loaded module and a function that reads a vector file as JSON.

/** Op name -> WASM method, from the table in OPS.md. */
export function parseOps(opsMarkdown) {
  const ops = new Map();
  for (const line of opsMarkdown.split("\n")) {
    const m = /^\| `([a-z0-9_.]+)` \| .*? \| `([a-z0-9_]+)` \| /.exec(line);
    if (m) ops.set(m[1], m[2]);
  }
  return ops;
}

/** Whether two JSON values are equal, whatever the order of keys. */
export function sameJson(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) {
    return a.length === b.length && a.every((v, i) => sameJson(v, b[i]));
  }
  const ka = Object.keys(a);
  const kb = Object.keys(b);
  return ka.length === kb.length && ka.every((k) => k in b && sameJson(a[k], b[k]));
}

/** The paths where two values differ, never the values (they may be keys). */
function firstDifference(want, got, path = "") {
  if (sameJson(want, got)) return [];
  if (
    want !== null &&
    got !== null &&
    typeof want === "object" &&
    typeof got === "object" &&
    !Array.isArray(want) &&
    !Array.isArray(got)
  ) {
    const out = [];
    for (const k of new Set([...Object.keys(want), ...Object.keys(got)])) {
      out.push(...firstDifference(want[k], got[k], `${path}/${k}`));
    }
    return out.slice(0, 8);
  }
  return [path || "/"];
}

/**
 * Runs the cases of one file. Returns `{ passed, skipped, failures }`.
 *
 * @param wasm  the module of a build with `test-support`
 * @param file  the parsed vector file
 * @param ops   the result of `parseOps`
 * @param options.skipTags  tags to skip (`native-only` is always skipped)
 */
export function runVectorFile(wasm, file, ops, options = {}) {
  const skipTags = new Set(["native-only", ...(options.skipTags ?? [])]);
  const result = { passed: 0, skipped: 0, failures: [] };
  for (const c of file.cases) {
    if (c.tags.some((t) => skipTags.has(t))) {
      result.skipped++;
      continue;
    }
    const method = ops.get(c.op);
    if (!method) {
      result.failures.push({ id: c.id, reason: "op is not in OPS.md" });
      continue;
    }
    let reply;
    try {
      reply = JSON.parse(wasm.test_run_case(method, JSON.stringify(c)));
    } catch (e) {
      result.failures.push({ id: c.id, reason: `trap (${e?.name ?? "error"})` });
      continue;
    }
    if (reply.code === "unknown_op") {
      result.failures.push({ id: c.id, reason: `op ${c.op} is not run by the WASM build` });
    } else if (reply.rng_left) {
      result.failures.push({ id: c.id, reason: "recorded draws not all consumed" });
    } else if (c.status === "valid") {
      if (!reply.ok) {
        result.failures.push({ id: c.id, reason: `expected success, got error ${reply.code}` });
      } else if (!sameJson(c.expect, reply.output)) {
        const at = firstDifference(c.expect, reply.output).join(", ");
        result.failures.push({ id: c.id, reason: `output differs from expect at ${at}` });
      } else {
        result.passed++;
      }
    } else if (reply.ok) {
      result.failures.push({ id: c.id, reason: "expected an error, got success" });
    } else if (reply.code !== c.expect_error) {
      result.failures.push({
        id: c.id,
        reason: `expected error ${c.expect_error}, got ${reply.code}`,
      });
    } else {
      result.passed++;
    }
  }
  return result;
}

// ------------------------------------------------- third-party vector files

function ext(wasm, kind, input) {
  return JSON.parse(wasm.test_external(kind, JSON.stringify(input)));
}

class Tally {
  constructor() {
    this.valid = 0;
    this.invalid = 0;
    this.acceptableAccepted = 0;
    this.acceptableRejected = 0;
    this.failures = [];
  }

  result(kind, accepted, id) {
    if (kind === "valid" && accepted) this.valid++;
    else if (kind === "invalid" && !accepted) this.invalid++;
    else if (kind === "acceptable") {
      if (accepted) this.acceptableAccepted++;
      else this.acceptableRejected++;
    } else {
      this.failures.push({ id, reason: `result ${kind} but accepted = ${accepted}` });
    }
  }
}

function wycheproofTests(file) {
  const all = file.testGroups.flatMap((g) => g.tests.map((t) => [g, t]));
  if (all.length !== file.numberOfTests) throw new Error("the file's own count");
  return all;
}

function expectEqual(failures, id, what, got, want) {
  if (got !== want) failures.push({ id, reason: `${what} differs` });
}

/**
 * Runs a third-party file by name. `read(path)` returns the parsed JSON of a
 * file below `vectors/external/`. Returns `{ name, passed, failures, notes }`.
 */
export async function runExternal(wasm, name, read) {
  const failures = [];
  let passed = 0;
  const notes = [];
  const file = await read(name);

  switch (name) {
    case "rfc9106-argon2id.json":
      for (const c of file.cases) {
        const r = ext(wasm, "argon2id_unchecked", {
          password: c.password, salt: c.salt, secret: c.secret, ad: c.associated_data,
          m_kib: c.memory_kib, t: c.passes, p: c.lanes, len: c.tag_len,
        });
        if (r.ok && r.tag === c.tag) passed++;
        else failures.push({ id: c.id, reason: "tag differs" });
      }
      break;
    case "rfc5869-hkdf.json":
      for (const c of file.cases) {
        const r = ext(wasm, "hkdf", { salt: c.salt, ikm: c.ikm, info: c.info, len: c.length });
        if (r.ok && r.okm === c.okm) passed++;
        else failures.push({ id: c.id, reason: "okm differs" });
      }
      break;
    case "rfc8032-ed25519.json":
      for (const c of file.cases) {
        const pk = ext(wasm, "ed25519_public_key", { seed: c.secret_key });
        const sig = ext(wasm, "ed25519_sign", { seed: c.secret_key, msg: c.message });
        const ok = ext(wasm, "ed25519_verify", { pk: c.public_key, msg: c.message, sig: c.signature });
        const bad = ext(wasm, "ed25519_verify", { pk: c.public_key, msg: c.message + "00", sig: c.signature });
        if (pk.pk === c.public_key && sig.sig === c.signature && ok.ok && !bad.ok) passed++;
        else failures.push({ id: c.id, reason: "public key, signature or verification differs" });
      }
      break;
    case "xchacha-draft-03.json":
      for (const c of file.cases) {
        const blob = c.nonce + c.ciphertext + c.tag;
        const sealed = ext(wasm, "aead_seal_fixed", { key: c.key, aad: c.aad, pt: c.plaintext, nonce: c.nonce });
        const opened = ext(wasm, "aead_open", { key: c.key, aad: c.aad, blob });
        if (sealed.ok && sealed.blob === blob && !sealed.rng_left && opened.ok && opened.pt === c.plaintext) {
          passed++;
        } else failures.push({ id: c.id, reason: "seal or open differs" });
      }
      break;
    case "rfc6238-totp.json":
      for (const c of file.cases) {
        const counter = String(Math.floor(c.time / c.period));
        const r = ext(wasm, "hotp", { algorithm: c.algorithm, key: c.secret, counter, digits: c.digits });
        if (r.ok && r.hotp === c.totp) passed++;
        else failures.push({ id: c.id, reason: "code differs" });
      }
      break;
    case "rfc4226-hotp.json":
      for (const c of file.cases) {
        const r = ext(wasm, "hotp", { algorithm: "SHA1", key: c.secret, counter: String(c.counter), digits: 6 });
        if (r.ok && r.hotp === c.hotp && r.digest === c.hmac) passed++;
        else failures.push({ id: c.id, reason: "hotp or hmac differs" });
      }
      break;
    case "rfc9807-opaque-ristretto255.json":
      for (const v of file.vectors) {
        const { input, output } = v;
        const wide = (h) => h + "00".repeat(32);
        const ids = input.client_identity !== undefined
          ? { client_identity: input.client_identity, server_identity: input.server_identity }
          : {};
        const reg = ext(wasm, "opaque_rfc_register", {
          password: input.password, response: output.registration_response, ...ids,
          draws: [wide(input.blind_registration), input.envelope_nonce],
        });
        const login = ext(wasm, "opaque_rfc_login", {
          password: input.password, ke2: output.KE2, context: v.configuration.Context, ...ids,
          draws: [wide(input.blind_login), input.client_keyshare_seed, input.client_nonce],
        });
        const good =
          reg.ok && !reg.rng_left &&
          reg.request === output.registration_request &&
          reg.upload === output.registration_upload &&
          reg.export_key === output.export_key &&
          reg.server_public_key === input.server_public_key &&
          login.ok && !login.rng_left &&
          login.ke1 === output.KE1 && login.ke3 === output.KE3 &&
          login.export_key === output.export_key &&
          login.session_key === output.session_key &&
          login.server_public_key === input.server_public_key;
        if (good) passed++;
        else failures.push({ id: v.id, reason: "a message, key or output differs" });
      }
      break;
    case "rfc9497-oprf-ristretto255.json":
      notes.push(
        "not run: the OPRF vectors exercise the `voprf` crate directly, which the binding does not export; RFC 9807 (built on it) is run",
      );
      break;
    case "wycheproof/xchacha20_poly1305_test.json": {
      const t = new Tally();
      for (const [, c] of wycheproofTests(file)) {
        const id = String(c.tcId);
        const blob = c.iv + c.ct + c.tag;
        const opened = ext(wasm, "aead_open", { key: c.key, aad: c.aad, blob });
        if (c.result === "valid") {
          const sealed = ext(wasm, "aead_seal_fixed", { key: c.key, aad: c.aad, pt: c.msg, nonce: c.iv });
          if (opened.ok && opened.pt === c.msg && sealed.ok && sealed.blob === blob) t.valid++;
          else t.failures.push({ id, reason: "valid case: open or seal differs" });
        } else if (c.result === "invalid" && !opened.ok && opened.code === "decrypt") t.invalid++;
        else t.failures.push({ id, reason: `unexpected ${c.result}` });
      }
      expectEqual(t.failures, "count", "valid + invalid", t.valid + t.invalid, 315);
      passed = t.valid + t.invalid;
      failures.push(...t.failures);
      break;
    }
    case "wycheproof/chacha20_poly1305_test.json": {
      const t = new Tally();
      for (const [, c] of wycheproofTests(file)) {
        const r = ext(wasm, "chacha20poly1305_open", { key: c.key, iv: c.iv, aad: c.aad, ct: c.ct, tag: c.tag });
        const accepted = r.ok;
        if (accepted && r.pt !== c.msg) t.failures.push({ id: String(c.tcId), reason: "plaintext differs" });
        t.result(c.result, accepted, String(c.tcId));
      }
      expectEqual(t.failures, "count", "valid + invalid", t.valid + t.invalid, 325);
      passed = t.valid + t.invalid;
      failures.push(...t.failures);
      break;
    }
    case "wycheproof/ed25519_test.json": {
      const t = new Tally();
      for (const [g, c] of wycheproofTests(file)) {
        const r = ext(wasm, "ed25519_verify", { pk: g.publicKey.pk, msg: c.msg, sig: c.sig });
        t.result(c.result, r.ok, String(c.tcId));
      }
      expectEqual(t.failures, "count", "valid", t.valid, 117);
      expectEqual(t.failures, "count", "invalid", t.invalid, 64);
      // The strict verifier: the 8 small-order keys are rejected and the 21
      // mixed-order ones are accepted.
      expectEqual(t.failures, "count", "acceptable rejected", t.acceptableRejected, 8);
      expectEqual(t.failures, "count", "acceptable accepted", t.acceptableAccepted, 21);
      passed = t.valid + t.invalid + t.acceptableAccepted + t.acceptableRejected;
      failures.push(...t.failures);
      break;
    }
    case "wycheproof/ecdsa_secp256r1_sha256_test.json": {
      const t = new Tally();
      for (const [g, c] of wycheproofTests(file)) {
        const r = ext(wasm, "p256_verify", { pk: g.publicKey.uncompressed, msg: c.msg, sig: c.sig });
        t.result(c.result, r.ok, String(c.tcId));
      }
      expectEqual(t.failures, "count", "valid", t.valid, 174);
      expectEqual(t.failures, "count", "invalid", t.invalid, 310);
      passed = t.valid + t.invalid + t.acceptableAccepted + t.acceptableRejected;
      failures.push(...t.failures);
      break;
    }
    case "wycheproof/hkdf_sha256_test.json": {
      const t = new Tally();
      for (const [, c] of wycheproofTests(file)) {
        const r = ext(wasm, "hkdf", { salt: c.salt, ikm: c.ikm, info: c.info, len: c.size });
        if (r.ok && r.okm !== c.okm) t.failures.push({ id: String(c.tcId), reason: "okm differs" });
        t.result(c.result, r.ok, String(c.tcId));
      }
      expectEqual(t.failures, "count", "valid", t.valid, 83);
      expectEqual(t.failures, "count", "invalid", t.invalid, 3);
      passed = t.valid + t.invalid;
      failures.push(...t.failures);
      break;
    }
    case "wycheproof/hmac_sha256_test.json": {
      const t = new Tally();
      for (const [g, c] of wycheproofTests(file)) {
        const r = ext(wasm, "hmac", { key: c.key, msg: c.msg });
        const tagLen = g.tagSize / 8;
        const accepted = r.ok && c.tag.length === tagLen * 2 && r.mac.slice(0, tagLen * 2) === c.tag;
        t.result(c.result, accepted, String(c.tcId));
      }
      expectEqual(t.failures, "count", "valid", t.valid, 66);
      expectEqual(t.failures, "count", "invalid", t.invalid, 108);
      passed = t.valid + t.invalid;
      failures.push(...t.failures);
      break;
    }
    default:
      failures.push({ id: name, reason: "no adapter for this file" });
  }
  return { name, passed, failures, notes };
}

/** The third-party files that have an adapter, in the order they are run. */
export const EXTERNAL_FILES = [
  "rfc9106-argon2id.json",
  "rfc5869-hkdf.json",
  "rfc8032-ed25519.json",
  "xchacha-draft-03.json",
  "rfc6238-totp.json",
  "rfc4226-hotp.json",
  "rfc9807-opaque-ristretto255.json",
  "rfc9497-oprf-ristretto255.json",
  "wycheproof/xchacha20_poly1305_test.json",
  "wycheproof/chacha20_poly1305_test.json",
  "wycheproof/ed25519_test.json",
  "wycheproof/ecdsa_secp256r1_sha256_test.json",
  "wycheproof/hkdf_sha256_test.json",
  "wycheproof/hmac_sha256_test.json",
];

/** The files of `vectors/internal/`, in the order they are run. */
export const INTERNAL_FILES = [
  "tlv", "unicode", "codes", "kdf", "wrap", "unlock", "item", "padding", "cbor-limits",
  "tomb-tag", "checkpoint", "proofs", "rekey", "export", "opaque", "account", "totp",
  "passkey", "origin", "sheet", "methods", "sync",
].map((n) => `${n}.json`);

/**
 * The files of `vectors/internal/` that no WASM runner reads: the server half
 * of the login has no WebAssembly binding, and every case in them is
 * `native-only`. They are listed so that a new file cannot be forgotten, not
 * run; the Rust tests of `ferret-server-auth` and `tools/xcheck` read them.
 */
export const NATIVE_ONLY_FILES = ["server-opaque", "server-secrets"].map((n) => `${n}.json`);
