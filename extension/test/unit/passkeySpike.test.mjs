// The Node-only parts of the passkey spike (extension/test/spikes/passkey): the
// software authenticator and the relying party that checks it must agree, and must
// disagree about anything that is wrong, or a pass in Firefox would mean nothing.
// The spike never reaches a package of the real build.
import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { build } from "../../scripts/build.mjs";
import { Authenticator, b64u, DomError, resolveRpId } from "../spikes/passkey/addon/authenticator.mjs";
import { buildSpikeXpi, spikeManifest } from "../spikes/passkey/build.mjs";
import { verifyAssertion, verifyRegistration } from "../spikes/passkey/rp.mjs";
import { extensionRoot, makeRoot } from "./buildHelpers.mjs";
import { readZip } from "../../scripts/lib/archive.mjs";

const ORIGIN = "https://rp.example";
const rpOf = (/** @type {Partial<{ requireUv: boolean }>} */ extra = {}) => ({ origin: ORIGIN, rpId: "rp.example", requireUv: true, userHandle: b64u(randomBytes(16)), ...extra });

/** Registers and signs in once; returns what the relying party saw. */
async function roundTrip(/** @type {{ uv?: boolean, rpOrigin?: string, tamper?: (r: any) => void }} */ { uv = true, rpOrigin = ORIGIN, tamper } = {}) {
  const auth = new Authenticator();
  const rp = { ...rpOf(), origin: rpOrigin };
  const regChallenge = b64u(randomBytes(32));
  const created = await auth.create({ origin: ORIGIN, uv, rpId: "rp.example", challenge: regChallenge, user: { id: rp.userHandle, name: "alice" }, pubKeyCredParams: [{ alg: -7 }] });
  assert.ok("result" in created);
  const reg = verifyRegistration(rp, { id: created.result.id, clientDataJSON: created.result.clientDataJSON, attestationObject: created.result.attestationObject }, regChallenge);
  if (!reg.ok || !reg.credential) return { reg, auth };
  const authChallenge = b64u(randomBytes(32));
  const got = await auth.get({ origin: ORIGIN, uv, rpId: "rp.example", challenge: authChallenge });
  assert.ok("result" in got);
  const body = { ...got.result };
  tamper?.(body);
  return { reg, auth, assertion: verifyAssertion(rp, body, authChallenge, reg.credential) };
}

test("the_authenticator_and_the_relying_party_agree", async () => {
  const { reg, assertion, auth } = await roundTrip();
  assert.deepEqual(reg.errs, []);
  assert.equal(reg.ok, true);
  assert.deepEqual(assertion, { ok: true, errs: [], signatureValid: true });
  assert.deepEqual(auth.keyFlags(), [{ type: "private", extractable: false }]);
  assert.equal(await auth.tryExportPrivate(), "refused: InvalidAccessError");
});

test("the_relying_party_rejects_what_is_wrong", async () => {
  // A changed signature, a changed challenge, another origin in the client data, and a missing user verification all fail.
  const flipped = await roundTrip({ tamper: (r) => { const sig = Buffer.from(r.signature, "base64url"); sig[sig.length - 1] ^= 1; r.signature = sig.toString("base64url"); } });
  assert.equal(flipped.assertion?.ok, false);
  assert.equal(flipped.assertion?.signatureValid, false);
  const otherOrigin = await roundTrip({ rpOrigin: "https://other.example" });
  assert.equal(otherOrigin.reg.ok, false, "client data of another origin fails the registration");
  assert.match(otherOrigin.reg.errs.join(), /clientData\.origin/);
  const noUv = await roundTrip({ uv: false });
  assert.equal(noUv.reg.ok, false, "UV flag missing");
  assert.match(noUv.reg.errs.join(), /UV flag/);
  const reuse = await roundTrip();
  assert.ok(reuse.assertion);
  const rp = rpOf();
  assert.deepEqual(verifyRegistration(rp, { id: "x", clientDataJSON: "e30", attestationObject: "oA" }, null), { ok: false, errs: ["no challenge issued"] });
});

test("the_authenticator_follows_the_origin_and_rp_id_rules_and_refuses_user_verification_it_cannot_do", async () => {
  assert.equal(resolveRpId("https://login.example.com", "example.com"), "example.com");
  assert.equal(resolveRpId("http://localhost:8080", null), "localhost");
  for (const [origin, rpId] of [
    ["https://example.com", "login.example.com"], ["https://evilexample.com", "example.com"], ["https://a.github.io", "github.io"],
    ["http://example.com", "example.com"], ["https://127.0.0.1", "127.0.0.1"], ["https://x.test", "test"], ["null", null],
  ]) {
    assert.throws(() => resolveRpId(origin, rpId), DomError, `${origin} / ${rpId}`);
  }
  const auth = new Authenticator();
  await assert.rejects(
    auth.create({ origin: ORIGIN, uv: false, userVerification: "required", challenge: b64u(randomBytes(32)), user: { id: b64u(randomBytes(8)), name: "a" } }),
    { name: "NotAllowedError" },
  );
  // A credential of one RP does not answer another, and excludeCredentials is honoured.
  const made = await auth.create({ origin: ORIGIN, uv: true, challenge: b64u(randomBytes(32)), user: { id: b64u(randomBytes(8)), name: "a" } });
  assert.ok("result" in made);
  await assert.rejects(auth.create({ origin: ORIGIN, uv: true, challenge: b64u(randomBytes(32)), user: { id: b64u(randomBytes(8)), name: "a" }, excludeCredentials: [made.result.id] }), { name: "InvalidStateError" });
  assert.deepEqual(await auth.get({ origin: "https://other.example", uv: true, challenge: b64u(randomBytes(32)) }), { use: "native", reason: "no credential" });
  // Non-canonical base64url is refused.
  await assert.rejects(auth.create({ origin: ORIGIN, uv: true, challenge: "AB=", user: { id: "AA", name: "a" } }), { name: "TypeError" });
});

test("a_foreign_key_does_not_pass_for_the_registered_one", async () => {
  const { reg } = await roundTrip();
  assert.ok(reg.credential);
  const auth = new Authenticator();
  const rp = rpOf();
  const challenge = b64u(randomBytes(32));
  const created = await auth.create({ origin: ORIGIN, uv: true, challenge, user: { id: rp.userHandle, name: "a" } });
  assert.ok("result" in created);
  // The relying party holds a different public key for that credential id.
  const other = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const signChallenge = b64u(randomBytes(32));
  const got = await auth.get({ origin: ORIGIN, uv: true, challenge: signChallenge });
  assert.ok("result" in got);
  const result = verifyAssertion(rp, got.result, signChallenge, { id: got.result.id, key: other.publicKey });
  assert.equal(result.ok, false);
  assert.equal(result.signatureValid, false);
});

test("the_spike_add_on_builds_for_both_manifest_versions_and_declares_a_main_world_script", () => {
  for (const manifest of /** @type {const} */ (["mv3", "mv2"])) {
    for (const hosts of /** @type {const} */ (["granted", "optional"])) {
      const m = spikeManifest({ manifest, hosts });
      assert.equal(m.manifest_version, manifest === "mv3" ? 3 : 2);
      assert.deepEqual(m.content_scripts.map((/** @type {any} */ c) => c.world ?? "ISOLATED"), ["MAIN", "ISOLATED"]);
      assert.ok(m.content_scripts.every((/** @type {any} */ c) => c.run_at === "document_start"));
      assert.equal("externally_connectable" in m, false);
      assert.equal("web_accessible_resources" in m, false);
    }
  }
  const { xpi } = buildSpikeXpi({ manifest: "mv3" });
  assert.ok(xpi.endsWith(".xpi"));
});

test("nothing_of_the_spike_is_in_any_package_of_the_real_build", async () => {
  const env = makeRoot();
  try {
    const options = { root: extensionRoot, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath };
    for (const manifest of ["mv3", "mv2"]) {
      for (const variant of ["release", "test"]) {
        const built = await build({ ...options, manifest, variant });
        const paths = [...built.files.keys()];
        assert.deepEqual(paths.filter((p) => /spike|passkey|main-world|relay\.js|authenticator/i.test(p)), [], `${manifest} ${variant}: no spike file`);
        const manifestJson = JSON.parse(String(built.files.get("manifest.json")));
        assert.equal("content_scripts" in manifestJson, false, `${manifest} ${variant}: the real build still has no content script`);
      }
    }
    const spike = buildSpikeXpi({ manifest: "mv3" });
    assert.ok(readZip(readFileSync(spike.xpi)).has("main-world.js"));
  } finally {
    env.cleanup();
  }
});
