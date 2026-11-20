// DPoP proofs of a device client (RFC 9449 § 4): the header and the claims the
// server's strict reader takes, `htu` without query and fragment, `ath` over
// the token's ASCII text, `iat` on the server's clock, and an ES256 signature
// that WebCrypto verifies, the same as for the RFC's own examples.
// Spec: Fase 1 § 7.6.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";
import { generateDeviceKey, thumbprint } from "../../src/auth/deviceKey.mjs";
import { accessTokenHash, createClock, createProof, htuOf, JTI_BYTES } from "../../src/auth/dpop.mjs";
import { web } from "./helpers.mjs";

const FIXTURES = join(web, "..", "crates", "ferret-server", "tests", "fixtures");
const SERVER = "https://vault.ferret.test";
const NOW = 1_793_491_200;
/** The fixture generator next to js_proofs.json, which exports its inputs. */
const generator = () => import(pathToFileURL(join(FIXTURES, "dpop", "generate.mjs")).href);
const token = (fill) => Buffer.alloc(32, fill).toString("base64url");

/** The header, the claims and the signature bytes of a compact JWS. */
function parts(proof) {
  const [header, claims, signature] = proof.split(".");
  assert.equal(proof.split(".").length, 3);
  for (const segment of [header, claims, signature]) assert.match(segment, /^[A-Za-z0-9_-]+$/);
  return {
    headerText: Buffer.from(header, "base64url").toString("utf8"),
    claimsText: Buffer.from(claims, "base64url").toString("utf8"),
    header: JSON.parse(Buffer.from(header, "base64url").toString("utf8")),
    claims: JSON.parse(Buffer.from(claims, "base64url").toString("utf8")),
    signature: Buffer.from(signature, "base64url"),
    input: `${header}.${claims}`,
  };
}

/** Whether WebCrypto verifies the proof's ES256 signature with `jwk`. */
async function verifies(proof, jwk) {
  const { signature, input } = parts(proof);
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, new TextEncoder().encode(input));
}

/** A clock that is at `NOW` on the server's side. */
function serverClock() {
  const clock = createClock({ now: () => 5_000 });
  clock.observe(new Date(NOW * 1000).toUTCString());
  return clock;
}

test("proof_header_and_claims_are_what_the_server_expects", async () => {
  const key = await generateDeviceKey(SERVER);
  const proof = await createProof(key, { method: "POST", url: `${SERVER}/api/auth/opaque/login/finish`, clock: serverClock() });
  const p = parts(proof);
  // Exactly typ, alg and the four public members of the key, in this order and without white space.
  assert.equal(
    p.headerText,
    `{"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"${key.publicJwk.x}","y":"${key.publicJwk.y}"}}`,
  );
  // Exactly jti, htm, htu and iat (no ath without a token).
  assert.deepEqual(Object.keys(p.claims), ["jti", "htm", "htu", "iat"]);
  assert.equal(p.claimsText, JSON.stringify(p.claims));
  assert.equal(p.claims.htm, "POST");
  assert.equal(p.claims.htu, `${SERVER}/api/auth/opaque/login/finish`);
  assert.equal(p.claims.iat, NOW);
  assert.equal(Number.isSafeInteger(p.claims.iat), true);
  // jti: 16 random bytes as base64url (22 visible ASCII characters, within the server's 16 to 64).
  assert.match(p.claims.jti, /^[A-Za-z0-9_-]{22}$/);
  assert.equal(Buffer.from(p.claims.jti, "base64url").length, JTI_BYTES);
  // r ‖ s: 64 bytes, 86 characters; WebCrypto verifies it with the public JWK.
  assert.equal(p.signature.length, 64);
  assert.equal(proof.split(".")[2].length, 86);
  assert.equal(await verifies(proof, key.publicJwk), true);
  assert.ok(proof.length < 4096);

  // Every proof has a new jti, and a changed byte does not verify.
  const again = await createProof(key, { method: "POST", url: `${SERVER}/api/auth/opaque/login/finish`, clock: serverClock() });
  assert.notEqual(parts(again).claims.jti, p.claims.jti);
  const other = await generateDeviceKey(SERVER);
  assert.equal(await verifies(proof, other.publicJwk), false);
  const [h, c, s] = proof.split(".");
  const tampered = `${h}.${Buffer.from(p.claimsText.replace('"POST"', '"PUT"')).toString("base64url")}.${s}`;
  assert.equal(await verifies(tampered, key.publicJwk), false);

  // What a proof refuses to be made from.
  const clock = serverClock();
  const url = `${SERVER}/api/sync/changes`;
  for (const [request, why] of [
    [{ method: "get", url, clock }, "a lower-case method"],
    [{ method: "", url, clock }, "no method"],
    [{ method: "GET", url, clock: undefined }, "no clock"],
    [{ method: "GET", url: "/api/sync/changes", clock }, "a relative URL"],
    [{ method: "GET", url: "ftp://vault.ferret.test/x", clock }, "not http(s)"],
    [{ method: "GET", url, clock, accessToken: "short" }, "a token of the wrong form"],
    [{ method: "GET", url, clock, accessToken: `${token(1)}=` }, "a padded token"],
    [{ method: "GET", url, clock: { nowSeconds: () => 1.5 } }, "a fractional time"],
  ]) {
    await assert.rejects(createProof(key, request), TypeError, why);
  }
  await assert.rejects(createProof({ ...key, publicJwk: { ...key.publicJwk, crv: "P-384" } }, { method: "GET", url, clock }), TypeError);
});

test("htu_drops_query_and_fragment", async () => {
  const key = await generateDeviceKey(SERVER);
  const clock = serverClock();
  for (const [url, htu] of [
    [`${SERVER}/api/sync/changes?since=5&limit=100#top`, `${SERVER}/api/sync/changes`],
    [`${SERVER}/api/sync/changes?`, `${SERVER}/api/sync/changes`],
    [`${SERVER}/api/sync/changes#`, `${SERVER}/api/sync/changes`],
    [new URL("/api/sync/items/a1?x=1", SERVER), `${SERVER}/api/sync/items/a1`],
    ["HTTPS://Vault.Ferret.Test:443/api/sync/events", `${SERVER}/api/sync/events`],
    ["http://127.0.0.1:3041/api/sync/events?x#y", "http://127.0.0.1:3041/api/sync/events"],
  ]) {
    assert.equal(htuOf(url), htu, String(url));
    const proof = await createProof(key, { method: "GET", url, clock });
    assert.equal(parts(proof).claims.htu, htu, String(url));
  }
});

test("ath_is_sha256_of_the_token_ascii", async () => {
  // The example of RFC 9449 § 7.1 (Figures 13 and 14).
  const { RFC9449_RESOURCE_EXAMPLE: rfc } = await generator();
  assert.equal(await accessTokenHash(rfc.accessToken), rfc.ath);
  assert.equal(parts(rfc.proof).claims.ath, rfc.ath);

  // A Ferret token: SHA-256 of its 43 ASCII characters, not of the 32 bytes they encode.
  const access = token(0x22);
  const key = await generateDeviceKey(SERVER);
  const proof = await createProof(key, { method: "GET", url: `${SERVER}/api/sync/changes`, accessToken: access, clock: serverClock() });
  const { claims } = parts(proof);
  assert.deepEqual(Object.keys(claims), ["jti", "htm", "htu", "iat", "ath"]);
  const { createHash } = await import("node:crypto");
  assert.equal(claims.ath, createHash("sha256").update(access, "ascii").digest("base64url"));
  assert.notEqual(claims.ath, createHash("sha256").update(Buffer.from(access, "base64url")).digest("base64url"));
  assert.equal(claims.ath.length, 43);
  // No token, no ath; a null token is no token.
  const without = await createProof(key, { method: "GET", url: `${SERVER}/api/sync/changes`, accessToken: null, clock: serverClock() });
  assert.equal(Object.hasOwn(parts(without).claims, "ath"), false);
  for (const bad of ["", "a b", "é", 5]) await assert.rejects(accessTokenHash(bad), TypeError);
});

test("iat_uses_the_server_clock_offset", async () => {
  let local = 1_700_000_000_250;
  const clock = createClock({ now: () => local });
  // Before an answer is seen, the local clock.
  assert.equal(clock.nowSeconds(), 1_700_000_000);
  // A missing or unreadable Date header changes nothing.
  for (const header of [null, "", "yesterday", "Thu, 99 Xyz 2026 00:00:00 GMT"]) {
    clock.observe(header);
    assert.equal(clock.nowSeconds(), 1_700_000_000, String(header));
  }
  // The first Date header sets the offset: the server is 3 600 s ahead.
  clock.observe(new Date((1_700_000_000 + 3_600) * 1000).toUTCString());
  assert.equal(clock.nowSeconds(), 1_700_003_600);
  // The offset follows the local clock as it moves.
  local += 10_000;
  assert.equal(clock.nowSeconds(), 1_700_003_610);
  // A later answer does not move it ...
  clock.observe(new Date(1_000_000_000_000).toUTCString());
  assert.equal(clock.nowSeconds(), 1_700_003_610);
  // ... a resync (after dpop_invalid) does; an unreadable one keeps what there was.
  clock.resync("not a date");
  assert.equal(clock.nowSeconds(), 1_700_003_610);
  clock.resync(new Date((1_700_000_010 - 120) * 1000).toUTCString());
  assert.equal(clock.nowSeconds(), 1_700_000_010 - 120);

  // The proof carries the server's time, not the local one.
  const key = await generateDeviceKey(SERVER);
  const proof = await createProof(key, { method: "GET", url: `${SERVER}/api/sync/changes`, clock });
  assert.equal(parts(proof).claims.iat, 1_700_000_010 - 120);
  // Without options, the local clock of the platform.
  const real = createClock();
  assert.ok(Math.abs(real.nowSeconds() - Math.floor(Date.now() / 1000)) <= 1);
});

test("the_examples_of_rfc_9449_verify_under_webcrypto", async () => {
  // The signature form of the client (WebCrypto's ECDSA) is the one of the RFC's examples, signed with
  // the key of the server's wire fixture.
  const { jwk, jkt } = JSON.parse(readFileSync(join(FIXTURES, "wire", "dpop_jwk.json"), "utf8"));
  const { RFC9449_EXAMPLES, RFC9449_RESOURCE_EXAMPLE } = await generator();
  for (const example of [...RFC9449_EXAMPLES, RFC9449_RESOURCE_EXAMPLE]) {
    assert.equal(await verifies(example.proof, jwk), true, `Figure ${example.figure}`);
    const p = parts(example.proof);
    assert.equal(p.header.typ, "dpop+jwt");
    assert.equal(p.header.alg, "ES256");
    assert.equal(await thumbprint(p.header.jwk), jkt);
    assert.equal(p.claims.iat, example.iat);
  }
});

test("the_js_proofs_fixture_is_what_the_client_makes_now", async () => {
  // tests/fixtures/dpop/js_proofs.json is written by generate.mjs from this client code. Its signatures
  // are randomized, so the check here is: the header and the claims are byte for byte what the client
  // makes now from the same inputs, every signature verifies, and the key is the fixed test key.
  const generate = await generator();
  const file = JSON.parse(readFileSync(join(FIXTURES, "dpop", "js_proofs.json"), "utf8"));
  const now = await generate.makeFixture();
  assert.deepEqual(Object.keys(file), Object.keys(now));
  for (const field of ["format", "comment", "now", "vault_url", "key", "access_token", "rfc9449"]) {
    assert.deepEqual(file[field], now[field], field);
  }
  assert.deepEqual(file.key.jwk, generate.testPublicJwk());
  assert.equal(file.proofs.length, now.proofs.length);
  for (const [i, entry] of file.proofs.entries()) {
    const fresh = now.proofs[i];
    const { proof: _a, ...request } = entry;
    const { proof: _b, ...freshRequest } = fresh;
    assert.deepEqual(request, freshRequest);
    const [h1, c1] = entry.proof.split(".");
    const [h2, c2] = fresh.proof.split(".");
    assert.equal(h1, h2, `${entry.name}: header`);
    assert.equal(c1, c2, `${entry.name}: claims`);
    assert.equal(await verifies(entry.proof, file.key.jwk), true, entry.name);
    assert.equal(parts(entry.proof).claims.iat, generate.NOW, `${entry.name}: the server's time, though the local clock is an hour off`);
  }
});
