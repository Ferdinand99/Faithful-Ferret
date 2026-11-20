// Writes js_proofs.json: DPoP proofs made by the web client's own code
// (web/src/auth/deviceKey.mjs and dpop.mjs), which tests/dpop_interop.rs runs
// through the server's check.
//
//   node generate.mjs     write js_proofs.json
//
// The proofs are signed with a fixed test key: the P-256 scalar of 32 bytes of
// 0x11, the key `DeviceKey::new(0x11)` of tests/support/dpop.rs. Only this
// script imports it (the client never imports a key; it makes one). The key
// goes through generateDeviceKey with a WebCrypto whose generateKey hands back
// the test key, so the public JWK in the file comes from a real
// `exportKey("jwk")`, copied by the client code. The `jti` bytes come from a
// fixed source and the clock is an hour slow until it sees the server's `Date`,
// so everything but the ECDSA signatures (which are randomized) is the same on
// every run; web/test/unit/dpop.test.mjs checks that the file still matches
// what the client makes.
//
// The file also carries the example proofs of RFC 9449 (Figures 2 and 7, made
// with the key of ../wire/dpop_jwk.json), and the thumbprint the client
// computes for that key.
import { createECDH, createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { generateDeviceKey, thumbprint } from "../../../../../web/src/auth/deviceKey.mjs";
import { createClock, createProof } from "../../../../../web/src/auth/dpop.mjs";

export const DIR = dirname(fileURLToPath(import.meta.url));

/** The server's time when the proofs were made: `START` of the server's tests. */
export const NOW = 1_793_491_200;
/** How far the client's own clock is off (it is behind by an hour, less a quarter second). */
export const LOCAL_OFFSET_MS = -3_600_000 + 250;
/** The vault origin of the server's tests (`VAULT_URL`). */
export const VAULT_URL = "https://vault.ferret.test";
/** The test key: the P-256 scalar of 32 bytes of 0x11. */
export const TEST_SCALAR = Buffer.alloc(32, 0x11);
/** The access token that goes with the proofs that carry one: 32 bytes of 0x22. */
export const ACCESS_TOKEN = Buffer.alloc(32, 0x22).toString("base64url");

/** The requests the proofs are for. `path` is what the server's `htu` is built from. */
export const REQUESTS = Object.freeze([
  { name: "device_login", method: "POST", url: `${VAULT_URL}/api/auth/opaque/login/finish`, path: "/api/auth/opaque/login/finish", token: false },
  { name: "refresh", method: "POST", url: `${VAULT_URL}/api/auth/token/refresh`, path: "/api/auth/token/refresh", token: false },
  { name: "changes_with_query", method: "GET", url: `${VAULT_URL}/api/sync/changes?since=5&limit=100#top`, path: "/api/sync/changes", token: true },
  { name: "item_put", method: "PUT", url: `${VAULT_URL}/api/sync/items/a1a2a3a4a5a6a7a8a9aaabacadaeafb0`, path: "/api/sync/items/a1a2a3a4a5a6a7a8a9aaabacadaeafb0", token: true },
  { name: "events", method: "GET", url: `${VAULT_URL}/api/sync/events`, path: "/api/sync/events", token: true },
]);

/**
 * The example proofs of RFC 9449, with the key of ../wire/dpop_jwk.json:
 * Figure 2 (§ 4.1; the same proof is in Figure 5) and Figure 7 (§ 5).
 */
export const RFC9449_EXAMPLES = Object.freeze([
  {
    figure: 2,
    origin: "https://server.example.com",
    method: "POST",
    path: "/token",
    iat: 1_562_262_616,
    proof:
      "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19" +
      ".eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ" +
      ".2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg",
  },
  {
    figure: 7,
    origin: "https://server.example.com",
    method: "POST",
    path: "/token",
    iat: 1_562_265_296,
    proof:
      "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19" +
      ".eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjY1Mjk2fQ" +
      ".pAqut2IRDm_De6PR93SYmGBPXpwrAk90e8cP2hjiaG5QsGSuKDYW7_X620BxqhvYC8ynrrvZLTk41mSRroapUA",
  },
]);

/**
 * The example proof of RFC 9449 for a protected resource (Figure 13, § 7.1),
 * with `ath` for its access token (Figure 14). Its token is not a Ferret token,
 * so only the web client's tests use it (the `ath` and the signature).
 */
export const RFC9449_RESOURCE_EXAMPLE = Object.freeze({
  figure: 13,
  accessToken: "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
  ath: "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo",
  htu: "https://resource.example.org/protectedresource",
  iat: 1_562_262_618,
  proof:
    "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19" +
    ".eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9" +
    ".2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA",
});

/** The public JWK of the test key, from the scalar. */
export function testPublicJwk() {
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(TEST_SCALAR);
  const point = ecdh.getPublicKey(); // 0x04 ‖ x ‖ y
  return { kty: "EC", crv: "P-256", x: point.subarray(1, 33).toString("base64url"), y: point.subarray(33, 65).toString("base64url") };
}

/**
 * A WebCrypto whose generateKey hands back the test key (the private half
 * non-extractable, as the client makes it) and whose exportKey is the real one.
 * `exported` receives the members of each real export.
 * @param {string[][]} exported
 */
export async function testSubtle(exported) {
  const jwk = testPublicJwk();
  const algorithm = { name: "ECDSA", namedCurve: "P-256" };
  const privateKey = await crypto.subtle.importKey("jwk", { ...jwk, d: TEST_SCALAR.toString("base64url") }, algorithm, false, ["sign"]);
  const publicKey = await crypto.subtle.importKey("jwk", jwk, algorithm, true, ["verify"]);
  return {
    generateKey: async () => ({ privateKey, publicKey }),
    exportKey: async (/** @type {"jwk"} */ format, /** @type {CryptoKey} */ key) => {
      const out = await crypto.subtle.exportKey(format, key);
      exported.push(Object.keys(out).sort());
      return out;
    },
  };
}

/** A fixed source of `jti` bytes: SHA-256 of a label and a counter. */
export function fixedRand() {
  let counter = 0;
  return {
    getRandomValues(/** @type {Uint8Array} */ array) {
      const block = createHash("sha256").update(`ferret dpop fixture/jti/${counter}`).digest();
      counter += 1;
      array.set(block.subarray(0, array.length));
      return array;
    },
  };
}

/** The client's clock: an hour slow, then set from the server's `Date` header. */
export function fixedClock() {
  const clock = createClock({ now: () => NOW * 1000 + LOCAL_OFFSET_MS });
  clock.observe(new Date(NOW * 1000).toUTCString());
  return clock;
}

/** Makes the content of js_proofs.json. */
export async function makeFixture() {
  /** @type {string[][]} */
  const exported = [];
  const key = await generateDeviceKey(VAULT_URL, { subtle: /** @type {SubtleCrypto} */ (/** @type {unknown} */ (await testSubtle(exported))) });
  const clock = fixedClock();
  const rand = fixedRand();
  const proofs = [];
  for (const request of REQUESTS) {
    const proof = await createProof(key, { method: request.method, url: request.url, accessToken: request.token ? ACCESS_TOKEN : null, clock, rand });
    proofs.push({ ...request, proof });
  }
  const rfc = JSON.parse(readFileSync(join(DIR, "..", "wire", "dpop_jwk.json"), "utf8"));
  return {
    format: "ferret-dpop-js-proofs/1",
    comment:
      "DPoP proofs made by web/src/auth/dpop.mjs with the test key (scalar 32 bytes of 0x11), at the server time `now`; " +
      "`key.exported_members` are the members of the real exportKey the public JWK was copied from. Written by generate.mjs.",
    now: NOW,
    vault_url: VAULT_URL,
    key: { jwk: key.publicJwk, jkt: await thumbprint(key.publicJwk), exported_members: exported[0] },
    access_token: ACCESS_TOKEN,
    proofs,
    rfc9449: { jwk: rfc.jwk, jkt: await thumbprint(rfc.jwk), examples: RFC9449_EXAMPLES },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const fixture = await makeFixture();
  writeFileSync(join(DIR, "js_proofs.json"), `${JSON.stringify(fixture, null, 2)}\n`);
}
