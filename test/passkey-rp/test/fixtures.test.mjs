// Checks of the fixtures themselves, run in a container on the fixture's test network
// (scripts/lanbox-passkey-rp.sh test). A matrix that tests Ferret against a relying party that
// accepts anything proves nothing, so every check that matters is shown from both sides: the
// untampered response is accepted, and the same response with one thing changed is refused.
//
//   the_fixtures_reject_a_tampered_signature_rp_hash_origin_cross_origin_and_flags
//
// The two relying parties differ on purpose: webauthn-rs checks everything (the strict one),
// @simplewebauthn/server is what many sites use and does not look at crossOrigin. The expected
// answers below are per library, and a library that changes its mind fails the test.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { request } from "node:https";
import { describe, test } from "node:test";
import { FLAG, SoftAuthenticator } from "./softauth.mjs";

const HOST = "rp-a.test";
const ORIGIN = `https://${HOST}`;

/** @param {string} path @param {any} body @param {string} [origin] "none" sends no Origin header @param {string} [host] */
function post(path, body, origin = ORIGIN, host = HOST) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = request(
      { host, port: 443, path, method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(payload), ...(origin === "none" ? {} : { origin }) } },
      (res) => {
        /** @type {Buffer[]} */
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode, json: JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") }));
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

const sidOf = () => `t-${randomBytes(6).toString("hex")}`;
const USER = { name: "alice", displayName: "Alice" };

/**
 * Registers a credential with the library `lib` (untampered unless `t` says otherwise).
 * @param {"rs" | "swa"} lib @param {import("./softauth.mjs").Tamper} [t] @param {Record<string, unknown>} [opts]
 */
async function register(lib, t = {}, opts = {}) {
  const sid = sidOf();
  const auth = new SoftAuthenticator();
  const start = /** @type {any} */ (await post(`/api/${lib}/register/start`, { sid, rpId: HOST, user: USER, userVerification: "preferred", residentKey: "preferred", attestation: "none", ...opts }));
  assert.equal(start.json.ok, true, `register/start: ${JSON.stringify(start.json)}`);
  const credential = auth.create(start.json.options, ORIGIN, t);
  const finish = /** @type {any} */ (await post(`/api/${lib}/register/finish`, { sid, credential }));
  return { sid, auth, start: start.json, finish };
}

/** @param {"rs" | "swa"} lib @param {string} sid @param {SoftAuthenticator} auth @param {import("./softauth.mjs").Tamper} [t] @param {Record<string, unknown>} [opts] */
async function authenticate(lib, sid, auth, t = {}, opts = {}) {
  const start = /** @type {any} */ (await post(`/api/${lib}/auth/start`, { sid, rpId: HOST, userVerification: "preferred", allow: "all", ...opts }));
  assert.equal(start.json.ok, true, `auth/start: ${JSON.stringify(start.json)}`);
  const credential = auth.get(start.json.options, ORIGIN, t);
  return /** @type {any} */ (await post(`/api/${lib}/auth/finish`, { sid, credential }));
}

for (const lib of /** @type {const} */ (["rs", "swa"])) {
  describe(`fixture ${lib}`, () => {
    test("accepts an untampered registration and sign-in (the positive control)", async () => {
      const { sid, auth, finish } = await register(lib);
      assert.equal(finish.status, 200, JSON.stringify(finish.json));
      assert.equal(finish.json.ok, true);
      assert.equal(finish.json.flags.uv, true);
      assert.equal(finish.json.flags.be, true);
      assert.equal(finish.json.flags.bs, true);
      const signIn = await authenticate(lib, sid, auth);
      assert.equal(signIn.status, 200, JSON.stringify(signIn.json));
      assert.equal(signIn.json.ok, true);
      // A counter of 0 forever is what a synced passkey sends: accepted again and again.
      const again = await authenticate(lib, sid, auth);
      assert.equal(again.json.ok, true, JSON.stringify(again.json));
    });

    test("the_fixtures_reject_a_tampered_signature_rp_hash_origin_cross_origin_and_flags: tampered sign-in", async () => {
      // Every case: one change to a response that is otherwise good. Refused by both libraries unless the table says otherwise.
      /** @type {{ name: string, tamper: import("./softauth.mjs").Tamper, accepted?: ("rs" | "swa")[] }[]} */
      const cases = [
        { name: "signature", tamper: { tamperSignature: true } },
        { name: "RP ID hash", tamper: { rpId: "rp-b.test" } },
        { name: "origin", tamper: { origin: "https://evil.rp-a.test" } },
        { name: "origin of another site", tamper: { origin: "https://rp-b.test" } },
        { name: "challenge", tamper: { challenge: Buffer.alloc(32, 7).toString("base64url") } },
        { name: "user presence missing", tamper: { flags: FLAG.UV | FLAG.BE | FLAG.BS } },
        { name: "user verification missing (required)", tamper: { flags: FLAG.UP | FLAG.BE | FLAG.BS } },
        // crossOrigin: the strict one refuses; the other one does not look (and says so in its answer).
        { name: "crossOrigin true", tamper: { crossOrigin: true }, accepted: ["swa"] },
        // Backup state without backup eligibility is not a state the specification allows; both libraries know.
        { name: "backup state without eligibility", tamper: { flags: FLAG.UP | FLAG.UV | FLAG.BS } },
      ];
      for (const c of cases) {
        const { sid, auth, finish } = await register(lib);
        assert.equal(finish.json.ok, true, `${c.name}: setup: ${JSON.stringify(finish.json)}`);
        // The same response, untampered, is accepted (so a refusal below is the change's doing).
        const control = await authenticate(lib, sid, auth, {}, { userVerification: "required" });
        assert.equal(control.json.ok, true, `${lib} on ${c.name}: the untampered control: ${JSON.stringify(control.json)}`);
        const r = await authenticate(lib, sid, auth, c.tamper, { userVerification: "required" });
        const accepted = r.json.ok === true;
        assert.equal(accepted, (c.accepted ?? []).includes(lib), `${lib} on ${c.name}: ${JSON.stringify(r.json)}`);
        if (accepted && c.name === "crossOrigin true") assert.equal(r.json.clientCrossOrigin, true, "the answer must say what the site was told");
      }
    });

    test("the_fixtures_reject_a_tampered_signature_rp_hash_origin_cross_origin_and_flags: tampered registration", async () => {
      /** @type {{ name: string, tamper: import("./softauth.mjs").Tamper, opts?: Record<string, unknown>, accepted?: ("rs" | "swa")[] }[]} */
      const cases = [
        { name: "RP ID hash", tamper: { rpId: "rp-b.test" } },
        { name: "origin", tamper: { origin: "https://evil.rp-a.test" } },
        { name: "challenge", tamper: { challenge: Buffer.alloc(32, 9).toString("base64url") } },
        { name: "user presence missing", tamper: { flags: FLAG.UV | FLAG.BE | FLAG.BS } },
        { name: "user verification missing (required)", tamper: { flags: FLAG.UP | FLAG.BE | FLAG.BS }, opts: { userVerification: "required" } },
        { name: "crossOrigin true", tamper: { crossOrigin: true }, accepted: ["swa"] },
        { name: "backup state without eligibility", tamper: { flags: FLAG.UP | FLAG.UV | FLAG.BS } },
      ];
      for (const c of cases) {
        const control = await register(lib, {}, c.opts);
        assert.equal(control.finish.json.ok, true, `${lib} on ${c.name}: the untampered control: ${JSON.stringify(control.finish.json)}`);
        const { finish } = await register(lib, c.tamper, c.opts);
        const accepted = finish.json.ok === true;
        assert.equal(accepted, (c.accepted ?? []).includes(lib), `${lib} on ${c.name}: ${JSON.stringify(finish.json)}`);
      }
    });

    test("accepts what a site must accept: user verification not asked for, passkey without backup flags", async () => {
      const { sid, auth, finish } = await register(lib, { flags: FLAG.UP }, { userVerification: "discouraged" });
      assert.equal(finish.json.ok, true, JSON.stringify(finish.json));
      assert.equal(finish.json.flags.uv, false);
      const r = await authenticate(lib, sid, auth, { flags: FLAG.UP }, { userVerification: "discouraged" });
      assert.equal(r.json.ok, true, JSON.stringify(r.json));
    });

    test("refuses a counter that goes back", async () => {
      const { sid, auth } = await register(lib, { counter: 0 });
      const first = await authenticate(lib, sid, auth, { counter: 5 });
      assert.equal(first.json.ok, true, JSON.stringify(first.json));
      const back = await authenticate(lib, sid, auth, { counter: 3 });
      assert.equal(back.json.ok, false, `${lib} accepted a counter that went from 5 to 3`);
    });

    test("a discoverable request finds the credential by its id and the user handle", async () => {
      const { sid, auth } = await register(lib);
      const r = await authenticate(lib, sid, auth, {}, { allow: "none" });
      assert.equal(r.json.ok, true, JSON.stringify(r.json));
    });

    test("holds the answer back when asked (the late-accepted write of UK130)", async () => {
      const sid = sidOf();
      const auth = new SoftAuthenticator();
      const start = /** @type {any} */ (await post(`/api/${lib}/register/start`, { sid, rpId: HOST, user: USER }));
      const credential = auth.create(start.json.options, ORIGIN);
      const t0 = Date.now();
      const finish = /** @type {any} */ (await post(`/api/${lib}/register/finish?hold=800`, { sid, credential }));
      assert.equal(finish.json.ok, true);
      assert.ok(Date.now() - t0 >= 750, "the answer came before the hold ended");
    });

    test("the user.id of 65 bytes is the page's problem, not the library's: a fixture does not hide it", async () => {
      const sid = sidOf();
      const start = /** @type {any} */ (await post(`/api/${lib}/register/start`, { sid, rpId: HOST, user: { ...USER, id: Buffer.alloc(65, 1).toString("base64url") } }));
      // The fixture hands the options on; the 65-byte handle reaches the page unchanged, where the browser throws TypeError.
      if (start.json.ok) assert.equal(Buffer.from(start.json.options.user.id, "base64url").length, 65);
    });
  });
}

describe("the API of the fixture", () => {
  test("takes only the origins of the fixture", async () => {
    const body = { sid: sidOf(), rpId: HOST, user: USER };
    for (const origin of ["https://evil.example", "http://rp-a.test", "https://rp-a.test:8443", "none"]) {
      for (const lib of ["rs", "swa"]) {
        const r = /** @type {any} */ (await post(`/api/${lib}/register/start`, body, origin));
        assert.equal(r.status, 403, `${lib} with Origin ${origin}: ${JSON.stringify(r.json)}`);
      }
    }
    const ok = /** @type {any} */ (await post("/api/rs/register/start", body, "https://login.rp-a.test"));
    assert.equal(ok.json.ok, true, JSON.stringify(ok.json));
    // A trailing dot names the same host.
    const dotted = /** @type {any} */ (await post("/api/rs/register/start", body, "https://rp-a.test."));
    assert.equal(dotted.json.ok, true, JSON.stringify(dotted.json));
  });

  test("an opaque origin (a sandboxed frame) may fetch options for a fixture RP ID and never finish", async () => {
    for (const lib of ["rs", "swa"]) {
      const sid = sidOf();
      const start = /** @type {any} */ (await post(`/api/${lib}/register/start`, { sid, rpId: HOST, user: USER }, "null"));
      assert.equal(start.json.ok, true, `${lib}: ${JSON.stringify(start.json)}`);
      const named = /** @type {any} */ (await post(`/api/${lib}/register/start`, { sid, rpId: "evil.example", user: USER }, "null"));
      assert.equal(named.status, 403, `${lib}: an RP ID that is not the fixture's`);
      const auth = new SoftAuthenticator();
      const finish = /** @type {any} */ (await post(`/api/${lib}/register/finish`, { sid, credential: auth.create(start.json.options, "null") }, "null"));
      assert.equal(finish.status, 403, `${lib}: finish with an opaque origin`);
    }
  });

  test("serves the test pages on every listed host", async () => {
    for (const host of ["rp-a.test", "login.rp-a.test", "rp-b.test", "attacker.test", "vault-fixture.test", "user.github.io", "evil.github.io", "xn--rp--8cd.test"]) {
      const res = await fetch(`https://${host}/ceremony.html`);
      assert.equal(res.status, 200, host);
      assert.match(await res.text(), /Passkey fixture/);
    }
  });

  test("the browser library is served", async () => {
    const res = await fetch(`https://${HOST}/vendor/simplewebauthn-browser.js`);
    assert.equal(res.status, 200);
    assert.match(await res.text(), /startRegistration/);
  });
});
