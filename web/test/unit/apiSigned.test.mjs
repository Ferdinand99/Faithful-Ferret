// The signed call: the exact bytes go out as the body, the nonce and the proof go in their two headers, and a
// redirect is never followed.
import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError, createApi } from "../../src/api.mjs";
import { b64u } from "../../src/b64.mjs";

const json = (value, status = 200, headers = {}) =>
  new Response(typeof value === "string" ? value : JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });

function fakeFetch(answer) {
  const calls = [];
  return {
    calls,
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      return answer(url, init);
    },
  };
}

const nonce = () => Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const proof = () => Uint8Array.from({ length: 64 }, (_, i) => 255 - i);
/** A body with its own key order and spacing: the proof is over these bytes, not over a value. */
const body = () => new TextEncoder().encode('{"wrap":"AAAA",  "kek_generation":5,"manifest":{"z":1,"a":2}}');

test("send_signed_sends_the_exact_bytes_and_the_two_headers_and_never_follows_redirects", async () => {
  const { calls, fetchImpl } = fakeFetch(() => json({ kek_generation: 5, seq: 9 }));
  const api = createApi({ fetchImpl });
  const bytes = body();
  const copy = Uint8Array.from(bytes);
  const answer = await api.sendSigned("PUT", "/api/vault/unlock-methods/password", bytes, { nonce: nonce(), proof: proof() });
  assert.deepEqual({ ...answer }, { kek_generation: 5, seq: 9 });

  assert.equal(calls.length, 1);
  const { url, init } = calls[0];
  assert.equal(url, "/api/vault/unlock-methods/password");
  assert.equal(init.method, "PUT");
  // The body is the array that was given: the same bytes, not a copy that was parsed and written again.
  assert.equal(init.body, bytes);
  assert.deepEqual(init.body, copy);
  // The two headers are base64url without padding: 32 bytes are 43 characters, 64 bytes are 86.
  assert.equal(init.headers["Ferret-Nonce"], b64u.encode(nonce()));
  assert.equal(init.headers["Ferret-Proof"], b64u.encode(proof()));
  assert.equal(init.headers["Ferret-Nonce"].length, 43);
  assert.equal(init.headers["Ferret-Proof"].length, 86);
  assert.match(init.headers["Ferret-Nonce"], /^[A-Za-z0-9_-]+$/);
  assert.match(init.headers["Ferret-Proof"], /^[A-Za-z0-9_-]+$/);
  // The headers of every write are there too, and nothing else was added.
  assert.equal(init.headers["Ferret-Protocol"], "1");
  assert.equal(init.headers["Content-Type"], "application/json");
  assert.deepEqual(Object.keys(init.headers).sort(), ["Accept", "Content-Type", "Ferret-Nonce", "Ferret-Proof", "Ferret-Protocol"]);
  // Same origin, no cache, and a redirect is an error, never followed.
  assert.equal(init.credentials, "same-origin");
  assert.equal(init.cache, "no-store");
  assert.equal(init.redirect, "error");

  // POST goes the same way.
  await api.sendSigned("POST", "/api/vault/recover", bytes, { nonce: nonce(), proof: proof() });
  assert.equal(calls[1].init.method, "POST");
  assert.equal(calls[1].init.body, bytes);

  // The headers of a signed call are not on the other calls.
  await api.put("/api/sync/items/00", { b: 2 });
  assert.equal(calls[2].init.headers["Ferret-Nonce"], undefined);
  assert.equal(calls[2].init.headers["Ferret-Proof"], undefined);
  await api.post("/api/auth/logout", { a: 1 }, { headers: { "Ferret-Nonce": "x", "Ferret-Proof": "y" } });
  assert.equal(calls[3].init.headers["Ferret-Nonce"], undefined, "a caller of post cannot add the headers");
  assert.equal(calls[3].init.headers["Ferret-Proof"], undefined);
});

test("send_signed_never_follows_a_redirect_whatever_the_browser_does", async () => {
  // The browser refuses with redirect "error": fetch rejects. That is a network error, and nothing leaks.
  const refused = fakeFetch(() => Promise.reject(new TypeError("redirect")));
  const a = createApi({ fetchImpl: refused.fetchImpl });
  await assert.rejects(a.sendSigned("PUT", "/api/x", body(), { nonce: nonce(), proof: proof() }), (e) => e instanceof ApiError && e.code === "network");
  assert.equal(refused.calls.length, 1, "no second request");

  // A fetch that did follow (a redirected answer, an opaque redirect, a 3xx) is a bad answer.
  for (const make of [
    () => Object.defineProperty(json({ ok: true }), "redirected", { value: true }),
    () => Object.defineProperty(json({ ok: true }), "type", { value: "opaqueredirect" }),
    () => new Response(null, { status: 307, headers: { location: "https://evil.test/" } }),
  ]) {
    const { calls, fetchImpl } = fakeFetch(make);
    const api = createApi({ fetchImpl });
    await assert.rejects(api.sendSigned("POST", "/api/x", body(), { nonce: nonce(), proof: proof() }), (e) => e instanceof ApiError && e.code === "bad_response");
    assert.equal(calls.length, 1);
  }
});

test("send_signed_gives_the_servers_codes_and_checks_the_answer_like_the_other_writes", async () => {
  for (const [status, code] of [[401, "denied"], [403, "reauth_required"], [409, "write_conflict"], [400, "bad_request"]]) {
    const { fetchImpl } = fakeFetch(() => json({ error: code }, status));
    const api = createApi({ fetchImpl });
    await assert.rejects(api.sendSigned("PUT", "/api/x", body(), { nonce: nonce(), proof: proof() }), (e) => e instanceof ApiError && e.status === status && e.code === code);
  }
  // An answer that is not JSON is bad.
  const { fetchImpl } = fakeFetch(() => new Response("<html>", { status: 200, headers: { "content-type": "text/html" } }));
  await assert.rejects(createApi({ fetchImpl }).sendSigned("PUT", "/api/x", body(), { nonce: nonce(), proof: proof() }), (e) => e.code === "bad_response");
});

test("send_signed_refuses_what_cannot_be_a_signed_call_before_anything_is_sent", async () => {
  const { calls, fetchImpl } = fakeFetch(() => json({}));
  const api = createApi({ fetchImpl });
  const good = { nonce: nonce(), proof: proof() };
  const refuse = (promise) => assert.rejects(promise, TypeError);
  await refuse(api.sendSigned("GET", "/api/x", body(), good));
  await refuse(api.sendSigned("PATCH", "/api/x", body(), good));
  await refuse(api.sendSigned("put", "/api/x", body(), good));
  await refuse(api.sendSigned("PUT", "/api/x", '{"a":1}', good));
  await refuse(api.sendSigned("PUT", "/api/x", { a: 1 }, good));
  await refuse(api.sendSigned("PUT", "/api/x", body(), { nonce: new Uint8Array(31), proof: proof() }));
  await refuse(api.sendSigned("PUT", "/api/x", body(), { nonce: new Uint8Array(33), proof: proof() }));
  await refuse(api.sendSigned("PUT", "/api/x", body(), { nonce: nonce(), proof: new Uint8Array(63) }));
  await refuse(api.sendSigned("PUT", "/api/x", body(), { nonce: nonce(), proof: new Uint8Array(65) }));
  await refuse(api.sendSigned("PUT", "/api/x", body(), { nonce: Array.from(nonce()), proof: proof() }));
  await refuse(api.sendSigned("PUT", "/api/x", body(), { nonce: nonce() }));
  await refuse(api.sendSigned("PUT", "/api/x", body(), null));
  // The path stays on this origin.
  for (const path of ["//evil.test/x", "https://evil.test/x", "/a\\b", "/a b", "api/x", ""]) {
    await refuse(api.sendSigned("PUT", path, body(), good));
  }
  assert.equal(calls.length, 0, "nothing was sent");
});

test("send_signed_sends_a_delete_with_its_body_and_the_two_headers", async () => {
  const { calls, fetchImpl } = fakeFetch(() => json({ seq: 4 }));
  const api = createApi({ fetchImpl });
  const bytes = body();
  const answer = await api.sendSigned("DELETE", "/api/vault/unlock-methods/00112233445566778899aabbccddeeff", bytes, { nonce: nonce(), proof: proof() });
  assert.deepEqual({ ...answer }, { seq: 4 });
  const { init } = calls[0];
  assert.equal(init.method, "DELETE");
  assert.equal(init.body, bytes, "the bytes that were signed are the body of the delete");
  assert.equal(init.headers["Ferret-Nonce"], b64u.encode(nonce()));
  assert.equal(init.headers["Ferret-Proof"], b64u.encode(proof()));
  assert.equal(init.headers["Ferret-Protocol"], "1");
  assert.equal(init.redirect, "error");
});
