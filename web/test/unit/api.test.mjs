// The API client: headers, error mapping, redirects, answers that are not JSON.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { test } from "node:test";
import { ApiError, createApi } from "../../src/api.mjs";
import { b64u } from "../../src/b64.mjs";

/** A fetch that records its calls and answers from `answer(url, init)`. */
function fakeFetch(answer) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return answer(url, init);
  };
  return { calls, fetchImpl };
}

const json = (value, status = 200, headers = {}) =>
  new Response(typeof value === "string" ? value : JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });

/** Runs `promise` and returns the ApiError it rejects with. */
async function failure(promise) {
  try {
    await promise;
  } catch (error) {
    assert.ok(error instanceof ApiError, `expected an ApiError, got ${error}`);
    return error;
  }
  assert.fail("expected an ApiError");
}

test("api_adds_protocol_header_on_mutations_only", async () => {
  const { calls, fetchImpl } = fakeFetch(() => json({ ok: true }));
  const api = createApi({ fetchImpl });
  await api.get("/api/auth/session");
  await api.post("/api/auth/logout", { a: 1 });
  await api.put("/api/sync/items/00", { b: 2 });
  await api.post("/api/auth/logout");

  const [get, post, put, bare] = calls.map((c) => c.init);
  assert.equal(get.method, "GET");
  assert.equal(get.headers["Ferret-Protocol"], undefined);
  assert.equal(get.headers["Content-Type"], undefined);
  assert.equal(get.body, undefined);
  for (const [init, method] of [[post, "POST"], [put, "PUT"], [bare, "POST"]]) {
    assert.equal(init.method, method);
    assert.equal(init.headers["Ferret-Protocol"], "1");
    assert.equal(init.headers["Content-Type"], "application/json");
  }
  assert.equal(post.body, '{"a":1}');
  assert.equal(put.body, '{"b":2}');
  assert.equal(bare.body, undefined);
  // Every call: same-origin cookies, no cache, no redirect.
  for (const { init } of calls) {
    assert.equal(init.credentials, "same-origin");
    assert.equal(init.cache, "no-store");
    assert.equal(init.redirect, "error");
  }
});

test("api_sends_a_string_or_bytes_body_exactly_as_given", async () => {
  const { calls, fetchImpl } = fakeFetch(() => json({ rev: 1, seq: 2, replayed: false }));
  const api = createApi({ fetchImpl });
  // A body with its own key order and spacing, the way a first try sent it.
  const text = '{ "idem":"00112233445566778899aabbccddeeff",  "base_rev":0 }';
  const bytes = new TextEncoder().encode(text);
  await api.put("/api/sync/items/ab", text);
  await api.put("/api/sync/items/ab", bytes);
  await api.put("/api/sync/items/ab", bytes);
  assert.equal(calls[0].init.body, text);
  assert.equal(calls[1].init.body, bytes);
  assert.equal(calls[2].init.body, bytes);
  assert.deepEqual(Array.from(calls[1].init.body), Array.from(calls[2].init.body));
});

test("api_refuses_a_path_that_is_not_on_this_origin", async () => {
  const { calls, fetchImpl } = fakeFetch(() => json({}));
  const api = createApi({ fetchImpl, base: "https://vault.example" });
  for (const path of ["//evil.example/x", "https://evil.example/x", "api/x", ""]) {
    await assert.rejects(api.get(path), TypeError, JSON.stringify(path));
  }
  await api.get("/api/x");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://vault.example/api/x");
});

test("api_maps_error_body_to_api_error_code", async () => {
  const cases = [
    [400, "bad_request", true],
    [401, "unauthorized", false],
    [403, "manifest_not_writable", true],
    [403, "forbidden_origin", true],
    [404, "not_found", false],
    [413, "too_large", true],
    [413, "quota_exceeded", true],
    [422, "idem_reuse", true],
    [422, "tombstone_invalid", true],
    [422, "profile_rejected", true],
    [429, "throttled", false],
    [500, "internal", false],
  ];
  for (const [status, code, terminal] of cases) {
    const { fetchImpl } = fakeFetch(() => json({ error: code }, status));
    const error = await failure(createApi({ fetchImpl }).put("/api/sync/items/ab", "{}"));
    assert.equal(error.status, status);
    assert.equal(error.code, code);
    assert.equal(error.terminal, terminal, `${status} ${code}`);
    assert.equal(error.retryAfter, null);
    assert.ok(error instanceof Error);
  }
});

test("api_reads_the_floor_of_a_gone_feed_and_the_current_row_of_a_conflict", async () => {
  const gone = fakeFetch(() => json({ error: "gone", min_valid_since: 12 }, 410));
  const error = await failure(createApi({ fetchImpl: gone.fetchImpl }).get("/api/sync/changes?since=3"));
  assert.equal(error.code, "gone");
  assert.equal(error.status, 410);
  assert.equal(error.minValidSince, 12);
  assert.equal(error.terminal, false);

  // A 409 from an item write is the current row, not {"error": …}.
  const live = {
    current_rev: 4,
    blob: b64u.encode(new Uint8Array(40).fill(7)),
    tag: b64u.encode(new Uint8Array(32).fill(8)),
    deleted: false,
  };
  const conflict = fakeFetch(() => json(live, 409));
  const c = await failure(createApi({ fetchImpl: conflict.fetchImpl }).put("/api/sync/items/ab", "{}"));
  assert.equal(c.status, 409);
  assert.equal(c.code, "conflict");
  assert.equal(c.body.current_rev, 4);
  assert.equal(c.body.deleted, false);

  const deleted = fakeFetch(() => json({ current_rev: 5, deleted: true }, 409));
  const d = await failure(createApi({ fetchImpl: deleted.fetchImpl }).put("/api/sync/items/ab", "{}"));
  assert.equal(d.code, "conflict");
  assert.equal(d.body.deleted, true);
  assert.equal(d.body.blob, undefined);

  // A 409 with a body that is not a valid row is not trusted.
  const odd = fakeFetch(() => json({ current_rev: -1, deleted: false }, 409));
  assert.equal((await failure(createApi({ fetchImpl: odd.fetchImpl }).put("/api/x", "{}"))).code, "bad_response");

  // A 409 with {"error"} (registration is closed) keeps its code.
  const closed = fakeFetch(() => json({ error: "registration_closed" }, 409));
  assert.equal((await failure(createApi({ fetchImpl: closed.fetchImpl }).post("/api/x", {}))).code, "registration_closed");
});

test("api_does_not_trust_an_error_body_it_cannot_read", async () => {
  for (const body of [
    "<html>bad gateway</html>",
    "{}",
    '{"error":5}',
    '{"error":"Not Valid!"}',
    '{"error":"a","error":"b"}',
    "[]",
    "",
  ]) {
    const { fetchImpl } = fakeFetch(() => json(body, 502));
    const error = await failure(createApi({ fetchImpl }).get("/api/x"));
    assert.equal(error.status, 502);
    assert.equal(error.code, "bad_response", JSON.stringify(body));
  }
  const html = fakeFetch(() => new Response("<html></html>", { status: 502, headers: { "content-type": "text/html" } }));
  assert.equal((await failure(createApi({ fetchImpl: html.fetchImpl }).get("/api/x"))).code, "bad_response");
});

test("api_exposes_retry_after_on_429", async () => {
  const { fetchImpl } = fakeFetch(() => json({ error: "throttled" }, 429, { "retry-after": "17" }));
  const error = await failure(createApi({ fetchImpl }).post("/api/auth/opaque/login/start", {}));
  assert.equal(error.status, 429);
  assert.equal(error.code, "throttled");
  assert.equal(error.retryAfter, 17);
  assert.equal(error.terminal, false);

  for (const value of ["soon", "-3", "1.5", "Wed, 21 Oct 2026 07:28:00 GMT", ""]) {
    const odd = fakeFetch(() => json({ error: "throttled" }, 429, { "retry-after": value }));
    const e = await failure(createApi({ fetchImpl: odd.fetchImpl }).get("/api/x"));
    assert.equal(e.retryAfter, null, JSON.stringify(value));
  }
});

test("api_never_follows_redirects", async () => {
  // The call asks for a redirect to be an error ...
  const { calls, fetchImpl } = fakeFetch(() => json({}));
  await createApi({ fetchImpl }).get("/api/x");
  assert.equal(calls[0].init.redirect, "error");

  // ... a fetch that refuses one is a network error ...
  const refused = fakeFetch(() => {
    throw new TypeError("redirect mode is set to error");
  });
  const e1 = await failure(createApi({ fetchImpl: refused.fetchImpl }).get("/api/x"));
  assert.equal(e1.code, "network");
  assert.equal(e1.status, 0);

  // ... and an answer that is a redirect anyway is not used.
  const moved = fakeFetch(() => new Response(null, { status: 302, headers: { location: "https://evil.example/" } }));
  const e2 = await failure(createApi({ fetchImpl: moved.fetchImpl }).get("/api/x"));
  assert.equal(e2.code, "bad_response");
  assert.equal(e2.status, 302);
  const followed = fakeFetch(() => {
    const response = json({ error: "x" });
    Object.defineProperty(response, "redirected", { value: true });
    return response;
  });
  assert.equal((await failure(createApi({ fetchImpl: followed.fetchImpl }).get("/api/x"))).code, "bad_response");
});

test("api_never_follows_redirects_with_the_real_fetch", async () => {
  let hits = 0;
  const server = createServer((request, response) => {
    hits += 1;
    if (request.url === "/other") {
      response.writeHead(200, { "content-type": "application/json" }).end('{"followed":true}');
    } else {
      response.writeHead(302, { location: "/other" }).end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    const error = await failure(createApi({ base }).get("/start"));
    assert.equal(error.code, "network");
    assert.equal(hits, 1, "the redirect target was not requested");
  } finally {
    server.close();
  }
});

test("api_rejects_non_json_responses", async () => {
  const wrong = [
    new Response("ok", { status: 200, headers: { "content-type": "text/plain" } }),
    new Response("<html></html>", { status: 200, headers: { "content-type": "text/html; charset=utf-8" } }),
    new Response('{"a":1}', { status: 200 }),
    new Response('{"a":1}', { status: 200, headers: { "content-type": "application/jsonp" } }),
  ];
  for (const response of wrong) {
    const { fetchImpl } = fakeFetch(() => response);
    const error = await failure(createApi({ fetchImpl }).get("/api/x"));
    assert.equal(error.code, "bad_response");
    assert.equal(error.status, 200);
  }
  // JSON that the strict reader refuses: a repeated field, a fraction, a big number.
  for (const body of ['{"a":1,"a":2}', '{"a":1.5}', '{"a":9007199254740992}', "not json", ""]) {
    const { fetchImpl } = fakeFetch(() => json(body));
    assert.equal((await failure(createApi({ fetchImpl }).get("/api/x"))).code, "bad_response", body);
  }
  // A JSON answer, with a charset or in capitals, is fine; 204 has no body.
  const fine = fakeFetch(() => json({ a: 1 }, 200, { "content-type": "Application/JSON; charset=utf-8" }));
  assert.deepEqual({ ...(await createApi({ fetchImpl: fine.fetchImpl }).get("/api/x")) }, { a: 1 });
  const none = fakeFetch(() => new Response(null, { status: 204 }));
  assert.equal(await createApi({ fetchImpl: none.fetchImpl }).post("/api/auth/logout"), null);
});

test("api_checks_an_answer_against_its_wire_shape_when_asked", async () => {
  const good = { account_id: "00112233445566778899aabbccddeeff", email: "a@example.org", scope: "full", origin: "vault" };
  const { fetchImpl } = fakeFetch(() => json(good));
  const api = createApi({ fetchImpl });
  assert.equal((await api.get("/api/auth/session", { shape: "session_res" })).email, "a@example.org");
  await assert.rejects(api.get("/api/auth/session", { shape: "no_such_shape" }), TypeError);

  const bad = fakeFetch(() => json({ ...good, extra: 1 }));
  const error = await failure(createApi({ fetchImpl: bad.fetchImpl }).get("/api/auth/session", { shape: "session_res" }));
  assert.equal(error.code, "bad_response");
});
