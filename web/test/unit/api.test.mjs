// The API client: headers, error mapping, redirects, answers that are not JSON.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { join } from "node:path";
import { test } from "node:test";
import { ApiError, createApi } from "../../src/api.mjs";
import { b64u } from "../../src/b64.mjs";
import { SERVER_HEADERS_JSON } from "../serve.mjs";

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
  const bs = String.fromCharCode(92);
  const paths = [
    "//evil.example/x",
    "https://evil.example/x",
    "api/x",
    "",
    // A URL parser reads these as another host.
    `/${bs}evil.example/x`,
    "/\t/evil.example/x",
    "/\n/evil.example/x",
    "/\r/evil.example/x",
    "/ /evil.example/x",
    `/a${bs}b`,
    "/a\u0000b",
    "/a\u007fb",
    "/a\u0085b",
    "/a b",
    null,
    42,
  ];
  for (const path of paths) {
    await assert.rejects(api.get(path), TypeError, JSON.stringify(path));
  }
  assert.equal(calls.length, 0, "nothing was sent");
  await api.get("/api/x");
  await api.get("/api/sync/changes?since=3&limit=500");
  assert.equal(calls.length, 2);
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

test("api_checks_the_form_of_a_conflict_answer", async () => {
  const blob = b64u.encode(new Uint8Array(40).fill(7));
  const tag = b64u.encode(new Uint8Array(32).fill(8));
  for (const body of [
    { current_rev: 2, deleted: false }, // live without its row
    { current_rev: 2, deleted: false, blob },
    { current_rev: 2, deleted: true, blob, tag }, // deleted with a row
    { current_rev: 2, deleted: true, tag },
  ]) {
    const { fetchImpl } = fakeFetch(() => json(body, 409));
    const error = await failure(createApi({ fetchImpl }).put("/api/sync/items/ab", "{}"));
    assert.equal(error.code, "bad_response", JSON.stringify(body));
  }
});

// The status of every code, from the table both sides read: the client decides
// what to do with an error from its status, so a code that moves to another
// status in the server must show up here.
test("api_handles_every_error_code_with_the_status_the_server_gives_it", async () => {
  const dir = join(SERVER_HEADERS_JSON, "..");
  const statuses = JSON.parse(readFileSync(join(dir, "error_statuses.json"), "utf8"));
  const codes = JSON.parse(readFileSync(join(dir, "error_codes.json"), "utf8"));
  assert.deepEqual(Object.keys(statuses), codes, "same codes in the same order");
  const TERMINAL = [400, 403, 413, 422];
  for (const code of codes) {
    const status = statuses[code];
    assert.ok(Number.isInteger(status) && status >= 400 && status <= 599, `${code}: ${status}`);
    if (code === "conflict") continue; // a 409 conflict has the current row as its body, tested above
    const { fetchImpl } = fakeFetch(() => json({ error: code }, status));
    const error = await failure(createApi({ fetchImpl }).put("/api/sync/items/ab", "{}"));
    assert.equal(error.status, status, code);
    assert.equal(error.code, code);
    assert.equal(error.terminal, TERMINAL.includes(status), `${code} (${status})`);
  }
  // The codes the sync engine may retry: every code whose status is not terminal (this includes 5xx).
  const retryable = codes.filter((code) => !TERMINAL.includes(statuses[code]));
  assert.deepEqual(retryable, [
    "unauthorized", "denied", "registration_closed", "throttled", "conflict", "not_found", "internal", "gone", "busy",
    "checkpoint_stale",
  ]);
});

// ------------------------------------------------------------------- stream

const eventStream = (body = "", status = 200, headers = {}) =>
  new Response(body, { status, headers: { "content-type": "text/event-stream", ...headers } });

test("api_stream_gives_the_reader_of_a_200_event_stream_and_sends_the_right_request", async () => {
  const { calls, fetchImpl } = fakeFetch(() => eventStream("event: hello\ndata: {}\n\n"));
  const controller = new AbortController();
  const reader = await createApi({ fetchImpl, base: "https://vault.example" }).stream("/api/sync/events", { signal: controller.signal });
  assert.equal(typeof reader.read, "function");
  const { value } = await reader.read();
  assert.equal(new TextDecoder().decode(value), "event: hello\ndata: {}\n\n");

  const { url, init } = calls[0];
  assert.equal(url, "https://vault.example/api/sync/events");
  assert.equal(init.method, "GET");
  assert.equal(init.credentials, "same-origin");
  assert.equal(init.cache, "no-store");
  assert.equal(init.redirect, "error");
  assert.equal(init.headers["Ferret-Protocol"], "1");
  assert.equal(init.headers.Accept, "text/event-stream");
  assert.equal(init.signal, controller.signal, "the caller's signal, with no time limit of ours");

  // The media type may carry parameters and any case.
  const loose = fakeFetch(() => eventStream("", 200, { "content-type": "Text/Event-Stream; charset=utf-8" }));
  assert.ok(await createApi({ fetchImpl: loose.fetchImpl }).stream("/api/sync/events"));
  assert.equal(loose.calls[0].init.signal, undefined, "no signal when none was given");

  // A path that leaves the origin is refused before anything is sent.
  const sent = fakeFetch(() => eventStream());
  await assert.rejects(createApi({ fetchImpl: sent.fetchImpl }).stream("//evil.example/api/sync/events"), TypeError);
  await assert.rejects(createApi({ fetchImpl: sent.fetchImpl }).stream("/\\evil.example"), TypeError);
  assert.equal(sent.calls.length, 0);
});

test("api_stream_refuses_a_non_event_stream_answer_and_never_follows_redirects", async () => {
  const cancelled = [];
  /** A response whose body says when it has been dropped. */
  const withBody = (status, type, headers = {}) =>
    new Response(
      new ReadableStream({
        start: (c) => c.enqueue(new TextEncoder().encode("x")),
        cancel: () => void cancelled.push(status),
      }),
      { status, headers: { "content-type": type, ...headers } },
    );

  // A 200 that is not an event stream: a proxy page, JSON, or no type at all.
  for (const type of ["text/html", "application/json", "text/plain", "application/octet-stream"]) {
    const { fetchImpl } = fakeFetch(() => withBody(200, type));
    const error = await failure(createApi({ fetchImpl }).stream("/api/sync/events"));
    assert.equal(error.code, "bad_response", type);
    assert.equal(error.status, 200);
  }
  const bare = fakeFetch(() => new Response("x", { status: 200 }));
  assert.equal((await failure(createApi({ fetchImpl: bare.fetchImpl }).stream("/api/sync/events"))).code, "bad_response");
  // An event stream with no body cannot be read.
  const empty = fakeFetch(() => new Response(null, { status: 200, headers: { "content-type": "text/event-stream" } }));
  assert.equal((await failure(createApi({ fetchImpl: empty.fetchImpl }).stream("/api/sync/events"))).code, "bad_response");
  // A success that is not a 200 is no stream either, even with the right type.
  for (const status of [202, 206]) {
    const { fetchImpl } = fakeFetch(() => withBody(status, "text/event-stream"));
    assert.equal((await failure(createApi({ fetchImpl }).stream("/api/sync/events"))).code, "bad_response", `${status}`);
  }
  await new Promise((resolve) => setImmediate(resolve));
  assert.ok(cancelled.length >= 6, "the bodies that were refused are dropped");

  // A redirect is an error: the request asks for that, a fetch that refuses is a network error, and an answer that is one anyway is not used.
  const { calls, fetchImpl } = fakeFetch(() => eventStream());
  await createApi({ fetchImpl }).stream("/api/sync/events");
  assert.equal(calls[0].init.redirect, "error");
  const refused = fakeFetch(() => {
    throw new TypeError("redirect mode is set to error");
  });
  const e1 = await failure(createApi({ fetchImpl: refused.fetchImpl }).stream("/api/sync/events"));
  assert.deepEqual([e1.status, e1.code], [0, "network"]);
  const moved = fakeFetch(() => new Response(null, { status: 302, headers: { location: "https://evil.example/" } }));
  const e2 = await failure(createApi({ fetchImpl: moved.fetchImpl }).stream("/api/sync/events"));
  assert.deepEqual([e2.status, e2.code], [302, "bad_response"]);
  const followed = fakeFetch(() => {
    const response = eventStream();
    Object.defineProperty(response, "redirected", { value: true });
    return response;
  });
  assert.equal((await failure(createApi({ fetchImpl: followed.fetchImpl }).stream("/api/sync/events"))).code, "bad_response");

  // An abort is told apart from a network error.
  const stop = new AbortController();
  const aborting = fakeFetch(() => {
    stop.abort();
    throw new DOMException("aborted", "AbortError");
  });
  assert.equal((await failure(createApi({ fetchImpl: aborting.fetchImpl }).stream("/api/sync/events", { signal: stop.signal }))).code, "aborted");
});

test("api_stream_maps_the_error_answers_of_the_event_route", async () => {
  const cases = [
    [401, { error: "unauthorized" }, {}, "unauthorized", null],
    [429, { error: "throttled" }, { "retry-after": "30" }, "throttled", 30],
    [400, { error: "protocol_header_missing" }, {}, "protocol_header_missing", null],
    [403, { error: "forbidden_origin" }, {}, "forbidden_origin", null],
  ];
  for (const [status, body, headers, code, retryAfter] of cases) {
    const { fetchImpl } = fakeFetch(() => json(body, status, headers));
    const error = await failure(createApi({ fetchImpl }).stream("/api/sync/events"));
    assert.deepEqual([error.status, error.code, error.retryAfter], [status, code, retryAfter]);
  }
  // A proxy's page for an error is not an answer we can read.
  const page = fakeFetch(() => new Response("<html>502</html>", { status: 502, headers: { "content-type": "text/html" } }));
  assert.equal((await failure(createApi({ fetchImpl: page.fetchImpl }).stream("/api/sync/events"))).code, "bad_response");
  const odd = fakeFetch(() => json("not an object", 500));
  assert.equal((await failure(createApi({ fetchImpl: odd.fetchImpl }).stream("/api/sync/events"))).code, "bad_response");
});

test("api_stream_reads_a_real_event_stream_and_ends_with_the_signal", async () => {
  const server = createServer((request, response) => {
    if (request.url !== "/api/sync/events") {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store, no-transform" });
    response.write('event: hello\ndata: {"seq":3}\n\n');
    // The stream stays open until the client goes.
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    const controller = new AbortController();
    const reader = await createApi({ base }).stream("/api/sync/events", { signal: controller.signal });
    const { value } = await reader.read();
    assert.equal(new TextDecoder().decode(value), 'event: hello\ndata: {"seq":3}\n\n');
    const next = reader.read();
    controller.abort();
    await assert.rejects(next);
  } finally {
    server.closeAllConnections();
    server.close();
  }
});
